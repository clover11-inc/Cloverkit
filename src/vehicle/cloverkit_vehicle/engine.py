"""One cancellable adapter owner, shared state, scan evidence and bounded live data."""
import collections, copy, json, math, os, queue, secrets, subprocess, sys, threading, time, uuid
from pathlib import Path
from . import __version__,subprocess_environment
from .adapters import BluetoothSerial, usb_adapters
from .reference import Reference
from .storage import Storage, atomic_json
from .traffic import Journal,event,GETTERS,read_command

def identity():return uuid.uuid4().hex
def unavailable(state='no_response',detail=''):return dict(time=time.time(),state=state,value=None,unit='',ecu='unknown',detail=detail)

class Worker:
    def __init__(self):
        self.event_callback=None
        self.process=subprocess.Popen([sys.executable,'-m','cloverkit_vehicle.backend'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1,env=subprocess_environment())
        self.replies=queue.Queue(maxsize=2)
        def read():
            for line in self.process.stdout:
                try:
                    reply=json.loads(line)
                    if 'traffic' in reply:
                        if self.event_callback:self.event_callback(reply['traffic'])
                        continue
                    self.replies.put(reply,timeout=1)
                except (ValueError,queue.Full):break
            try:self.replies.put(dict(ok=False,error='Adapter worker disconnected'),timeout=1)
            except queue.Full:pass
        self.reader=threading.Thread(target=read,daemon=True);self.reader.start()
    def call(self,op,cancel=None,timeout=12,**fields):
        if self.process.poll() is not None:raise ConnectionError('Adapter worker stopped')
        try:self.process.stdin.write(json.dumps(dict(op=op,**fields))+'\n');self.process.stdin.flush()
        except (BrokenPipeError,OSError):raise ConnectionError('Adapter worker disconnected')
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            if cancel is not None and cancel.is_set():self.close();raise InterruptedError('Cancelled')
            try:reply=self.replies.get(timeout=.1)
            except queue.Empty:continue
            if not reply['ok']:
                if op=='terminal' and reply.get('error_type')=='ValueError':raise ValueError(reply['error'])
                raise ConnectionError(reply['error'])
            return reply['result']
        self.close();raise TimeoutError('Adapter timed out; check connection and ignition, then reconnect')
    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=3)
        for stream in (self.process.stdin,self.process.stdout):
            if stream:stream.close()
        if threading.current_thread()!=self.reader:self.reader.join(timeout=2)

class Demo:
    """Deterministic simulated data; no transport or code-clear operation."""
    def __init__(self):self.tick=0
    def call(self,op,cancel=None,timeout=12,**fields):
        if cancel and cancel.is_set():raise InterruptedError('Cancelled')
        if op=='trace':return {'enabled':bool(fields.get('enabled'))}
        if op=='terminal':
            candidates={'RPM':'010C','SPEED':'010D','COOLANT_TEMP':'0105','THROTTLE_POS':'0111','GET_DTC':'03','GET_CURRENT_DTC':'07','PERMANENT_DTC':'0A','ELM_VERSION':'ATI','ELM_VOLTAGE':'ATRV'}
            name=read_command(fields.get('command',''),candidates)
            if name not in candidates:raise ValueError('Adapter getter not simulated in Demo')
            return dict(command=candidates[name],parameter=name,responses=self.call('query',name=name),read_only=True,demo=True)
        if op=='clear':raise ValueError('Code clearing is disabled in demo')
        if op=='connect':
            names=['RPM','SPEED','COOLANT_TEMP','THROTTLE_POS','SHORT_FUEL_TRIM_1','ELM_VOLTAGE','STATUS','VIN','GET_DTC','GET_CURRENT_DTC','PERMANENT_DTC','DTC_RPM','DTC_COOLANT_TEMP','CALIBRATION_ID','CVN']
            return dict(protocol='DEMO ISO 15765-4 CAN',protocol_id='6',library='CloverKit deterministic simulator',adapter='DEMO',
                        supported=[dict(id=n,label=n.replace('_',' ').title(),mode=2 if n.startswith('DTC_') else 1 if n in names[:7] else 9,advertised=True) for n in names])
        name=fields.get('name');self.tick+=1;t=self.tick
        values={'RPM':(800+round(300*math.sin(t/7)), 'revolutions_per_minute'),'SPEED':(0,'kilometer_per_hour'),
                'COOLANT_TEMP':(87,'degree_Celsius'),'THROTTLE_POS':(12+round(4*math.sin(t/5),1),'percent'),
                'SHORT_FUEL_TRIM_1':(4.5,'percent'),'ELM_VOLTAGE':(13.8,'volt'),
                'STATUS':({'MIL':True,'DTC_count':1,'ignition_type':'spark','MISFIRE_MONITORING':{'available':True,'complete':True},'CATALYST_MONITORING':{'available':True,'complete':False}},''),
                'VIN':('DEMO-NOT-A-REAL-VIN',''),'GET_DTC':([['P0301','Cylinder 1 misfire detected']],''),
                'GET_CURRENT_DTC':([['P0171','System too lean (bank 1)']],''),'PERMANENT_DTC':([],''),
                'DTC_RPM':(2140,'revolutions_per_minute'),'DTC_COOLANT_TEMP':(91,'degree_Celsius'),
                'CALIBRATION_ID':('DEMO-CAL-1',''),'CVN':('DEADBEEF',''),'ELM_VERSION':('DEMO ELM simulator','')}
        if name not in values:return [unavailable('unsupported')]
        value,unit=values[name]
        return [dict(time=time.time(),state='measured',value=value,unit=unit,ecu='0x7e8')]
    def close(self):pass

class Engine:
    def __init__(self,root=None,worker_factory=Worker):
        self.storage=Storage(root);self.reference=Reference();self.worker_factory=worker_factory
        self.lock=threading.RLock();self.cancel=threading.Event();self.jobs=queue.Queue(maxsize=12)
        self.traffic=Journal(self.storage.root);self.terminal_results=collections.OrderedDict()
        self.backend=None;self.bluetooth=None;self.selected=[];self.recording=None;self.history={};self.clear_ticket=None
        self.state=dict(schema=1,version=__version__,state='disconnected',demo=False,progress='Choose an adapter or Demo',
                        vehicle={'id':identity(),'nickname':'Unidentified vehicle','make':''},supported=[],live={},scan=None,error='',recording=None)
        self.stopped=threading.Event();self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
    def update(self,**fields):
        with self.lock:self.state.update(fields)
    def snapshot(self):
        with self.lock:state=copy.deepcopy(self.state);state['history']=copy.deepcopy(self.history)
        now=time.time();state['server_time']=now
        state['traffic_enabled']=self.traffic.enabled
        for reading in state['live'].values():
            if reading['state']=='measured' and state['state'] not in ('connected','scanning'):reading['state']='disconnected'
            elif reading['state']=='measured' and now-reading['time']>5:reading['state']='stale'
            reading['age_seconds']=max(0,round(now-reading['time'],1))
        return state
    def submit(self,op,**fields):
        if op in ('cancel','disconnect'):
            self.cancel.set()
            if op=='cancel':return dict(accepted=True)
        if self.jobs.full():raise ValueError('An operation is already queued; wait or cancel')
        self.jobs.put_nowait((op,fields));return dict(accepted=True)
    def run(self):
        while not self.stopped.is_set():
            try:op,fields=self.jobs.get(timeout=.15)
            except queue.Empty:
                if self.backend and self.selected:
                    try:self.poll()
                    except Exception as e:self.failure(e)
                continue
            try:
                if op!='disconnect':self.cancel.clear()
                if op=='connect':self.connect(**fields)
                elif op=='demo':self.connect(demo=True)
                elif op=='disconnect':
                    from .ssh_access import revoke
                    revoke();self.disconnect()
                elif op=='scan':self.scan()
                elif op=='select':self.select(**fields)
                elif op=='vehicle':self.vehicle(**fields)
                elif op=='record':self.record(**fields)
                elif op=='prepare_clear':self.prepare_clear()
                elif op=='clear':self.clear(**fields)
                elif op=='raw':self.update(raw_logging=bool(fields.get('enabled')))
                elif op=='trace':self.trace(bool(fields.get('enabled')))
                elif op=='terminal':self.terminal(**fields)
                elif op=='reconnect':
                    options=self.state.get('connection',{}).copy()
                    if not options:raise ValueError('Select an adapter first')
                    self.connect(**options)
                else:raise ValueError('Unknown diagnostic operation')
            except Exception as e:self.failure(e)
    def failure(self,e):
        if self.state['state']=='connecting' or isinstance(e,(InterruptedError,ConnectionError,TimeoutError,OSError)):
            self.disconnect();self.update(state='cancelled' if isinstance(e,InterruptedError) else 'disconnected')
        self.update(error=str(e)[:1200],progress='Operation ended: '+str(e)[:180])
    def disconnect(self):
        self.record(False)
        if self.backend:self.backend.close()
        self.backend=None
        if self.bluetooth:
            try:self.bluetooth.close()
            except (ValueError,OSError):pass
            self.bluetooth=None
        self.selected=[];self.clear_ticket=None
        self.update(state='disconnected',progress='Disconnected; saved evidence retained',recording=None,clear_confirmation=None)
    def connect(self,adapter=None,transport='usb',baud=38400,demo=False):
        self.disconnect();self.cancel.clear();self.history={}
        self.update(state='connecting',progress='Checking selected adapter, protocol and supported parameters',error='',demo=demo,live={},scan=None,supported=[])
        if demo:
            self.backend=Demo();info=self.backend.call('connect');options={'demo':True}
        else:
            if transport=='usb':
                selected=next((p for p in usb_adapters() if p['id']==adapter),None)
                if not selected:raise ValueError('Selected USB adapter is missing; refresh the adapter list')
                port=selected['device']
            elif transport=='bluetooth':
                self.bluetooth=BluetoothSerial(adapter);port=self.bluetooth.open()
            else:raise ValueError('Supported transports: USB or Bluetooth Classic SPP')
            self.backend=self.worker_factory();self.backend.event_callback=lambda row:self.traffic.capture(row,demo=False)
            self.backend.call('trace',enabled=self.traffic.enabled,cancel=self.cancel)
            info=self.backend.call('connect',port=port,baud=int(baud),timeout=90,cancel=self.cancel)
            options=dict(adapter=adapter,transport=transport,baud=baud)
            atomic_json(self.storage.root/'adapter.json',options)
        self.update(state='connected',progress='Connected — scan engine / emissions or select live values',connection=options,**info)
        self.vehicle(nickname='Demo vehicle' if demo else 'Unidentified vehicle',new=True)
        self.select(['RPM','SPEED','COOLANT_TEMP','THROTTLE_POS'])
    def vehicle(self,nickname=None,make=None,vehicle_id=None,new=False):
        old=self.state['vehicle'].copy()
        if new:old=dict(id=identity(),nickname='Unidentified vehicle',make='')
        if vehicle_id:
            saved=next((s for s in self.storage.list() if s['vehicle']==vehicle_id and s['demo']==self.state['demo']),None)
            if not saved:raise ValueError('Choose a saved vehicle in the same real/demo mode')
            old=self.storage.get(saved['id'])['vehicle'].copy()
        if nickname is not None:old['nickname']=str(nickname).strip()[:80] or 'Unidentified vehicle'
        if make is not None:
            make=str(make).upper().strip()
            if make and make not in self.reference.catalog()['counts']['makes']:raise ValueError('Manufacturer not in the bundled reference catalog; leave blank for generic codes')
            old['make']=make
        if self.recording:raise ValueError('Stop recording before changing vehicle identity')
        self.update(vehicle=old)
    def query(self,name):
        if not self.backend:raise ValueError('Connect to a vehicle or choose Demo')
        if self.cancel.is_set():raise InterruptedError('Cancelled')
        result=self.backend.call('query',name=name,cancel=self.cancel)
        if self.state['demo'] and self.traffic.enabled:
            self.traffic.capture(event('TX',('DEMO '+name+'\r').encode()),demo=True)
            self.traffic.capture(event('RX',(json.dumps(result)+'\r>').encode()),demo=True)
        if self.state.get('raw_logging'):
            path=self.storage.root/'adapter-raw.jsonl'
            if path.exists() and path.stat().st_size>2_000_000:
                backup=path.with_suffix('.previous.jsonl');os.replace(path,backup)
            with open(path,'a',encoding='utf-8') as stream:stream.write(json.dumps(dict(time=time.time(),parameter=name,responses=result))+'\n')
            path.chmod(0o600)
        return result
    def trace(self,enabled=True):
        self.traffic.enabled=enabled
        if self.backend:self.backend.call('trace',enabled=enabled,cancel=self.cancel)
        self.update(traffic_enabled=enabled)
    def terminal(self,command='',request_id=''):
        try:
            if not self.backend:raise ValueError('Connect to a vehicle or choose Demo first')
            if not self.traffic.enabled:self.trace(True)
            result=self.backend.call('terminal',command=command,cancel=self.cancel)
            if self.state['demo']:
                self.traffic.capture(event('TX',(result['command']+'\r').encode()),demo=True)
                self.traffic.capture(event('RX',(json.dumps(result['responses'])+'\r>').encode()),demo=True)
            reply=dict(id=request_id,state='complete',result=result,time=time.time())
        except Exception as exc:
            reply=dict(id=request_id,state='error',error=str(exc),time=time.time())
            with self.lock:self.terminal_results[request_id]=reply
            if isinstance(exc,(ConnectionError,TimeoutError,InterruptedError)):raise
        with self.lock:
            self.terminal_results[request_id]=reply
            while len(self.terminal_results)>40:self.terminal_results.popitem(last=False)
    def terminal_result(self,key):
        with self.lock:return copy.deepcopy(self.terminal_results.get(key,dict(id=key,state='pending')))
    def select(self,parameters):
        if not isinstance(parameters,list) or len(parameters)>24:raise ValueError('Select up to 24 live parameters per polling cycle')
        supported={c['id'] for c in self.state['supported'] if c.get('mode')==1 or c['id']=='ELM_VOLTAGE'}
        self.selected=list(dict.fromkeys(p for p in parameters if p in supported))
        self.update(selected=self.selected)
    def poll(self):
        for name in list(self.selected):
            for reading in self.query(name):
                key=name+'@'+reading.get('ecu','unknown')
                with self.lock:
                    self.state['live'][key]=dict(reading,parameter=name)
                    history=self.history.setdefault(key,[])
                    history.append(dict(time=reading['time'],value=reading.get('value'),state=reading['state']));del history[:-120]
                if self.recording:self.storage.append(self.recording,name,reading)
            if not self.jobs.empty() or self.stopped.wait(.1):return
    def scan(self):
        if not self.backend:raise ValueError('Connect to a vehicle or choose Demo')
        scan=dict(schema=1,app_version=__version__,id=identity(),created_at=time.time(),demo=self.state['demo'],
                  vehicle=self.state['vehicle'].copy(),adapter=self.state.get('adapter'),connection=self.state.get('connection'),
                  protocol=self.state.get('protocol'),codes=[],coverage={},freeze_frames={},readiness=[],vehicle_info={},monitors={},
                  scope='Standard engine / emissions. Other modules and overall vehicle health not assessed.',complete=False)
        requests=['STATUS','GET_DTC','GET_CURRENT_DTC','PERMANENT_DTC','VIN','CALIBRATION_ID','CVN','ELM_VOLTAGE']
        requests += [c['id'] for c in self.state['supported'] if c.get('mode') in (2,6) and c.get('advertised') and not c['id'].startswith(('PIDS_','MIDS_','DTC_PIDS_'))]
        statuses={'GET_DTC':'stored','GET_CURRENT_DTC':'pending','PERMANENT_DTC':'permanent'}
        self.update(state='scanning',scan=copy.deepcopy(scan),error='')
        try:
            for index,name in enumerate(dict.fromkeys(requests)):
                self.update(progress=f'Scan {index+1}/{len(requests)} · '+name)
                results=self.query(name) if name in {c['id'] for c in self.state['supported']} else [unavailable('unsupported')]
                scan['coverage'][name]=copy.deepcopy(results)
                for r in results:
                    if r['state']!='measured':continue
                    if name in statuses:
                        for value in r['value'] or []:
                            if not isinstance(value,(tuple,list)) or not value:continue
                            code=self.reference.describe(value[0],scan['vehicle'].get('make',''))
                            scan['codes'].append(dict(code,status=statuses[name],ecu=r.get('ecu','unknown'),time=r['time']))
                    elif name=='STATUS':scan['readiness'].append(r)
                    elif name.startswith('DTC_'):scan['freeze_frames'].setdefault(name,[]).append(r)
                    elif name.startswith('MONITOR_'):scan['monitors'].setdefault(name,[]).append(r)
                    else:scan['vehicle_info'].setdefault(name,[]).append(r)
                self.update(scan=copy.deepcopy(scan))
            vin=next((r['value'] for r in scan['vehicle_info'].get('VIN',[]) if isinstance(r['value'],str) and len(r['value'])==17 and not scan['demo']),None)
            if vin:
                scan['vehicle']['vin']=vin;scan['vehicle']['id']='vin:'+vin
                self.update(vehicle=scan['vehicle'].copy())
            scan['complete']=True;self.update(state='connected',progress='Scan complete — coverage and unavailable checks retained')
        finally:
            scan['ended_at']=time.time();self.storage.save(scan);self.update(scan=copy.deepcopy(scan))
    def record(self,enabled=True):
        if not enabled:
            if self.recording:self.storage.end_recording(self.recording)
            self.recording=None
        elif not self.backend:raise ValueError('Connect before recording')
        elif not self.recording:
            self.recording=identity();self.storage.begin_recording(self.recording,self.state['vehicle']['id'],self.state['demo'])
        self.update(recording=self.recording)
    def prepare_clear(self):
        if self.state['demo']:raise ValueError('Code clearing is disabled in Demo')
        if not self.backend:raise ValueError('Connect first')
        self.clear_ticket=None;self.update(clear_confirmation=None)
        self.scan()  # Always save fresh pre-clear evidence before offering the confirmation.
        self.clear_ticket=dict(token=secrets.token_urlsafe(20),expires=time.monotonic()+90,scan=self.state['scan']['id'])
        self.update(clear_confirmation=dict(token=self.clear_ticket['token'],preclear_scan=self.clear_ticket['scan'],
                    warning='Clearing can erase codes and freeze frames and reset readiness. Permanent codes cannot be erased on demand.'))
    def clear(self,token='',confirm=''):
        ticket=self.clear_ticket;self.clear_ticket=None;self.update(clear_confirmation=None)
        if self.state['demo'] or not ticket or time.monotonic()>ticket['expires'] or not secrets.compare_digest(str(token),ticket['token']) or confirm!='CLEAR ENGINE CODES':
            raise ValueError('Fresh explicit confirmation required; no clear request sent')
        result=self.backend.call('clear',cancel=self.cancel);self.update(clear_result=result,progress='Clear acknowledged; rescanning to verify');self.scan()
    def close(self):
        from .ssh_access import revoke
        revoke()
        self.cancel.set();self.stopped.set();self.thread.join(timeout=5)
        if self.thread.is_alive() and self.backend:self.backend.close();self.thread.join(timeout=5)
        self.disconnect()
