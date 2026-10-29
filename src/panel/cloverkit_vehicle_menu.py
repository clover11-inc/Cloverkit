"""CloverKit menu integration. Slow adapter work never runs on the panel thread."""
import threading,time
import sys
from pathlib import Path
from urllib.parse import urlencode
from cloverkit_vehicle_readable import label, entries, code_detail, page as detail_page, SECTIONS

def install(Panel,namespace):
    base=Path('/usr/local/lib/cloverkit/vehicle')
    if not base.exists():base=Path(__file__).resolve().parents[1]/'vehicle'
    for folder in (base,base/'vendor'):
        if str(folder) not in sys.path:sys.path.insert(0,str(folder))
    from cloverkit_vehicle.client import ensure,request
    from cloverkit_vehicle.presentation import compact
    old_items,old_lines,old_handle=Panel.items,Panel.lines,Panel.handle
    if 'Vehicle Diagnostics' not in Panel.HOME:Panel.HOME.insert(Panel.HOME.index('Game Boy'),'Vehicle Diagnostics')
    pages={'Vehicle Diagnostics','Vehicle connect','Vehicle codes','Vehicle live','Vehicle reports','Vehicle setup','Vehicle parameters','Vehicle clear','Vehicle evidence','Vehicle code details','Vehicle explanation','Vehicle section','Vehicle reading','Vehicle remote access','Vehicle traffic','Vehicle traffic history'}
    def start(panel,operation=None,**fields):
        if getattr(panel,'_vehicle_pending',False):panel.message='Vehicle operation pending';return
        panel._vehicle_pending=True
        def work():
            try:
                ensure()
                if operation:request('/api/action',dict(op=operation,**fields))
                panel._vehicle_state=request();panel._vehicle_saved=request('/api/saved')
                if panel.page in ('Vehicle traffic','Vehicle traffic history'):panel._vehicle_traffic=request('/api/traffic?tail=1&limit=500')
                if panel.page in ('Vehicle connect','Vehicle setup') and (time.monotonic()-getattr(panel,'_vehicle_adapter_time',0)>20):
                    panel._vehicle_adapters=request('/api/adapters',timeout=8);panel._vehicle_adapter_time=time.monotonic()
                panel._vehicle_error=''
            except Exception as e:panel._vehicle_error=str(e)[:300]
            finally:panel._vehicle_pending=False;panel._vehicle_updated=time.monotonic()
        threading.Thread(target=work,daemon=True).start()
    def state(panel):return getattr(panel,'_vehicle_state',{})
    def items(panel,data):
        if panel.page not in pages:return old_items(panel,data)
        if panel.page=='Vehicle Diagnostics':return ['Connect to vehicle','Read fault codes','Live readings','Vehicle information & readiness','Saved reports','Adapter setup','Demo','Disconnect','Clear fault codes','Remote access & data flow','Return']
        if panel.page=='Vehicle remote access':return ['View adapter traffic','Return']
        if panel.page=='Vehicle traffic':return ['Pause traffic capture' if state(panel).get('traffic_enabled') else 'Start traffic capture','View traffic history','Remote access instructions','Return']
        if panel.page=='Vehicle traffic history':return []
        if panel.page=='Vehicle connect':
            adapters=getattr(panel,'_vehicle_adapters',{})
            return [*[a['label']+' · '+a['device'] for a in adapters.get('usb',[])],*[a['label']+' · '+a['id'] for a in adapters.get('bluetooth',{}).get('devices',[])],'Refresh adapters','Bluetooth discovery / pairing','Reconnect selected adapter','Return']
        if panel.page=='Vehicle codes':return [*[c['code']+' - '+c.get('description','Definition unavailable')+' ('+c['status']+')' for c in (state(panel).get('scan') or {}).get('codes',[])],'Readings & emissions readiness','Read fault codes again','Clear fault codes','Return']
        if panel.page=='Vehicle live':return ['Select readings','Stop recording' if state(panel).get('recording') else 'Start recording','Refresh','Return']
        if panel.page=='Vehicle parameters':return [('✓ ' if c['id'] in state(panel).get('selected',[]) else '+ ')+c['label'] for c in state(panel).get('supported',[]) if c.get('mode')==1 or c['id']=='ELM_VOLTAGE']+['Return']
        if panel.page=='Vehicle reports':return [('DEMO ' if s['demo'] else '')+time.strftime('%d %b %H:%M',time.localtime(s['created']))+' '+s['vehicle'] for s in getattr(panel,'_vehicle_saved',[])]+['Refresh reports','Return']
        if panel.page=='Vehicle clear':return ['Cancel / keep evidence','Confirm clear engine codes']
        if panel.page=='Vehicle code details':return ['What this code means','Possible causes','Readings when a fault occurred','What to check next','Definition sources','Return']
        if panel.page=='Vehicle evidence':return [name for name,key in SECTIONS]+['Return']
        if panel.page=='Vehicle section':
            return [title+' - '+values[0] for title,values,ecu in entries(state(panel).get('scan') or {},getattr(panel,'_vehicle_section','readiness'))]+['Return']
        if panel.page in ('Vehicle explanation','Vehicle reading'):return []
        return ['Refresh diagnostics','Return']
    def handle(panel,key):
        if key=='quit':return old_handle(panel,key)
        if panel.page=='Home' and key in ('enter','right'):
            actions=panel.items(panel.collector.snapshot())
            if actions and actions[min(panel.selected,len(actions)-1)]=='Vehicle Diagnostics':
                panel.page='Vehicle Diagnostics';panel.details=None;panel.selected=0;start(panel);return
        if panel.page not in pages:return old_handle(panel,key)
        actions=items(panel,{})
        if key in ('up','down'):
            if panel.page in ('Vehicle explanation','Vehicle reading','Vehicle traffic history'):panel._vehicle_scroll=max(0,getattr(panel,'_vehicle_scroll',0)+(3 if key=='down' else -3));return
            panel.selected=(panel.selected+(1 if key=='down' else -1))%max(1,len(actions));return
        if key in ('left','back'):
            parents={'Vehicle parameters':'Vehicle live','Vehicle traffic history':'Vehicle traffic','Vehicle Diagnostics':'Home','Vehicle clear':'Vehicle codes','Vehicle code details':'Vehicle codes','Vehicle explanation':'Vehicle code details','Vehicle reading':'Vehicle section','Vehicle section':getattr(panel,'_vehicle_section_parent','Vehicle evidence'),'Vehicle evidence':getattr(panel,'_vehicle_evidence_parent','Vehicle codes')}
            panel.page=parents.get(panel.page,'Vehicle Diagnostics');panel.selected=0;panel.details=None;return
        if key not in ('enter','right') or not actions:return
        index=min(panel.selected,len(actions)-1);choice=actions[index];page=panel.page
        if choice=='Return':handle(panel,'back');return
        elif page=='Vehicle Diagnostics':
            if choice=='Connect to vehicle':panel.page='Vehicle connect';start(panel)
            elif choice=='Read fault codes':panel.page='Vehicle codes';start(panel,'scan')
            elif choice=='Live readings':panel.page='Vehicle live';start(panel)
            elif choice=='Vehicle information & readiness':panel.page='Vehicle evidence';panel._vehicle_evidence_parent='Vehicle Diagnostics'
            elif choice=='Saved reports':panel.page='Vehicle reports';start(panel)
            elif choice=='Adapter setup':panel.page='Vehicle setup';start(panel)
            elif choice=='Clear fault codes':start(panel,'prepare_clear');panel.page='Vehicle clear'
            elif choice=='Remote access & data flow':panel.page='Vehicle remote access'
            elif choice=='Demo':start(panel,'demo')
            elif choice=='Disconnect':start(panel,'disconnect')
        elif page=='Vehicle remote access':panel.page='Vehicle traffic';start(panel)
        elif page=='Vehicle traffic':
            if choice=='View traffic history':panel._vehicle_traffic_frozen=list(getattr(panel,'_vehicle_traffic',{}).get('events',[]));panel._vehicle_scroll=0;panel.page='Vehicle traffic history'
            elif choice=='Remote access instructions':panel.page='Vehicle remote access'
            else:start(panel,'trace',enabled=choice=='Start traffic capture')
        elif page=='Vehicle connect':
            adapters=getattr(panel,'_vehicle_adapters',{});devices=adapters.get('usb',[])+adapters.get('bluetooth',{}).get('devices',[])
            if index<len(devices):start(panel,'connect',adapter=devices[index]['id'],transport=devices[index]['transport'])
            elif choice=='Refresh adapters':panel._vehicle_adapter_time=0;start(panel)
            elif choice=='Reconnect selected adapter':start(panel,'reconnect')
            else:panel.page='Vehicle setup'
        elif page=='Vehicle codes':
            codes=(state(panel).get('scan') or {}).get('codes',[])
            if index<len(codes):panel._vehicle_code=codes[index];panel._vehicle_scroll=0;panel.page='Vehicle code details'
            elif choice=='Readings & emissions readiness':panel.page='Vehicle evidence';panel._vehicle_evidence_parent='Vehicle codes'
            elif choice=='Read fault codes again':start(panel,'scan')
            else:start(panel,'prepare_clear');panel.page='Vehicle clear'
        elif page=='Vehicle evidence':
            panel._vehicle_section=SECTIONS[index][1];panel._vehicle_section_parent='Vehicle evidence';panel.page='Vehicle section'
        elif page=='Vehicle code details':
            if choice=='Readings when a fault occurred':panel._vehicle_section='freeze_frames';panel._vehicle_section_parent='Vehicle code details';panel.page='Vehicle section'
            else:panel._vehicle_explanation=choice;panel._vehicle_scroll=0;panel.page='Vehicle explanation'
        elif page=='Vehicle section':
            readings=entries(state(panel).get('scan') or {},panel._vehicle_section)
            if index<len(readings):panel._vehicle_reading=readings[index];panel._vehicle_scroll=0;panel.page='Vehicle reading'
        elif page=='Vehicle clear':
            if index==0:panel.page='Vehicle codes'
            else:
                ticket=state(panel).get('clear_confirmation')
                if ticket:start(panel,'clear',token=ticket['token'],confirm='CLEAR ENGINE CODES');panel.page='Vehicle codes'
                else:panel.message='Wait for pre-clear report; demo clearing is disabled'
        elif page=='Vehicle live':
            if choice=='Select readings':panel.page='Vehicle parameters'
            elif choice=='Refresh':start(panel)
            else:start(panel,'record',enabled=choice=='Start recording')
        elif page=='Vehicle parameters':
            params=[c for c in state(panel).get('supported',[]) if c.get('mode')==1 or c['id']=='ELM_VOLTAGE']
            if index<len(params):
                selected=list(state(panel).get('selected',[]));pid=params[index]['id']
                if pid in selected:selected.remove(pid)
                else:selected.append(pid)
                start(panel,'select',parameters=selected)
        elif page=='Vehicle reports':
            saved=getattr(panel,'_vehicle_saved',[])
            if index<len(saved):start(panel,'vehicle',vehicle_id=saved[index]['vehicle']);panel.message='Selected saved vehicle; browser/console exports available'
            else:start(panel)
        else:start(panel)
        if panel.page!=page:panel.selected=0
    def lines(panel,data,capacity=30,cols=80):
        if panel.page not in pages:return old_lines(panel,data,capacity,cols)
        s=state(panel)
        if not getattr(panel,'_vehicle_pending',False) and time.monotonic()-getattr(panel,'_vehicle_updated',0)>1.5:start(panel)
        titles={'Vehicle Diagnostics':'Vehicle diagnostics','Vehicle codes':'Fault codes','Vehicle evidence':'Readings & vehicle information','Vehicle code details':'Fault summary','Vehicle explanation':getattr(panel,'_vehicle_explanation','Fault explanation'),'Vehicle section':next((title for title,key in SECTIONS if key==getattr(panel,'_vehicle_section','')), 'Recorded readings'),'Vehicle reading':'Reading details','Vehicle live':'Live readings'}
        rows=[('DEMO · ' if s.get('demo') else '')+titles.get(panel.page,panel.page),s.get('state','Starting local service').upper()]
        if s.get('state') not in ('connected','disconnected'):rows.append(s.get('progress',''))
        error=getattr(panel,'_vehicle_error','') or s.get('error','')
        if error:rows+=['Error: '+error]
        if panel.page=='Vehicle Diagnostics':
            vehicle=s.get('vehicle',{});rows += [vehicle.get('nickname',''),s.get('protocol','No vehicle connected'),'Engine / emissions only','']
            scan=s.get('scan') or {};readiness=scan.get('readiness',[])
            mils=[r.get('value',{}).get('MIL') for r in readiness if isinstance(r.get('value'),dict)]
            rows += ['Engine warning: '+('ON' if any(v is True for v in mils) else 'OFF' if mils and all(v is False for v in mils) else 'not read'),
                     ' | '.join(status+': '+str(sum(c['status']==status for c in scan.get('codes',[]))) for status in ('stored','pending','permanent')),'']
        elif panel.page=='Vehicle remote access':
            rows += ['PC keyboard: SSH / serial / browser','SSH menu: sudo bh-panel','Browser via SSH tunnel, PC command:','ssh -L 8767:127.0.0.1:8767','  clover@CLOVERKIT_IP','Open http://127.0.0.1:8767','On CloverKit:','sudo cloverkit-vehicle access','Raw read terminal over SSH:','sudo cloverkit-vehicle terminal','Same connection / one adapter owner','']
        elif panel.page in ('Vehicle traffic','Vehicle traffic history'):
            journal=getattr(panel,'_vehicle_traffic',{})
            events=getattr(panel,'_vehicle_traffic_frozen',[]) if panel.page=='Vehicle traffic history' else journal.get('events',[])[-4:]
            rows += ['TX = command | RX = adapter bytes','DEMO is simulated; real capture is opt-in.']
            detail=[]
            for event in events:
                detail += [time.strftime('%H:%M:%S',time.localtime(event['time']))+' '+('DEMO ' if event.get('demo') else '')+event['direction']+' '+event['text'].replace('\r','\\r').replace('\n','\\n')]
            if panel.page=='Vehicle traffic history':
                import textwrap
                wrapped=[part for line in detail for part in (textwrap.wrap(line,max(20,cols-2)) or [''])]
                return rows+['Snapshot history; U/D scroll']+wrapped[getattr(panel,'_vehicle_scroll',0):][:max(1,capacity-len(rows)-1)]
            rows += [line[:max(30,cols-2)] for line in detail]+['']
        elif panel.page=='Vehicle codes':
            scan=s.get('scan') or {};counts={status:sum(c['status']==status for c in scan.get('codes',[])) for status in ('stored','pending','permanent')}
            rows += [' | '.join(f'{key}: {n}' for key,n in counts.items()),'Not all modules are assessed.','']
            if not scan:rows+=['Choose Read fault codes to run a scan.']
            elif not scan.get('complete'):rows+=['Scan in progress; results are partial.']
            elif not scan.get('codes'):rows+=['No fault codes returned. Check scan coverage.']
        elif panel.page=='Vehicle live':
            for name,r in list(s.get('live',{}).items())[:4]:
                rows += [label(r.get('parameter',name))+': '+(compact(r.get('value'),r.get('unit','')) if r.get('state')=='measured' else r.get('state','unknown').upper())]
                values=[v['value'] for v in s.get('history',{}).get(name,[]) if v.get('state')=='measured' and type(v.get('value')) in (int,float)][-24:]
                if values:
                    lo,hi=min(values),max(values);rows+=['Recent range: '+compact(lo,r.get('unit',''))+' to '+compact(hi,r.get('unit',''))]
        elif panel.page=='Vehicle clear':
            ticket=s.get('clear_confirmation') or {};rows += ['Clear erases evidence / freeze frames.','Readiness monitors may reset.','Permanent codes cannot be forced clear.','Pre-clear report: '+('saved' if ticket else 'waiting / not available'),'']
        elif panel.page=='Vehicle setup':
            bt=getattr(panel,'_vehicle_adapters',{}).get('bluetooth',{});rows += ['USB: explicit adapter selection only','Bluetooth: '+bt.get('state','checking'),'For pairing / PIN, SSH or serial:','cloverkit-vehicle bluetooth discover','cloverkit-vehicle bluetooth pair','  --address AA:BB:CC:DD:EE:FF','Offline browser / export access:','cloverkit-vehicle access','Alternate baud: console or browser','No Wi-Fi/Flipper serial changes.','']
        elif panel.page=='Vehicle code details':
            import textwrap
            c=getattr(panel,'_vehicle_code',{});rows += [c.get('code','')+' · '+c.get('status','')]
            rows += textwrap.wrap(c.get('description','Definition unavailable'),max(20,cols-2))
            rows += ['Detected condition; cause not confirmed.','Select a topic for more detail.','']
        elif panel.page=='Vehicle explanation':
            c=getattr(panel,'_vehicle_code',{});rows += [c.get('code','')+' · '+c.get('status',''),'']
            return detail_page(panel,rows,code_detail(c,panel._vehicle_explanation),capacity,cols)
        elif panel.page=='Vehicle reading':
            title,values,ecu=getattr(panel,'_vehicle_reading',('Reading',['Not available'],'unknown'))
            return detail_page(panel,rows,[title,*values,'Engine module: '+ecu],capacity,cols)
        elif panel.page=='Vehicle evidence':
            rows += ['Select a summary to explore its readings.','Saved scan results; not live readings.','']
            if not s.get('scan'):rows += ['Read fault codes first to collect results.','']
        elif panel.page=='Vehicle section':
            readings=entries(s.get('scan') or {},getattr(panel,'_vehicle_section','readiness'))
            rows += [str(len(readings))+' results · Select one for full details.','']
            if getattr(panel,'_vehicle_section','')=='freeze_frames':rows += ['Scan snapshot; may relate to another fault.','']
            if not readings:rows += ['No results recorded for this section.','Run Read fault codes to collect supported data.','']
        return rows+[panel.mark(i,item) for i,item in enumerate(items(panel,data))]
    Panel.items,Panel.lines,Panel.handle=items,lines,handle
