# SPDX-License-Identifier: GPL-2.0-only
"""Isolated python-OBD worker. All ELM traffic is owned by this one process.

Upstream decoders/protocol handling are reused, not reimplemented. Raw messages
are checked before decoding so short frames are never silently padded to zero.
"""
import copy, json, math, re, sys, time

def plain(value,depth=0):
    if depth>6:return str(value)[:300]
    if value is None or isinstance(value,(str,bool,int)):return value
    if isinstance(value,float):return value if math.isfinite(value) else None
    if isinstance(value,bytes):return value.decode('ascii',errors='replace').strip('\0')
    if isinstance(value,(list,tuple)):return [plain(v,depth+1) for v in value]
    if isinstance(value,dict):return {str(k):plain(v,depth+1) for k,v in value.items()}
    if hasattr(value,'magnitude'):return dict(value=plain(value.magnitude,depth+1),unit=str(value.units))
    if hasattr(value,'tests'):return [plain(v,depth+1) for v in value.tests]
    if hasattr(value,'__dict__'):return {k:plain(v,depth+1) for k,v in vars(value).items() if not k.startswith('_')}
    return str(value)[:500]

def legacy_dtc_extension(protocol):
    """Pinned python-OBD legacy parser only normalizes Mode 03; add 07/0A."""
    original=protocol.parse_message
    def parse(message):
        frames=message.frames
        if frames and frames[0].data and frames[0].data[0] in (0x47,0x4a):
            service=frames[0].data[0]
            if any(not frame.data or frame.data[0]!=service for frame in frames):return False
            payload=b''.join(bytes(frame.data[1:]) for frame in frames)
            if len(payload)%2:return False
            message.data=bytearray([service,0])+payload  # legacy has no CAN count byte
            return True
        return original(message)
    protocol.parse_message=parse

def decode_messages(command,messages):
    records=[];now=time.time()
    for message in messages:
        raw=bytes(message.data);ecu=getattr(message,'tx_id',None)
        ecu=hex(ecu) if isinstance(ecu,int) else str(ecu or 'unknown')
        base=dict(time=now,ecu=ecu,raw=raw.hex().upper(),unit='')
        if raw and raw[0]==0x7f:
            records.append(dict(base,state='negative_response',value=None,detail=raw.hex().upper()));continue
        if command.mode==2:
            if len(raw)<3:
                records.append(dict(base,state='invalid',value=None,detail='Missing freeze-frame identifier'));continue
            base['freeze_frame']=raw[2]
            # The Mode 02 frame number is not part of the Mode 01 decoder payload.
            message=copy.copy(message);message.data=bytearray(raw[:2]+raw[3:]);raw=bytes(message.data)
        if command.mode is not None and (not raw or raw[0] != command.mode+0x40):
            records.append(dict(base,state='invalid',value=None,detail='Unexpected response service'));continue
        minimum={'VIN':19,'CALIBRATION_ID':18,'CVN':6}.get(command.name,command.bytes)
        if minimum and len(raw)<minimum:
            records.append(dict(base,state='invalid',value=None,detail=f'Short response: {len(raw)}/{command.bytes} bytes'));continue
        if command.mode in (1,2,6,9) and (len(raw)<2 or raw[1]!=command.pid):
            records.append(dict(base,state='invalid',value=None,detail='Unexpected parameter ID'));continue
        if command.mode in (3,7,10) and (len(raw)<2 or len(raw)<2+2*raw[1]):
            records.append(dict(base,state='invalid',value=None,detail='Incomplete trouble-code payload'));continue
        try:
            if command.name=='VIN':
                text=raw[2:].lstrip(b'\0\x01\x02\x03').decode('ascii',errors='replace').strip('\0 ')
                value=text if re.fullmatch(r'[A-HJ-NPR-Z0-9]{17}',text) else None
            elif command.name in ('CALIBRATION_ID','CVN'):
                payload=raw[2:];size=16 if command.name=='CALIBRATION_ID' else 4
                if len(payload)%size==1 and payload[0]*size==len(payload)-1:payload=payload[1:]
                if not payload or len(payload)%size:value=None
                elif command.name=='CVN':value=[payload[i:i+size].hex().upper() for i in range(0,len(payload),size)]
                else:value=[payload[i:i+size].decode('ascii',errors='replace').strip('\0 ') for i in range(0,len(payload),size)]
            else:value=plain(command.decode([message]))
            unit=''
            if isinstance(value,dict) and set(value)=={'value','unit'}:unit=value['unit'];value=value['value']
            records.append(dict(base,state='measured' if value is not None else 'invalid',value=value,unit=unit))
        except (ValueError,TypeError,IndexError,KeyError,ZeroDivisionError,OverflowError) as e:
            records.append(dict(base,state='invalid',value=None,detail=str(e)[:200]))
    return records or [dict(time=now,ecu='unknown',state='no_response',value=None,unit='')]

class Backend:
    def __init__(self):self.connection=None;self.obd=None;self.commands={};self.trace_enabled=False;self.emit=lambda direction,data:None
    def connect(self,port,baud=38400):
        import obd
        from .adapters import usb_adapters
        self.obd=obd
        if not (port in [p['device'] for p in usb_adapters()] or re.fullmatch(r'/dev/rfcomm\d+',port)):
            raise ValueError('Selected port is not an available USB/owned Bluetooth adapter')
        if baud not in (9600,38400,115200):raise ValueError('Choose 9600, 38400 or 115200 baud')
        # Explicit port/baud: upstream must never search or open another serial link.
        import serial
        from .traffic import SerialTap
        factory=serial.serial_for_url
        serial.serial_for_url=lambda *args,**kwargs:SerialTap(factory(*args,**kwargs),self.emit,lambda:self.trace_enabled)
        try:self.connection=obd.OBD(portstr=port,baudrate=baud,fast=False,timeout=1,check_voltage=False)
        finally:serial.serial_for_url=factory
        if not self.connection.is_connected():
            status=str(self.connection.status());self.close()
            raise ValueError('ELM/vehicle connection failed ('+status+'). Check ignition, socket power, selected adapter and baud rate.')
        if self.connection.protocol_id() in ('1','2','3','4','5'):
            legacy_dtc_extension(self.connection.interface._ELM327__protocol)
        self.commands={c.name:c for c in self.connection.supported_commands if c.mode in (1,2,3,6,7,9) or c.name in ('ELM_VERSION','ELM_VOLTAGE')}
        for name in ('GET_DTC','GET_CURRENT_DTC','STATUS','VIN','CALIBRATION_ID','CVN'):
            if hasattr(obd.commands,name):self.commands.setdefault(name,getattr(obd.commands,name))
        # Service 0A shares the standard DTC payload format handled by upstream.
        from obd.decoders import dtc
        self.commands['PERMANENT_DTC']=obd.OBDCommand('PERMANENT_DTC','Permanent emissions trouble codes',b'0A',0,dtc)
        self.extend_parameters()
        return dict(protocol=self.connection.protocol_name(),protocol_id=self.connection.protocol_id(),
                    supported=[dict(id=n,label=c.desc,mode=c.mode,pid=c.pid,advertised=c in self.connection.supported_commands) for n,c in sorted(self.commands.items())],
                    library='python-OBD '+obd.__version__,adapter=self.query('ELM_VERSION'))
    def extend_parameters(self):
        from pathlib import Path
        from .profiles import formula
        specs=json.loads((Path(__file__).parent/'data/pids.json').read_text())['parameters']
        known={c.pid for c in self.commands.values() if c.mode==1}
        supported=set();base=0
        # Discover the whole standard bitmap chain, not just the library's older table.
        while base<=0xe0:
            cmd=self.obd.OBDCommand('CAPABILITIES','Supported standard PIDs',f'01{base:02X}'.encode(),0,lambda messages:True)
            messages=self.connection.query(cmd,force=True).messages;continuation=False
            for message in messages:
                d=bytes(message.data)
                if len(d)!=6 or d[:2]!=bytes([0x41,base]):continue
                bits=int.from_bytes(d[2:],'big')
                supported.update(base+i for i in range(1,33) if bits & (1<<(32-i)))
                continuation|=bool(bits&1)
            if not continuation:break
            base+=32
        for spec in specs:
            pid=int(spec['pid'],16)
            if pid not in supported or pid in known or spec.get('unit')=='bitmap':continue
            def decoder(messages,spec=spec):
                payload=bytes(messages[0].data)[2:]
                if 'formula' not in spec:return dict(raw=payload.hex().upper(),interpretation='Encoded field; not decoded')
                return dict(value=formula(spec['formula'],payload),unit=spec['unit'])
            name=f'PID01_{pid:02X}'
            command=self.obd.OBDCommand(name,spec['name']['en'],f'01{pid:02X}'.encode(),spec['bytes']+2,decoder)
            self.commands[name]=command;self.connection.supported_commands.add(command)
    def query(self,name):
        if name not in self.commands:raise ValueError('Parameter is not in the discovered command set')
        original=self.commands[name]
        if original.mode==6 and self.connection.protocol_id() not in ('6','7','8','9'):
            return [dict(time=time.time(),ecu='unknown',state='unsupported',value=None,unit='',detail='Mode 06 decoding requires CAN')]
        if name not in ('PERMANENT_DTC','GET_DTC','GET_CURRENT_DTC','VIN','CALIBRATION_ID','CVN') and original not in self.connection.supported_commands:
            return [dict(time=time.time(),ecu='unknown',state='unsupported',value=None,unit='')]
        clone=original.clone();clone.bytes=0;clone.decode=lambda messages:True
        from obd.protocols import ECU
        clone.ecu=ECU.ALL  # Preserve every responding ECU for per-message decoding.
        if original.mode==2:clone.command+=b'00'  # explicit freeze frame 0
        response=self.connection.query(clone,force=True)
        return [dict(r,decoder_source='OBDex CC0-1.0 (community, vehicle-unverified)' if name.startswith('PID01_') else 'python-OBD 0.7.3 / CloverKit normalization') for r in decode_messages(original,response.messages)]
    def clear(self):
        if not self.connection:raise ValueError('Not connected')
        cmd=self.obd.commands.CLEAR_DTC.clone();cmd.bytes=0;cmd.decode=lambda messages:True
        result=self.connection.query(cmd,force=True)
        # An empty/nonpositive response must never be reported as success.
        if not any(bytes(m.data)[:1]==b'\x44' for m in result.messages):raise ValueError('Clear request was not positively acknowledged; status is unknown')
        return dict(state='acknowledged',note='Rescan to verify. Permanent codes clear only after vehicle criteria are satisfied.')
    def terminal(self,command):
        from .traffic import GETTERS,read_command
        if not self.connection:raise ValueError('Connect to a vehicle before using the terminal')
        candidates={name:c.command.decode().upper()+('00' if c.mode==2 else '') for name,c in self.commands.items()}
        candidates.update({name:request for request,name in GETTERS.items()})
        name=read_command(command,candidates)
        if name not in self.commands:
            from obd.decoders import raw_string
            request=next(request for request,value in GETTERS.items() if value==name)
            self.commands[name]=self.obd.OBDCommand(name,'Adapter information',request.encode(),0,raw_string)
            self.connection.supported_commands.add(self.commands[name])
        return dict(command=candidates[name],parameter=name,responses=self.query(name),read_only=True)
    def close(self):
        if self.connection:self.connection.close()
        self.connection=None

def main():
    import logging
    logging.basicConfig(stream=sys.stderr,level=logging.WARNING)
    backend=Backend()
    from .traffic import event
    def emit(direction,data):print(json.dumps(dict(traffic=event(direction,data))),flush=True)
    backend.emit=emit
    try:
        for line in sys.stdin:
            try:
                if len(line)>8192:raise ValueError('Oversized worker request')
                request=json.loads(line);op=request['op']
                if op=='connect':value=backend.connect(request['port'],request.get('baud',38400))
                elif op=='query':value=backend.query(request['name'])
                elif op=='clear':value=backend.clear()
                elif op=='trace':backend.trace_enabled=bool(request.get('enabled'));value={'enabled':backend.trace_enabled}
                elif op=='terminal':value=backend.terminal(request.get('command',''))
                elif op=='close':backend.close();value=True
                else:raise ValueError('Unknown worker operation')
                response=dict(ok=True,result=value)
            except Exception as e:response=dict(ok=False,error=type(e).__name__+': '+str(e)[:1000],error_type=type(e).__name__)
            print(json.dumps(response,allow_nan=False),flush=True)
    finally:backend.close()

if __name__=='__main__':main()
