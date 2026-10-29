"""Bounded actual serial traffic capture and shared-owner terminal command policy."""
import json,os,re,threading,time
from collections import deque

GETTERS={'ATI':'ELM_VERSION','ATRV':'ELM_VOLTAGE','ATDP':'ADAPTER_PROTOCOL','ATDPN':'ADAPTER_PROTOCOL_ID','AT@1':'ADAPTER_DESCRIPTION'}

def read_command(command,candidates):
    if not isinstance(command,str) or not 1<=len(command)<=64 or any(ord(c)<32 or ord(c)>126 for c in command):raise ValueError('Enter one printable read command; control characters and command chaining are rejected')
    text=command.strip().upper()
    compact=candidates[text] if re.fullmatch('[A-Z][A-Z0-9_]*',text) and text in candidates else text.replace(' ','')
    if compact in GETTERS:return GETTERS[compact]
    if not re.fullmatch('[0-9A-F]{2,6}',compact):raise ValueError('Use a supported reading name, standard read request, or ATI / ATRV / ATDP / ATDPN / AT@1')
    if compact[:2] not in ('01','02','03','06','07','09','0A'):raise ValueError('This terminal reads only. Clearing uses the separate confirmed workflow; ECU write/control services are not forwarded.')
    match=next((name for name,request in candidates.items() if request==compact),None)
    if match is None:raise ValueError('Request is not in this connection’s discovered read-command set')
    return match

class SerialTap:
    """Transparent serial proxy; captures real bytes without an extra port reader."""
    def __init__(self,port,emit,enabled):
        object.__setattr__(self,'_port',port);object.__setattr__(self,'_emit',emit);object.__setattr__(self,'_enabled',enabled)
    def __getattr__(self,name):return getattr(self._port,name)
    def __setattr__(self,name,value):setattr(self._port,name,value)
    def write(self,data):
        count=self._port.write(data)
        if self._enabled() and count:self._emit('TX',bytes(data[:count]))
        return count
    def read(self,size=1):
        data=self._port.read(size)
        if self._enabled() and data:self._emit('RX',bytes(data))
        return data

class Journal:
    def __init__(self,root,limit=1000):
        self.root=root;self.lock=threading.Lock();self.items=deque(maxlen=limit);self.sequence=0;self.enabled=False;self.error=''
    def capture(self,event,demo=False):
        if not self.enabled:return
        with self.lock:
            self.sequence+=1
            row=dict(sequence=self.sequence,time=event.get('time',time.time()),direction=event.get('direction','?'),
                     text=str(event.get('text',''))[:2048],hex=str(event.get('hex',''))[:4096],
                     bytes=event.get('bytes',0),truncated=bool(event.get('truncated')),demo=bool(demo))
            self.items.append(row)
            try:
                path=self.root/'serial-traffic.jsonl'
                if path.exists() and path.stat().st_size>=2_000_000:os.replace(path,self.root/'serial-traffic.previous.jsonl')
                with open(path,'a',encoding='utf-8') as stream:stream.write(json.dumps(row,ensure_ascii=True)+'\n')
                path.chmod(0o600)
            except OSError as exc:
                self.error='Traffic persistence failed: '+str(exc);self.enabled=False
    def snapshot(self,after=0,limit=200,tail=False):
        after=max(0,int(after));limit=max(1,min(500,int(limit)))
        with self.lock:
            rows=[r.copy() for r in self.items if r['sequence']>after]
            rows=rows[-limit:] if tail else rows[:limit]
            first=self.items[0]['sequence'] if self.items else self.sequence+1
            return dict(enabled=self.enabled,error=self.error,events=rows,oldest_sequence=first,latest_sequence=self.sequence,
                        gap=after>0 and after<first-1,scope='Actual serial TX/RX when connected; simulated events explicitly marked DEMO')

def event(direction,data):
    raw=bytes(data)
    return dict(time=time.time(),direction=direction,bytes=len(raw),text=raw[:2048].decode('ascii',errors='backslashreplace'),
                hex=raw[:2048].hex().upper(),truncated=len(raw)>2048)
