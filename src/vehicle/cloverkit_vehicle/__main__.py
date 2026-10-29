"""CloverKit console entry point; ordinary use is fully offline."""
import argparse,json,sys,time
from urllib.parse import urlencode
from .client import ensure,request
from .service import serve
from .storage import home

def main():
    p=argparse.ArgumentParser(description='CloverKit Vehicle Diagnostics — offline engine/emissions diagnostics')
    sub=p.add_subparsers(dest='command',required=True)
    s=sub.add_parser('serve');s.add_argument('--bind',default='127.0.0.1');s.add_argument('--port',type=int,default=8767)
    for name in ('status','adapters','demo','scan','disconnect','cancel','access','saved','recordings','reconnect'):sub.add_parser(name)
    s=sub.add_parser('connect');s.add_argument('adapter');s.add_argument('--transport',choices=['usb','bluetooth'],default='usb');s.add_argument('--baud',type=int,choices=[9600,38400,115200],default=38400)
    s=sub.add_parser('live');s.add_argument('parameters',nargs='*',default=['RPM','SPEED','COOLANT_TEMP'])
    s=sub.add_parser('record');s.add_argument('mode',choices=['start','stop'])
    s=sub.add_parser('lookup');s.add_argument('query');s.add_argument('--make',default='')
    s=sub.add_parser('export');s.add_argument('id');s.add_argument('--format',choices=['json','html','csv'],default='json')
    s=sub.add_parser('compare');s.add_argument('previous');s.add_argument('current')
    s=sub.add_parser('vehicle');s.add_argument('--nickname');s.add_argument('--make');s.add_argument('--vehicle-id')
    s=sub.add_parser('bluetooth');s.add_argument('operation',choices=['status','discover','pair']);s.add_argument('--address');s.add_argument('--pin',default='1234')
    s=sub.add_parser('traffic');s.add_argument('--follow',action='store_true');s.add_argument('--json',action='store_true')
    s=sub.add_parser('trace');s.add_argument('mode',choices=['on','off'])
    s=sub.add_parser('terminal');s.add_argument('command_text',nargs='?')
    sub.add_parser('clear')
    a=p.parse_args()
    if a.command=='serve':serve(a.bind,a.port);return
    if a.command=='lookup':
        from .reference import Reference
        print(json.dumps(Reference().query(a.query,a.make),indent=2,ensure_ascii=False));return
    ensure()
    if a.command=='access':
        print('PC: ssh -L 8767:127.0.0.1:8767 clover@<CloverKit-address>\nThen open http://127.0.0.1:8767\nToken: '+(home()/'access.token').read_text().strip());return
    if a.command=='trace':print(json.dumps(request('/api/action',dict(op='trace',enabled=a.mode=='on'))));return
    if a.command=='traffic':
        cursor=0
        while True:
            journal=request('/api/traffic?'+urlencode(dict(after=cursor,limit=500)))
            if journal['gap']:print('[Older traffic fell outside the bounded buffer]',file=sys.stderr)
            for row in journal['events']:
                cursor=row['sequence']
                print(json.dumps(row) if a.json else time.strftime('%H:%M:%S',time.localtime(row['time']))+(' DEMO ' if row['demo'] else ' ')+row['direction']+' '+repr(row['text']),flush=True)
            if not a.follow:return
            time.sleep(.5)
    if a.command=='terminal':
        def send(command):
            key=request('/api/action',dict(op='terminal',command=command))['id']
            for i in range(900):
                result=request('/api/terminal?'+urlencode(dict(id=key)))
                if result['state']=='error':raise ValueError(result['error'])
                if result['state']=='complete':print(json.dumps(result['result'],indent=2,ensure_ascii=False));return
                time.sleep(.1)
            raise ValueError('Terminal request did not finish; inspect status or cancel')
        if a.command_text is not None:send(a.command_text);return
        print('CloverKit OBD terminal — shared connection, read-only. Examples: RPM, 010C, 03, ATI.\n:pause stops live polling; :quit leaves this terminal. Clearing uses the confirmed diagnostics workflow.')
        while True:
            try:command=input('obd> ').strip()
            except EOFError:return
            if command in (':quit',':exit'):return
            if command==':pause':request('/api/action',dict(op='select',parameters=[]));print('Live polling paused; choose readings in Live dashboard to resume.');continue
            if not command:continue
            try:send(command)
            except ValueError as exc:print(str(exc),file=sys.stderr)
    if a.command=='bluetooth':
        if a.operation=='status':value=request('/api/adapters')['bluetooth']
        else:value=request('/api/bluetooth',dict(op=a.operation,address=a.address,pin=a.pin),timeout=35)
    elif a.command in ('status','adapters','saved','recordings'):value=request('/api/'+('state' if a.command=='status' else a.command))
    elif a.command=='export':
        print(request('/api/report?'+urlencode(dict(id=a.id,format=a.format))));return
    elif a.command=='compare':value=request('/api/compare?'+urlencode(dict(previous=a.previous,current=a.current)))
    elif a.command=='clear':
        request('/api/action',dict(op='prepare_clear'));print('Saving a fresh pre-clear scan...')
        for i in range(600):
            state=request();ticket=state.get('clear_confirmation')
            if ticket:break
            if state.get('error'):raise ValueError(state['error'])
            time.sleep(.2)
        else:raise ValueError('Pre-clear scan did not complete; no clear request sent')
        print(ticket['warning']);print('Pre-clear report: '+ticket['preclear_scan'])
        confirmation=input('Type CLEAR ENGINE CODES to proceed, anything else cancels: ')
        if confirmation!='CLEAR ENGINE CODES':print('Cancelled; no clear request sent');return
        value=request('/api/action',dict(op='clear',token=ticket['token'],confirm=confirmation))
    else:
        fields=dict(op=a.command)
        if a.command=='connect':fields.update(adapter=a.adapter,transport=a.transport,baud=a.baud)
        if a.command=='live':fields.update(op='select',parameters=a.parameters)
        if a.command=='record':fields.update(enabled=a.mode=='start')
        if a.command=='vehicle':fields.update({k:v for k,v in vars(a).items() if k!='command' and v is not None})
        value=request('/api/action',fields)
    print(json.dumps(value,indent=2,ensure_ascii=False))

if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyboardInterrupt) as e:print('CloverKit: '+str(e),file=sys.stderr);raise SystemExit(1)
