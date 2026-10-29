"""Local authenticated API and offline browser. No cloud, CDN, telemetry or auto-probing."""
import hmac, json, os, secrets, signal, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from .adapters import bluetooth_discover, bluetooth_pair, bluetooth_status, usb_adapters
from .engine import Engine
from .engine import identity
from .storage import home

class API:
    def __init__(self,engine):self.engine=engine
    def get(self,path,params):
        e=self.engine
        one=lambda k,default='':params.get(k,[default])[0]
        if path=='/api/state':return e.snapshot()
        if path=='/api/adapters':return dict(usb=usb_adapters(),bluetooth=bluetooth_status())
        if path=='/api/lookup':return e.reference.query(one('q'),one('make'),int(one('limit','40')))
        if path=='/api/catalog':return e.reference.catalog()
        if path=='/api/traffic':return e.traffic.snapshot(int(one('after','0')),int(one('limit','200')),one('tail')=='1')
        if path=='/api/terminal':return e.terminal_result(one('id'))
        if path=='/api/saved':return e.storage.list()
        if path=='/api/recordings':return e.storage.recordings()
        if path=='/api/scan':return e.storage.get(one('id'))
        if path=='/api/compare':return e.storage.compare(one('previous'),one('current'))
        if path=='/api/report':return e.storage.export(one('id'),one('format','json'))
        raise ValueError('Unknown API route')
    def post(self,path,data):
        if path=='/api/action':
            allowed={'connect','demo','disconnect','cancel','scan','select','vehicle','record','prepare_clear','clear','raw','reconnect','trace','terminal'}
            op=data.pop('op',None)
            if op not in allowed:raise ValueError('Unknown action')
            if op=='terminal':
                key=identity();self.engine.submit('terminal',command=data.get('command',''),request_id=key)
                return dict(accepted=True,id=key)
            return self.engine.submit(op,**data)
        if path=='/api/bluetooth':
            if self.engine.state['state'] in ('connecting','scanning'):raise ValueError('Finish or cancel the current operation first')
            if data.get('op')=='discover':return bluetooth_discover()
            if data.get('op')=='pair':return bluetooth_pair(data.get('address',''),data.get('pin','1234'))
            raise ValueError('Choose discovery or explicit pairing')
        raise ValueError('Unknown API route')

def handler(api,token):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass  # No VINs, credentials or request URLs in access logs.
        def reply(self,value,status=200,kind='application/json; charset=utf-8'):
            raw=(json.dumps(value,ensure_ascii=False,allow_nan=False) if kind.startswith('application/json') else value).encode('utf-8')
            self.send_response(status);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(raw)))
            self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' blob:; object-src 'none'; frame-ancestors 'none'")
            self.end_headers()
            try:self.wfile.write(raw)
            except (BrokenPipeError,ConnectionResetError):pass
        def authorized(self):
            actual=self.headers.get('Authorization','')
            return hmac.compare_digest(actual,'Bearer '+token)
        def do_GET(self):
            parts=urlsplit(self.path)
            if parts.path in ('/','/app.js','/remote.js','/style.css'):
                name={'/':'index.html','/app.js':'app.js','/remote.js':'remote.js','/style.css':'style.css'}[parts.path]
                kind={'/':'text/html','/app.js':'text/javascript','/remote.js':'text/javascript','/style.css':'text/css'}[parts.path]+'; charset=utf-8'
                self.reply((Path(__file__).parent/'web'/name).read_text(encoding='utf-8'),kind=kind);return
            if not self.authorized():self.reply(dict(error='Enter the local access token from cloverkit-vehicle access'),401);return
            try:self.reply(api.get(parts.path,parse_qs(parts.query)))
            except (ValueError,OSError,KeyError,TypeError) as exc:self.reply(dict(error=str(exc)[:1200]),400)
        def do_POST(self):
            if not self.authorized():self.reply(dict(error='Unauthorized'),401);return
            origin=self.headers.get('Origin')
            if origin and urlsplit(origin).netloc!=self.headers.get('Host'):self.reply(dict(error='Cross-origin actions refused'),403);return
            try:
                size=int(self.headers.get('Content-Length','0'))
                if not 0<size<=16384:raise ValueError('Invalid request size')
                if self.headers.get('Content-Type','').split(';')[0]!='application/json':raise ValueError('JSON required')
                data=json.loads(self.rfile.read(size))
                if not isinstance(data,dict):raise ValueError('Object required')
                self.reply(api.post(urlsplit(self.path).path,data))
            except (ValueError,OSError,KeyError,TypeError) as exc:self.reply(dict(error=str(exc)[:1200]),400)
    return Handler

class Server(ThreadingHTTPServer):
    daemon_threads=True
    request_queue_size=8
    def get_request(self):
        sock,address=super().get_request();sock.settimeout(10);return sock,address

def serve(bind='127.0.0.1',port=8767):
    import fcntl
    root=home();root.mkdir(parents=True,exist_ok=True,mode=0o700)
    lock=open(root/'owner.lock','a')
    try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:raise SystemExit('Vehicle service already owns this data directory')
    token_path=root/'access.token'
    token=token_path.read_text().strip() if token_path.exists() else secrets.token_urlsafe(32)
    token_path.write_text(token+'\n');token_path.chmod(0o600)
    engine=Engine(root);server=Server((bind,int(port)),handler(API(engine),token))
    def stop(*args):threading.Thread(target=server.shutdown,daemon=True).start()
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    try:
        print(f'CloverKit Vehicle Diagnostics listening on {bind}:{server.server_port}; local token required',flush=True)
        server.serve_forever(poll_interval=.2)
    finally:server.server_close();engine.close();lock.close()
