"""Local/console client. UI clients share the service instead of opening adapters."""
import json, os, subprocess, sys, time, urllib.error, urllib.request
from .storage import home
from . import subprocess_environment

URL='http://127.0.0.1:8767'

def request(path='/api/state',data=None,timeout=4):
    token=(home()/'access.token').read_text().strip()
    headers={'Authorization':'Bearer '+token}
    raw=None
    if data is not None:raw=json.dumps(data).encode();headers['Content-Type']='application/json'
    req=urllib.request.Request(URL+path,data=raw,headers=headers)
    # Ignore proxy environment for local diagnostics and private session data.
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req,timeout=timeout) as response:return json.load(response)
    except urllib.error.HTTPError as exc:
        try:raise ValueError(json.load(exc).get('error','Request failed'))
        finally:exc.close()

def ensure():
    try:return request()
    except (OSError,ValueError):pass
    root=home();root.mkdir(parents=True,exist_ok=True,mode=0o700)
    if (root/'service.log').exists() and (root/'service.log').stat().st_size>1_000_000:
        os.replace(root/'service.log',root/'service.previous.log')
    log=open(root/'service.log','ab');os.chmod(root/'service.log',0o600)
    subprocess.Popen([sys.executable,'-m','cloverkit_vehicle','serve'],stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True,env=subprocess_environment());log.close()
    for i in range(40):
        try:return request()
        except (OSError,ValueError):time.sleep(.1)
    raise ValueError('Vehicle service did not start; inspect '+str(root/'service.log'))
