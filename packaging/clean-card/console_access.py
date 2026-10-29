#!/usr/bin/python3
"""Local-screen control of the restricted shared USB serial account."""
import json,os,subprocess,sys
from pathlib import Path
sys.path.insert(0,'/usr/local/lib/bh-interactive')
from console_password import generate
from cloverkit_optional_setup import send_access
STATE=Path('/run/cloverkit-console-access.json')
def main():
    if os.geteuid()!=0:raise SystemExit('Use the local CloverKit System menu.')
    operation=sys.argv[1] if len(sys.argv)==2 else 'status'
    if operation=='off':
        subprocess.run(['passwd','-l','console'],check=True,stdout=subprocess.DEVNULL)
        subprocess.run(['pkill','-TERM','-u','console'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        STATE.unlink(missing_ok=True)
    elif operation=='on':
        password=generate()
        subprocess.run(['chpasswd'],input='console:'+password+'\n',text=True,check=True)
        delivery=send_access('Shared USB serial console','console',password,'cloverkit.local')
        STATE.write_text(json.dumps({'username':'console','password':password,'email':delivery})+'\n');STATE.chmod(0o600)
        subprocess.run(['systemctl','start','ssh.service'],check=True)
    elif operation!='status':raise ValueError('Use on, off or status')
    if STATE.exists():
        state=json.loads(STATE.read_text());print('USB serial console: ON\nUsername: console\nPassphrase: '+state['password']+'\nEmail: '+state['email'])
    else:print('USB serial console: OFF')
if __name__=='__main__':main()
