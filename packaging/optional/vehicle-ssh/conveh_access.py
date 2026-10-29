#!/usr/bin/python3
"""Scoped root helper for temporary Vehicle Diagnostics SSH access."""
import fcntl,json,os,pwd,secrets,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path('/run/cloverkit-conveh')
PANEL=Path('/usr/local/lib/bh-interactive')

def call(argv,**kw):return subprocess.run(argv,check=True,timeout=12,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,**kw)
def publish(value):
 fd,tmp=tempfile.mkstemp(dir=ROOT,prefix='.access-')
 try:
  with os.fdopen(fd,'w') as out:json.dump(value,out);out.flush();os.fsync(out.fileno())
  os.chmod(tmp,0o600);os.replace(tmp,ROOT/'access.json')
 finally:Path(tmp).unlink(missing_ok=True)
def status():
 try:data=json.loads((ROOT/'access.json').read_text())
 except (OSError,ValueError):return {'enabled':False}
 if data.get('expires',0)<time.time():return disable()
 return dict(data,enabled=True)
def disable():
 (ROOT/'access.json').unlink(missing_ok=True)
 call(['/usr/bin/passwd','-l','conveh'])
 return {'enabled':False}
def enable():
 sys.path.insert(0,str(PANEL));from console_password import generate
 disable();password=generate()
 call(['/usr/sbin/chpasswd'],input='conveh:'+password+'\n',text=True)
 result=subprocess.run(['/usr/bin/passwd','-S','conveh'],text=True,capture_output=True,check=True,timeout=10).stdout.split()
 if len(result)<2 or result[1]!='P':raise ValueError('Vehicle SSH password was not activated')
 data=dict(username='conveh',password=password,token=secrets.token_hex(24),expires=time.time()+8*3600,email='not configured')
 # Optional owner-configured SMTP only; never a baked-in project/author account.
 try:
  from cloverkit_optional_setup import send_access
  data['email']=send_access('Vehicle Diagnostics','conveh',password,os.uname().nodename)
 except Exception:data['email']='FAILED'
 try:publish(data)
 except BaseException:disable();raise
 return dict(data,enabled=True)
def main():
 if os.geteuid()!=0 or len(sys.argv)!=2 or sys.argv[1] not in ('enable','disable','status','session'):raise SystemExit('Use the installed Vehicle SSH controls')
 account=pwd.getpwnam('conveh')
 if account.pw_dir!='/var/empty/conveh' or account.pw_shell!='/bin/sh':raise SystemExit('Unexpected conveh account configuration')
 ROOT.mkdir(mode=0o700,exist_ok=True)
 if ROOT.is_symlink() or ROOT.stat().st_uid!=0:raise SystemExit('Unsafe runtime directory')
 os.chmod(ROOT,0o700)
 if sys.argv[1]=='session':
  os.environ['CLOVERKIT_VEHICLE_HOME']='/var/lib/cloverkit/vehicle'
  sys.path[:0]=['/usr/local/lib/cloverkit/vehicle','/usr/local/lib/cloverkit/vehicle/vendor',str(PANEL)]
  from cloverkit_vehicle.ssh_console import session
  return session(status)
 with open(ROOT/'control.lock','a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  value={'enable':enable,'disable':disable,'status':status}[sys.argv[1]]()
  print(json.dumps(value))
 return 0
if __name__=='__main__':
 try:raise SystemExit(main())
 except (OSError,ValueError,subprocess.SubprocessError) as exc:raise SystemExit('Vehicle SSH: '+str(exc))
