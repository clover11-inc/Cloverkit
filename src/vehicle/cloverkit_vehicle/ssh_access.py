"""Temporary SSH account controls; no passwords in process arguments."""
import json,os,subprocess
from pathlib import Path
HELPER=Path('/usr/local/lib/cloverkit/vehicle/conveh_access.py')
def control(operation):
 if operation not in ('enable','disable','status'):raise ValueError('Invalid SSH control')
 result=subprocess.run(['/usr/bin/sudo','-n','/usr/bin/python3','-I',str(HELPER),operation],text=True,capture_output=True,timeout=45)
 if result.returncode:raise ValueError('Vehicle SSH control failed; install the conveh update or check sudo permissions')
 return json.loads(result.stdout)
def revoke():
 # Only the real root service touches the system account; tests/custom data stay isolated.
 if os.geteuid()!=0 or os.environ.get('CLOVERKIT_VEHICLE_HOME','/var/lib/cloverkit/vehicle')!='/var/lib/cloverkit/vehicle' or not HELPER.is_file():return
 try:
  Path('/run/cloverkit-conveh/access.json').unlink(missing_ok=True)
  subprocess.run(['/usr/bin/python3','-I',str(HELPER),'disable'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
 except (OSError,subprocess.SubprocessError):pass
