"""Read-only host prerequisite inventory. No radio, serial, service or account changes."""
# SPDX-License-Identifier: GPL-2.0-or-later
import argparse,importlib.util,json,platform,shutil,sys
from pathlib import Path
GROUPS={'panel':(['nmcli','ip'],['PIL']),'wireless':(['iw','tshark','tcpdump','rfkill'],['scapy']),
'ethernet':(['ip','ethtool','tcpdump'],[]),'security':(['nmap'],[]),'ble':(['bluetoothctl'],['bleak']),
'performance':(['iperf3'],[]),'vehicle-usb':([],[]),'vehicle-classic':(['rfcomm','sdptool','bluetoothctl'],[]),'optional-vpn':(['openvpn'],[])}
def main():
 p=argparse.ArgumentParser();p.add_argument('--strict',action='store_true');a=p.parse_args()
 result=dict(platform=platform.system(),architecture=platform.machine(),python=platform.python_version(),python_supported=sys.version_info>=(3,10),runtime_activation='not performed',groups={})
 for name,(commands,modules) in GROUPS.items():result['groups'][name]={'missing_commands':[n for n in commands if not shutil.which(n)],'missing_python_modules':[n for n in modules if importlib.util.find_spec(n) is None]}
 result['local_framebuffer_present']=Path('/dev/fb0').exists();result['radio_configuration_present']=Path('/etc/cloverkit/radios.json').exists()
 result['note']='OS dependencies are not bundled. OBD pure-Python dependencies and reference data are bundled. Presence is not driver or monitor-mode certification.'
 print(json.dumps(result,indent=2));return int(a.strict and (platform.system()!='Linux' or not result['python_supported'] or any(g['missing_commands'] or g['missing_python_modules'] for g in result['groups'].values())))
if __name__=='__main__':raise SystemExit(main())
