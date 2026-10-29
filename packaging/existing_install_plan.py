#!/usr/bin/env python3
"""Read-only preflight for installing CloverKit beside an existing Blackhat setup."""
import argparse,json,platform
from pathlib import Path

VERSION='0.1.0-alpha.2'
PROTECTED=(
 'boot/armbianEnv.txt','boot/boot.cmd','etc/fstab','etc/hostname',
 'etc/NetworkManager/system-connections','etc/ssh','etc/passwd','etc/shadow',
 'etc/udev/rules.d','etc/modprobe.d','etc/modules-load.d',
 'usr/local/bin/bh-panel','usr/local/bin/bh-serial-gateway','mnt/bh',
)

def inspect(root):
    root=Path(root)
    if not root.is_absolute():raise ValueError('System root must be absolute')
    result={'mode':'read-only preflight','app_version':VERSION,'changes_made':False,
      'startup_default':'off; explicit enable required','installation_approved':False,
      'proposed_layout':{'application':'/opt/cloverkit/releases/'+VERSION,'configuration':'/etc/cloverkit','state':'/var/lib/cloverkit','logs':'/var/log/cloverkit'},
      'existing_paths_preserved':{p:(root/p).exists() for p in PROTECTED},
      'target_detected':False,'native_radio_count':0,'usb_radio_count':0,
      'blockers':['Existing-system activation is not implemented yet.','Runtime paths and native-radio discovery must be relocated before activation.','Existing serial/display services must not be replaced.']}
    model=root/'proc/device-tree/model'
    if model.is_file():result['target_detected']='blackhat' in model.read_bytes().decode(errors='ignore').lower()
    for p in (root/'sys/class/net').glob('*'):
      if not (p/'phy80211').exists():continue
      try:bus=(p/'device/subsystem').resolve().name
      except OSError:continue
      if bus=='sdio':result['native_radio_count']+=1
      elif bus=='usb':result['usb_radio_count']+=1
    result['existing_cloverkit_config']=(root/'etc/cloverkit').exists()
    if not result['target_detected']:result['blockers'].append('Blackhat hardware has not been confirmed.')
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--system-root',type=Path,default=Path('/'));a=p.parse_args()
    print(json.dumps(inspect(a.system_root),indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
