#!/usr/bin/python3
"""Cold-boot native naming before NetworkManager; no fixed USB MACs or port labels."""
import json,subprocess,time,sys,os
from pathlib import Path
NET=Path('/sys/class/net')
CONFIG=Path('/etc/cloverkit/radios.json')
def call(*args):return subprocess.run(args,check=True,timeout=15,capture_output=True,text=True)
def main():
    if os.geteuid()!=0:raise RuntimeError('Root required')
    call('/usr/sbin/modprobe','rtw88_8723ds')
    for attempt in range(80):
        radios=[p for p in NET.iterdir() if (p/'phy80211').exists()]
        native=[p for p in radios if (p/'device/subsystem').resolve().name=='sdio']
        if len(native)==1:break
        time.sleep(.25)
    if len(native)!=1:raise RuntimeError('Expected exactly one native SDIO Wi-Fi radio')
    mac=(native[0]/'address').read_text().strip().lower()
    if CONFIG.exists() and json.loads(CONFIG.read_text())['roles']['wlan0']['mac']!=mac:raise RuntimeError('Native identity changed; local owner review required')
    usb=sorted((p for p in radios if (p/'device/subsystem').resolve().name=='usb'),key=lambda p:p.name)
    desired=[(native[0],'wlan0')]+[(p,'wlan'+str(i)) for i,p in enumerate(usb,1)]
    moves=[(p,'ckboot'+str(i),name) for i,(p,name) in enumerate(desired) if p.name!=name]
    for p,temp,name in moves:
        data=json.loads(call('/usr/sbin/ip','-j','address','show','dev',p.name).stdout)
        if any(a.get('scope')=='global' for row in data for a in row.get('addr_info',[])):raise RuntimeError('Refusing to rename a connected radio')
    for p,temp,name in moves:
        call('/usr/sbin/ip','link','set',p.name,'down')
        call('/usr/sbin/ip','link','set',p.name,'name',temp)
    for p,temp,name in moves:call('/usr/sbin/ip','link','set',temp,'name',name)
    CONFIG.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if not CONFIG.exists():
        CONFIG.write_text(json.dumps({'schema':2,'roles':{'wlan0':{'mac':mac,'bus':'sdio'}}},indent=2)+'\n');CONFIG.chmod(0o600)
    sys.path.insert(0,'/usr/local/lib/bh-interactive')
    from cloverkit_radio_identity import assert_layout
    assert_layout()
    print('Native wlan0 protected; USB adapters discovered dynamically.')
if __name__=='__main__':main()
