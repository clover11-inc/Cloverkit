"""Journal and recover only the external radios owned by Advanced Scan."""
import fcntl
import json
from pathlib import Path
import re
import subprocess
from cloverkit_insights import atomic_json, load_json, verify_external

JOURNAL=Path('/run/cloverkit/passive-radio-restore.json')

def guard(record,root=Path('/sys/class/net')):
    if not re.fullmatch(r'phy\d+',record.get('phy','')):raise RuntimeError('Invalid physical radio identity')
    name=record['name'];verify_external(name,root)
    physical=(root/name/'phy80211').resolve(strict=True)
    if physical.name!=record['phy']:raise RuntimeError('Physical radio identity changed; refusing recovery')
    peers=[p.name for p in root.iterdir() if (p/'phy80211').exists() and (p/'phy80211').resolve()==physical]
    if peers!=[name]:raise RuntimeError('Additional interfaces on development radio; refusing recovery')

def save(records,session,journal=JOURNAL):
    rows=[{k:r[k] for k in ('name','phy','managed','uuid','was_up','original_type')} for r in records]
    atomic_json(journal,dict(session=session,radios=rows))

def clear(session,journal=JOURNAL):
    data=load_json(journal)
    if data.get('session')==session:Path(journal).unlink(missing_ok=True)

def active_captures():
    result=[]
    for directory in Path('/proc').iterdir():
        if not directory.name.isdigit():continue
        try:args=[s.decode(errors='replace') for s in (directory/'cmdline').read_bytes().split(b'\0') if s]
        except OSError:continue
        if args and Path(args[0]).name in ('tshark','dumpcap','tcpdump'):
            if any(args[i] in ('-i','--interface') and args[i+1] in ('wlan1','wlan2','any') for i in range(len(args)-1)) or any(a in ('-iwlan1','-iwlan2','--interface=wlan1','--interface=wlan2') for a in args):
                result.append((directory.name,Path(args[0]).name))
    return result

def call(args):
    result=subprocess.run(args,capture_output=True,text=True,timeout=20)
    if result.returncode:raise RuntimeError(' '.join(args)+': '+(result.stderr or result.stdout).strip())
    return result.stdout

def restore(record,runner=call,root=Path('/sys/class/net')):
    if record.get('original_type')!='managed' or record.get('managed') not in ('yes','no') or type(record.get('was_up')) is not bool:
        raise RuntimeError('Invalid restoration record')
    guard(record,root);name=record['name']
    info=runner(['iw','dev',name,'info'])
    if not re.search(r'^\s*type (?:managed|monitor)\s*$',info,re.M):raise RuntimeError('Radio is in another tool mode; recovery refused')
    for args in (['ip','link','set',name,'down'],['iw','dev',name,'set','type','managed'],['ip','link','set',name,'up' if record['was_up'] else 'down'],['nmcli','device','set',name,'managed',record['managed']]):
        guard(record,root);runner(args)
    info=runner(['iw','dev',name,'info'])
    if not re.search(r'^\s*type managed\s*$',info,re.M):raise RuntimeError('Managed mode restoration was not verified')
    if record['managed']=='yes' and re.fullmatch(r'[0-9a-fA-F-]{36}',record.get('uuid','')):
        guard(record,root);runner(['nmcli','connection','up','uuid',record['uuid'],'ifname',name])

def recover(journal=JOURNAL,phy_root=Path('/sys/class/ieee80211')):
    journal=Path(journal)
    if not journal.exists():return []
    if active_captures():raise RuntimeError('External capture still active; recovery refused')
    data=json.loads(journal.read_text());rows=data.get('radios')
    if not isinstance(rows,list) or len(rows)>2:raise RuntimeError('Invalid radio restoration journal')
    restored=[]
    for record in rows:
        name=record.get('name');phy=record.get('phy','')
        if name not in ('wlan1','wlan2') or not re.fullmatch(r'phy\d+',phy):raise RuntimeError('Invalid recovery identity')
        if not (phy_root/phy).exists():
            # Physical IDs are not reused within a boot. A replugged adapter
            # must never receive the departed device's old restoration state.
            archive=journal.with_name('passive-radio-unplugged.json')
            prior=load_json(archive).get('radios',[])
            atomic_json(archive,dict(radios=(prior+[record])[-16:]))
            restored.append(name+': previous physical radio unplugged; stale state archived')
            continue
        guard(record)
        with open('/run/lock/cloverkit-passive-'+record['phy']+'.lock','a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);restore(record);restored.append(record['name'])
    journal.unlink();return restored

def recover_orphans():
    """Explicit one-time repair when older code left no restoration journal."""
    if active_captures():raise RuntimeError('External capture is active; stop it before recovery')
    repaired=[]
    for name in ('wlan1','wlan2'):
        verify_external(name)
        info=call(['iw','dev',name,'info'])
        if not re.search(r'^\s*type monitor\s*$',info,re.M):continue
        phy=(Path('/sys/class/net')/name/'phy80211').resolve().name
        managed=call(['nmcli','-g','GENERAL.NM-MANAGED','device','show',name]).strip()
        record=dict(name=name,phy=phy,managed=managed,uuid='',was_up=True,original_type='managed')
        with open('/run/lock/cloverkit-passive-'+phy+'.lock','a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);restore(record);repaired.append(name)
    return repaired
