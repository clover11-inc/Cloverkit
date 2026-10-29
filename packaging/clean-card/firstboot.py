#!/usr/bin/python3
"""Activate only a new, marked CloverKit image. Never migrate a running owner card."""
import hashlib,json,os,pwd,shutil,subprocess,sys,tarfile,time,threading
from pathlib import Path
HERE=Path('/boot/bh/cloverkit-clean')
STATE=Path('/var/lib/cloverkit/clean-install.json')
def run(args,**kwargs):
    timeout=kwargs.pop('timeout',120)
    if args[0] not in ('apt-get','/usr/lib/armbian/armbian-resize-filesystem'):
        return subprocess.run(args,check=True,timeout=timeout,**kwargs)
    stop=threading.Event();started=time.monotonic();log=getattr(kwargs.get('stdout'),'name',None)
    def heartbeat():
        while not stop.wait(20):
            tail=''
            if log:
                try:
                    with open(log,'rb') as stream:
                        stream.seek(0,2);stream.seek(max(0,stream.tell()-2048));lines=stream.read().decode(errors='replace').splitlines()
                    if lines:tail=' | '+''.join(c for c in lines[-1] if c.isprintable())[:100]
                except OSError:pass
            label='Dependency setup' if args[0]=='apt-get' else 'Card expansion'
            print('CloverKit: '+label+' | '+str(int(time.monotonic()-started))+'s elapsed'+tail,flush=True)
    worker=threading.Thread(target=heartbeat,daemon=True);worker.start()
    try:return subprocess.run(args,check=True,timeout=timeout,**kwargs)
    finally:stop.set();worker.join(timeout=1)
def write(path,text,mode=0o644):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text);path.chmod(mode)
def progress(text):print('CloverKit: '+text,flush=True)
def enable_unit_offline(unit):
    source=Path('/etc/systemd/system')/unit
    targets=[line.split('=',1)[1].split() for line in source.read_text().splitlines() if line.startswith('WantedBy=')]
    for group in targets:
        for target in group:
            if target not in ('multi-user.target','sysinit.target'):raise RuntimeError('Unexpected enable target')
            link=Path('/etc/systemd/system')/(target+'.wants')/unit
            link.parent.mkdir(parents=True,exist_ok=True)
            if link.is_symlink():
                if link.resolve()!=source.resolve():raise RuntimeError('Conflicting enabled unit')
            elif link.exists():raise RuntimeError('Unexpected enable path')
            else:link.symlink_to(source)
def verify():
    if os.geteuid()!=0:raise RuntimeError('Root required')
    manifest=json.loads((HERE/'payload-manifest.json').read_text())
    build=manifest['build_id']
    if 'cloverkit.clean='+build not in Path('/proc/cmdline').read_text().split():raise RuntimeError('Clean-image boot marker missing')
    uuid=run(['findmnt','-n','-o','UUID','/'],text=True,capture_output=True).stdout.strip()
    if uuid!=manifest['root_uuid']:raise RuntimeError('Unexpected root filesystem; refusing activation')
    if STATE.exists():
        old=json.loads(STATE.read_text())
        if old['build_id']!=build:raise RuntimeError('A different installed build is present')
    if Path('/etc/cloverkit/owner-configured.json').exists():raise RuntimeError('Owner-configured installation; refuses clean provisioning')
    for row in manifest['files']:
        rel=Path(row['path'])
        if rel.is_absolute() or '..' in rel.parts:raise RuntimeError('Unsafe payload path')
        path=HERE/rel
        if path.is_symlink() or hashlib.file_digest(path.open('rb'),'sha256').hexdigest()!=row['sha256']:raise RuntimeError('Payload changed: '+row['path'])
    return manifest
def main():
    manifest=verify();build=manifest['build_id'];progress('verified clean image and all offline payloads')
    rootdev=run(['findmnt','-n','-o','SOURCE','/'],text=True,capture_output=True).stdout.strip()
    if not rootdev.startswith('/dev/mmcblk') or run(['lsblk','-n','-o','PARTN',rootdev],text=True,capture_output=True).stdout.strip()!='2':raise RuntimeError('Expected SD-card root partition 2')
    progress('expanding this new SD card using the supplied Armbian resize helper')
    with (HERE/'resize.log').open('a') as log:run(['/usr/lib/armbian/armbian-resize-filesystem','start'],stdout=log,stderr=subprocess.STDOUT,timeout=600)
    if Path('/var/run/resize2fs-reboot').exists():
        progress('partition expansion requires a reboot; installation will resume automatically')
        run(['systemctl','--no-block','reboot']);return
    if shutil.disk_usage('/').free<250*1024*1024:raise RuntimeError('Insufficient root filesystem space after expansion')
    policy=Path('/usr/sbin/policy-rc.d');old_policy=policy.read_bytes() if policy.exists() else None
    old_mode=policy.stat().st_mode&0o777 if policy.exists() else None
    progress('installing verified offline diagnostic dependencies; this can take several minutes')
    write(policy,'#!/bin/sh\nexit 101\n',0o755)
    source=HERE/'offline.sources.list';source.write_text('deb [trusted=yes] file:'+str(HERE/'offline-repo')+' ./\n')
    options=['-o','Dir::Etc::sourcelist='+str(source),'-o','Dir::Etc::sourceparts=-','-o','Acquire::Languages=none','-o','APT::Get::List-Cleanup=0']
    cache=json.loads((HERE/'offline-repo/manifest.json').read_text())
    env=dict(os.environ,DEBIAN_FRONTEND='noninteractive')
    try:
        with (HERE/'dependencies.log').open('a') as log:
            run(['apt-get',*options,'update'],env=env,stdout=log,stderr=subprocess.STDOUT,timeout=600)
            run(['apt-get',*options,'--no-install-recommends','-y','-o','Dpkg::Options::=--force-confold','install',*cache['targets']],env=env,stdout=log,stderr=subprocess.STDOUT,timeout=1800)
    finally:
        if old_policy is None:policy.unlink(missing_ok=True)
        else:policy.write_bytes(old_policy);policy.chmod(old_mode)
    audit=run(['dpkg','--audit'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    if audit.stdout.strip():raise RuntimeError('dpkg reports unfinished package configuration; see dependencies.log')
    progress('installing CloverKit runtime and local documentation')
    archive=HERE/'runtime.tar.gz'
    with tarfile.open(archive,'r:gz') as tar:
        # Root paths are generated from the verified manifest; no links/devices allowed.
        for member in tar.getmembers():
            name=Path(member.name)
            if name.is_absolute() or '..' in name.parts or not (member.isfile() or member.isdir()):raise RuntimeError('Unsafe runtime archive')
        tar.extractall('/',filter='data')
    files=json.loads((HERE/'runtime-files.json').read_text())
    for row in files:
        target=Path('/')/row['path']
        if hashlib.file_digest(target.open('rb'),'sha256').hexdigest()!=row['sha256']:raise RuntimeError('Installed file verification failed: '+row['path'])
        target.chmod(row['mode'])
    share=Path('/usr/local/share/cloverkit')
    if share.is_symlink():
        if os.readlink(share)!='/opt/cloverkit':raise RuntimeError('Unexpected documentation link')
    elif share.exists():raise RuntimeError('Unexpected pre-existing documentation directory')
    else:share.symlink_to('/opt/cloverkit',target_is_directory=True)
    Path('/mnt').mkdir(exist_ok=True)
    if not os.path.ismount('/mnt'):run(['mount','--bind','/boot/bh','/mnt'])
    Path('/mnt/roms').mkdir(exist_ok=True)
    Path('/mnt/scripts').mkdir(exist_ok=True)
    Path('/var/lib/cloverkit').mkdir(exist_ok=True,parents=True,mode=0o700)
    progress('removing stock credentials and creating fresh locked operator/guest accounts')
    for name in ('admin','console','conwifi','conveh'):
        try:pwd.getpwnam(name)
        except KeyError:
            if name=='conveh':run(['useradd','--system','--home-dir','/var/empty/conveh','--shell','/bin/sh',name])
            else:run(['useradd','--create-home','--shell','/bin/bash',name])
        run(['passwd','-l',name],stdout=subprocess.DEVNULL)
    groups=[g for g in ('sudo','dialout','video','input') if (Path('/etc/group').read_text().find(g+':')>=0)]
    run(['usermod','-a','-G',','.join(groups),'admin'])
    run(['passwd','-l','root'],stdout=subprocess.DEVNULL)
    write('/etc/hostname','cloverkit\n')
    write('/etc/hosts','127.0.0.1 localhost\n127.0.1.1 cloverkit\n::1 localhost ip6-localhost ip6-loopback\n')
    for path in Path('/etc/ssh').glob('ssh_host_*'):path.unlink(missing_ok=True)
    for base in (Path('/root'),Path('/home/admin')):
        for rel in ('.ssh','.bash_history','.python_history','.lesshst'):
            path=base/rel
            if path.is_dir():shutil.rmtree(path)
            else:path.unlink(missing_ok=True)
    for folder in ('/etc/NetworkManager/system-connections','/var/lib/bluetooth','/var/lib/NetworkManager'):
        path=Path(folder)
        if path.exists():
            for child in path.iterdir():
                if child.is_dir():shutil.rmtree(child)
                else:child.unlink()
    for path in (Path('/etc/machine-id'),Path('/var/lib/dbus/machine-id'),Path('/var/lib/systemd/random-seed')):path.unlink(missing_ok=True)
    run(['systemd-machine-id-setup'])
    Path('/var/lib/dbus').mkdir(parents=True,exist_ok=True)
    Path('/var/lib/dbus/machine-id').symlink_to('/etc/machine-id')
    run(['ssh-keygen','-A'],stdout=subprocess.DEVNULL)
    Path('/run/sshd').mkdir(parents=True,exist_ok=True)
    run(['/usr/sbin/sshd','-t'])
    run(['/usr/sbin/visudo','-cf','/etc/sudoers.d/cloverkit-owner'],stdout=subprocess.DEVNULL)
    run(['/usr/sbin/visudo','-cf','/etc/sudoers.d/cloverkit-conveh'],stdout=subprocess.DEVNULL)
    for name in ('ssh.service','ssh.socket','nfs-server.service','rpcbind.service','rpcbind.socket','iperf3.service','getty@tty1.service'):
        # Temporary first-boot masks can prevent systemctl disable from editing
        # enablement links. Remove only these fresh-image wanted-unit links.
        for folder in Path('/etc/systemd/system').glob('*.wants'):
            for link in folder.iterdir():
                if link.is_symlink() and (link.name==name or link.resolve().name==name):link.unlink()
        subprocess.run(['systemctl','disable',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    # Guest passwords stay locked until the corresponding local feature explicitly enables access.
    progress('registering this board native radio and checking core imports')
    run(['/usr/local/bin/cloverkit-name-radios'])
    run(['/usr/bin/python3','-c','import PIL,scapy.all,bleak,serial,requests'])
    run(['/usr/bin/python3','-c',"import sys;sys.path.insert(0,'/usr/local/lib/bh-interactive');import bh_panel"])
    run(['/usr/bin/python3','/opt/cloverkit/tools/verify_package.py'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    for command in ('nmcli','iw','tshark','tcpdump','bluetoothctl','nmap','iperf3','ethtool','rfkill'):
        if not shutil.which(command):raise RuntimeError('Missing diagnostic dependency: '+command)
    subprocess.run(['systemctl','disable','armbian-firstrun.service'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    for unit in ('bh-boot.service','cloverkit-radio-names.service','bh-serial-gateway.service','cloverkit-boot-splash.service','cloverkit-serial.service','cloverkit-target-clean.service','cloverkit-guest-lock.service'):
        enable_unit_offline(unit)
    progress('checking installed systemd units')
    with (HERE/'service-validation.log').open('w') as log:run(['systemd-analyze','verify',*[str(p) for p in Path('/etc/systemd/system').glob('cloverkit-*.service')],'/etc/systemd/system/bh-serial-gateway.service'],env=dict(os.environ,SYSTEMD_UNIT_PATH='/etc/systemd/system:/usr/lib/systemd/system'),stdout=log,stderr=subprocess.STDOUT)
    result={'schema':1,'build_id':build,'installed':True,'installed_at':int(time.time()),'hardware_test':'pending','personal_configuration_imported':False,'offline_dependencies':len(cache['packages'])}
    write(STATE,json.dumps(result,indent=2)+'\n',0o600)
    write('/etc/cloverkit/clean-image.json',json.dumps({'build_id':build,'clean_image':True},indent=2)+'\n',0o644)
    # Normal boots start only after all validation above succeeded.
    env=Path('/boot/armbianEnv.txt')
    original=env.read_text().splitlines();normal=[]
    for line in original:
        if line.startswith('extraargs='):
            line='extraargs='+' '.join(x for x in line.split('=',1)[1].split() if not x.startswith(('systemd.run=','systemd.run_success_action=','systemd.run_failure_action=','systemd.mask=','cloverkit.clean=')))
        if line.startswith('console='):line='console=serial'
        if line.startswith('extraargs='):line+=' systemd.show_status=false quiet'
        normal.append(line)
    write(env,'\n'.join(normal)+'\n')
    progress('ready — panel enabled; no saved Wi-Fi, email, VPN, Flipper pairing or active SSH credentials')
if __name__=='__main__':
    try:main()
    except Exception as error:
        import traceback;traceback.print_exc();raise SystemExit(1)
