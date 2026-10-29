#!/usr/bin/python3
"""Configure an installation-local management account from a private terminal."""
import getpass,json,os,re,subprocess,sys
from pathlib import Path

def call(args,**kwargs):return subprocess.run(args,check=True,timeout=90,**kwargs)
def valid_username(name):
    return bool(re.fullmatch(r'[a-z][a-z0-9_-]{0,31}',name)) and name not in {'root','console','conwifi','conveh','nobody'}
def write_private(path,text,mode=0o600):
    path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_name(path.name+'.owner-setup-new')
    temp.write_text(text);temp.chmod(mode);temp.replace(path)
def main():
    if os.geteuid()!=0:raise SystemExit('Run sudo cloverkit-owner-setup from the local console.')
    if not sys.stdin.isatty():raise SystemExit('An interactive terminal is required.')
    import pwd
    marker=Path('/etc/cloverkit/owner-configured.json')
    previous=json.loads(marker.read_text()).get('username') if marker.exists() else None
    default=previous or 'admin'
    print('CloverKit owner setup')
    while True:
        name=input('Management username ['+default+']: ').strip() or default
        if not valid_username(name):
            print('Use a lowercase letter followed by letters, numbers, underscores or dashes; maximum 32 characters. Restricted account names cannot be used.');continue
        try:
            account=pwd.getpwnam(name)
        except KeyError:account=None
        if account and (account.pw_uid<1000 or name not in (previous,'admin')):
            print('That account already exists and is not this installation\'s configured owner. Choose another name.');continue
        break
    while True:
        first=getpass.getpass('New operator password (at least 12 characters): ')
        if len(first)<12 or any(c in first for c in '\n\r\x00'):
            print('Password must contain at least 12 characters.');continue
        second=getpass.getpass('Repeat password: ')
        if first==second:break
        print('Passwords did not match. Try again.')
    if account is None:call(['/usr/sbin/useradd','-m','-s','/bin/bash',name])
    groups=['sudo']
    import grp
    for group in ('dialout','video','input'):
        try:grp.getgrnam(group);groups.append(group)
        except KeyError:pass
    call(['/usr/sbin/usermod','-a','-G',','.join(groups),name])
    ssh=Path('/etc/ssh/sshd_config.d/00-cloverkit-clean.conf')
    original=ssh.read_text()
    updated,count=re.subn(r'^AllowUsers .*$', 'AllowUsers '+name+' console conwifi conveh',original,flags=re.M)
    if count!=1:raise ValueError('Expected clean-install SSH allowlist missing; no configuration changed.')
    paths={ssh:updated,Path('/etc/sudoers.d/cloverkit-owner'):name+' ALL=(ALL:ALL) ALL\n'}
    vehicle=Path('/etc/sudoers.d/cloverkit-conveh')
    if vehicle.exists():
        paths[vehicle]=re.sub(r'^[a-z][a-z0-9_-]* ALL=\(root\) NOPASSWD: (.*conveh_access\.py enable.*)$',lambda m:name+' ALL=(root) NOPASSWD: '+m[1],vehicle.read_text(),flags=re.M)
    saved={p:(p.read_bytes(),p.stat().st_mode&0o777) for p in paths}
    try:
        for p,text in paths.items():write_private(p,text,0o440 if 'sudoers.d' in str(p) else 0o644)
        call(['/usr/sbin/visudo','-c'],stdout=subprocess.DEVNULL)
        call(['/usr/sbin/sshd','-t'])
        call(['/usr/sbin/chpasswd'],input=name+':'+first+'\n',text=True)
    except BaseException:
        for p,(data,mode) in saved.items():p.write_bytes(data);p.chmod(mode)
        raise
    first=second=None
    write_private(Path('/etc/cloverkit/operator.env'),'CLOVERKIT_USER='+name+'\n')
    drop=Path('/etc/systemd/system/cloverkit-serial.service.d/owner.conf')
    write_private(drop,'[Service]\nEnvironmentFile=/etc/cloverkit/operator.env\n',0o644)
    call(['/usr/bin/systemctl','daemon-reload'])
    write_private(marker,json.dumps({'configured':True,'username':name})+'\n')
    if input('Enable SSH for '+name+' on networks you connect to? [y/N]: ').strip().lower()=='y':
        call(['/usr/bin/systemctl','enable','--now','ssh.service'])
        call(['/usr/bin/systemctl','reload','ssh.service'])
        print('SSH enabled for '+name+'. Root SSH and unrestricted guest logins remain disabled.')
    elif subprocess.run(['/usr/bin/systemctl','is-active','--quiet','ssh.service']).returncode==0:
        call(['/usr/bin/systemctl','reload','ssh.service'])
    if input('Set up a new Wi-Fi connection now? [y/N]: ').strip().lower()=='y':
        ssid=input('Wi-Fi network name: ').strip()
        if not ssid:raise ValueError('A network name is required')
        call(['/usr/bin/nmcli','--ask','device','wifi','connect',ssid,'ifname','wlan0'])
    print('Owner setup complete: '+name+'. Existing accounts and home files were not deleted.')
    print('Reboot when convenient to apply the owner identity to the shared serial-console service.')
    print('Optional setup: sudo cloverkit-setup email / vpn / recovery-hotspot')
if __name__=='__main__':
    try:main()
    except (OSError,ValueError,subprocess.CalledProcessError,subprocess.TimeoutExpired,KeyboardInterrupt) as error:raise SystemExit('Setup stopped: '+str(error))
