"""Optional CloverKit email/VPN setup; nothing sends or connects on import."""
import getpass,json,os,re,shutil,smtplib,ssl,stat,tempfile
from email.message import EmailMessage
from pathlib import Path

CONFIG=Path('/etc/cloverkit')
def atomic_private(path,data):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    if path.is_symlink():raise ValueError('Configuration symlink refused')
    fd,tmp=tempfile.mkstemp(prefix='.cloverkit-',dir=path.parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'w') as f:f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if Path(tmp).exists():Path(tmp).unlink()

def private_json(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077:
        raise ValueError('Configuration must be root-owned and private')
    return json.loads(path.read_text())

def clean(value):
    if not isinstance(value,str) or any(c in value for c in '\r\n\x00'):raise ValueError('Invalid field')
    return value.strip()

def email_settings(root=CONFIG):
    try:
        d=private_json(root/'email.json')
        if not d.get('enabled'):return None
        for field in ('host','username','password','sender','recipient'):clean(d[field])
        if d['tls'] not in ('starttls','ssl') or not 1<=int(d['port'])<=65535:raise ValueError('Invalid SMTP settings')
        return d
    except (OSError,ValueError,KeyError,TypeError):return None

def send_access(kind,username,password,host,root=CONFIG):
    """Shared credential notification for scan reports, serial console and future uses.

    Returns a status only. Caller retains local access details on absent/failed email.
    Never logs credentials or exception text.
    """
    settings=email_settings(root)
    if settings is None:return 'NOT CONFIGURED'
    try:
        kind,username,password,host=map(clean,(kind,username,password,host))
        message=EmailMessage()
        message['Subject']='CloverKit — '+kind+' access'
        message['From']=settings['sender'];message['To']=settings['recipient']
        message.set_content('CloverKit '+kind+'\n\nSSH: ssh -t '+username+'@'+host+'\nPassword: '+password+'\n\nTemporary access. Access ends when its owning workflow disables it.\n')
        context=ssl.create_default_context()
        cls=smtplib.SMTP_SSL if settings['tls']=='ssl' else smtplib.SMTP
        kwargs={'timeout':15}
        if settings['tls']=='ssl':kwargs['context']=context
        with cls(settings['host'],int(settings['port']),**kwargs) as client:
            if settings['tls']=='starttls':client.ehlo();client.starttls(context=context);client.ehlo()
            client.login(settings['username'],settings['password'])
            client.send_message(message)
        return 'SENT'
    except (OSError,ValueError,smtplib.SMTPException):return 'FAILED'

def wizard(kind,root=CONFIG):
    if os.geteuid()!=0:raise SystemExit('Run the installed setup wizard with sudo from SSH or serial.')
    if not os.isatty(0):raise SystemExit('Setup needs an interactive SSH or serial terminal.')
    print('CloverKit — '+kind.upper()+' setup\nNo email is sent and no VPN connection is started by setup.')
    if kind=='email':
        enabled=input('Enable optional access emails? [y/N]: ').strip().lower()=='y'
        if not enabled:atomic_private(root/'email.json',json.dumps({'enabled':False})+'\n');return
        d={'enabled':True,'host':clean(input('SMTP server: ')),'port':int(input('SMTP port [587]: ') or '587'),'tls':clean(input('TLS mode starttls/ssl [starttls]: ') or 'starttls')}
        d['username']=clean(input('SMTP username: '));d['password']=clean(getpass.getpass('SMTP/app password (hidden): '))
        d['sender']=clean(input('Sender email: '));d['recipient']=clean(input('Access notification recipient: '))
        if d['tls'] not in ('starttls','ssl') or not 1<=d['port']<=65535 or not all(d.get(k) for k in ('host','username','password','sender','recipient')):raise ValueError('Incomplete email settings')
        if any(not re.fullmatch(r'[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+',d[k]) for k in ('sender','recipient')):raise ValueError('Invalid email address')
        atomic_private(root/'email.json',json.dumps(d,indent=2)+'\n')
        print('Email configured. Notifications are sent only when an access workflow requests them.')
    elif kind=='vpn':
        if input('Configure optional OpenVPN? [y/N]: ').strip().lower()!='y':
            atomic_private(root/'vpn.json',json.dumps({'configured':False})+'\n');return
        source=Path(input('Path to provider .ovpn profile: ').strip())
        data=source.read_text();profile=validate_profile(data)
        user=clean(input('VPN username (blank if profile uses certificates only): '))
        if user:
            password=clean(getpass.getpass('VPN password (hidden): '))
            atomic_private(root/'vpn/auth.txt',user+'\n'+password+'\n')
            profile+='\nauth-user-pass /etc/cloverkit/vpn/auth.txt\n'
        elif any(line.strip().startswith('auth-user-pass') for line in data.splitlines()):
            raise ValueError('This profile requires VPN username/password')
        atomic_private(root/'vpn/client.ovpn',profile)
        atomic_private(root/'vpn.json',json.dumps({'configured':True,'provider':'user-supplied OpenVPN profile','auto_connect':False})+'\n')
        print('VPN configured; disconnected. Use System > VPN > On when ready.')
    else:raise ValueError('Unknown setup type')

def validate_profile(data):
    # Import self-contained profiles only. Do not copy arbitrary provider script/config paths.
    allowed={'client','dev','dev-type','proto','remote','remote-random','remote-random-hostname','resolv-retry','nobind','persist-key','persist-tun','remote-cert-tls','verify-x509-name','auth','cipher','data-ciphers','data-ciphers-fallback','auth-nocache','auth-user-pass','verb','mute','mute-replay-warnings','connect-retry','connect-retry-max','connect-timeout','ping','ping-restart','keepalive','reneg-sec','tls-client','tls-version-min','tls-cipher','tls-ciphersuites','key-direction','route','route-ipv6','redirect-gateway','redirect-private','dhcp-option','explicit-exit-notify','pull','pull-filter','route-nopull','tun-mtu','mssfix','sndbuf','rcvbuf','fast-io','compress','comp-lzo','allow-compression','auth-retry'}
    external={'ca','cert','key','pkcs12','tls-auth','tls-crypt','tls-crypt-v2','auth-gen-token-secret'}
    output=[];tag=None;has_client=False;has_remote=False
    for line in data.splitlines():
        stripped=line.strip()
        if tag:
            output.append(line)
            if stripped=='</'+tag+'>':tag=None
            continue
        if stripped.startswith('<') and stripped.endswith('>'):
            current=stripped[1:-1]
            if current not in external:raise ValueError('Unsupported embedded profile block')
            tag=current;output.append(line);continue
        fields=stripped.split()
        if not fields or fields[0].startswith(('#',';')):output.append(line);continue
        name=fields[0].lstrip('-')
        if name not in allowed or name in external:raise ValueError('Profile needs review: '+name)
        if name=='auth-user-pass':continue
        if name=='client':has_client=True
        if name=='remote':has_remote=True
        output.append(line)
    if tag or not has_client or not has_remote:raise ValueError('Use a complete client profile with a remote server')
    if not any(line.strip()=='remote-cert-tls server' for line in output):output.append('remote-cert-tls server')
    return '\n'.join(output)+'\n'
