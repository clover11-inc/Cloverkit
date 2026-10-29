"""Optional saved recovery-hotspot override; no personal profile defaults."""
import configparser,io,json,os,subprocess,time,uuid
from pathlib import Path
from cloverkit_optional_setup import CONFIG,atomic_private,clean,private_json
PROFILE='cloverkit-recovery'
def profile_text(ssid,password,mac,identity):
    if not 1<=len(ssid.encode('utf-8'))<=32:raise ValueError('SSID must be 1–32 bytes')
    if not 8<=len(password)<=63 or not password.isascii():raise ValueError('WPA hotspot password must be 8–63 ASCII characters')
    c=configparser.ConfigParser(interpolation=None)
    c['connection']={'id':PROFILE,'uuid':identity,'type':'wifi','interface-name':'wlan0','autoconnect':'false'}
    # SSID keyfile byte-list avoids interpretation of punctuation/backslashes.
    c['wifi']={'mode':'infrastructure','ssid':''.join(str(b)+';' for b in ssid.encode('utf-8')),'mac-address':mac}
    escaped=password.replace('\\','\\\\').replace('\t','\\t')
    c['wifi-security']={'key-mgmt':'wpa-psk','psk':escaped}
    c['ipv4']={'method':'auto'};c['ipv6']={'method':'auto'}
    f=io.StringIO();c.write(f,space_around_delimiters=False);return f.getvalue()
def setup(root=CONFIG):
    import getpass
    if os.geteuid()!=0 or not os.isatty(0):raise SystemExit('Use sudo cloverkit-setup recovery-hotspot in SSH or serial.')
    print('CloverKit — Recovery hotspot\nThis is a hotspot on your phone/router that CloverKit joins to regain management access.')
    if input('Enable recovery hotspot override? [y/N]: ').strip().lower()!='y':
        atomic_private(root/'recovery-hotspot.json',json.dumps({'enabled':False})+'\n')
        subprocess.run(['systemctl','disable','--now','cloverkit-recovery-hotspot.timer'],capture_output=True,timeout=15)
        print('Recovery override disabled; existing connection left unchanged.');return
    ssid=clean(input('Hotspot network name (SSID): '))
    password=clean(getpass.getpass('Hotspot Wi-Fi password (hidden): '))
    if getpass.getpass('Confirm password: ')!=password:raise ValueError('Passwords do not match')
    from cloverkit_radio_identity import check,ROLES
    check('wlan0')
    try:identity=str(uuid.UUID(private_json(root/'recovery-hotspot.json')['profile_uuid']))
    except (OSError,ValueError,KeyError):identity=str(uuid.uuid4())
    profile=profile_text(ssid,password,ROLES['wlan0'][0],identity)
    if input('Save and enable automatic recovery override? [y/N]: ').strip().lower()!='y':
        print('Not saved.');return
    path=root/'recovery-hotspot.nmconnection';atomic_private(path,profile)
    result=subprocess.run(['nmcli','connection','load',str(path)],capture_output=True,text=True,timeout=15)
    if result.returncode:raise RuntimeError('NetworkManager profile import failed; override not enabled')
    atomic_private(root/'recovery-hotspot.json',json.dumps({'enabled':True,'profile_uuid':identity,'ssid':ssid,'interface':'wlan0','poll_seconds':30})+'\n')
    timer=subprocess.run(['systemctl','enable','--now','cloverkit-recovery-hotspot.timer'],capture_output=True,timeout=15)
    if timer.returncode:raise RuntimeError('Hotspot saved but recovery timer could not be enabled; check installation')
    print('Recovery hotspot saved; automatic override enabled when it is visible.')
def once(root=CONFIG):
    try:d=private_json(root/'recovery-hotspot.json')
    except (OSError,ValueError):return
    if not d.get('enabled'):return
    from cloverkit_radio_identity import check
    check('wlan0')
    identity=str(uuid.UUID(d['profile_uuid']))
    current=subprocess.run(['nmcli','-g','GENERAL.CON-UUID','device','show','wlan0'],capture_output=True,text=True,timeout=8)
    if current.stdout.strip()==identity:return
    subprocess.run(['nmcli','device','wifi','rescan','ifname','wlan0'],capture_output=True,timeout=12)
    visible=subprocess.run(['nmcli','-t','--escape','no','-f','SSID','device','wifi','list','ifname','wlan0','--rescan','no'],capture_output=True,text=True,timeout=10)
    if d['ssid'] not in visible.stdout.splitlines():return
    # Explicit opt-in override: may replace the current management connection.
    result=subprocess.run(['nmcli','--wait','15','connection','up','uuid',identity,'ifname','wlan0'],capture_output=True,text=True,timeout=20)
    print('CloverKit recovery hotspot: '+('connected' if result.returncode==0 else 'connection failed'))
