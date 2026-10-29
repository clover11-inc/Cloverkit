"""Protect the native SDIO radio; discover USB radios without saved USB identities."""
import json,re
from pathlib import Path

def load_roles(path=Path('/etc/cloverkit/radios.json')):
    try:
        row=json.loads(path.read_text())['roles']['wlan0']
        if row['bus']!='sdio' or not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',row['mac']):raise ValueError('native role')
        return {'wlan0':(row['mac'],'sdio')}
    except (OSError,KeyError,ValueError,TypeError) as error:
        raise RuntimeError('Native radio setup incomplete; scanning blocked') from error
ROLES=load_roles()

def check(name,root=Path('/sys/class/net')):
    if name not in ('wlan0','wlan1','wlan2'):raise RuntimeError('Unsupported radio')
    iface=root/name
    bus=(iface/'device/subsystem').resolve(strict=True).name
    expected='sdio' if name=='wlan0' else 'usb'
    if bus!=expected:raise RuntimeError('Wrong hardware bus: '+name)
    if name=='wlan0' and (iface/'address').read_text().strip().lower()!=ROLES['wlan0'][0]:raise RuntimeError('Native identity mismatch; scanning blocked')
    return (iface/'phy80211').resolve(strict=True)

def assert_layout(root=Path('/sys/class/net')):
    protected=check('wlan0',root)
    for name in ('wlan1','wlan2'):
        if (root/name).exists() and check(name,root)==protected:raise RuntimeError('USB adapter shares native radio')

def verify_usb(name,root=Path('/sys/class/net')):
    if name not in ('wlan1','wlan2'):raise RuntimeError('Only USB test adapters allowed')
    assert_layout(root)
    return check(name,root)
