"""Offline MAC attribution. Registered vendor is not a device-model identity."""
from functools import lru_cache
from pathlib import Path
import re
import json
import subprocess

DB_PATHS = (Path('/usr/local/lib/bh-interactive/manuf'), Path('/usr/share/wireshark/manuf'),
            Path('/usr/share/misc/manuf'), Path('/usr/share/ieee-data/oui.txt'))
OPTIONAL_FIELDS = ('wps.device_name','wps.manufacturer','wps.model_name','wlan.cisco.ccx1.name','wlan.vs.cisco.apname_v2')
CAPABILITIES = Path('/usr/local/lib/bh-interactive/identity-fields.json')

MAC = re.compile(r'(?:[0-9A-F]{2}:){5}[0-9A-F]{2}')


def parse_database(text):
    entries = {}
    for line in text.splitlines():
        line = line.split('#',1)[0].strip()
        if not line:
            continue
        ieee = re.match(r'^([0-9A-Fa-f-]{8})\s+\(hex\)\s+(.+)$',line)
        if ieee:
            prefix, vendor = ieee.groups()
            bits = 24
        else:
            pieces = line.split(None,2)
            if len(pieces) < 2:
                continue
            prefix = pieces[0]
            vendor = pieces[2] if len(pieces)>2 else pieces[1]
            if '/' in prefix:
                prefix, width = prefix.split('/',1)
                if not width.isdigit():
                    continue
                bits = int(width)
            else:
                bits = len(prefix.replace(':','').replace('-',''))*4
        compact = prefix.replace(':','').replace('-','')
        if not re.fullmatch(r'[0-9A-Fa-f]+',compact) or not 24 <= bits <= 48 or len(compact)>12 or len(compact)*4 < bits:
            continue
        number = int(compact.ljust(12,'0'),16) >> (48-bits)
        entries[(bits,number)] = vendor.strip()
    return entries


class Vendors:
    def __init__(self, paths=DB_PATHS):
        self.entries = {}
        self.source = None
        for path in paths:
            try:
                entries = parse_database(Path(path).read_text(errors='replace'))
            except OSError:
                continue
            if entries:
                self.entries, self.source = entries, str(path)
                break
        self.widths = sorted({bits for bits,_ in self.entries},reverse=True)

    @lru_cache(maxsize=10000)
    def lookup(self, address):
        address = str(address).upper()
        if not MAC.fullmatch(address):
            return None
        first = int(address[:2],16)
        if first & 3:  # Group/local addresses cannot provide reliable vendor identity.
            return None
        number = int(address.replace(':',''),16)
        for bits in self.widths:
            vendor = self.entries.get((bits,number >> (48-bits)))
            if vendor:
                return vendor
        return None


@lru_cache(maxsize=1)
def database():
    return Vendors()


def identify(address, role=None, hostname=None, model=None, vendors=None, advertised_vendor=None):
    address = str(address).upper()
    vendors = vendors if vendors is not None else database()
    valid = bool(MAC.fullmatch(address))
    local = bool(int(address[:2],16)&2) if valid else False
    group = bool(int(address[:2],16)&1) if valid else False
    vendor = vendors.lookup(address)
    result = dict(vendor=vendor or 'Unknown', role=role or 'Unknown', device_type='Unknown',
                  confidence='Unknown', name=hostname or None, model=model or None,
                  address_kind='Group address' if group else 'Locally administered / possibly private' if local else 'Global MAC' if valid else 'Invalid MAC',
                  evidence=[])
    if vendor:
        result['evidence'].append('Registered MAC prefix: '+vendor+'; may identify the network-chip maker')
    elif local:
        result['evidence'].append('Local bit set; manufacturer cannot be inferred from this prefix')
    elif not vendors.entries:
        result['evidence'].append('Offline manufacturer database unavailable')
    else:
        result['evidence'].append('No manufacturer match in the local database')
    if role:
        result['evidence'].append('Observed '+role+' frame role; not a device-model identification')
    if advertised_vendor:
        result['advertised_vendor'] = advertised_vendor
        result['evidence'].append('Advertised manufacturer: '+str(advertised_vendor)+'; self-reported')
    clue_vendor = advertised_vendor or vendor
    if role == 'AP':
        result.update(device_type='Access point',confidence='Observed role')
    elif hostname and re.search(r'\b(printer|laserjet|officejet|deskjet)\b',hostname,re.I):
        result.update(device_type='Likely printer',confidence='Likely')
        result['evidence'].append('Advertised name contains a printer keyword')
    elif clue_vendor and re.search(r'\b(brother|zebra)\b',clue_vendor,re.I):
        result.update(device_type='Likely printer/label device',confidence='Likely')
        result['evidence'].append('Vendor commonly produces printing devices; model unconfirmed')
    elif clue_vendor and 'espressif' in clue_vendor.lower():
        result.update(device_type='Likely embedded/IoT device',confidence='Likely')
        result['evidence'].append('Espressif network hardware; finished product unconfirmed')
    elif clue_vendor and 'raspberry pi' in clue_vendor.lower():
        result.update(device_type='Likely single-board computer',confidence='Likely')
        result['evidence'].append('Raspberry Pi registered prefix; finished product unconfirmed')
    if hostname:
        result['evidence'].append('Advertised name: '+str(hostname))
    if model:
        result['evidence'].append('Reported model: '+str(model)+'; not verified from MAC')
    return result


def summary(address, role=None, **evidence):
    info = identify(address,role,**evidence)
    if info['address_kind'].startswith('Locally'):
        vendor = 'Private/local MAC'
    else:
        vendor = info['vendor']
    kind = info['device_type'] if info['device_type'] != 'Unknown' else (role or 'Type unknown')
    if info.get('advertised_vendor'):
        vendor += ' | Advertised '+info['advertised_vendor']
    if info.get('name'):
        kind += ' | Name '+str(info['name'])
    if info.get('model'):
        kind += ' | Advertised model '+str(info['model'])
    return vendor+' | '+kind


def install_database(destination=Path('/usr/local/lib/bh-interactive/manuf')):
    """Use installed Wireshark data, without web queries or new dependencies."""
    for path in DB_PATHS[1:]:
        try:
            text = path.read_text(errors='replace')
        except OSError:
            continue
        if len(parse_database(text)) >= 100:
            destination.write_text(text); destination.chmod(0o644)
            return True
    try:
        result = subprocess.run(['/usr/bin/tshark','-G','manuf'],capture_output=True,text=True,timeout=20)
        if result.returncode == 0 and len(parse_database(result.stdout)) >= 100:
            destination.write_text(result.stdout); destination.chmod(0o644)
            return True
    except (OSError,subprocess.TimeoutExpired):
        pass
    try:
        return bool(parse_database(destination.read_text()))
    except OSError:
        return False


def identity_fields():
    try:
        values = json.loads(CAPABILITIES.read_text())
        return [field for field in OPTIONAL_FIELDS if field in values]
    except (OSError,ValueError,TypeError):
        return []


def install_capabilities():
    fields = []
    try:
        result = subprocess.run(['/usr/bin/tshark','-G','fields'],capture_output=True,text=True,timeout=20)
        if result.returncode == 0:
            supported = {p[2] for line in result.stdout.splitlines() if len(p:=line.split('\t'))>2 and p[0]=='F'}
            fields = [field for field in OPTIONAL_FIELDS if field in supported]
    except (OSError,subprocess.TimeoutExpired):
        print('WARNING: Optional identity fields unavailable; offline MAC lookup remains enabled.')
    CAPABILITIES.write_text(json.dumps(fields))
    CAPABILITIES.chmod(0o644)


def client_metadata(path):
    """Bounded JSON comment; never interpret generated shell commands."""
    try:
        with Path(path).open() as source:
            for _ in range(8):
                line = source.readline(4096)
                if line.startswith('# CLIENT_INFO '):
                    info = json.loads(line[len('# CLIENT_INFO '):])
                    return info if isinstance(info,dict) else {}
    except (OSError,ValueError):
        pass
    return {}


def client_label(address, device=None):
    device = device or {}
    evidence = device.get('identity',{})
    info = identify(address, 'Client' if device.get('links') or device.get('bssid') else 'Probe transmitter',
                    **{k:v for k,v in evidence.items() if k in ('hostname','model','advertised_vendor')})
    name = info.get('name') or info.get('advertised_vendor') or (
        'Private device' if info['address_kind'].startswith('Locally') else info['vendor'])
    name = re.sub(r'[\x00-\x1f\x7f]', ' ',str(name))[:40]
    parts = [('Client ' if device.get('links') or device.get('bssid') else 'Device ')+name, address]
    channels = sorted({str(link['channel']) for link in device.get('links',{}).values() if link.get('channel')})
    if device.get('channel'):
        channels.append(str(device['channel']))
    if channels:
        parts.append('CH '+','.join(dict.fromkeys(channels)))
    if device.get('rssi') is not None:
        parts.append(str(device['rssi'])+' dBm last seen')
    return ' | '.join(parts)


if __name__ == '__main__':
    install_capabilities()
    if not install_database():
        print('WARNING: Manufacturer database unavailable; MAC roles/private-address labels still work.')
