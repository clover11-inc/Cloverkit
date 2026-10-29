"""Explicit USB/Classic selection. Discovery never probes serial ports."""
import json, os, re, shutil, subprocess, time
from pathlib import Path

MAC = re.compile(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}')

def usb_adapters(ports=None):
    if ports is None:
        from serial.tools.list_ports import comports
        ports=comports()
    result=[]
    for p in ports:
        label=' '.join(str(getattr(p,k,'') or '') for k in ('manufacturer','product','description'))
        device=str(p.device)
        if not getattr(p,'vid',None) or re.search(r'flipper|blackhat|debug|st.link',label,re.I):continue
        if getattr(p,'vid',None)==0x0483 and getattr(p,'pid',None)==0x5740:continue
        if not (device.startswith(('/dev/ttyUSB','/dev/ttyACM')) or re.fullmatch(r'COM\d+',device)):continue
        identity=f'{p.vid:04x}:{p.pid:04x}:{p.serial_number or p.location or device}'
        result.append(dict(id=identity,device=device,transport='usb',label=label.strip() or 'USB serial (ELM unverified)',
                           vid=f'{p.vid:04x}',pid=f'{p.pid:04x}',serial=p.serial_number,location=p.location,
                           verified_elm=False))
    return result

def command(args,seconds=15,input=None):
    try:
        p=subprocess.run(args,input=input,text=True,capture_output=True,timeout=seconds,check=False)
    except subprocess.TimeoutExpired:raise ValueError('Bluetooth operation timed out; check controller and adapter power')
    except FileNotFoundError:raise ValueError('Bluetooth tools missing: install BlueZ and bluez-tools/rfcomm for Classic SPP')
    if p.returncode:raise ValueError((p.stderr or p.stdout or 'Bluetooth operation failed')[-1200:])
    return re.sub(r'\x1b\[[0-9;]*[A-Za-z]','',p.stdout)[-32000:]

def _bluetooth_status():
    if not shutil.which('bluetoothctl'):return dict(state='unavailable',reason='BlueZ bluetoothctl is not installed',devices=[])
    controllers=command(['bluetoothctl','list'],seconds=2)
    if not re.search(r'Controller '+MAC.pattern,controllers):return dict(state='unavailable',reason='No Bluetooth controller available',devices=[])
    text=command(['bluetoothctl','devices'],seconds=2)
    devices=[dict(id=m.group(1).upper(),label=m.group(2),transport='bluetooth') for m in re.finditer(r'Device ('+MAC.pattern+r') (.+)',text)]
    return dict(state='available',controllers=controllers,devices=devices,reason='Classic SPP required; BLE serial is not assumed')

def bluetooth_status():
    try:return _bluetooth_status()
    except (OSError,ValueError) as e:return dict(state='unavailable',reason=str(e),devices=[])

def bluetooth_discover():
    status=bluetooth_status()
    if status['state']!='available':return status
    command(['bluetoothctl','--timeout','8','scan','on'],seconds=12)
    return bluetooth_status()

def bluetooth_pair(address,pin='1234'):
    if not MAC.fullmatch(address) or not re.fullmatch(r'\d{4,6}',pin):raise ValueError('Select a valid Bluetooth address and 4–6 digit PIN')
    # Agent lifetime covers this explicit pairing only; never trust unrelated devices.
    text=command(['bluetoothctl','--timeout','20','--agent','KeyboardOnly','pair',address],seconds=25,input=pin+'\n')
    info=command(['bluetoothctl','info',address])
    if 'Paired: yes' not in info:raise ValueError('Pairing did not complete. Check the adapter PIN and use bluetoothctl interactively if it prompts.')
    return dict(state='paired',address=address,details=info)

class BluetoothSerial:
    def __init__(self,address):self.address=address;self.path=None
    def open(self):
        if not MAC.fullmatch(self.address):raise ValueError('Invalid Bluetooth address')
        info=command(['bluetoothctl','info',self.address])
        if 'Paired: yes' not in info:raise ValueError('Pair the selected adapter first')
        text=command(['sdptool','browse',self.address],seconds=15)
        sections=re.split(r'Service Name:',text)
        section=next((s for s in sections if '0x1101' in s and re.search(r'Channel: (\d+)',s)),None)
        if not section:raise ValueError('No Classic Serial Port Profile (0x1101). BLE adapters need model-specific transport support.')
        channel=re.search(r'Channel: (\d+)',section).group(1)
        for n in range(16):
            path='/dev/rfcomm'+str(n)
            if Path(path).exists():continue
            command(['rfcomm','bind',str(n),self.address,channel]);self.path=path;return path
        raise ValueError('No free RFCOMM device available')
    def close(self):
        if self.path:
            try:command(['rfcomm','release',self.path],seconds=5)
            finally:self.path=None
