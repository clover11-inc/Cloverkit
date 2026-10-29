"""Bounded BlueZ readiness and USB-controller fallback for Device watch."""
import asyncio,subprocess,time
from pathlib import Path
def usb_adapter(name):
    if name not in ('hci0','hci1'):return False
    path=(Path('/sys/class/bluetooth')/name/'device').resolve()
    return path.exists() and any(p.name.startswith('usb') for p in path.parents)
def property_value(name,key):
    p=subprocess.run(['/usr/bin/busctl','--system','--timeout=4','get-property','org.bluez','/org/bluez/'+name,'org.bluez.Adapter1',key],capture_output=True,text=True,timeout=5)
    if p.returncode:raise RuntimeError('Bluetooth controller not ready: '+(p.stderr.strip()[-240:] or 'BlueZ rejected property read'))
    value=p.stdout.strip()
    if value not in ('b true','b false'):raise RuntimeError('Unexpected Bluetooth controller state')
    return value=='b true'
def power(name,value):
    p=subprocess.run(['/usr/bin/busctl','--system','--timeout=4','set-property','org.bluez','/org/bluez/'+name,'org.bluez.Adapter1','Powered','b','true' if value else 'false'],capture_output=True,text=True,timeout=5)
    if p.returncode:raise RuntimeError('Bluetooth power request: '+(p.stderr.strip()[-240:] or 'BlueZ rejected request'))
async def ready(name):
    deadline=time.monotonic()+15
    last='controller not ready'
    while True:
        try:
            if property_value(name,'Discovering'):raise RuntimeError('controller already scanning')
            if property_value(name,'Powered'):return
            try:power(name,True)
            except (RuntimeError,subprocess.TimeoutExpired) as error:last=str(error)
            # BlueZ may report InProgress/Busy while power-on is completing.
            if property_value(name,'Powered'):return
        except (RuntimeError,subprocess.TimeoutExpired) as error:
            last=str(error)
            if 'already scanning' in last:raise
        if time.monotonic()>=deadline:raise RuntimeError(last)
        await asyncio.sleep(1)
async def scan_ready(preferred,duration,scanner,progress=None,explicit=False,event=None):
    candidates=[preferred]
    if not explicit:
        candidates += [n for n in ('hci1','hci0') if n!=preferred and usb_adapter(n)]
    errors=[]
    for name in candidates:
        try:
            await ready(name)
            if event:event('stage',phase='SCANNING BLE',adapter=name,duration=duration)
            devices=await scanner(name,duration,progress=progress)
            return name,devices
        except asyncio.CancelledError:raise
        except Exception as error:
            errors.append(name+': '+str(error))
            if event:event('stage',phase='BLE RADIO UNAVAILABLE',adapter=name)
        # Leave BlueZ and the controller ready for the next run. scanner.stop()
        # still ends discovery; no background scan or saved boot policy is added.
    raise RuntimeError('; '.join(errors))
