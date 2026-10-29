"""Prepare a clean SD-specific activation payload without accessing the original device."""
from pathlib import Path
import hashlib,io,json,re,tarfile,uuid,stat,sys
ROOT=Path(__file__).resolve().parent
REPO=ROOT.parents[1]
WORK=Path(sys.argv[1]).resolve();OUT=WORK/'payload';OUT.mkdir(parents=True,exist_ok=True)
BUILD='cloverkit-clean-20261029-'+uuid.uuid4().hex[:10]
rows={}
def add(path,data,mode=0o644):
    if path.startswith('/') or '..' in Path(path).parts:raise ValueError(path)
    rows[path]=(data.encode() if isinstance(data,str) else data,mode)
m=json.loads((REPO/'build/install-manifest.json').read_text())
for row in m['files']:
    if row['target'].startswith('usr/local/share/cloverkit/'):continue
    data=(REPO/row['source']).read_bytes()
    if hashlib.sha256(data).hexdigest()!=row['sha256']:raise RuntimeError('Source guard: '+row['source'])
    path=row['target']
    if path.startswith('mnt/'):path='boot/bh/'+path[4:]
    add(path,data,row['mode'])
archive=WORK/'source/cloverkit-0.1.0-alpha.2-source.tar.gz'
with tarfile.open(archive,'r:gz') as source:
    for member in source:
        if not member.isfile():continue
        path=Path(member.name)
        if path.is_absolute() or '..' in path.parts:raise RuntimeError('Unsafe source archive')
        # Published source archive has one package root.
        rel=Path(*path.parts[1:])
        if not rel.parts:continue
        add('opt/cloverkit/'+rel.as_posix(),source.extractfile(member).read(),member.mode&0o777)
add('usr/local/lib/bh-interactive/cloverkit_radio_identity.py',(ROOT/'radio_identity.py').read_bytes())
if (ROOT/'release-clover-boot.png').exists():
    art=(ROOT/'release-clover-boot.png').read_bytes()
    if hashlib.sha256(art).hexdigest()!='ae038f9bdb918a764bec630b76ae82a5b22b3d6d19d73ebebb866c43d57c4c95':raise RuntimeError('Original CloverKit artwork guard failed')
    add('usr/local/lib/bh-interactive/clover-boot.png',art)
    add('opt/cloverkit/assets/release-clover-boot.png',art)
add('usr/local/bin/cloverkit-name-radios',(ROOT/'name_radios.py').read_bytes(),0o755)
for name,target,mode in [('wifi-scan','usr/local/bin/wifi-scan',0o755),('cloverkit_radio_recovery.py','usr/local/lib/bh-interactive/cloverkit_radio_recovery.py',0o644)]:
    if (ROOT/'fixes'/name).exists():add(target,(ROOT/'fixes'/name).read_bytes(),mode)
for name,target,mode in [('device-watch','usr/local/bin/device-watch',0o755),('cloverkit-device-watch-wifi','usr/local/bin/cloverkit-device-watch-wifi',0o755),('cloverkit_ble_ready.py','usr/local/lib/bh-interactive/cloverkit_ble_ready.py',0o644),('cloverkit_wifi_group.py','usr/local/lib/bh-interactive/cloverkit_wifi_group.py',0o644),('secscan-lcd-run','usr/local/bin/secscan-lcd-run',0o755),('bh_panel.py','usr/local/lib/bh-interactive/bh_panel.py',0o644)]:
    if (ROOT/'fixes'/name).exists():add(target,(ROOT/'fixes'/name).read_bytes(),mode)
for name,target,mode in [('cloverkit_security_radio.py','usr/local/lib/bh-interactive/cloverkit_security_radio.py',0o644),('secscan.py','boot/bh/security/secscan.py',0o755),('secscan-events','usr/local/bin/secscan-events',0o755),('clover_compact_pages.py','usr/local/lib/bh-interactive/clover_compact_pages.py',0o644)]:
    if (ROOT/'fixes'/name).exists():add(target,(ROOT/'fixes'/name).read_bytes(),mode)
add('usr/local/bin/cloverkit-owner-setup',(ROOT/'owner_setup.py').read_bytes(),0o755)
add('etc/sudoers.d/cloverkit-command-path','Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"\n',0o440)
add('usr/local/lib/bh-interactive/console_access.py',(ROOT/'console_access.py').read_bytes())
for op in ('on','off','status'):add('usr/local/bin/console-'+op,'#!/bin/sh\nexec /usr/bin/python3 /usr/local/lib/bh-interactive/console_access.py '+op+'\n',0o755)
wifi=(REPO/'src/commands/conwifi-run').read_text().replace('password=secrets.token_urlsafe(12)','from console_password import generate\n            password=generate()')
add('usr/local/bin/conwifi-run',wifi,0o755)
add('usr/local/bin/conwifi-run-local',wifi,0o755)
scope=(REPO/'src/panel/cloverkit_release_scope.py').read_text()
scope=scope.replace("namespace['CONTROLS'].pop('Console',None)","# Shared USB serial account provisioned on clean cards.")
scope=scope.replace("('Console','PC Recovery')","('PC Recovery',)")
scope=scope.replace("['Email setup','VPN setup','Recovery hotspot']","['Owner setup','Email setup','VPN setup','Recovery hotspot']")
scope=scope.replace("setup_pages={'Email setup'","setup_pages={'Owner setup':'owner','Email setup'")
scope=scope.replace("'2. Run: sudo cloverkit-setup '+feature","'2. Run: sudo '+('cloverkit-owner-setup' if feature=='owner' else 'cloverkit-setup '+feature)")
add('usr/local/lib/bh-interactive/cloverkit_release_scope.py',scope)
opt=REPO/'packaging/optional/vehicle-ssh'
add('usr/local/lib/cloverkit/vehicle/conveh_access.py',(opt/'conveh_access.py').read_bytes())
add('usr/local/bin/conveh-session',(opt/'conveh-session').read_bytes(),0o755)
add('etc/sudoers.d/cloverkit-conveh',(opt/'cloverkit-conveh').read_text().replace('@OPERATOR@','admin'),0o440)
add('etc/ssh/sshd_config.d/00-cloverkit-clean.conf','''# Fresh owner configuration; no inherited credentials.
PermitRootLogin no
PasswordAuthentication yes
PermitEmptyPasswords no
AllowUsers admin console conwifi conveh
Match User console
    ForceCommand /usr/local/bin/console
    DisableForwarding yes
    PermitUserRC no
    PermitTTY yes
Match User conwifi
    ForceCommand /usr/bin/python3 /usr/local/lib/bh-interactive/conwifi_report.py
    DisableForwarding yes
    PermitUserRC no
    PermitTTY yes
Match User conveh
    ForceCommand /usr/local/bin/conveh-session
    DisableForwarding yes
    PermitUserRC no
    PermitTTY yes
Match all
''')
add('etc/sudoers.d/cloverkit-owner','admin ALL=(ALL:ALL) ALL\n',0o440)
services={p.name:p.read_text() for p in (REPO/'packaging/systemd').glob('*.service')}
services['cloverkit-serial.service']=services['cloverkit-serial.service'].replace('CLOVERKIT_USER=clover','CLOVERKIT_USER=admin')
services['bh-boot.service']='''[Unit]
Description=Blackhat boot payload mount for CloverKit
RequiresMountsFor=/boot
After=local-fs.target
Before=bh-serial-gateway.service cloverkit-target-clean.service
[Service]
Type=oneshot
ExecStart=/bin/mount --bind /boot/bh /mnt
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
'''
services['bh-serial-gateway.service']=services['bh-serial-gateway.service'].replace('After=local-fs.target','After=local-fs.target bh-boot.service cloverkit-radio-names.service\nRequires=bh-boot.service\nWants=cloverkit-radio-names.service')
for name in ('clover_boot_splash.py','clover_lcd_panel.py'):
    add('usr/local/lib/bh-interactive/'+name,(ROOT/'fixes'/name).read_bytes())
services['cloverkit-radio-names.service']=services['cloverkit-radio-names.service'].replace('Assign protected built-in and development USB radio names','Protect native radio and discover USB adapters')
services['cloverkit-target-clean.service']=services['cloverkit-target-clean.service'].replace('After=mnt.mount\nBefore=bh-boot.service','After=bh-boot.service\nRequires=bh-boot.service')
services['cloverkit-guest-lock.service']='''[Unit]
Description=Lock temporary CloverKit SSH accounts at boot
Before=ssh.service sshd.service
[Service]
Type=oneshot
ExecStart=/usr/bin/passwd -l console
ExecStart=/usr/bin/passwd -l conwifi
ExecStart=/usr/bin/passwd -l conveh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
'''
for name,data in services.items():add('etc/systemd/system/'+name,data)
add('etc/systemd/system/NetworkManager.service.d/cloverkit-native.conf','[Unit]\nRequires=cloverkit-radio-names.service\nAfter=cloverkit-radio-names.service\n')
# The legacy display/getty must not race the single persistent panel owner.
add('etc/systemd/system/getty@tty1.service.d/cloverkit-disable.conf','[Unit]\nConditionPathExists=/run/cloverkit-manual-tty1\n')
add('etc/systemd/system/ssh.service.d/cloverkit-guests.conf','[Unit]\nRequires=cloverkit-guest-lock.service\nAfter=cloverkit-guest-lock.service\n')
add('etc/motd','''CloverKit clean-card test build
Local panel: bh-screen | terminal panel: bh-panel
First owner setup: sudo cloverkit-owner-setup
Docs: cloverkit docs
No previous networks, email, VPN or Flipper pairing are configured.
''')
readme='''# CloverKit clean-card test build

This is Blackhat OS v1.4 plus the CloverKit 0.1.0-alpha.2 toolkit. It uses the first-version fresh-card installation flow, not the newer alongside installer.

First boot installs verified dependencies offline, expands the new card, removes stock credentials, generates host keys and registers the native SDIO radio. It reboots into CloverKit Home. Keep stable power connected throughout installation; a resize may cause an additional reboot.

Owner credentials, saved Wi-Fi networks, SMTP, VPN and recovery hotspot start unconfigured. SSH starts disabled. Use the physical serial console (115200 8N1), Ctrl-C for its recovery shell, then run `cloverkit-owner-setup` to create your own login and optional new network. Flipper controls use a generic protocol and do not need a stored Flipper identity. No Flipper companion app is bundled. Use PC serial or SSH. This image does not change the Flipper firmware or SD card.

Core menus, Wi-Fi/ethernet tools, BLE/security reports, waterfall, restricted vehicle diagnostics and shared USB serial console are installed. Optional VPN/email/hotspot require local setup. PC recovery media, ROMs and private exploit databases are not included. Six GHz needs suitable hardware. This uses the new OS's own 7.1.13 kernel/drivers, not copied modules from the old card.

Status: `/var/lib/cloverkit/clean-install.json`. Install logs: `/boot/bh/cloverkit-clean/install.log`, `dependencies.log`, `service-validation.log`. Docs: `cloverkit docs`. The pristine image is separate from data generated during testing; do not publish an image copied from the used/tested card.

This is a clean-device test candidate, not a claim that physical boot, every driver or every feature has already passed. GPL-2.0-or-later for CloverKit; third-party components retain their licences. No warranty.
'''
add('opt/cloverkit/CLEAN-CARD.md',readme)
with tarfile.open(OUT/'runtime.tar.gz','w:gz') as tar:
    for name,(data,mode) in sorted(rows.items()):
        info=tarfile.TarInfo(name);info.size=len(data);info.mode=mode;info.uid=info.gid=0;info.mtime=0;tar.addfile(info,io.BytesIO(data))
records=[dict(path=name,sha256=hashlib.sha256(data).hexdigest(),mode=mode) for name,(data,mode) in sorted(rows.items())]
(OUT/'runtime-files.json').write_text(json.dumps(records,indent=2)+'\n')
for name in ('firstboot.py','firstboot.sh'):(OUT/name).write_bytes((ROOT/name).read_bytes())
# Copy only verified packages; do not include private audit inputs or source-device state.
import shutil
shutil.copytree(WORK/'offline-repo',OUT/'offline-repo',dirs_exist_ok=True)
(OUT/'READ-ME-FIRST.md').write_text(readme,encoding='utf-8')
files=[dict(path=p.relative_to(OUT).as_posix(),sha256=hashlib.sha256(p.read_bytes()).hexdigest(),size=p.stat().st_size) for p in sorted(OUT.rglob('*')) if p.is_file() and p.name!='payload-manifest.json']
approved={'runtime.tar.gz','runtime-files.json','firstboot.py','firstboot.sh','READ-ME-FIRST.md'}
for row in files:
    if row['path'] not in approved and not row['path'].startswith('offline-repo/'):raise RuntimeError('Unexpected payload file; choose a fresh build folder: '+row['path'])
manifest=dict(schema=1,build_id=BUILD,root_uuid='5df32696-365e-4fde-bc56-e5ad6e08cbba',base='Blackhat OS Armbian v1.4',base_zip_sha256='f67d718f148f0fd4503c471ee7e6b7a75a0b84ad906ce155e1dcbd628fce3af3',personal_configuration_imported=False,files=files)
(OUT/'payload-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
for name,(data,mode) in rows.items():
    if name.endswith('.py') or data.startswith((b'#!/usr/bin/python',b'#!/usr/bin/env python')):compile(data,name,'exec')
print(json.dumps({'build_id':BUILD,'runtime_files':len(records),'payload_MiB':round(sum(p.stat().st_size for p in OUT.rglob('*') if p.is_file())/2**20,1)},indent=2))
