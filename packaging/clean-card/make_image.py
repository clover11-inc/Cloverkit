"""Create and read-back-check a new image; never modify the pristine upstream image."""
from pathlib import Path
import hashlib,json,shutil,struct,sys
from pyfatfs.PyFatFS import PyFatFS
ROOT=Path(__file__).resolve().parent
OUT=Path(sys.argv[1]).resolve();OUT.mkdir(parents=True,exist_ok=True)
BASE=OUT/'blackhat-armbian-v1.4-clean-base.img'
IMAGE=OUT/'CloverKit-0.1.0-alpha.2-Blackhat-v1.4.img'
payload=OUT/'payload';manifest=json.loads((payload/'payload-manifest.json').read_text())
shutil.copyfile(BASE,IMAGE)
with PyFatFS(str(IMAGE),offset=4194304,read_only=False) as fs:
    # Only the clean CloverKit launcher catalogue is exposed to the panel.
    for path in ('/bh/scripts','/bh/roms'):
        if fs.exists(path):fs.removetree(path)
        fs.makedirs(path,recreate=True)
    config='''# CloverKit clean image: no preconfigured networks or credentials.
export SSID=""
export PASS=""
export SCREEN_ENABLED=true
'''
    fs.writebytes('/bh/blackhat.conf',config.encode())
    fs.makedirs('/bh/cloverkit-clean',recreate=True)
    for p in sorted(payload.rglob('*')):
        relative=p.relative_to(payload).as_posix();target='/bh/cloverkit-clean/'+relative
        if p.is_dir():fs.makedirs(target,recreate=True)
        else:
            fs.makedirs(str(Path(target).parent).replace('\\','/'),recreate=True)
            fs.writebytes(target,p.read_bytes())
    env=(ROOT/'boot-armbianEnv.txt').read_text()
    args='systemd.run=/boot/bh/cloverkit-clean/firstboot.sh systemd.run_success_action=reboot systemd.run_failure_action=none '
    args+=' '.join('systemd.mask='+name for name in ('NetworkManager.service','NetworkManager-wait-online.service','ssh.service','ssh.socket','bh-boot.service','armbian-firstrun.service'))
    args+=' cloverkit.clean='+manifest['build_id']+' consoleblank=0 vt.global_cursor_default=0'
    lines=[line+' '+args if line.startswith('extraargs=') else line for line in env.splitlines()]
    fs.writebytes('/armbianEnv.txt',('\n'.join(lines)+'\n').encode())
    fs.writebytes('/CLOVERKIT-READ-ME.txt',(payload/'READ-ME-FIRST.md').read_bytes())
checks=[]
with PyFatFS(str(IMAGE),offset=4194304,read_only=True) as fs:
    for row in manifest['files']:
        raw=fs.readbytes('/bh/cloverkit-clean/'+row['path'])
        if hashlib.sha256(raw).hexdigest()!=row['sha256']:raise RuntimeError('Image payload verification failed: '+row['path'])
    if fs.listdir('/bh/scripts'):raise RuntimeError('Unapproved stock launchers remain')
    boot=fs.readbytes('/armbianEnv.txt').decode()
    if 'cloverkit.clean='+manifest['build_id'] not in boot:raise RuntimeError('Boot marker missing')
    checks+=['FAT readback: every payload hash verified','No stock saved Wi-Fi credentials or launchers exposed','Offline first-boot marker present']
def range_hash(path,offset,length):
    digest=hashlib.sha256()
    with path.open('rb') as f:
        f.seek(offset)
        while length:
            chunk=f.read(min(4*1024*1024,length))
            if not chunk:raise RuntimeError('Unexpected EOF')
            digest.update(chunk);length-=len(chunk)
    return digest.hexdigest()
for label,start,length in [('bootloader',0,4194304),('root filesystem',272629760,3498049536)]:
    if range_hash(BASE,start,length)!=range_hash(IMAGE,start,length):raise RuntimeError('Pristine '+label+' changed')
    checks.append('Upstream '+label+' preserved byte-for-byte')
sha=hashlib.file_digest(IMAGE.open('rb'),'sha256').hexdigest()
(OUT/(IMAGE.name+'.sha256')).write_text(sha+'  '+IMAGE.name+'\n')
result=dict(schema=1,build_id=manifest['build_id'],image=IMAGE.name,size=IMAGE.stat().st_size,sha256=sha,checks=checks,sd_card_written=False,physical_boot_test='pending',original_device_accessed=False)
(OUT/'image-validation.json').write_text(json.dumps(result,indent=2)+'\n')
shutil.copyfile(payload/'READ-ME-FIRST.md',OUT/'READ-ME-FIRST.md')
print(json.dumps(result,indent=2))
