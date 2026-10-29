#!/usr/bin/env python3
"""Build a fresh-card image from pinned upstream inputs; never open a physical drive."""
# SPDX-License-Identifier: GPL-2.0-or-later
import argparse,hashlib,json,os,shutil,subprocess,sys,tarfile,time,urllib.request,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent
REPO=ROOT.parents[1]

def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def obtain(row,dest,local=None):
 if dest.exists() and dest.stat().st_size==row['size'] and sha(dest)==row['sha256']:return
 dest.parent.mkdir(parents=True,exist_ok=True)
 part=dest.with_name(dest.name+'.partial')
 try:
  if local is not None:
   if local.resolve()==dest.resolve():raise ValueError('Cached input has the wrong size/hash: '+dest.name)
   shutil.copyfile(local,part)
  else:
   print('Downloading '+dest.name,flush=True)
   req=urllib.request.Request(row['url'],headers={'User-Agent':'CloverKit-source-build'})
   with urllib.request.urlopen(req,timeout=90) as source,part.open('wb') as target:
    shutil.copyfileobj(source,target,4*1024*1024)
  if part.stat().st_size!=row['size'] or sha(part)!=row['sha256']:raise ValueError('Input checksum mismatch: '+dest.name)
  part.replace(dest)
 except BaseException:
  part.unlink(missing_ok=True);raise

def verify_payload(work):
 folder=work/'payload';manifest=json.loads((folder/'payload-manifest.json').read_text())
 for row in manifest['files']:
  p=folder/row['path']
  if p.is_symlink() or p.stat().st_size!=row['size'] or sha(p)!=row['sha256']:raise ValueError('Payload hash mismatch: '+row['path'])
 with tarfile.open(folder/'runtime.tar.gz') as archive:
  expected={r['path']:r for r in json.loads((folder/'runtime-files.json').read_text())}
  members=archive.getmembers()
  if len(members)!=len(expected):raise ValueError('Runtime entry count mismatch')
  for m in members:
   name=Path(m.name)
   if name.is_absolute() or '..' in name.parts or not m.isfile():raise ValueError('Unsafe runtime archive')
   raw=archive.extractfile(m).read()
   if hashlib.sha256(raw).hexdigest()!=expected[m.name]['sha256']:raise ValueError('Runtime member hash mismatch')
   if m.name.endswith('.py') or raw.startswith((b'#!/usr/bin/python',b'#!/usr/bin/env python')):compile(raw,m.name,'exec')
 for name in ('firstboot.py','firstboot.sh'):
  if (folder/name).read_bytes()!=(ROOT/name).read_bytes():raise ValueError('First-boot source mismatch')
 result={'passed':True,'build_id':manifest['build_id'],'payload_files':len(manifest['files']),'runtime_files':len(expected),'physical_drive_accessed':False,'hardware_test':'not performed by builder'}
 (work/'payload-checks.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps(result,indent=2),flush=True)

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--work',type=Path,default=REPO/'.build/sd')
 p.add_argument('--base-archive',type=Path)
 p.add_argument('--offline-cache',type=Path)
 p.add_argument('--prepare-only',action='store_true')
 a=p.parse_args();work=a.work.resolve()
 if sys.version_info[:2]!=(3,14):raise ValueError('Use Python 3.14 to match the tested build/parser environment.')
 if work==REPO or work in REPO.parents:raise ValueError('Choose a separate build folder, not the source root or a parent.')
 if work.is_symlink():raise ValueError('Symlink build folder refused')
 work.mkdir(parents=True,exist_ok=True)
 pins=json.loads((ROOT/'inputs.json').read_text());base=pins['base']
 # These are pristine upstream downloads, never an image read from a used card.
 obtain(base,work/base['file'],a.base_archive)
 image=work/'blackhat-armbian-v1.4-clean-base.img'
 if not image.exists() or image.stat().st_size!=base['image_size'] or sha(image)!=base['image_sha256']:
  with zipfile.ZipFile(work/base['file']) as archive:
   candidates=[m for m in archive.infolist() if m.filename.endswith('.img') and m.file_size==base['image_size']]
   if len(candidates)!=1:raise ValueError('Expected one pristine image in upstream archive')
   with archive.open(candidates[0]) as inp,image.open('wb') as out:shutil.copyfileobj(inp,out,4*1024*1024)
  if sha(image)!=base['image_sha256']:raise ValueError('Pristine image hash mismatch')
 cache=work/'offline-repo';cache.mkdir(exist_ok=True)
 for row in pins['offline_repo']['packages']:
  local=(a.offline_cache/row['file']) if a.offline_cache else None
  obtain(row,cache/row['file'],local)
 (cache/'manifest.json').write_text(json.dumps(pins['offline_repo'],indent=2)+'\n')
 shutil.copyfile(ROOT/'Packages',cache/'Packages')
 env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
 # Source and image construction touch files under work only.
 for command in ([sys.executable,str(REPO/'tools/package.py'),'--output',str(work/'source')],
                 [sys.executable,str(ROOT/'prepare_payload.py'),str(work)]):
  subprocess.run(command,cwd=REPO,env=env,check=True)
 verify_payload(work)
 if not a.prepare_only:subprocess.run([sys.executable,str(ROOT/'make_image.py'),str(work)],cwd=REPO,env=env,check=True)
 print('Build finished. No SD card was opened or written.',flush=True)

if __name__=='__main__':
 try:main()
 except (ValueError,OSError,subprocess.SubprocessError) as error:raise SystemExit('CloverKit image build: '+str(error))
