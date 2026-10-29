"""Create deterministic, checksummed source archives from audited inputs."""
# SPDX-License-Identifier: GPL-2.0-or-later
import argparse,gzip,hashlib,io,json,tarfile,zipfile
from pathlib import Path
from release_inputs import inputs,mode
from privacy_audit import audit
ROOT=Path(__file__).resolve().parents[1]
EPOCH=1793059200

def package(root,destination,private=()):
 report=audit(root,private)
 if not report['passed']:raise ValueError('Privacy audit failed; inspect tools/privacy_audit.py output')
 version=(root/'VERSION').read_text(encoding='utf-8').strip();prefix='cloverkit-'+version
 payload={name:path.read_bytes() for path,name in inputs(root)}
 manifest=dict(schema=1,brand='CloverKit',version=version,license='GPL-2.0-or-later; per-component exceptions in NOTICE.md',files=[dict(path=name,sha256=hashlib.sha256(raw).hexdigest(),size=len(raw),mode=mode(name,raw)) for name,raw in sorted(payload.items())],privacy=report)
 payload['RELEASE-MANIFEST.json']=(json.dumps(manifest,indent=2)+'\n').encode()
 payload['SHA256SUMS']=(''.join(hashlib.sha256(raw).hexdigest()+'  '+name+'\n' for name,raw in sorted(payload.items()))).encode()
 destination.mkdir(parents=True,exist_ok=True);tarpath=destination/(prefix+'-source.tar.gz');zippath=destination/(prefix+'-source.zip')
 # Fixed metadata prevents user names, local paths or wall-clock times leaking into archives.
 with tarpath.open('wb') as out,gzip.GzipFile(filename='',mode='wb',fileobj=out,mtime=EPOCH) as compressed,tarfile.open(fileobj=compressed,mode='w') as archive:
  for name,raw in sorted(payload.items()):
   info=tarfile.TarInfo(prefix+'/'+name);info.size=len(raw);info.mode=mode(name,raw);info.mtime=EPOCH;info.uid=info.gid=0;info.uname=info.gname='root';archive.addfile(info,io.BytesIO(raw))
 with zipfile.ZipFile(zippath,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
  for name,raw in sorted(payload.items()):
   info=zipfile.ZipInfo(prefix+'/'+name,(2026,10,27,0,0,0));info.create_system=3;info.external_attr=(0o100000|mode(name,raw))<<16;info.compress_type=zipfile.ZIP_DEFLATED;archive.writestr(info,raw)
 checks=''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in (tarpath,zippath))
 (destination/(prefix+'-SHA256SUMS')).write_text(checks,encoding='ascii')
 print(json.dumps(dict(version=version,files=len(payload),archives=[dict(name=p.name,bytes=p.stat().st_size) for p in (tarpath,zippath)],privacy_passed=True),indent=2))
 return tarpath,zippath

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,default=ROOT/'dist');p.add_argument('--private-values',type=Path);a=p.parse_args()
 values=[v.encode() for v in json.loads(a.private_values.read_text(encoding='utf-8'))] if a.private_values else []
 package(ROOT,a.output,values)
if __name__=='__main__':main()
