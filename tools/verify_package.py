"""Verify an extracted source package against its release manifest and checksums."""
# SPDX-License-Identifier: GPL-2.0-or-later
import argparse,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def verify(root):
 manifest=json.loads((root/'RELEASE-MANIFEST.json').read_text(encoding='utf-8'));errors=[]
 for row in manifest['files']:
  relative=Path(row['path'])
  if relative.is_absolute() or '..' in relative.parts:raise ValueError('Unsafe manifest path')
  path=root/relative
  if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=row['sha256']:errors.append(row['path'])
 for line in (root/'SHA256SUMS').read_text(encoding='ascii').splitlines():
  expected,name=line.split('  ',1);relative=Path(name)
  if relative.is_absolute() or '..' in relative.parts:raise ValueError('Unsafe checksum path')
  path=root/relative
  if not path.is_file() or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=expected:errors.append(name)
 return dict(version=manifest['version'],files_checked=len(manifest['files']),passed=not errors,errors=sorted(set(errors)))
def main():
 p=argparse.ArgumentParser();p.add_argument('--root',type=Path,default=ROOT);a=p.parse_args()
 try:result=verify(a.root)
 except FileNotFoundError:print('Release manifest absent: run this from an extracted source archive or isolated installed copy. Maintainers: build/package first.');return 2
 print(json.dumps(result,indent=2));return int(not result['passed'])
if __name__=='__main__':raise SystemExit(main())
