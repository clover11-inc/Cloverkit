"""Archive inputs: explicit roots, no captures, credentials, caches or build debris."""
# SPDX-License-Identifier: GPL-2.0-or-later
from pathlib import Path
ROOTS={'.github','src','tools','tests','catalog','config','docs','docs-src','packaging','LICENSES','vendor','assets','release-notes','hardware'}
TOP={'.gitignore','.gitattributes','README.md','INSTALL.md','VERSION','LICENSE','NOTICE.md','THIRD-PARTY.md','THIRD-PARTY.json','SECURITY.md','CONTRIBUTING.md','CHANGELOG.md','cloverkit','RELEASE.json'}
BUILD={'build/install-manifest.json','build/check-results.json','build/validation.json'}
def selected(path):
 parts=path.parts;name=path.as_posix()
 if parts and parts[0]=='flipper' or path.suffix=='.fap':return False
 if path.name in {'access.token','email.json','vpn.json','recovery-hotspot.json','radios.json','id_rsa','id_ed25519','.env'} or path.name.startswith('.env.'):return False
 if any(p in {'__pycache__','.git','.vscode','.local','node_modules'} for p in parts) or path.suffix in {'.pyc','.pyo','.elf','.o','.sav','.pcap','.pcapng','.log','.pem','.key','.p12','.pfx','.token','.db','.sqlite'}:return False
 if path.suffix=='.sqlite3' and name!='src/vehicle/cloverkit_vehicle/data/codes.sqlite3':return False
 if name in TOP or name in BUILD:return True
 if parts and parts[0] in ROOTS:return True
 return False
def inputs(root):
 for p in sorted(root.rglob('*')):
  if not p.is_file():continue
  relative=p.relative_to(root)
  if selected(relative):
   if p.is_symlink():raise ValueError('Symlink in release inputs: '+relative.as_posix())
   yield p,relative.as_posix()
def mode(name,data):return 0o755 if name=='cloverkit' or name.startswith(('src/commands/','src/launchers/')) or data.startswith(b'#!') else 0o644
