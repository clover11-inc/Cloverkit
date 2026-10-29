"""Assemble checksummed payload manifest without host changes."""
import hashlib,json
from pathlib import Path
from generate_docs import generate
ROOT=Path(__file__).resolve().parents[1]
BLOCKED={'packet-scan','packet-beacon.sh','packet-ndp.sh','packet-scan.sh'}
def build():
    generate();files=[]
    mappings=[('src/panel','usr/local/lib/bh-interactive'),('src/commands','usr/local/bin'),('src/launchers','mnt/scripts'),('src/security','mnt/security'),('src/vehicle','usr/local/lib/cloverkit/vehicle'),('LICENSES','usr/local/share/cloverkit/LICENSES')]
    mappings += [(s,'usr/local/share/cloverkit/'+s) for s in ('tools','catalog','docs/generated','docs-src')]
    for source,destination in mappings:
        for p in sorted((ROOT/source).rglob('*')):
            if not p.is_file() or '__pycache__' in p.parts or p.suffix=='.pyc' or p.name in BLOCKED:continue
            files.append(dict(source=p.relative_to(ROOT).as_posix(),target=(Path(destination)/p.relative_to(ROOT/source)).as_posix(),sha256=hashlib.sha256(p.read_bytes()).hexdigest(),mode=0o755 if source in ('src/commands','src/launchers') else 0o644))
    out=ROOT/'build';out.mkdir(exist_ok=True)
    manifest=dict(brand='CloverKit',version=(ROOT/'VERSION').read_text().strip(),state='open-source-alpha-isolated-install',activation='host-disabled-isolated-install-available',files=files)
    (out/'install-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print('CloverKit build: '+str(len(files))+' payload files; activation disabled')
if __name__=='__main__':build()
