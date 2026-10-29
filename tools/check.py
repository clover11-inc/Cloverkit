"""Offline syntax, scope, documentation and payload integrity checks."""
import ast,hashlib,json,shutil,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
errors=[];checked=0
for folder in ('src','tools','packaging'):
    for p in (ROOT/folder).rglob('*'):
        if not p.is_file() or p.suffix in ('.png','.sqlite3','.pyc') or '__pycache__' in p.parts or 'vendor' in p.parts:continue
        text=p.read_text(errors='replace');first=text.splitlines()[0] if text.splitlines() else ''
        if p.suffix=='.py' or first.startswith('#!') and 'python' in first:
            try:ast.parse(text,filename=str(p));checked+=1
            except SyntaxError as e:errors.append(str(e))
        elif first.startswith('#!') and any(s in first for s in ('bash','/sh')) and shutil.which('bash'):
            r=subprocess.run(['bash','-n',str(p)],capture_output=True,text=True);checked+=1
            if r.returncode:errors.append(str(p)+': '+r.stderr)
if (ROOT/'flipper').exists():errors.append('Companion files must remain outside the release')
features=json.loads((ROOT/'catalog/features.json').read_text())['features']
for f in features:
    if not all(f.get(k) for k in ('what','when','value','limits')):errors.append('Missing perspective '+f['id'])
    if not (ROOT/'docs/generated'/(f['id']+'.md')).exists():errors.append('Missing docs '+f['id'])
m=json.loads((ROOT/'build/install-manifest.json').read_text())
for f in m['files']:
    if hashlib.sha256((ROOT/f['source']).read_bytes()).hexdigest()!=f['sha256']:errors.append('Hash mismatch '+f['source'])
    if Path(f['target']).name=='packet-scan':errors.append('Excluded payload '+f['target'])
    if Path(f['target']).name=='conwifi-run-local' and f['source']!='packaging/clean-card/runtime/usr/local/bin/conwifi-run-local':errors.append('Unreviewed local scan launcher '+f['target'])
result=dict(syntax_files=checked,feature_topics=len(features),payload_files=len(m['files']),errors=errors,hardware_tests_run=False,host_activation_run=False,fap_compiled=(ROOT/'flipper/dist/cloverkit.fap').is_file())
(ROOT/'build/check-results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2));raise SystemExit(bool(errors))
