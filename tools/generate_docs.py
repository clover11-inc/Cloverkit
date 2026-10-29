"""Generate current-build local reference without reusing historical docs."""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def generate():
    features=json.loads((ROOT/'catalog/features.json').read_text())['features']
    folder=ROOT/'docs/generated';folder.mkdir(parents=True,exist_ok=True)
    index=['# CloverKit local guide','','Generated from the release catalog and source hashes.','','Topics:']
    for f in features:
        rows=['# '+f['title'],'','Status: '+f['status'],'Access: '+f['menu'],'','## What it does',f['what'],'','## When to use it',f['when'],'','## Why it is useful',f['value'],'','## Limits and effects',f['limits'],'','## Source']
        rows+=['- '+s+' | SHA256 '+hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in f['sources']]
        if not f['sources']:rows+=['No active implementation included for this deferred integration.']
        (folder/(f['id']+'.md')).write_text('\n'.join(rows)+'\n')
        index.append('- '+f['id']+' — '+f['title']+' ['+f['status']+']')
    feature_rows=['# CloverKit complete feature map','','Source availability and validation are separate. Alpha is not hardware certification.','','| Feature | Access | What / value | Status |','|---|---|---|---|']
    for f in features:feature_rows.append('| '+f['title']+' | '+f['menu'].replace('|','/')+' | '+f['what'].replace('|','/')+' '+f['value'].replace('|','/')+' | '+f['status']+' |')
    (folder/'features.md').write_text('\n'.join(feature_rows)+'\n')
    processes=[]
    for base in ('src/commands','src/panel','src/security','src/launchers','src/vehicle/cloverkit_vehicle'):
        for p in sorted((ROOT/base).rglob('*')):
            if not p.is_file() or p.suffix in ('.png','.sqlite3','.pyc') or '__pycache__' in p.parts:continue
            rel=p.relative_to(ROOT).as_posix();data=p.read_text(errors='replace')
            purpose=''
            try:purpose=(ast.get_docstring(ast.parse(data)) or '').split('\n')[0]
            except (SyntaxError,ValueError):pass
            if not purpose:purpose='Entry point / helper for '+p.stem.replace('_',' ').replace('-',' ')+'. See referenced backends for effects.'
            processes.append(dict(purpose=purpose,path=rel,sha256=hashlib.sha256(p.read_bytes()).hexdigest(),features=[f['id'] for f in features if rel in f['sources']],references=sorted(set(re.findall(r'/usr/local/(?:bin|lib)/[A-Za-z0-9_./-]+',data)))))
    (folder/'processes.json').write_text(json.dumps(processes,indent=2)+'\n')
    rows=['# CloverKit process/source reference','','Static source relationships, not a running-process list. Literal references do not establish complete dependency closure.','']
    for p in processes:
        rows+=['## '+p['path'],'Workflow: '+(', '.join(p['features']) or 'Support helper; individual purpose review pending'),'Purpose: '+p['purpose'],'SHA256: '+p['sha256'],'Referenced helpers: '+(', '.join(p['references']) or 'No literal local helper references.'),'']
    (folder/'processes.md').write_text('\n'.join(rows)+'\n')
    gates=json.loads((ROOT/'docs-src/release-gates.json').read_text())
    (folder/'release-status.md').write_text('# CloverKit release status\n\n'+gates['status']+'\n\n'+'\n'.join('- '+s for s in gates.get('unvalidated',gates.get('gates',[])))+'\n')
    index+=['','- features — complete feature map','- processes — source/helper reference','- release-status — unfinished work']
    (folder/'index.md').write_text('\n'.join(index)+'\n')
    return len(features),len(processes)
if __name__=='__main__':print('CloverKit docs: %s topics, %s process/source entries'%generate())
