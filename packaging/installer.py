#!/usr/bin/env python3
"""CloverKit planner and isolated staging installer; host activation is gated."""
import argparse,hashlib,json,shutil,sys,tempfile,os
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def safe_prefix(value):
    entered=Path(value).expanduser()
    if not entered.is_absolute() or '..' in entered.parts:raise ValueError('Use an absolute isolated prefix')
    if any(p.is_symlink() for p in (entered,*entered.parents)):raise ValueError('Symlink prefixes refused')
    target=entered.resolve()
    if target in (Path('/'),Path('/usr'),Path('/etc'),Path('/mnt'),ROOT.resolve()) or target in ROOT.resolve().parents or ROOT.resolve() in target.parents:raise ValueError('Refusing a live/project root prefix')
    return target
def isolated_install(prefix):
    sys.path.insert(0,str(ROOT/'tools'))
    from release_inputs import inputs,mode
    destination=safe_prefix(prefix)/('cloverkit-'+(ROOT/'VERSION').read_text().strip())
    if destination.exists():raise ValueError('Version already installed; existing files were preserved')
    if (ROOT/'RELEASE-MANIFEST.json').exists():
        from verify_package import verify
        if not verify(ROOT)['passed']:raise ValueError('Release package verification failed')
    destination.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.cloverkit-install-',dir=destination.parent) as folder:
        payload=Path(folder)/'source';payload.mkdir();records=[]
        for path,name in inputs(ROOT):
            raw=path.read_bytes();out=payload/name;out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(raw);out.chmod(mode(name,raw))
            records.append(dict(path=name,sha256=hashlib.sha256(raw).hexdigest(),size=len(raw),mode=mode(name,raw)))
        document=dict(schema=1,version=(ROOT/'VERSION').read_text().strip(),files=records)
        (payload/'RELEASE-MANIFEST.json').write_text(json.dumps(document,indent=2)+'\n')
        (payload/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.relative_to(payload).as_posix()+'\n' for p in sorted(payload.rglob('*')) if p.is_file()))
        all_files=[dict(path=p.relative_to(payload).as_posix(),sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in sorted(payload.rglob('*')) if p.is_file()]
        (payload/'.cloverkit-isolated.json').write_text(json.dumps(dict(schema=1,version=document['version'],files=all_files),indent=2)+'\n')
        payload.rename(destination)
    print('Installed isolated CloverKit source: '+str(destination))
    print('Docs: python3 '+str(destination/'tools/cloverkit.py')+' docs')
    print('Offline demo: python3 '+str(destination/'tools/vehicle.py')+' serve')
    print('No services/accounts/interfaces changed. No global commands or runtime compatibility paths replaced.')
    return 0
def isolated_uninstall(prefix):
    destination=safe_prefix(prefix)/('cloverkit-'+(ROOT/'VERSION').read_text().strip());record=destination/'.cloverkit-isolated.json'
    if record.is_symlink() or not record.is_file():raise ValueError('Not a tracked isolated CloverKit installation')
    rows=json.loads(record.read_text())['files']
    for row in rows:
        relative=Path(row['path']);path=destination/relative
        if relative.is_absolute() or '..' in relative.parts or any(p.is_symlink() for p in (path,*path.parents)):raise ValueError('Unsafe installed path')
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=row['sha256']:raise ValueError('Installed file changed/missing; uninstall refused: '+row['path'])
    for row in rows:(destination/row['path']).unlink()
    record.unlink()
    for path in sorted((p for p in destination.rglob('*') if p.is_dir()),key=lambda p:len(p.parts),reverse=True):
        try:path.rmdir()
        except OSError:pass
    try:destination.rmdir()
    except OSError:pass
    print('Removed tracked unchanged package files. Runtime data and untracked files were preserved.');return 0

def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='action',required=True)
    sub.add_parser('plan');s=sub.add_parser('stage');s.add_argument('--root',required=True);i=sub.add_parser('install');i.add_argument('--prefix');u=sub.add_parser('uninstall');u.add_argument('--prefix',required=True)
    a=p.parse_args()
    if a.action=='uninstall':return isolated_uninstall(a.prefix)
    if a.action=='install' and a.prefix:return isolated_install(a.prefix)
    if a.action=='install':
        print('CloverKit: host activation disabled. Use install --prefix /separate/location for an isolated source install. Nothing changed.',file=sys.stderr);return 2
    m=json.loads((ROOT/'build/install-manifest.json').read_text());targets=set()
    for f in m['files']:
        target=Path(f['target']);source=(ROOT/f['source']).resolve()
        if target.is_absolute() or '..' in target.parts or f['target'] in targets:raise ValueError('Unsafe/duplicate target')
        source.relative_to(ROOT.resolve());targets.add(f['target'])
        if hashlib.sha256(source.read_bytes()).hexdigest()!=f['sha256']:raise ValueError('Source changed; rebuild: '+f['source'])
    if a.action=='plan':
        print('CloverKit '+m['version']+' — '+str(len(targets))+' files; no service/account/network changes')
        for f in m['files']:print('/'+f['target'])
        return 0
    entered=Path(a.root).expanduser()
    if not entered.is_absolute():raise ValueError('Use absolute staging path')
    if any(part.is_symlink() for part in (entered,*entered.parents)):raise ValueError('Symlink staging paths refused')
    target=entered.resolve()
    if target in (Path('/'),Path('/usr'),Path('/etc'),Path('/mnt'),Path('/home'),ROOT.resolve()) or target in ROOT.resolve().parents:raise ValueError('Refusing live/project root')
    if target.exists():raise ValueError('Destination already exists; use a new separate directory')
    target.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.cloverkit-stage-',dir=target.parent) as tmp:
        payload=Path(tmp)/'payload';payload.mkdir()
        for f in m['files']:
            out=payload/f['target'];out.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/f['source'],out);out.chmod(f['mode'])
        (payload/'CLOVERKIT-STAGING.json').write_text(json.dumps(dict(not_activated=True,version=m['version']))+'\n')
        payload.rename(target)
    print('CloverKit staged at '+str(target)+'; nothing activated.');return 0
if __name__=='__main__':
    try:raise SystemExit(main())
    except (ValueError,OSError,KeyError) as e:print('CloverKit: '+str(e),file=sys.stderr);raise SystemExit(1)
