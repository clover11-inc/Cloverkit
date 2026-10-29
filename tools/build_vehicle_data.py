"""Build the offline reference database from pinned, attributed upstream snapshots.

Build-only dependency: PyYAML. Runtime uses SQLite from the Python standard library.
No definitions are executed, and no diagnostic request is imported from code text.
"""
import argparse, hashlib, json, re, sqlite3, subprocess
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
CODE = re.compile(r'[PCBU][0-3][0-9A-F]{3}')

def generic(code):
    return (code[1] == '0' or code[0] == 'P' and
            (code[1] == '2' or 'P3400' <= code <= 'P3999') or
            code[0] == 'U' and code[1] == '3')

def build(sources):
    destination = ROOT / 'src/vehicle/cloverkit_vehicle/data'
    destination.mkdir(parents=True, exist_ok=True)
    out = destination / 'codes.sqlite3'
    if out.exists(): out.unlink()
    db = sqlite3.connect(out)
    db.executescript('''CREATE TABLE definitions(code TEXT,make TEXT,title TEXT,detail TEXT,
      source TEXT,license TEXT,verification TEXT,PRIMARY KEY(code,make,source));
      CREATE INDEX code_idx ON definitions(code); CREATE INDEX make_idx ON definitions(make);
      CREATE TABLE provenance(name TEXT PRIMARY KEY,url TEXT,revision TEXT,license TEXT);
      CREATE TABLE reference(name TEXT PRIMARY KEY,document TEXT);''')
    specs = [('obdex','https://github.com/foerbsnavi/obdex','CC0-1.0','LICENSE-DATA'),
             ('dtc-database','https://github.com/Wal33D/dtc-database','MIT','LICENSE'),
             ('SAEJ1979','https://github.com/OBDb/SAEJ1979','CC-BY-SA-4.0','LICENSE')]
    license_dir = ROOT / 'LICENSES/vehicle'; license_dir.mkdir(parents=True,exist_ok=True)
    manifest = []; excluded = 0
    for name,url,license_id,filename in specs:
        folder=sources/name
        revision=subprocess.check_output(['git','-C',str(folder),'rev-parse','HEAD'],text=True).strip()
        db.execute('INSERT INTO provenance VALUES(?,?,?,?)',(name,url,revision,license_id))
        license_data=(folder/filename).read_bytes()
        (license_dir/(name+'.txt')).write_bytes(license_data)
        manifest.append(dict(name=name,url=url,revision=revision,license=license_id))
    for path in sorted((sources/'obdex/data/generic').glob('*.yaml')):
        for entry in yaml.safe_load(path.read_text(encoding='utf-8')):
            code=entry['code'].upper()
            if not CODE.fullmatch(code) or not generic(code): excluded+=1;continue
            title=entry.get('title',{}).get('en',code)
            db.execute('INSERT INTO definitions VALUES(?,?,?,?,?,?,?)',
                       (code,'GENERIC',title,json.dumps(entry,ensure_ascii=False),'obdex','CC0-1.0','community reference; not vehicle verified'))
    for path in sorted((sources/'dtc-database/data/source-data').glob('*.txt')):
        make='GENERIC' if path.stem in ('p_codes','b_codes','c_codes','u_codes') else path.stem.removesuffix('_codes').upper()
        for line in path.read_text(encoding='utf-8-sig').splitlines():
            if ' - ' not in line:continue
            code,title=line.split(' - ',1);code=code.strip().upper();title=title.strip()
            if not CODE.fullmatch(code) or not title or make=='GENERIC' and not generic(code):excluded+=1;continue
            db.execute('INSERT OR IGNORE INTO definitions VALUES(?,?,?,?,?,?,?)',
                       (code,make,title,'{}','dtc-database','MIT','community reference; manufacturer applicability unverified'))
    # Reference data only: these upstream definitions are not automatically executable profiles.
    standard=json.loads((sources/'SAEJ1979/signalsets/v3/default.json').read_text())
    db.execute('INSERT INTO reference VALUES(?,?)',('SAEJ1979',json.dumps(standard)))
    for path in (sources/'obdex/data/pids').glob('*.yaml'):
        parameters=yaml.safe_load(path.read_text(encoding='utf-8'))
        db.execute('INSERT INTO reference VALUES(?,?)',('obdex/'+path.name,json.dumps(parameters)))
        if path.name=='mode01.yaml':
            (destination/'pids.json').write_text(json.dumps(dict(source='https://github.com/foerbsnavi/obdex',license='CC0-1.0',verification='community definitions; verify against vehicle',parameters=parameters),indent=2)+'\n',encoding='utf-8')
    db.commit()
    counts=dict(definitions=db.execute('SELECT count(*) FROM definitions').fetchone()[0],
                unique_codes=db.execute('SELECT count(DISTINCT code) FROM definitions').fetchone()[0],
                makes=[r[0] for r in db.execute("SELECT DISTINCT make FROM definitions WHERE make!='GENERIC' ORDER BY make")],
                rejected_rows=excluded)
    db.execute('VACUUM');db.close()
    manifest=dict(schema=1,sources=manifest,counts=counts,sha256=hashlib.sha256(out.read_bytes()).hexdigest(),
                  policy='All eligible rows retained; conflicting sources preserved. No repair, price, or driving-safety claims inferred.')
    (destination/'provenance.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(counts,indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('sources',type=Path);build(parser.parse_args().sources)
