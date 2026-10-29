"""Private, bounded local session/recording storage and self-contained exports."""
import csv, html, io, json, os, re, sqlite3, time
from contextlib import contextmanager
from pathlib import Path

def home(): return Path(os.environ.get('CLOVERKIT_VEHICLE_HOME','/var/lib/cloverkit/vehicle'))

class Storage:
    def __init__(self,root=None):
        self.root=Path(root) if root else home();self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.path=self.root/'sessions.sqlite3'
        with self.db() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY,vehicle TEXT,created REAL,demo INTEGER,document TEXT);
              CREATE TABLE IF NOT EXISTS recordings(id TEXT PRIMARY KEY,vehicle TEXT,started REAL,ended REAL,demo INTEGER);
              CREATE TABLE IF NOT EXISTS samples(recording TEXT,time REAL,pid TEXT,ecu TEXT,value TEXT,unit TEXT,state TEXT);
              CREATE INDEX IF NOT EXISTS samples_recording ON samples(recording,time);''')
            db.execute('UPDATE recordings SET ended=? WHERE ended IS NULL',(time.time(),))
        self.path.chmod(0o600)
    @contextmanager
    def db(self):
        db=sqlite3.connect(self.path,timeout=5);db.execute('PRAGMA foreign_keys=ON')
        try:
            with db:yield db
        finally:db.close()
    def save(self,scan):
        with self.db() as db:
            db.execute('INSERT OR REPLACE INTO scans VALUES(?,?,?,?,?)',(scan['id'],scan['vehicle']['id'],scan['created_at'],int(scan['demo']),json.dumps(scan,allow_nan=False)))
            db.execute('DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY created DESC LIMIT 500)')
        return scan['id']
    def list(self):
        with self.db() as db:
            return [dict(id=r[0],vehicle=r[1],created=r[2],demo=bool(r[3])) for r in db.execute('SELECT id,vehicle,created,demo FROM scans ORDER BY created DESC LIMIT 500')]
    def get(self,key):
        with self.db() as db:row=db.execute('SELECT document FROM scans WHERE id=?',(key,)).fetchone()
        if not row:raise ValueError('Saved scan not found')
        return json.loads(row[0])
    def compare(self,left,right):
        a,b=self.get(left),self.get(right)
        if a['vehicle']['id']!=b['vehicle']['id'] or a['demo']!=b['demo']:raise ValueError('Choose scans of the same selected vehicle and mode')
        def codes(s):return {(r['code'],r['status'],r.get('ecu','unknown')) for r in s['codes']}
        return dict(previous=left,current=right,added=sorted(codes(b)-codes(a)),removed=sorted(codes(a)-codes(b)),
                    readiness_previous=a.get('readiness'),readiness_current=b.get('readiness'),
                    caution='A missing code is not proof of repair; compare coverage and response states.',coverage_previous=a.get('coverage'),coverage_current=b.get('coverage'))
    def begin_recording(self,key,vehicle,demo):
        with self.db() as db:db.execute('INSERT INTO recordings VALUES(?,?,?,NULL,?)',(key,vehicle,time.time(),int(demo)))
    def append(self,key,pid,reading):
        with self.db() as db:
            count=db.execute('SELECT count(*) FROM samples WHERE recording=?',(key,)).fetchone()[0]
            if count>=100000:raise ValueError('Recording reached 100,000 samples; start another recording')
            db.execute('INSERT INTO samples VALUES(?,?,?,?,?,?,?)',(key,reading['time'],pid,reading.get('ecu','unknown'),json.dumps(reading.get('value')),reading.get('unit',''),reading['state']))
    def end_recording(self,key):
        with self.db() as db:db.execute('UPDATE recordings SET ended=? WHERE id=?',(time.time(),key))
    def recordings(self):
        with self.db() as db:return [dict(id=r[0],vehicle=r[1],started=r[2],ended=r[3],demo=bool(r[4])) for r in db.execute('SELECT * FROM recordings ORDER BY started DESC LIMIT 500')]
    def csv(self,key):
        output=io.StringIO();writer=csv.writer(output);writer.writerow(['utc_epoch','parameter','ecu','value','unit','state'])
        with self.db() as db:
            if not db.execute('SELECT id FROM recordings WHERE id=?',(key,)).fetchone():raise ValueError('Recording not found')
            for r in db.execute('SELECT time,pid,ecu,value,unit,state FROM samples WHERE recording=? ORDER BY time',(key,)):writer.writerow(r)
        return output.getvalue()
    def export(self,key,kind):
        if kind=='csv':return self.csv(key)
        scan=self.get(key)
        if kind=='json':return json.dumps(scan,indent=2,ensure_ascii=False,allow_nan=False)
        if kind!='html':raise ValueError('Export format must be json, csv or html')
        esc=lambda x:html.escape(str(x))
        rows=''.join('<tr><td>'+esc(c['code'])+'</td><td>'+esc(c['status'])+'</td><td>'+esc(c.get('ecu','unknown'))+'</td><td>'+esc(c['description'])+'</td></tr>' for c in scan['codes'])
        return '<!doctype html><meta charset="utf-8"><title>CloverKit vehicle report</title><style>body{font:16px system-ui;max-width:900px;margin:2em auto;padding:1em}th,td{padding:.6em;border:1px solid #ccc}pre{white-space:pre-wrap;overflow-wrap:anywhere}h1{color:#176d3b}</style><h1>CloverKit Vehicle Diagnostics'+(' — DEMO' if scan['demo'] else '')+'</h1><p>Engine / emissions coverage only. No whole-vehicle health claim.</p><table><tr><th>Code<th>Status<th>ECU<th>Description</tr>'+rows+'</table><h2>Full evidence and coverage</h2><pre>'+esc(json.dumps(scan,indent=2,ensure_ascii=False))+'</pre>'

def atomic_json(path,value):
    path=Path(path);tmp=path.with_suffix('.tmp')
    with open(tmp,'w',encoding='utf-8') as stream:
        json.dump(value,stream,indent=2,allow_nan=False);stream.flush();os.fsync(stream.fileno())
    tmp.chmod(0o600);os.replace(tmp,path)
