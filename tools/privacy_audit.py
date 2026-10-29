"""Offline privacy check for the exact selected archive inputs and nested vendor archives."""
# SPDX-License-Identifier: GPL-2.0-or-later
import argparse,hashlib,io,json,re,tarfile,zipfile
from pathlib import Path
from release_inputs import inputs
ROOT=Path(__file__).resolve().parents[1]
RULES={
 'private-key':rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
 'developer-windows-path':rb'[A-Za-z]:[\\/]Users[\\/](?!Public[\\/])[^\\/\s"<>]+[\\/]',
 'cloud-token':rb'(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|sk-[A-Za-z0-9]{36,})',
}
EMAIL=re.compile(rb'[A-Za-z0-9_.+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
def inspect(raw,name,private=(),third_party=False):
 findings=[]
 for code,pattern in RULES.items():
  if third_party and code=='developer-windows-path':continue  # Upstream tests contain synthetic Windows profile paths.
  if re.search(pattern,raw,re.I):findings.append(dict(file=name,rule=code))
 if any(value.lower() in raw.lower() for value in private):findings.append(dict(file=name,rule='private-owner-value'))
 if not third_party and not name.startswith(('LICENSES/','LICENSE','THIRD-PARTY')):
  emails=[e for e in EMAIL.findall(raw) if not e.lower().endswith((b'.invalid',b'@example.com',b'@example.org',b'@gnu.org',b'@fsf.org',b'@device.local',b'@cloverkit.local'))]
  emails=[e for e in emails if not (b'getty@' in e and e.endswith(b'.service'))]
  if emails:findings.append(dict(file=name,rule='review-nonexample-email'))
 # Exact reviewed clover PNG contains public C2PA CA certificate mail, not owner data.
 if hashlib.sha256(raw).hexdigest()=='9bc5857e0422510e015fa3e698cee585f1976261fb49dfcf8b2447c05ce9ae86' and set(EMAIL.findall(raw))=={bytes.fromhex('636140747275666f2e6169')}:
  findings=[f for f in findings if f['rule']!='review-nonexample-email']
 return findings
def audit(root,private=()):
 findings=[];count=0;nested=0
 for path,name in inputs(root):
  count+=1;raw=path.read_bytes();vendor=name.startswith(('src/vehicle/vendor/','vendor/','LICENSES/'))
  findings+=inspect(raw,name,private,vendor)
  if name.endswith('.whl'):
   with zipfile.ZipFile(io.BytesIO(raw)) as archive:
    for item in archive.infolist():
     if item.is_dir():continue
     nested+=1;findings+=inspect(archive.read(item),name+'::'+item.filename,private,True)
  elif name.startswith('vendor/') and name.endswith(('.tar.gz','.tar.xz','.tgz')):
   with tarfile.open(fileobj=io.BytesIO(raw),mode='r:*') as archive:
    for item in archive:
     if not item.isfile():continue
     nested+=1;findings+=inspect(archive.extractfile(item).read(),name+'::'+item.name,private,True)
 return dict(schema=1,files_checked=count,nested_members_checked=nested,findings=findings,passed=not findings,
             scope='Selected archive inputs, binary strings, wheel members and source archive members. No runtime accounts, scans or configuration are included. This is a release check, not a proof that all future user data is anonymous.')
def main():
 p=argparse.ArgumentParser();p.add_argument('--root',type=Path,default=ROOT);p.add_argument('--private-values',type=Path);p.add_argument('--output',type=Path);a=p.parse_args()
 private=[v.encode() for v in json.loads(a.private_values.read_text(encoding='utf-8'))] if a.private_values else []
 result=audit(a.root,private)
 if a.output:a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
 print(json.dumps(result,indent=2));return 0 if result['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
