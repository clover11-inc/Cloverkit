"""Explicit maintainer download of pinned vendor source archives; never run at install."""
# SPDX-License-Identifier: GPL-2.0-or-later
import argparse,email.parser,hashlib,json,urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def fetch(metadata):
 info=email.parser.Parser().parsestr(metadata.read_text(encoding="utf-8"));name,version=info['Name'],info['Version']
 request=urllib.request.Request(f'https://pypi.org/pypi/{name}/{version}/json',headers={'User-Agent':'CloverKit-source-package'})
 with urllib.request.urlopen(request,timeout=30) as reply:index=json.load(reply)
 source=next((row for row in index['urls'] if row['packagetype']=='sdist'),None)
 if not source:raise ValueError('Missing source distribution: '+name)
 with urllib.request.urlopen(source['url'],timeout=45) as reply:raw=reply.read()
 digest=hashlib.sha256(raw).hexdigest()
 if digest!=source['digests']['sha256']:raise ValueError('Source checksum mismatch: '+name)
 destination=ROOT/'vendor/vehicle/sources'/source['filename'];destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(raw)
 return dict(name=name,version=version,license=info.get('License-Expression') or info.get('License','See bundled notices'),source_url=source['url'],source_file=destination.relative_to(ROOT).as_posix(),source_sha256=digest)
def main():
 p=argparse.ArgumentParser();p.add_argument('--download',action='store_true');args=p.parse_args()
 if not args.download:p.error('Use --download explicitly; requires network access during maintenance only')
 with ThreadPoolExecutor(max_workers=4) as pool:rows=list(pool.map(fetch,sorted((ROOT/'src/vehicle/vendor').glob('*.dist-info/METADATA'))))
 rows.sort(key=lambda r:r['name'].lower())
 (ROOT/'THIRD-PARTY.json').write_text(json.dumps(dict(schema=1,components=rows),indent=2)+'\n')
 print('Verified and saved',len(rows),'pinned source archives.')
if __name__=='__main__':main()

