#!/usr/bin/env python3
"""CloverKit local documentation and package readiness."""
import argparse
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser(prog='cloverkit')
    sub=p.add_subparsers(dest='command',required=True)
    d=sub.add_parser('docs',help='Read locally generated documentation');d.add_argument('topic',nargs='?',default='index')
    sub.add_parser('status',help='Read package readiness, not live task state')
    a=p.parse_args()
    if a.command=='status':print((ROOT/'docs-src/release-gates.json').read_text());return 0
    allowed={p.stem:p for p in (ROOT/'docs/generated').glob('*.md')}
    if a.topic not in allowed:p.error('Unknown topic; use cloverkit docs')
    print(allowed[a.topic].read_text());return 0
if __name__=='__main__':raise SystemExit(main())
