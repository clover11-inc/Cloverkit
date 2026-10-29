#!/usr/bin/env python3
"""Run only the isolated Vehicle Diagnostics candidate with private candidate data."""
import os,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
base=ROOT/'src/vehicle'
if not base.exists():raise SystemExit('Use this launcher from the source candidate; installed systems use cloverkit-vehicle')
os.environ.setdefault('CLOVERKIT_VEHICLE_HOME',str(Path.home()/'.local/share/cloverkit/vehicle-demo'))
sys.path[:0]=[str(base),str(base/'vendor')]
from cloverkit_vehicle.__main__ import main
if len(sys.argv)==1:sys.argv.append('serve')
if __name__=='__main__':
    try:main()
    except (OSError,ValueError,KeyboardInterrupt) as exc:print('CloverKit: '+str(exc),file=sys.stderr);raise SystemExit(1)
