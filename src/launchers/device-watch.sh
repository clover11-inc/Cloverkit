#!/usr/bin/env python3
# BH_LCD_DISPATCH_PY_V1
import os
import sys

if os.environ.get("BH_LCD_DISPATCHED", "0") != "1":
    os.execv(
        "/usr/local/bin/lcd-run",
        [
            "/usr/local/bin/lcd-run",
            os.path.abspath(__file__),
            *sys.argv[1:]
        ]
    )


# BH_TARGET_WRAP_ATEXIT_V1
import atexit
import subprocess

def _lcd_wrap_generated_targets():
    try:
        subprocess.run(
            ["/usr/local/bin/lcd-wrap-targets"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except Exception:
        pass

atexit.register(_lcd_wrap_generated_targets)


# CLOVERKIT_DEVICE_WATCH_SINGLE_ENGINE_V1
if __name__ == '__main__':
    command=['/usr/local/bin/device-watch',*sys.argv[1:]]
    if os.geteuid()!=0:command=['sudo','-n',*command]
    raise SystemExit(subprocess.call(command))
