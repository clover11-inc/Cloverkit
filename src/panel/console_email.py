"""Compatibility notification entrypoint; uses the single CloverKit email configuration."""
import os,socket
from pathlib import Path
from cloverkit_optional_setup import send_access
def main():
    if os.geteuid()!=0:raise SystemExit('Use the installed Console activation hook')
    password=Path('/run/cloverkit/guest-password').read_text().strip()
    status=send_access('Serial console','console',password,socket.gethostname()+'.local')
    folder=Path('/run/cloverkit');folder.mkdir(mode=0o700,exist_ok=True)
    (folder/'console-email-status').write_text(status+'\n')
    print('Email: '+status+'; access details remain on the local Console page.')
    return 0 if status in ('SENT','NOT CONFIGURED') else 1
if __name__=='__main__':raise SystemExit(main())
