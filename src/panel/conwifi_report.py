#!/usr/bin/env python3
"""Forced SSH command: browse only the published Advanced scan snapshot."""
import json,os,select,shutil,sys,termios,time,tty
from pathlib import Path
sys.path.insert(0,'/usr/local/lib/bh-interactive')
import wifi_health_browser as browser
from wifi_health_browser import report,navigate,new_navigation
from wifi_health_view import colour
_original_page_data=browser.page_data
ROOT=Path('/run/cloverkit-conwifi')
BLOCKED={'survey_row','survey_column','survey_record','survey_save','unresolved','mapping_builder','mapping_review','toggle_member','review_manual','save_mapping'}

def page_data(task,nav):
    title,body,items=_original_page_data(task,nav)
    return title,body,[x for x in items if x['page'] not in BLOCKED]
browser.page_data=page_data

def browse(task,nav,key):
    navigate(task,nav,key)
    nav.pop('pending_mapping',None)
    return True

def load_task():
    data=json.loads((ROOT/'report.json').read_text())
    if data.get('schema')!=1:raise ValueError('Invalid scan snapshot')
    age=max(0,time.time()-data.get('updated_at',0))
    state='FAILED' if data.get('state')=='FAILED' else 'RUNNING' if data.get('state') not in ('STOPPED','COMPLETE') else 'COMPLETE'
    return dict(state=state,finder={'values':data,'received':time.monotonic()-age},metadata={'kind':'wifi-health'},lines=[])

def current_token():
    try:return (ROOT/'active').read_text()
    except OSError:return None

def main():
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print('Use ssh -t conwifi@HOST for the Advanced report.');return 1
    if not current_token():
        print('Wi-Fi console is disabled. Select Run with console on Cloverkit.');return 1
    token=current_token()
    nav=new_navigation();old=termios.tcgetattr(0);pending=b'';task=None
    try:
        tty.setraw(0)
        while current_token()==token:
            try:task=load_task()
            except (OSError,ValueError):pass
            size=shutil.get_terminal_size((80,24))
            if task:
                rows=report(task,nav,max(20,size.columns-1),max(5,size.lines-3))
            else:rows=['ADVANCED WI-FI REPORT','Waiting for this scan to publish its first snapshot...']
            rows+=['Arrows / WASD: browse | Enter/Right: open | Left/Backspace: back | Q: exit']
            # Plain printable output prevents advertised network names acting as terminal escapes.
            clean=lambda line: ''.join(c if c.isprintable() else ' ' for c in str(line))
            sys.stdout.write('\x1b[?25l\x1b[H\x1b[2J'+'\r\n'.join(colour(clean(x)[:size.columns-1], '') for x in rows));sys.stdout.flush()
            if not select.select([0],[],[],0.3)[0]:continue
            raw=os.read(0,128)
            if not raw:break
            pending+=raw
            while pending:
                codes={b'\x1b[A':'up',b'\x1b[B':'down',b'\x1b[C':'right',b'\x1b[D':'left'}
                match=next((c for c in codes if pending.startswith(c)),None)
                if match:key=codes[match];pending=pending[len(match):]
                elif pending.startswith(b'\x1b') and len(pending)<3:break
                else:
                    c=pending[0];pending=pending[1:]
                    if c in (3,4,ord('q'),ord('Q')):return 0
                    key={ord('w'):'up',ord('s'):'down',ord('a'):'left',ord('d'):'right',13:'right',10:'right',8:'left',127:'left'}.get(c)
                if task and key:browse(task,nav,key)
    finally:
        termios.tcsetattr(0,termios.TCSANOW,old)
        sys.stdout.write('\x1b[0m\x1b[?25h\x1b[2J\x1b[HWi-Fi console closed.\r\n');sys.stdout.flush()
    return 0
if __name__=='__main__':raise SystemExit(main())
