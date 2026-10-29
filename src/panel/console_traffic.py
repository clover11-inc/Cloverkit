#!/usr/bin/env python3
"""Observe TCP counters for sockets held by the restricted Console account."""
from pathlib import Path
import json
import os
import pwd
import re
import subprocess
import tempfile
import time

STATE = Path('/run/cloverkit/console-traffic.json')


def socket_inodes(uid, root=Path('/proc')):
    inodes=set()
    for process in root.iterdir():
        if not process.name.isdigit():
            continue
        try:
            # The sshd session process retains the connection socket.
            status=(process/'status').read_text()
            if not re.search(r'^Uid:\s+'+str(uid)+r'\s',status,re.M):
                continue
            for descriptor in (process/'fd').iterdir():
                try:
                    link=os.readlink(descriptor)
                except OSError:
                    continue
                match=re.fullmatch(r'socket:\[(\d+)\]',link)
                if match:inodes.add(match[1])
        except OSError:
            continue
    return inodes


def counters(text, inodes):
    result=[]
    seen=set()
    for block in re.split(r'\n(?=\S)',text):
        match=re.search(r'\bino:(\d+)\b',block)
        if not match or match[1] not in inodes or match[1] in seen:
            continue
        # Match sshd sockets only, excluding unrelated processes under this UID.
        if not re.search(r'users:\(.*"sshd(?:-session)?"',block):
            continue
        seen.add(match[1])
        tx=re.search(r'\bbytes_sent:(\d+)\b',block)
        rx=re.search(r'\bbytes_received:(\d+)\b',block)
        result.append(dict(inode=match[1],tx=int(tx[1]) if tx else None,rx=int(rx[1]) if rx else None))
    return result


def amount(number):
    if number is None:return 'Not reported'
    for suffix in ('B','KB','MB','GB'):
        if number<1024 or suffix=='GB':
            return f'{number:.1f} {suffix}' if suffix!='B' else f'{number:.0f} B'
        number/=1024


def snapshot(records, previous=None, now=None):
    now=time.monotonic() if now is None else now
    totals={key:sum(row[key] for row in records) if records and all(row[key] is not None for row in records) else None for key in ('rx','tx')}
    current=dict(time=now,inodes=sorted(row['inode'] for row in records),**totals)
    rates={key:None for key in totals}
    if previous and current['inodes']==previous.get('inodes') and 0<now-previous.get('time',now)<15:
        for key,total in totals.items():
            old=previous.get(key)
            if total is not None and old is not None and total>=old:
                rates[key]=(total-old)/(now-previous['time'])
    return current,rates


def main():
    if os.geteuid()!=0:
        print('SSH traffic: Requires Console status permissions')
        return
    try:
        uid=pwd.getpwnam('console').pw_uid
        inodes=socket_inodes(uid)
        result=subprocess.run(['/usr/bin/ss','-tinpe','state','established'],capture_output=True,text=True,timeout=1)
        if result.returncode:raise OSError('Socket diagnostics unavailable')
        records=counters(result.stdout,inodes)
        try:previous=json.loads(STATE.read_text())
        except (OSError,ValueError):previous=None
        current,rates=snapshot(records,previous)
        with tempfile.NamedTemporaryFile(mode='w',dir=STATE.parent,prefix='.console-traffic-',delete=False) as file:
            temporary=Path(file.name);json.dump(current,file)
        try:
            temporary.chmod(0o600);os.replace(temporary,STATE)
        finally:temporary.unlink(missing_ok=True)
        if not records:
            print('SSH connections: 0')
            print('SSH traffic: No attributable active connection')
            return
        print('SSH connections: '+str(len(records)))
        print('SSH RX: '+amount(current['rx'])+' | '+(amount(rates['rx'])+'/s' if rates['rx'] is not None else 'Measuring rate'))
        print('SSH TX: '+amount(current['tx'])+' | '+(amount(rates['tx'])+'/s' if rates['tx'] is not None else 'Measuring rate'))
        print('SSH RX/TX: received/sent by BH (encrypted TCP)')
    except (OSError,KeyError,ValueError,TypeError,subprocess.TimeoutExpired):
        print('SSH traffic: Not reported by this system')


if __name__=='__main__':main()
