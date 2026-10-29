#!/usr/bin/env python3
"""Passive infrastructure pair discovery, direction monitoring and client finding."""
import argparse
from collections import Counter, deque
import json
import math
import os
from pathlib import Path
import queue
import re
import signal
import statistics
import subprocess
import sys
import threading
import tempfile
import time

from device_identity import identity_fields

from probe_reader import CHANNELS, IP, IW, NM, TSHARK, choose_interface, run, station

SCAN_CHANNELS = list(range(1,14)) + sorted(set(CHANNELS + [120,124,128,144,165]) - set(range(1,14)))

FIELDS = ['wlan.ta', 'wlan.ra', 'wlan.bssid', 'wlan.fc.type', 'wlan.fc.type_subtype',
          'wlan.fc.tods', 'wlan.fc.fromds', 'wlan.fc.retry', 'frame.len',
          'radiotap.length', 'wlan_radio.channel', 'radiotap.dbm_antsignal', 'wlan_radio.data_rate', 'wlan.ssid']
NAMES = {4:'Probe request',5:'Probe response',8:'Beacon',10:'Disassociation',11:'Authentication',12:'Deauthentication',
         24:'Block Ack request',25:'Block Ack',27:'RTS',28:'CTS',29:'ACK',32:'Data',36:'Null',40:'QoS data',44:'QoS null'}


def number(value):
    try:
        n = float(str(value).split(',')[0])
        return n if math.isfinite(n) else None
    except ValueError:
        return None


def integer(value):
    flag = str(value).split(',')[0].strip().lower()
    if flag in ('true','false','yes','no'):
        return int(flag in ('true','yes'))
    try:
        return int(str(value).split(',')[0], 0)
    except ValueError:
        n = number(value)
        return int(n) if n is not None else None


def mac(value):
    try:
        return station(str(value).split(',')[0])
    except argparse.ArgumentTypeError:
        return ''


def frame(line, extra_fields=()):
    p = line.split('\t')
    p += [''] * max(0, len(FIELDS)-len(p))
    length, header = integer(p[8]), integer(p[9])
    return dict(ta=mac(p[0]), ra=mac(p[1]), bssid=mac(p[2]), kind=integer(p[3]), subtype=integer(p[4]),
                tods=integer(p[5]), fromds=integer(p[6]), retry=integer(p[7]),
                bytes=max(0,length-header) if length is not None and header is not None else None,
                channel=integer(p[10]), rssi=number(p[11]), phy=number(p[12]), ssid=decode_name(p[13]), advertised=dict(zip(extra_fields,p[len(FIELDS):])))


def decode_name(value):
    compact = value.replace(':','')
    if compact and len(compact)%2 == 0 and re.fullmatch('[0-9A-Fa-f]+',compact):
        return bytes.fromhex(compact).decode('utf-8',errors='replace')
    return value or '<hidden>'


def direction_state():
    return {name:dict(frames=0,bytes=0,data_bytes=0,retries=0,retry_known=0,missing_lengths=0,
                      types=Counter(),phy=Counter(),rssi=None) for name in ('ap_to_client','client_to_ap')}


def add_direction(row,f):
    row['frames'] += 1
    if f['bytes'] is not None:
        row['bytes'] += f['bytes']
        if f['kind'] == 2:
            row['data_bytes'] += f['bytes']
    else:
        row['missing_lengths'] += 1
    if f['retry'] in (0,1):
        row['retry_known'] += 1
        row['retries'] += f['retry']
    row['types'][NAMES.get(f['subtype'],f"Type {f['kind']}/{f['subtype']}")] += 1
    if f['kind'] == 2 and f['phy'] is not None:
        row['phy'][str(f['phy'])] += 1
    row['rssi'] = f['rssi']


def write_client_targets(rows, folder=Path('/mnt/scripts'), identities=None):
    """Persist validated tracking launchers; replace only our own marked files."""
    marker = '# CLOVERKIT_CLIENT_TARGET_V1'
    clients = {}
    for row in rows:
        client = station(row['station'])
        ch = int(row['channel'])
        if not 1 <= ch <= 196:
            continue
        clients[client] = {**row, 'station':client, 'channel':ch, 'identity':(identities or {}).get(client,{})}
    if not clients:
        return 0
    folder.mkdir(parents=True,exist_ok=True)
    for client,info in clients.items():
        ch = info['channel']
        dest = folder / ('TARGET-CLIENT-'+client.replace(':','')+'.sh')
        if dest.is_symlink() or (dest.exists() and marker not in dest.read_text()):
            raise RuntimeError('Existing client target is not owned by this generator: '+dest.name)
        body = '#!/bin/bash\n'+marker+'\n# CLIENT_INFO '+json.dumps({k:info.get(k) for k in ('station','channel','bssid','rssi','identity')},separators=(',',':'))+'\nexec /usr/local/bin/bh-wifi-peer client-track --station '+client+' --channel '+str(ch)+'\n'
        with tempfile.NamedTemporaryFile(mode='w',dir=folder,prefix='.client-target-',delete=False) as fh:
            temporary = Path(fh.name)
            fh.write(body)
        try:
            temporary.chmod(0o755)
            os.replace(temporary,dest)
        finally:
            temporary.unlink(missing_ok=True)
    return len(clients)


class Observations:
    def __init__(self, mode, client=None, ap=None):
        self.mode, self.client, self.ap = mode, client, ap
        self.peers, self.aps, self.identities = {}, {}, {}
        self.received, self.classes, self.channels, self.types = 0, Counter(), Counter(), Counter()
        self.directions = direction_state()
        self.samples = deque(maxlen=100)
        self.best, self.baselines = {}, {}
        self.last = None
        self.frames = 0
        self.limited = False

    def process(self, f, now, tuned_channel):
        ch = f['channel'] or tuned_channel
        self.received += 1
        self.types[NAMES.get(f['subtype'],f"Type {f['kind']}/{f['subtype']}")] += 1
        self.classes[{0:'Management',1:'Control',2:'Data'}.get(f['kind'],'Other')] += 1
        if ch:
            self.channels[str(ch)] += 1
        # Only sender-advertised management attributes are attributed to the TA.
        if f['ta'] and f['kind'] == 0 and f['subtype'] in (4,5,8):
            advertised = f.get('advertised',{})
            info = {key: str(value)[:128] for key,value in (
                ('hostname',advertised.get('wps.device_name') or advertised.get('wlan.vs.cisco.apname_v2') or advertised.get('wlan.cisco.ccx1.name')),
                ('model',advertised.get('wps.model_name')),('advertised_vendor',advertised.get('wps.manufacturer'))) if value}
            if info and (f['ta'] in self.identities or len(self.identities)<1000):
                self.identities[f['ta']] = {**self.identities.get(f['ta'],{}),**info,'role':'AP' if f['subtype'] in (5,8) else 'Probe transmitter'}
        if self.mode == 'peers':
            ap = f['bssid']
            if ap and f['kind'] == 0 and f['subtype'] in (5,8) and f['ta'] == ap:
                if ap not in self.aps and len(self.aps) >= 1000:
                    self.limited = True
                else:
                    row = self.aps.setdefault(ap,dict(bssid=ap,ssid=f['ssid'],channel=ch,beacons=0,rssi=None))
                    row.update(ssid=f['ssid'],channel=ch,rssi=f['rssi'])
                    row['beacons'] += 1
            # Infrastructure data or addressed AP/client management interactions.
            # Beacons/broadcast and WDS/IBSS data never establish a client pair.
            if f['kind'] not in (0,2) or (f['kind'] == 0 and f['subtype'] in (4,5,8)):
                return
            if f['kind'] == 2 and (f['tods'],f['fromds']) not in ((1,0),(0,1)):
                return
            direction = 'ap_to_client' if ap and f['ta'] == ap and f['ra'] else 'client_to_ap' if ap and f['ra'] == ap and f['ta'] else None
            if not direction:
                return
            client = f['ra'] if direction == 'ap_to_client' else f['ta']
            if client == ap:
                return
            key = (client,ap,ch)
            if key not in self.peers and len(self.peers) >= 1000:
                self.limited = True
                return
            row = self.peers.setdefault(key,dict(station=client,bssid=ap,channel=ch,frames=0,rssi=None,directions=direction_state()))
            row['frames'] += 1
            add_direction(row['directions'][direction],f)
            if f['ta'] == client:
                row['rssi'] = f['rssi']
            self.frames += 1
        elif self.mode == 'client-track':
            if f['ta'] != self.client:
                return
            self.frames += 1
            self.last = (now,ch)
            if f['rssi'] is not None and -127 <= f['rssi'] <= 0:
                self.samples.append((now,ch,f['rssi']))
        else:
            if f['bssid'] and f['bssid'] != self.ap:
                return
            direction = 'ap_to_client' if (f['ta'],f['ra']) == (self.ap,self.client) else 'client_to_ap' if (f['ta'],f['ra']) == (self.client,self.ap) else None
            if not direction:
                return
            self.frames += 1
            row = self.directions[direction]
            add_direction(row,f)

    def tracking(self, now):
        age = now-self.last[0] if self.last else None
        ch = self.last[1] if self.last else None
        samples = [rssi for t,c,rssi in self.samples if c == ch and now-t <= 2]
        current = round(statistics.median(samples),1) if samples else None
        trend = 'WAITING'
        if current is not None:
            previous = self.baselines.get(ch)
            trend = 'STRONGER' if previous is not None and current-previous >= 3 else 'WEAKER' if previous is not None and current-previous <= -3 else 'STEADY'
            self.baselines[ch] = current
            self.best[ch] = max(current,self.best.get(ch,current))
        return dict(station=self.client,tracking='TRACKING' if age is not None and age < 3 else 'NOT-SEEN' if age is not None else 'SEARCHING',
                    signal=current, best=self.best.get(ch),channel=ch,age=round(age,1) if age is not None else None,trend=trend)


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('mode',choices=['peers','pair','client-track'])
    parser.add_argument('--station',type=station)
    parser.add_argument('--bssid',type=station)
    parser.add_argument('--channel',type=int,choices=range(1,197))
    args = parser.parse_args(argv)
    if args.mode != 'peers' and not args.station:
        parser.error('Select a client MAC')
    if args.mode == 'pair' and (not args.bssid or not args.channel or args.bssid == args.station):
        parser.error('Pair monitoring requires a distinct AP BSSID and observed channel')
    return args


def main(argv=None):
    args = parse_args(argv)
    if os.geteuid() != 0:
        os.execv('/usr/bin/sudo',['sudo','-n','/usr/local/bin/bh-wifi-peer',*sys.argv[1:]])
    iface = choose_interface()
    if not iface or iface == 'wlan0':
        print('ERROR: No external Wi-Fi radio.',flush=True)
        return 1
    stop = threading.Event()
    old_handlers = {sig:signal.signal(sig,lambda *_:stop.set()) for sig in (signal.SIGTERM,signal.SIGINT)}
    capture = reader_thread = error_thread = None
    changed = False
    errors = deque(maxlen=8)
    q = queue.Queue(maxsize=10000)
    dropped = 0
    observations = Observations(args.mode,args.station,args.bssid)
    duration = 0 if args.mode == 'client-track' else 60
    try:
        if run([IP,'-4','-o','addr','show','dev',iface]).stdout.strip() or run([IP,'route','show','default','dev',iface]).stdout.strip():
            raise RuntimeError('External radio has an address/route; capture refused')
        info = run([IW,'dev',iface,'info'])
        match = re.search(r'^\s*type\s+(\S+)',info.stdout,re.M)
        if info.returncode or not match:
            raise RuntimeError('Cannot read original radio mode')
        original = match.group(1)
        original_up = bool(re.search(r'<[^>]*\bUP\b',run([IP,'link','show',iface]).stdout))
        managed = None
        if Path(NM).is_file():
            managed = run([NM,'-g','GENERAL.NM-MANAGED','device','show',iface]).stdout.strip()
            state = run([NM,'-g','GENERAL.STATE','device','show',iface]).stdout.strip()
            if managed not in ('yes','no') or state.startswith(('100','40','50','60','70','80','90')):
                raise RuntimeError('External radio is active or ownership is unknown')
        changed = True
        commands = ([[NM,'device','set',iface,'managed','no']] if managed else []) + [[IP,'link','set',iface,'down'],[IW,'dev',iface,'set','type','monitor'],[IP,'link','set',iface,'up']]
        for cmd in commands:
            result = run(cmd)
            if result.returncode:
                raise RuntimeError('Radio preparation failed: '+result.stderr.strip())
        channel = args.channel
        def tune(ch):
            result = run([IW,'dev',iface,'set','channel',str(ch)])
            return result.returncode == 0
        if channel and not tune(channel):
            raise RuntimeError('Selected channel is unsupported by this adapter')
        filt = None if args.mode == 'peers' else f'wlan.ta == {args.station}' if args.mode == 'client-track' else f'(wlan.ta == {args.station} && wlan.ra == {args.bssid}) || (wlan.ta == {args.bssid} && wlan.ra == {args.station})'
        cmd = [TSHARK,'-l','-n','-i',iface,'-T','fields','-E','occurrence=f']
        if filt:
            cmd += ['-Y',filt]
        extra_fields = identity_fields()
        for field in [*FIELDS,*extra_fields]:
            cmd += ['-e',field]
        capture = subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
        def reader():
            nonlocal dropped
            for line in capture.stdout:
                try:
                    q.put_nowait((line.rstrip('\r\n'),time.monotonic(),channel))
                except queue.Full:
                    dropped += 1
        def error_reader():
            for line in capture.stderr:
                errors.append(line.strip())
        reader_thread = threading.Thread(target=reader,daemon=True)
        error_thread = threading.Thread(target=error_reader,daemon=True)
        reader_thread.start(); error_thread.start()
        start = time.monotonic()
        emit_at = start
        hop_at = start+2 if channel else start
        index = 0
        previous = {key:0 for key in observations.directions}
        previous_time = start
        previous_frames = 0
        targets_generated = 0
        def drain():
            for _ in range(10000):
                try:
                    line,seen,ch = q.get_nowait()
                except queue.Empty:
                    break
                observations.process(frame(line,extra_fields),seen,ch)
        def emit(state,now):
            nonlocal previous_time, previous_frames
            dt = max(.001,now-previous_time)
            elapsed = max(.001,now-start)
            value = dict(mode=args.mode,state=state,interface=iface,duration=duration,elapsed=int(elapsed),remaining=max(0,duration-int(elapsed)) if duration else None,
                         frames=observations.received if args.mode == 'peers' else observations.frames, rate=round(((observations.received if args.mode == 'peers' else observations.frames)-previous_frames)/dt), received=observations.received, pair_frames=observations.frames, classes=dict(observations.classes), types=dict(observations.types), channels=dict(observations.channels), targets_generated=targets_generated, identities=observations.identities, channel=channel,station=args.station,bssid=args.bssid,dropped=dropped,limited=observations.limited)
            if args.mode == 'peers':
                value['rows'] = sorted(observations.peers.values(),key=lambda r:-r['frames'])
                value['aps'] = sorted(observations.aps.values(),key=lambda r:-(r['rssi'] if r['rssi'] is not None else -999))
                value['diagnostics'] = list(errors)
                if not observations.received:
                    value['warning'] = 'No frames received from TShark; check external adapter/driver/channel support.'
                elif not observations.frames:
                    value['warning'] = 'Frames received, but no addressed AP/client interactions observed.'
            elif args.mode == 'client-track':
                value.update(observations.tracking(now))
            else:
                value['directions'] = {}
                for key,row in observations.directions.items():
                    value['directions'][key] = {**row,'types':dict(row['types']),'phy':dict(row['phy']),
                        'mbps':round((row['data_bytes']-previous[key])*8/dt/1e6,3),
                        'average_mbps':round(row['data_bytes']*8/elapsed/1e6,3),
                        'retry_percent':round(row['retries']*100/row['retry_known'],1) if row['retry_known'] else None}
                    previous[key] = row['data_bytes']
            print('PACKET_LIVE_JSON '+json.dumps(value,separators=(',',':')),flush=True)
            previous_time = now
            previous_frames = observations.received if args.mode == 'peers' else observations.frames
        while not stop.is_set() and (not duration or time.monotonic()-start < duration):
            now = time.monotonic()
            if stop.is_set():
                break
            if capture.poll() is not None:
                error_thread.join(timeout=1)
                raise RuntimeError('Capture stopped: '+('; '.join(errors) or str(capture.returncode)))
            drain()
            if args.mode != 'pair' and now >= hop_at:
                # Follow recently heard client traffic; resume searching if it goes quiet.
                if args.mode == 'client-track' and observations.last and now-observations.last[0] < 8:
                    target = observations.last[1]
                    if target and target != channel and tune(target):
                        channel = target
                else:
                    for _ in SCAN_CHANNELS:
                        target = SCAN_CHANNELS[index % len(SCAN_CHANNELS)]; index += 1
                        if tune(target):
                            channel = target
                            break
                    else:
                        raise RuntimeError('No supported capture channel')
                hop_at = time.monotonic()+1
            if now >= emit_at:
                emit('LIVE',time.monotonic()); emit_at = time.monotonic()+1
            stop.wait(.05)
        capture.terminate()
        try:
            capture.wait(timeout=2)
        except subprocess.TimeoutExpired:
            capture.kill(); capture.wait(timeout=2)
        reader_thread.join(timeout=2)
        if reader_thread.is_alive():
            raise RuntimeError('Reader did not finish; results incomplete')
        drain()
        error_thread.join(timeout=1)
        if args.mode == 'peers':
            try:
                targets_generated = write_client_targets(observations.peers.values(), identities=observations.identities)
            except (OSError,RuntimeError) as error:
                print('WARNING: Client targets could not be saved: '+str(error),flush=True)
        emit('STOPPED' if stop.is_set() else 'COMPLETE',time.monotonic())
        return 0
    except (OSError,RuntimeError) as error:
        print('ERROR: '+str(error),flush=True)
        return 1
    finally:
        if capture and capture.poll() is None:
            capture.terminate()
            try:
                capture.wait(timeout=2)
            except subprocess.TimeoutExpired:
                capture.kill(); capture.wait(timeout=2)
        if changed:
            commands = [[IP,'link','set',iface,'down'],[IW,'dev',iface,'set','type',original],[IP,'link','set',iface,'up' if original_up else 'down']]
            if managed:
                commands += [[NM,'device','set',iface,'managed',managed]]
            for cmd in commands:
                try:
                    if run(cmd).returncode:
                        print('WARNING: External radio restoration failed',flush=True)
                except RuntimeError as error:
                    print('WARNING: '+str(error),flush=True)
        for sig,handler in old_handlers.items():
            signal.signal(sig,handler)


if __name__ == '__main__':
    raise SystemExit(main())
