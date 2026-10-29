#!/usr/bin/env python3
"""Passive probe collection/tracking on an external radio; no frame injection."""
import argparse
from collections import Counter, deque
import json
import os
from pathlib import Path
import queue
import re
import signal
import statistics
import subprocess
import sys
import threading
import time

CHANNELS = [1, 6, 11, 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 132, 136, 140, 149, 153, 157, 161]
IP = '/usr/sbin/ip'
IW = '/usr/sbin/iw'
NM = '/usr/bin/nmcli'
TSHARK = '/usr/bin/tshark'


def station(value):
    value = value.upper()
    if not re.fullmatch(r'(?:[0-9A-F]{2}:){5}[0-9A-F]{2}', value) or int(value[:2], 16) & 1:
        raise argparse.ArgumentTypeError('Expected a unicast station MAC address')
    return value


def decode_ssid(value):
    if not value:
        return '<broadcast>'
    compact = value.replace(':', '')
    if len(compact) % 2 == 0 and re.fullmatch('[0-9a-fA-F]+', compact):
        return bytes.fromhex(compact).decode('utf-8', errors='replace') or '<broadcast>'
    return value


def run(args):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=3, env={**os.environ, 'LC_ALL': 'C'})
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(str(error)) from error


def choose_interface():
    return next(iter(sorted(p.name for p in Path("/sys/class/net").glob("wlan*") if p.name != "wlan0" and (p/"wireless").is_dir())), None)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--station', type=station)
    parser.add_argument('--seconds', type=int, default=0, choices=[0, *range(10, 301)])
    args = parser.parse_args()
    if os.geteuid() != 0:
        os.execv('/usr/bin/sudo', ['sudo', '-n', '/usr/local/bin/bh-probe-reader', *sys.argv[1:]])
    iface = choose_interface()
    if not iface or iface == 'wlan0':
        print('ERROR: No external Wi-Fi adapter.', flush=True)
        return 1
    info = run([IW, 'dev', iface, 'info']).stdout
    match = re.search(r'^\s*type\s+(\S+)', info, re.M)
    if not match:
        print('ERROR: Could not read original radio mode.', flush=True)
        return 1
    original = match.group(1)
    original_up = bool(re.search(r"<[^>]*\bUP\b", run([IP, "link", "show", iface]).stdout))
    nm_exists = Path(NM).is_file()
    managed = 'yes'
    if nm_exists:
        managed = run([NM, '-g', 'GENERAL.NM-MANAGED', 'device', 'show', iface]).stdout.strip()
        if managed not in ('yes', 'no'):
            print('ERROR: Could not read original NetworkManager ownership.', flush=True)
            return 1
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    capture = None
    changed = False
    q = queue.Queue(maxsize=10000)
    pairs = Counter()
    last = {}
    channels = Counter()
    samples = deque(maxlen=20)
    best_by_channel = {}
    frames = 0
    limited = False
    try:
        changed = True
        if nm_exists:
            run([NM, 'device', 'set', iface, 'managed', 'no'])
        run([IP, 'link', 'set', iface, 'down'])
        if run([IW, 'dev', iface, 'set', 'type', 'monitor']).returncode:
            raise RuntimeError('External adapter does not enter monitor mode')
        run([IP, 'link', 'set', iface, 'up'])
        filt = 'wlan.fc.type_subtype == 4'
        if args.station:
            filt += ' && wlan.sa == ' + args.station.lower()
        capture = subprocess.Popen([TSHARK, '-l', '-n', '-i', iface, '-Y', filt, '-T', 'fields', '-E', 'occurrence=f', '-e', 'wlan.sa', '-e', 'wlan.ssid', '-e', 'wlan_radio.channel', '-e', 'radiotap.dbm_antsignal'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        errors = deque(maxlen=8)
        def reader():
            for line in capture.stdout:
                while not stop.is_set():
                    try:
                        q.put(line.rstrip('\r\n'), timeout=.1)
                        break
                    except queue.Full:
                        pass
        def error_reader():
            for line in capture.stderr:
                errors.append(line.strip())
        threading.Thread(target=reader, daemon=True).start()
        threading.Thread(target=error_reader, daemon=True).start()
        start = time.monotonic()
        hop = emit_at = start
        hop_index = previous = 0
        previous_time = start
        def emit(state, now):
            nonlocal previous, previous_time
            signal_value = None
            while samples and now - samples[0][0] > 2:
                samples.popleft()
            current_ch = last.get(args.station, {}).get("channel", "--")
            channel_samples = [v for _, v, ch in samples if ch == current_ch]
            if channel_samples:
                signal_value = round(statistics.median(channel_samples))
                best_by_channel[current_ch] = max(signal_value, best_by_channel.get(current_ch, signal_value))
            rows = [dict(station=sta, ssid=ssid, count=count, rssi=last[sta]['rssi'], channel=last[sta]['channel'], age=round(now-last[sta]['time'], 1)) for (sta, ssid), count in pairs.most_common()]
            value = dict(mode='device-track' if args.station else 'probes', state=state, interface=iface, duration=args.seconds, elapsed=min(args.seconds, int(now-start)) if args.seconds else int(now-start), remaining=max(0, args.seconds-int(now-start)) if args.seconds else None, frames=frames, rate=round((frames-previous)/max(.001, now-previous_time)), channels=dict(channels), stations=len(last), ssids=len({ssid for _, ssid in pairs if ssid != '<broadcast>'}), rows=rows, full_rows=True, limited=limited)
            if args.station:
                seen = last.get(args.station)
                age = now-seen['time'] if seen else None
                value.update(station=args.station, signal=signal_value, best=best_by_channel.get(current_ch), channel=current_ch, age=round(age, 1) if age is not None else None, tracking='TRACKING' if age is not None and age < 3 else 'NOT-SEEN' if seen else 'SEARCHING')
            print('PACKET_LIVE_JSON ' + json.dumps(value, separators=(',', ':')), flush=True)
            previous, previous_time = frames, now
        def drain(limit=1000):
            nonlocal frames, limited
            for _ in range(limit):
                try:
                    fields = q.get_nowait().split('\t')
                except queue.Empty:
                    break
                fields += [''] * max(0, 4-len(fields))
                try:
                    sta = station(fields[0])
                except argparse.ArgumentTypeError:
                    continue
                if args.station and sta != args.station:
                    continue
                ssid = decode_ssid(fields[1])
                try:
                    rssi = int(fields[3].split(',')[0])
                    if not -100 <= rssi <= -10:
                        rssi = None
                except ValueError:
                    rssi = None
                observed = time.monotonic()
                if (sta, ssid) not in pairs and len(pairs) >= 5000:
                    limited = True
                    continue
                pairs[(sta, ssid)] += 1
                last[sta] = dict(rssi=rssi, channel=fields[2] or '--', time=observed)
                frames += 1
                if fields[2]:
                    channels[fields[2]] += 1
                if args.station and rssi is not None:
                    samples.append((observed, rssi, fields[2] or "--"))
        while not stop.is_set() and (args.seconds == 0 or time.monotonic()-start < args.seconds):
            now = time.monotonic()
            if capture.poll() is not None:
                raise RuntimeError('Capture stopped: ' + ('; '.join(errors) or f'exit {capture.returncode}'))
            if now >= hop:
                for _ in CHANNELS:
                    ch = CHANNELS[hop_index % len(CHANNELS)]
                    hop_index += 1
                    if run([IW, 'dev', iface, 'set', 'channel', str(ch)]).returncode == 0:
                        break
                else:
                    raise RuntimeError('No supported capture channel could be selected')
                hop = time.monotonic()+2
            drain()
            if now >= emit_at:
                emit('LIVE', time.monotonic())
                emit_at = time.monotonic()+1
            stop.wait(.05)
        capture.terminate()
        try:
            capture.wait(timeout=2)
        except subprocess.TimeoutExpired:
            capture.kill()
            capture.wait(timeout=2)
        drain(10000)
        emit('CANCELLED' if stop.is_set() else 'COMPLETE', time.monotonic())
        return 143 if stop.is_set() else 0
    except (OSError, RuntimeError) as error:
        print('ERROR: ' + str(error), flush=True)
        return 1
    finally:
        stop.set()
        if capture:
            capture.terminate()
            try:
                capture.wait(timeout=2)
            except subprocess.TimeoutExpired:
                capture.kill()
                capture.wait(timeout=2)
        if changed:
            for cmd in ([IP, 'link', 'set', iface, 'down'], [IW, 'dev', iface, 'set', 'type', original], [IP, 'link', 'set', iface, 'up' if original_up else 'down']):
                try:
                    if run(cmd).returncode:
                        print('WARNING: Radio restoration command failed: ' + ' '.join(cmd), flush=True)
                except RuntimeError as error:
                    print('WARNING: ' + str(error), flush=True)
            if nm_exists:
                try:
                    run([NM, 'device', 'set', iface, 'managed', managed])
                except RuntimeError as error:
                    print('WARNING: ' + str(error), flush=True)


if __name__ == '__main__':
    raise SystemExit(main())
