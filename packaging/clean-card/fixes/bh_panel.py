#!/usr/bin/env python3
"""Standalone BlackHat panel; existing toolkit scripts are never edited."""
import argparse
import collections
import fcntl
import json
import os
import re
from pathlib import Path
import select
import shutil
import shlex
import signal
import struct
import subprocess
import sys
import termios
import threading
import textwrap
import time
import tty

from device_identity import identify, summary as identity_summary, client_label, client_metadata
from shared_console import get_snapshot as serial_snapshot
from wifi_health_browser import report as wifi_report, navigate as wifi_navigate, new_navigation as wifi_new_navigation, controls as wifi_controls, apply_mapping as wifi_apply_mapping
from wifi_health_view import view as wifi_health_lines, colour as wifi_health_colour, available_sections as wifi_sections
# WIFI_HEALTH_OPTIONAL_H20
# WIFI_HEALTH_DASHBOARD_V2


def command(argv, timeout=3):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip() if result.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def nm_fields(line):
    """Parse nmcli's escaped terse fields, including colons in SSIDs."""
    fields, value, escaped = [], [], False
    for char in line:
        if escaped:
            value.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(value))
            value = []
        else:
            value.append(char)
    if escaped:
        value.append("\\")
    return fields + ["".join(value)]


class Keys:
    def __init__(self):
        self.buffer = b""
        self.updated = 0.0

    def feed(self, data, now=None):
        self.buffer += data
        self.updated = time.monotonic() if now is None else now
        return self.drain(False)

    def drain(self, expire=False):
        events = []
        sequences = {b"\x1b[A": "up", b"\x1b[B": "down",
                     b"\x1b[C": "right", b"\x1b[D": "left",
                     b"\x1bOA": "up", b"\x1bOB": "down",
                     b"\x1bOC": "right", b"\x1bOD": "left"}
        while self.buffer:
            found = next((s for s in sequences if self.buffer.startswith(s)), None)
            if found:
                events.append(sequences[found])
                self.buffer = self.buffer[len(found):]
                continue
            if self.buffer.startswith(b"\x1b"):
                if not expire and any(s.startswith(self.buffer) for s in sequences):
                    break
                events.append("back")
                self.buffer = self.buffer[1:]
                continue
            char, self.buffer = self.buffer[0], self.buffer[1:]
            event = {3: "quit", 13: "enter", 10: "enter", 113: "quit",
                     119: "up", 115: "down", 97: "left", 100: "right",
                     114: "refresh"}.get(char)
            if event:
                events.append(event)
        return events

    def tick(self, now=None):
        now = time.monotonic() if now is None else now
        return self.drain(now - self.updated > 0.15)


def system_data():
    memory = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        memory[key] = int(value.split()[0])
    total = memory.get("MemTotal", 1)
    available = memory.get("MemAvailable", memory.get("MemFree", 0))
    usage = shutil.disk_usage("/")
    temperatures = []
    for path in Path("/sys/class/thermal").glob("thermal_zone*/temp"):
        try:
            temperatures.append(float(path.read_text()) / 1000)
        except (OSError, ValueError):
            pass
    return {
        "hostname": os.uname().nodename,
        "kernel": os.uname().release,
        "uptime": float(Path("/proc/uptime").read_text().split()[0]),
        "load": os.getloadavg(),
        "memory": 100 * (total - available) / total,
        "memory_used_mb": (total - available) / 1024,
        "memory_total_mb": total / 1024,
        "disk": 100 * usage.used / usage.total,
        "disk_free_gb": usage.free / 1024 ** 3,
        "temperature": max(temperatures) if temperatures else None,
    }


def network_data():
    devices = []
    raw = command(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status"])
    for line in raw.splitlines():
        row = nm_fields(line)
        if len(row) == 4:
            devices.append(dict(zip(("device", "type", "state", "connection"), row)))
    addresses = {}
    try:
        for interface in json.loads(command(["ip", "-j", "-4", "addr", "show"]) or "[]"):
            addresses[interface["ifname"]] = [a["local"] for a in interface.get("addr_info", [])]
    except (ValueError, KeyError):
        pass
    for device in devices:
        device["ip"] = ", ".join(addresses.get(device["device"], [])) or "--"
    networks = []
    raw = command(["nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL,SECURITY,DEVICE",
                   "device", "wifi", "list", "--rescan", "no"])
    for line in raw.splitlines():
        row = nm_fields(line)
        if len(row) == 5:
            networks.append(dict(zip(("active", "ssid", "signal", "security", "device"), row)))
    return {"devices": devices, "networks": networks, "available": bool(raw or devices)}


def service_data():
    services = []
    raw = command(["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--output=json"])
    try:
        for row in json.loads(raw or "[]"):
            name = row.get("unit", "")
            if any(word in name.lower() for word in ("ssh", "vpn", "wireguard", "tailscale", "iperf", "cloverkit")):
                services.append({"name": name, "state": row.get("active", "unknown"),
                                 "sub": row.get("sub", ""), "description": row.get("description", "")})
    except (ValueError, TypeError):
        pass
    return sorted(services, key=lambda row: row["name"])


CONTROLS = {
    "VPN": {"status": ["sudo", "-n", "/usr/local/bin/bh-vpn", "status"],
            "On": ["sudo", "-n", "/usr/local/bin/bh-vpn", "on"],
            "Off": ["sudo", "-n", "/usr/local/bin/bh-vpn", "off"]},
    "Console": {"status": ["/usr/local/bin/console-status"],
                "On": ["/usr/local/bin/console-on"], "Off": ["/usr/local/bin/console-off"]},
    "iperf": {"status": ["sudo", "-n", "/usr/local/bin/iperf-server", "status"],
              "On": ["sudo", "-n", "/usr/local/bin/iperf-server", "start"],
              "Off": ["sudo", "-n", "/usr/local/bin/iperf-server", "stop"]},
}


def control_data():
    values = {name: command(spec["status"], timeout=3) or "Status unavailable"
              for name, spec in CONTROLS.items()}
    return values


def serial_data():
    try:
        return serial_snapshot()
    except (OSError, ValueError, KeyError):
        return None


MONITOR_SCRIPT = Path("/mnt/scripts/monitor.sh")
MONITOR_STATE = Path("/tmp/bh-monitor")
SECURITY_REPORT = Path("/mnt/security/reports/latest.json")
STRUCTURED_KINDS = ("ethernet", "packet", "security")


class Task:
    """Only one selected backend task; stdout is displayed while it runs."""
    def __init__(self):
        self.lock = threading.Lock()
        self.process = None
        self.cancelled = False
        self.output = collections.deque(maxlen=2000)
        self.output_count = 0
        self.metadata = None
        self.finder = {}
        self.title = "No task selected"
        self.state = "IDLE"
        self.started = 0
        self.finished = 0
        self.thread = None
        self.stop_complete = threading.Event()
        self.stop_complete.set()
        self.stopping = False
        self.argv = []
        self.devices = {}

    def snapshot(self):
        with self.lock:
            return {"title": self.title, "state": self.state, "lines": list(self.output),
                    "count": self.output_count, "metadata": self.metadata, "finder": dict(self.finder),
                    "devices": dict(self.devices),
                    "stopping": self.stopping, "elapsed": (self.finished or time.monotonic()) - self.started if self.started else 0}

    def start(self, title, argv, metadata=None):
        from cloverkit_radio_identity import assert_layout
        try: assert_layout()
        except (RuntimeError,OSError) as error:
            self.record_line('Blocked: '+str(error)); return False
        with self.lock:
            if self.state == "RUNNING":
                return False
            self.title, self.state = title, "RUNNING"
            self.started = time.monotonic()
            self.finished = 0
            self.output.clear()
            self.output_count = 0
            self.metadata = metadata
            self.finder = {}
            self.record_line("Starting...")
            self.cancelled = False
            self.process = None
            self.argv = list(argv)
            self.stopping = False
            self.stop_complete.set()
        self.thread = threading.Thread(target=self.run, args=(argv,), daemon=True)
        self.thread.start()
        return True

    def record_line(self, line):
        """Caller holds lock. Keep raw history and the latest finder fields separately."""
        if line.startswith("WIFI_HEALTH_JSON "):
            try:
                values = json.loads(line[len("WIFI_HEALTH_JSON "):])
                if not isinstance(values, dict) or values.get("schema") != 1:
                    raise ValueError("Invalid Wi-Fi snapshot")
                self.metadata = {"kind": "wifi-health"}
                self.finder = {"values": values, "received": time.monotonic()}
                return
            except (ValueError, TypeError):
                line = "Invalid Wi-Fi update; waiting for next snapshot."
        for marker in ("LIVE_PACKET_JSON ", "PACKET_LIVE_JSON "):
            if line.startswith(marker):
                try:
                    values = json.loads(line[len(marker):])
                    if not isinstance(values, dict):
                        raise ValueError("Expected an object")
                    if values.get("mode") == "probes":
                        for row in values.get("rows", []):
                            mac = str(row.get("station", "")).upper()
                            if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", mac) or int(mac[:2], 16) & 1:
                                continue
                            old = self.devices.get(mac, {})
                            self.devices[mac] = {**old, "station": mac, "rssi": row.get("rssi"),
                                                 "ssids": sorted(set(old.get("ssids", [])) | {str(row.get("ssid", "<broadcast>"))})}
                    if values.get("mode") in ("peers", "stations"):
                        for row in values.get("rows", []):
                            client, ap = str(row.get("station", "")).upper(), str(row.get("bssid", "")).upper()
                            try:
                                channel = int(row.get("channel"))
                            except (ValueError, TypeError):
                                continue
                            if not all(re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", addr) and not int(addr[:2],16) & 1 for addr in (client,ap)) or client == ap or not 1 <= channel <= 196:
                                continue
                            old = self.devices.get(client, {})
                            links = dict(old.get("links", {}))
                            links[ap + "/" + str(channel)] = {"bssid":ap,"channel":channel,"frames":row.get("frames",0)}
                            self.devices[client] = {**old,"station":client,"links":links}
                            if values.get("mode") == "peers" and row.get("rssi") is not None:
                                self.devices[client]["rssi"] = row["rssi"]
                    for address, evidence in values.get("identities", {}).items():
                        address = str(address).upper()
                        if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}",address) or int(address[:2],16)&1 or not isinstance(evidence,dict):
                            continue
                        if evidence.get("role") != "AP":
                            self.devices[address] = {**self.devices.get(address,{}),"station":address,"identity":evidence}
                    self.metadata = {"kind": "packet"}
                    self.finder = {"values": values, "received": time.monotonic()}
                    return
                except (ValueError, TypeError):
                    line = "Invalid capture update; waiting for the next state."
        if self.metadata and self.metadata.get("kind") == "security" and line.startswith("{"):
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("Expected an object")
                kind = event.get("event")
                if kind == "state":
                    self.finder["stage"] = event.get("state", "Unknown")
                elif kind == "progress":
                    self.finder["progress"] = event
                    self.finder["received"] = time.monotonic()
                    self.finder["stage"] = event.get("stage", "Scanning")
                elif kind == "scan":
                    self.finder["summary"] = event
                    # Read full findings only when THIS run emits its scan result.
                    # Never show an old report while a new scan is running.
                    try:
                        report = json.loads(SECURITY_REPORT.read_text(encoding="utf-8"))
                        if event.get("timestamp") is not None and report.get("timestamp") == event.get("timestamp"):
                            self.finder["report"] = report
                    except (OSError, ValueError, TypeError):
                        pass
                elif kind == "attention":
                    self.finder["attention"] = [*self.finder.get("attention", []), event]
                elif kind == "error":
                    self.finder["error"] = event.get("message", "Scan failed")
                    if event.get("blocked"): self.finder["blocked"] = True
                else:
                    self.output.append(line)
                    self.output_count += 1
                return
            except (ValueError, TypeError):
                line = "Invalid security update; see backend report."
        if self.metadata and self.metadata.get("kind") == "ethernet" and line.startswith("ETHERNET_JSON "):
            try:
                values = json.loads(line[len("ETHERNET_JSON "):])
                if isinstance(values, dict) and values.get("event") == "state":
                    # Replace the entire state so reconnect/missing-adapter frames
                    # cannot inherit identity fields from the previous cable.
                    self.finder = {"values": values, "received": time.monotonic()}
                    return
            except (ValueError, TypeError):
                line = "Invalid Ethernet update; waiting for the next state."
        if re.search(r"(?:^|\s)Traceback \(most recent call last\):", line):
            self.finder["backend_error"] = True
        self.output.append(line)
        self.output_count += 1
        if not self.metadata:
            return
        kind = self.metadata.get("kind")
        if kind in ("host", "discovery"):
            clean = line.strip()
            if clean.startswith("STATE "):
                self.finder["status"] = clean[6:]
            if kind == "discovery":
                if clean.startswith("NETWORK "):
                    self.finder["network"] = clean[8:]
                elif clean.startswith("FOUND "):
                    self.finder["found"] = self.finder.get("found", 0) + 1
                elif re.fullmatch(r"HOSTS \d+", clean):
                    self.finder["reported"] = int(clean.split()[1])
                return
            match = re.match(r"(NAME|MAC|OS|WEB|HTTP|TLS|SSH)\s+(.+)", clean)
            if match:
                self.finder[match[1].lower()] = match[2]
            match = re.fullmatch(r"(\d{1,5})\s+(\S+)(?:\s+(.*))?", clean)
            if match and 0 < int(match[1]) <= 65535:
                self.finder["ports"] = [*self.finder.get("ports", []),
                                        (int(match[1]), match[2], match[3] or "")]
            if clean == "No common TCP ports open":
                self.finder["empty_report"] = True
            return
        if line.startswith('ACQUIRING '):
            self.finder['status']='ACQUIRING'
            self.finder['acquisition']=line[len('ACQUIRING '):]
        match = re.fullmatch(r"LOCKED (\d+) ([0-9A-F:]{17})", line.strip())
        if match:
            self.finder.update(freq=match[1], bssid=match[2])
        match = re.fullmatch(r"\S+ (-?\d+)dBm (\S+)", line.strip())
        if match:
            value = int(match[1])
            self.finder.update(signal=value, quality=match[2], status="TRACKING", signal_received=time.monotonic())
            self.finder["best"] = max(value, self.finder.get("best", value))
        match = re.fullmatch(r"\S+ (SCANNING|NOT-SEEN)", line.strip())
        if match:
            self.finder["status"] = match[1]
        match = re.fullmatch(r"(SEARCHING|STEADY|CLOSER\+\+?|FARTHER--?) (?:(\d+)s|UNTIL-STOP)", line.strip())
        if match:
            self.finder.update(trend=match[1], remaining=int(match[2]) if match[2] else None)

    def run(self, argv):
        environment = dict(os.environ)
        # Keep the original script body, but let this panel own its display.
        environment["BH_LCD_DISPATCHED"] = "1"
        environment["BH_INTERACTIVE_JOB"] = "1"
        environment["PYTHONUNBUFFERED"] = "1"
        environment.pop("BH_SERIAL_GATEWAY", None)
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, start_new_session=True, env=environment)
            with self.lock:
                self.process = proc
                was_cancelled = self.cancelled
            if was_cancelled:
                self.stop()
            buffer = b""
            while True:
                block = os.read(proc.stdout.fileno(), 4096)
                if not block:
                    break
                buffer += block.replace(b"\r", b"\n")
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    with self.lock:
                        self.record_line(line.decode(errors="replace"))
                if len(buffer) > 2 * 1024 * 1024:
                    with self.lock:
                        self.record_line(buffer.decode(errors="replace"))
                    buffer = b""
            rc = proc.wait()
            self.stop_complete.wait()
            with self.lock:
                if buffer:
                    self.record_line(buffer.decode(errors="replace"))
                self.state = "CANCELLED" if self.cancelled else "NOT READY" if self.finder.get("blocked") else "COMPLETE" if rc == 0 and not self.finder.get("backend_error") else "FAILED"
                self.finished = time.monotonic()
                if rc == 0 and self.finder.get("backend_error"):
                    self.record_line("Backend traceback detected; wrapper returned 0 despite the error.")
                self.record_line(f"{self.state} (exit {rc})")
                self.process = None
            proc.stdout.close()
        except OSError as error:
            with self.lock:
                self.state = "FAILED"
                self.finished = time.monotonic()
                self.record_line(str(error))
                self.process = None

    def stop(self):
        with self.lock:
            if self.state != "RUNNING" or self.stopping:
                return
            self.cancelled = True
            proc = self.process
            if proc is None:
                return  # run() honours cancellation once launch finishes.
            self.stopping = True
            self.stop_complete.clear()
            monitor = str(MONITOR_SCRIPT) in self.argv
            self.record_line("Stopping monitor and restoring radio..." if monitor else "Stopping task...")
        threading.Thread(target=self.finish_stop, args=(proc, monitor), daemon=True).start()

    def finish_stop(self, proc, monitor):
        try:
            if monitor:
                # The existing backend is a toggle. Only invoke its stop branch
                # when its state files exist; never accidentally start a capture.
                deadline = time.monotonic() + 5
                while proc.poll() is None and time.monotonic() < deadline:
                    time.sleep(.05)
                if (MONITOR_STATE / "tshark.pid").is_file() and (MONITOR_STATE / "interface").is_file():
                    environment = dict(os.environ, BH_LCD_DISPATCHED="1", BH_INTERACTIVE_JOB="1")
                    environment.pop("BH_SERIAL_GATEWAY", None)
                    cleanup = subprocess.Popen(script_argv(MONITOR_SCRIPT),
                                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                               stderr=subprocess.STDOUT, env=environment,
                                               start_new_session=True, text=True)
                    for line in cleanup.stdout:
                        with self.lock:
                            self.record_line(line.rstrip())
                    cleanup.stdout.close()
                    if cleanup.wait() != 0:
                        with self.lock:
                            self.record_line("Monitor cleanup failed; check the radio status.")
            self.ensure_stopped(proc, grace=15 if "/usr/local/bin/clover-direct-ethernet" in self.argv else 180 if (self.metadata or {}).get("kind") == "wifi-health" or any(path in self.argv for path in ("/usr/local/bin/conwifi-run", "/usr/local/bin/conwifi-run-local")) else 160 if "/usr/local/bin/bh-panel-packet-scan" in self.argv else 20 if any(binary in self.argv for binary in ("/usr/local/bin/bh-probe-reader", "/usr/local/bin/bh-wifi-peer", "/usr/local/bin/bh-panel-packet-general", "/usr/local/bin/bh-panel-packet-live")) else 3)
        except OSError as error:
            with self.lock:
                self.record_line(f"Stop failed: {error}")
        finally:
            self.stop_complete.set()

    @staticmethod
    def ensure_stopped(proc, grace=3):
        # Children may retain stdout after the launcher exits. Its dedicated
        # process group still belongs to this task and must also be stopped.
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            proc.poll()
            try:
                os.killpg(proc.pid, 0)
            except ProcessLookupError:
                return
            time.sleep(.05)
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


class Collector:
    def __init__(self):
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.refresh = threading.Event()
        self.data = {"system": {}, "network": {}, "services": [], "updated": 0,
                     "controls": {}, "stage": "Starting", "errors": []}
        self.thread = threading.Thread(target=self.run, daemon=True)

    def snapshot(self):
        with self.lock:
            return dict(self.data)

    def publish(self, **values):
        with self.lock:
            self.data.update(values)

    def run(self):
        next_network = next_services = 0
        while not self.stop.is_set():
            now = time.monotonic()
            refresh = self.refresh.is_set()
            self.refresh.clear()
            try:
                self.publish(stage="System", system=system_data(), updated=time.time())
                if refresh or now >= next_network:
                    self.publish(stage="Network")
                    self.publish(network=network_data())
                    next_network = now + 5
                if refresh or now >= next_services:
                    self.publish(stage="Services")
                    self.publish(services=service_data(), controls=control_data())
                    next_services = now + 5
                self.publish(controls={**self.snapshot().get("controls", {}), "serial": serial_data()})
                self.publish(stage="Live")
            except Exception as error:
                self.publish(stage="Read error", errors=[str(error)])
            self.stop.wait(1)


SCRIPT_CATEGORIES = ("Network", "Packet Captures", "Targets", "System & Devices", "Security", "Other Tools")


def script_category(path):
    name = path.stem.lower()
    if name.startswith("target-") or name == "target-clean":
        return "Targets"
    if name.startswith("packet-"):
        return "Packet Captures"
    if name == "device-watch" or name.startswith(("security", "sec-")):
        return "Security"
    if name == "iperf" or name.startswith("iperf-"):
        return "Network"
    if name in ("vpn", "console") or name.startswith(("vpn-", "console-")):
        return "System & Devices"
    if name in ("system", "display-mode", "serial", "pc-recovery") or name.startswith("pc-"):
        return "System & Devices"
    if name in ("wifi", "ethernet", "hosts", "monitor", "path-test") or name.startswith(("net-", "wifi-")):
        return "Network"
    return "Other Tools"


FUNCTION_PAGES = ("Network", "Packet Captures", "Security", "Other Tools")
NETWORK_SECTIONS = ("Wi-Fi hardware status", "Packet Captures")
FUNCTION_NAMES = {
    "wifi-health": "Scan Wi-Fi - Advanced",
    "wifi-waterfall": "Wi-Fi waterfall",
    "system": "Live system status", "device-watch": "Device watch",
    "display-mode": "Display mode", "serial": "Serial status", "pc-recovery": "PC recovery",
    "wifi": "Scan Wi-Fi - Basic", "ethernet": "Ethernet status", "hosts": "Discover hosts",
    "monitor": "Network monitor", "path-test": "Test network path",
    "net-direct-test": "Direct Ethernet - DHCP",
    "net-direct-passive": "Direct Ethernet - Passive",
    "net-direct-static": "Direct Ethernet - Static",
    "net-auto": "Automatic network", "net-direct": "Direct network", "net-off": "Network off",
    "vpn-toggle": "Toggle VPN", "console-toggle": "Toggle console",
    "iperf-toggle": "Toggle iperf server", "security-scan": "Security scan",
    "target-clean": "Clean generated targets",
    "packet-scan": "Packet scan", "packet-general": "General capture",
    "packet-beacon": "Beacons", "packet-deauth": "Deauthentication frames",
    "packet-eapol": "EAPOL frames", "packet-ndp": "Cisco NDP",
    "packet-probes": "Probe requests", "packet-raw": "Raw capture",
    "packet-stations": "Stations",
}


def script_argv(path, args=()):
    # A .sh filename is not an interpreter declaration (Device Watch is Python).
    with path.open("rb") as source:
        first_line = source.readline(4096).decode("utf-8", errors="replace").strip()
    interpreter = shlex.split(first_line[2:]) if first_line.startswith("#!") else ["/bin/bash"]
    if not interpreter:
        raise ValueError("Script has an empty interpreter declaration")
    return [*interpreter, str(path), *args]


def function_name(path):
    if path.stem.startswith("TARGET-CLIENT-"):
        compact = path.stem.removeprefix("TARGET-CLIENT-")
        if re.fullmatch(r"[0-9A-Fa-f]{12}",compact):
            address = ":".join(compact[i:i+2] for i in range(0,12,2)).upper()
            return client_label(address,client_metadata(path))
    if path.stem.startswith("TARGET-SSID-"):
        return "SSID " + path.stem[len("TARGET-SSID-"):]
    if path.stem.startswith("TARGET-NET-"):
        return "Host " + path.stem[len("TARGET-NET-"):].replace("-", ".")
    return FUNCTION_NAMES.get(path.stem, path.stem.replace("-", " "))


def target_metadata(path):
    """Read generated wrappers, never execute/evaluate their shell contents."""
    if path.name == "security-scan.sh":
        return {"kind": "security"}
    if path.name == "hosts.sh":
        return {"kind": "discovery", "name": "Discover hosts", "backend": "hosts.sh"}
    if not path.name.startswith("TARGET-"):
        return None
    result = {"kind": "target", "name": function_name(path), "backend": "Unknown"}
    try:
        source = path.read_text(errors="replace")
    except OSError:
        return result
    for line in source.splitlines():
        if not line.strip().startswith("exec "):
            continue
        try:
            tokens = shlex.split(line.strip(), comments=True)
        except ValueError:
            continue
        if len(tokens) < 2 or tokens[1] == "/usr/local/bin/lcd-run":
            continue
        result["backend"] = Path(tokens[1]).name
        if tokens[1] == "/usr/local/bin/host-profile" and len(tokens) > 2:
            if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", tokens[2]):
                result.update(kind="host", ip=tokens[2])
                return result
        if tokens[1] != "/usr/local/bin/ap-find-compact":
            continue
        # Only literal values supported by the verified finder protocol.
        result.update(kind="finder", duration=60, freqs=[], bssids=[])
        args = tokens[2:]
        if args and args[0].isdigit():
            result["duration"] = int(args.pop(0))
        while args:
            value = args.pop(0)
            if value == "--freqs" and args:
                result["freqs"] = [int(f) for f in args.pop(0).split() if f.isdigit()]
            elif re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", value):
                result["bssids"].append(value.upper())
        return result
    return result


def target_instructions(info):
    if info["kind"] == "security":
        return ["Security scan using the existing scan backend.",
                "Elapsed time stays visible while the backend scans.",
                "Network/BLE totals and findings appear when the report is ready.",
                "After completion: Centre opens the device findings list.",
                "Existing SAFE/BOUNDED checks and SSH-only LAB_ONLY gates remain in force."]
    if info["kind"] == "discovery":
        return ["Purpose: find responding devices on the entire wlan0 IPv4 subnet.",
                "Uses nmap -sn host discovery; this does not scan TCP ports.",
                "Only run where you are authorised to scan that whole subnet.",
                "Previous generated host targets are replaced by this discovery.",
                "After completion: Home > Targets > Network Hosts; select an IP.",
                "Run that host profile to inspect its common ports and services.",
                "Zero discovered hosts is not proof the subnet is empty.",
                "Discovery may miss filtered devices; backend errors are suppressed."]
    if info["kind"] == "host":
        ip = info["ip"]
        return [f"Purpose: profile services on {ip} (active network checks).",
                "Checks the 1000 most common TCP ports, not every port or UDP.",
                "Attempts service/version identification and an OS guess.",
                "Nmap timeout: 45s; DNS and follow-up checks can add time.",
                "May read HTTP title/header, HTTPS certificate and SSH banner.",
                "Results identify connection options; they do not grant access.",
                "SSH: use your authorised account; web: inspect http/https if open.",
                "OS/version clues may be uncertain. This is not a vulnerability scan.",
                "Empty output can mean filtering, timeout or scanner failure.",
                "Only run on a host you are authorised to scan."]
    if info["kind"] == "finder":
        return ["Purpose: locate this AP using beacon signal strength.",
                "Radio: wlan1   Runs until Stop in the interactive panel",
                "Frequencies: " + (", ".join(map(str, info["freqs"])) + " MHz" if info["freqs"] else "discovered at start"),
                f"Candidate APs: {len(info['bssids'])}",
                "Move slowly; compare readings with the radio held consistently.",
                "-45 dBm is stronger than -75 dBm; this is not distance.",
                "CLOSER/FARTHER indicates signal change, not guaranteed direction.",
                "NOT-SEEN: no recent target beacons; it does not prove AP is off.",
                "If not seen: move nearer, check wlan1, or rescan Wi-Fi for new channels.",
                "Completion ends the search; Stop ends it early. No ports are tested."]
    return ["Generated target action using the existing backend.",
            f"Backend: {info.get('backend', 'Unknown')}",
            "Read its output for results; COMPLETE means the command exited OK,",
            "not that every check passed. FAILED means a nonzero exit.",
            "Stop cancels the action; Back only leaves its output view.",
            "Use only for targets you are authorised to examine."]


class Panel:
    HOME = ["System", "Tasks", "Network", "Targets", "Security", "PC Recovery", "Game Boy", "Exit"]

    def __init__(self, collector, rom_dir=Path("/mnt/roms"), script_dir=Path("/mnt/scripts")):
        self.collector = collector
        self.rom_dir = rom_dir
        self.script_dir = script_dir
        self.script_group = None
        self.page = "Home"
        self.selected = 0
        self.details = None
        self.running = True
        self.message = ""
        self.game_requested = None
        self.task = Task()
        self.task_end = None
        self.ethernet_scroll = 0

    def items(self, data):
        if isinstance(self.details, str) and self.details in CONTROLS:
            return ["On", "Off", "Refresh status"]
        if isinstance(self.details, dict) and self.page == "Targets":
            links = self.details.get("links", {})
            return ["Track client (until Stop)", "Track probes (until Stop)",
                    *[f"Monitor AP {link['bssid']} CH{link['channel']} (60s)" for link in links.values()], "Return"]
        if isinstance(self.details, Path):
            return ["Run", "Return"]
        if self.page == "Home":
            return self.HOME
        if self.page == "Security Results":
            return [] if self.details is not None else security_devices(self.task.snapshot()["finder"].get("report", {}))
        if self.page == "Network":
            scripts = [p for p in self.script_groups().get("Network", []) if p.stem.lower() != "iperf-toggle"]
            performance = [p for p in scripts if p.stem.lower().startswith("iperf") or p.stem.lower() == "path-test"]
            discovery = [p for p in scripts if p.stem.lower() in ("hosts", "monitor")]
            connections = [p for p in scripts if p not in performance and p not in discovery and p.stem.lower() not in ("wifi", "wifi-health")]
            # WIFI_HEALTH_NETWORK_MENU_H23
            # WIFI_NETWORK_LAYOUT_H24_1
            basic = [p for p in scripts if p.stem.lower() == "wifi"]
            health = [p for p in scripts if p.stem.lower() == "wifi-health"]
            return ["Wi-Fi hardware status", *basic, *health, *connections, *discovery, "Packet Captures", "iperf", *performance]
        if self.page == "Packet Captures":
            order = {name: i for i, name in enumerate(("packet-general", "packet-scan", "packet-beacon", "packet-probes", "packet-stations", "packet-ndp", "packet-eapol", "packet-deauth", "packet-raw"))}
            scripts = sorted(self.script_groups().get("Packet Captures", []), key=lambda p: (order.get(p.stem.lower(), len(order)), p.stem.lower()))
            position = 1 if scripts and scripts[0].stem.lower() == "packet-general" else 0
            return [*scripts[:position], "WAP/client monitor", *scripts[position:]]
        if self.page in FUNCTION_PAGES:
            items=self.script_groups().get(self.page, [])
            if self.page == "Security":
                priority={"security-scan":0,"device-watch":1,"device-history":2}
                items=sorted(items,key=lambda path:(priority.get(path.stem.lower(),3),path.name.lower()))
            return items
        if self.page == "System":
            actions = [path for path in self.script_groups().get("System & Devices", [])
                       if path.stem.lower() not in ("system", "pc-recovery", "vpn-toggle", "console-toggle")]
            vpn = [path for path in actions if path.stem.lower() == "vpn" or path.stem.lower().startswith("vpn-")]
            console = [path for path in actions if path.stem.lower() == "console" or path.stem.lower().startswith("console-")]
            return ["VPN", *vpn, "Console", *console, *[path for path in actions if path not in vpn and path not in console]] + (["Other Tools"] if self.script_groups().get("Other Tools") else [])
        if self.page == "Wi-Fi hardware status":
            if self.details is not None:
                return ["Refresh status"]
            return [d for d in data.get("network", {}).get("devices", []) if d["type"] == "wifi"]
        if self.page == "Services":
            return ["On", "Off", "Refresh status"] if self.details is not None else list(CONTROLS) + self.script_groups().get("Services", [])
        if self.page == "Targets":
            if self.details is not None:
                return ["Run", "Return to scripts"]
            groups = self.script_groups()
            if self.script_group is None:
                return [name for name in groups if groups[name]] + (["Wi-Fi Devices"] if self.task.snapshot()["devices"] else [])
            if self.script_group == "Wi-Fi Devices":
                return sorted(self.task.snapshot()["devices"])
            return groups.get(self.script_group, [])
        if self.page == "Tasks":
            return ["Stop task"] if self.task.snapshot()["state"] == "RUNNING" else []
        if self.page == "Game Boy":
            try:
                return sorted(p for p in self.rom_dir.iterdir()
                              if p.is_file() and p.suffix.lower() in (".gb", ".gbc", ".gba"))
            except OSError:
                return []
        return []

    def script_groups(self):
        groups = {}
        try:
            scripts = sorted(p for p in self.script_dir.iterdir()
                             if p.is_file() and p.suffix == ".sh"
                             and not p.name.startswith(".") and ".pre-" not in p.name)
        except OSError:
            return groups
        for script in scripts:
            category = script_category(script)
            if self.page == "Targets":
                if category != "Targets":
                    continue
                name = script.stem.lower()
                category = ("Cleanup" if name == "target-clean" else
                            "Network Hosts" if name.startswith("target-net-") else
                            "Security Targets" if name.startswith("target-sec-") else
                            "BLE Targets" if name.startswith("target-ble-") else
                            "Wi-Fi Targets" if name.startswith(("target-ap-", "target-ssid-", "target-client-", "target-hidden-")) else "Other Targets")
            elif category == "Targets":
                continue
            groups.setdefault(category, []).append(script)
        order = ("Network Hosts", "Wi-Fi Targets", "BLE Targets", "Security Targets", "Other Targets", "Cleanup") if self.page == "Targets" else SCRIPT_CATEGORIES
        return {name: groups[name] for name in order if name in groups}

    def handle(self, key):
        data = self.collector.snapshot()
        items = self.items(data)
        if self.page == "Security Results" and self.details is not None and key in ("up", "down", "right"):
            self.ethernet_scroll = 0 if key == "right" else max(0, self.ethernet_scroll + (-3 if key == "up" else 3))
            return
        # WIFI_HEALTH_EVIDENCE_H19
        # WIFI_HEALTH_BROWSER_H23
        if self.page == "Tasks" and (self.task.snapshot()["metadata"] or {}).get("kind") == "wifi-health":
            if not hasattr(self, "wifi_navigation"): self.wifi_navigation = wifi_new_navigation()
            # WIFI_AP_MAPPING_H24
            if wifi_navigate(self.task.snapshot(), self.wifi_navigation, key):
                if self.wifi_navigation.get("pending_mapping"): self.message = wifi_apply_mapping(self.wifi_navigation)
                return
        if self.page == "Tasks" and key == "enter" and self.task.snapshot()["state"] != "RUNNING":
            if (self.task.snapshot()["metadata"] or {}).get("kind") == "security" and self.task.snapshot()["finder"].get("report"):
                self.page, self.details, self.selected = "Security Results", None, 0
                self.ethernet_scroll = 0
            if self.task.snapshot()["finder"].get("values", {}).get("mode") == "peers" and self.task.snapshot()["devices"]:
                self.page, self.script_group, self.details, self.selected = "Targets", "Wi-Fi Devices", None, 0
            self.task_end = None
            self.ethernet_scroll = 0
            return
        if self.page == "Tasks" and key in ("up", "down", "right"):
            task = self.task.snapshot()
            if task["metadata"] and task["metadata"].get("kind") in STRUCTURED_KINDS:
                self.ethernet_scroll = 0 if key == "right" else max(0, self.ethernet_scroll + (-3 if key == "up" else 3))
                return
            first = task["count"] - len(task["lines"])
            if key == "right":
                self.task_end = None
            else:
                end = task["count"] if self.task_end is None else self.task_end
                end = max(first + 1, min(task["count"], end + (-3 if key == "up" else 3)))
                self.task_end = None if end >= task["count"] else end
            return
        if key == "quit":
            self.running = False
        elif key == "refresh":
            self.collector.refresh.set()
        elif key in ("left", "back"):
            if self.details is not None:
                self.details = None
                self.selected = 0
                if self.page == "PC Recovery":
                    self.page = "Home"
            elif self.page == "Security Results":
                self.page, self.selected = "Tasks", 0
            elif self.page == "Targets" and self.script_group is not None:
                self.script_group, self.selected = None, 0
            elif self.page in NETWORK_SECTIONS:
                previous = self.page
                self.page = "Network"
                parent_items = self.items(data)
                self.selected = parent_items.index(previous) if previous in parent_items else 0
            elif self.page == "Other Tools":
                self.page, self.selected = "System", 0
            elif self.page != "Home":
                self.page, self.selected = "Home", 0
        elif key in ("up", "down") and items and (self.details is None or self.page in ("Services", "Wi-Fi hardware status", "Targets") or (isinstance(self.details, str) and self.details in CONTROLS) or isinstance(self.details, Path)):
            self.selected = (self.selected + (1 if key == "down" else -1)) % len(items)
        elif key in ("enter", "right") and items:
            self.selected = min(self.selected, len(items) - 1)
            item = items[self.selected]
            if self.page == "Home":
                if item == "Exit":
                    self.running = False
                else:
                    self.page, self.selected = item, 0
                    if item == "PC Recovery":
                        recovery = self.script_dir / "pc-recovery.sh"
                        self.details = recovery if recovery.is_file() else None
                    if item == "Targets":
                        self.script_group = None
            elif (self.page == "Network" and isinstance(item, str) and item in NETWORK_SECTIONS) or (self.page == "System" and item == "Other Tools"):
                self.page, self.selected, self.details = item, 0, None
            elif self.page == "Packet Captures" and item == "WAP/client monitor":
                self.start_task("AP/client traffic overview", ["/usr/local/bin/bh-wifi-peer", "peers"], {"kind":"packet"})
            elif self.page == "Targets" and isinstance(self.details, dict):
                if item == "Return":
                    self.details, self.selected = None, 0
                elif item == "Track client (until Stop)":
                    argv = ["/usr/local/bin/bh-wifi-peer", "client-track", "--station", self.details["station"]]
                    links = list(self.details.get("links", {}).values())
                    if links:
                        argv += ["--channel", str(links[-1]["channel"])]
                    self.start_task("Track client " + self.details["station"], argv, {"kind":"packet"})
                elif item.startswith("Monitor AP "):
                    link = list(self.details["links"].values())[self.selected-2]
                    self.start_task("WAP/client monitor", ["/usr/local/bin/bh-wifi-peer", "pair", "--station", self.details["station"], "--bssid", link["bssid"], "--channel", str(link["channel"])], {"kind":"packet"})
                else:
                    self.start_task("Track " + self.details["station"],
                                    ["/usr/local/bin/bh-probe-reader", "--station", self.details["station"], "--seconds", "0"], {"kind": "packet"})
            elif self.page == "Targets" and self.script_group == "Wi-Fi Devices":
                self.details = self.task.snapshot()["devices"].get(item)
                self.selected = 0
            elif isinstance(self.details, Path):
                if item == "Return":
                    self.details, self.selected = None, 0
                    if self.page == "PC Recovery":
                        self.page = "Home"
                elif self.details.is_file():
                    script = self.details
                    args = ["bh"] if script.name == "wifi.sh" else []
                    self.start_script(script, args)
                else:
                    self.message = "Function no longer available. Return to refresh the list."
            elif self.page == "Game Boy":
                if self.task.snapshot()["state"] == "RUNNING":
                    self.message = "A task is still running. Open Tasks to stop it."
                else:
                    self.game_requested = item
            elif self.page == "Targets" and self.script_group is None:
                self.script_group, self.selected = item, 0
            elif self.page == "Security Results":
                self.details, self.ethernet_scroll = item, 0
            elif self.page == "Tasks":
                self.task.stop()
            elif isinstance(self.details, str) and self.details in CONTROLS:
                if item == "Refresh status":
                    self.collector.refresh.set()
                else:
                    self.start_task(f"{self.details}: {item}", CONTROLS[self.details][item])
            elif self.page == "Wi-Fi hardware status" and self.details is not None:
                if item == "Refresh status":
                    self.collector.refresh.set()
                else:
                    self.start_script(Path("/mnt/scripts/wifi.sh"), ["bh"])
            else:
                self.details = item
                self.selected = 0

    def start_script(self, script, args=()):
        try:
            # CLOVER_DIRECT_ETHERNET_V1
            # DIRECT_ETHERNET_SUMMARY_V2
            if script.name in ("net-direct-test.sh", "net-direct-passive.sh", "net-direct-static.sh"):
                mode = {"net-direct-test.sh": "dhcp", "net-direct-passive.sh": "passive", "net-direct-static.sh": "static"}[script.name]
                self.start_task("Direct Ethernet - " + mode.upper(), ["sudo", "-n", "/usr/local/bin/clover-direct-ethernet", mode], {"kind": "direct-ethernet"})
            elif script.name == "wifi-waterfall.sh":
                self.start_task("Wi-Fi waterfall", ["sudo","-n","/usr/local/bin/wifi-passive-health-panel"], {"kind":"wifi-health"})
            elif script.name == "wifi-health.sh":
                self.start_task("Wi-Fi Health", ["sudo", "-n", "/usr/local/bin/wifi-passive-health-panel"], {"kind": "wifi-health"})
            elif script.name in ("packet-scan.sh", "packet-beacon.sh", "packet-ndp.sh"):
                self.start_task(function_name(script), ["/usr/local/bin/bh-panel-packet-scan", script.stem])
            elif script.name == "packet-probes.sh":
                self.start_task("Probe requests", ["/usr/local/bin/bh-probe-reader", "--seconds", "60"], {"kind": "packet"})
            elif script.name == "packet-general.sh":
                self.start_task("General capture", ["/usr/local/bin/bh-wifi-peer", "peers"], {"kind": "packet"})
            elif script.name in ("packet-deauth.sh", "packet-eapol.sh", "packet-stations.sh", "packet-raw.sh"):
                mode = script.stem.removeprefix("packet-")
                self.start_task(function_name(script), ["/usr/local/bin/bh-panel-packet-live", mode, "60"], {"kind": "packet"})
            elif (target_metadata(script) or {}).get("kind") == "finder":
                info = target_metadata(script)
                info = dict(info, duration=0)
                argv = ["/usr/local/bin/bh-panel-ap-find", "0"]
                if info["freqs"]:
                    argv += ["--freqs", " ".join(map(str, info["freqs"]))]
                argv += info["bssids"]
                self.start_task(function_name(script), argv, info)
            elif script.name == "ethernet.sh":
                backend = Path("/usr/local/bin/ethernet-live")
                if not backend.is_file():
                    self.message = "Ethernet live backend missing: /usr/local/bin/ethernet-live"
                    return
                self.start_task("Ethernet test", script_argv(backend, ["eth0"]), {"kind": "ethernet"})
            else:
                self.start_task(function_name(script), script_argv(script, args), target_metadata(script))
        except (OSError, ValueError) as error:
            self.message = f"Function unavailable: {error}"

    def start_task(self, title, argv, metadata=None):
        # TASK_AUTO_SWITCH_H12
        if self.task.snapshot()["state"] == "RUNNING" or not self.task.stop_complete.is_set():
            self.pending_task = (title, list(argv), metadata)
            self.task.stop()
            self.page, self.details, self.selected = "Tasks", None, 0
            self.message = "Switching to " + title + ": waiting for previous task cleanup."
            return
        started = self.task.start(title, argv, metadata=metadata) if metadata else self.task.start(title, argv)
        if started:
            self.wifi_navigation = wifi_new_navigation()
            self.wifi_selected = 0
            self.wifi_details, self.wifi_source = False, 0
            self.page, self.details, self.selected = "Tasks", None, 0
            self.task_end = None
            self.ethernet_scroll = 0
            self.message = ""
        else:
            self.page, self.details, self.selected = "Tasks", None, 0
            self.message = "A task is already running. Stop it here before starting another."

    def lines(self, data, capacity=30, cols=80):
        pending=getattr(self, "pending_task", None)
        if pending and self.task.snapshot()["state"] != "RUNNING" and self.task.stop_complete.is_set() and not self.task.thread.is_alive():
            self.pending_task=None
            self.start_task(*pending)
        if self.page == "Targets" and isinstance(self.details, dict):
            device = self.details
            identity = identify(device["station"], "Client" if device.get("links") else "Probe transmitter", **{k:v for k,v in device.get("identity",{}).items() if k in ("hostname","model","advertised_vendor")})
            return ["Wi-Fi device: " + device["station"],
                    "Vendor: " + identity['vendor'], "Observed role: " + identity['role'],
                    "Advertised name: " + str(identity.get("name") or "Not supplied"),
                    "Advertised model: " + str(identity.get("model") or "Not supplied"),
                    "Device type: " + identity['device_type'] + " | " + identity['confidence'],
                    identity['address_kind'], *["Evidence: " + clue for clue in identity['evidence']],
                    f"Last capture RSSI: {device.get('rssi') if device.get('rssi') is not None else '--'} dBm (historical)",
                    "Locally administered MAC: " + ("yes; may be randomized" if int(device['station'][:2], 16) & 2 else "no"),
                    "Requested SSIDs: " + ", ".join(device.get("ssids", [])),
                    "Track client uses frames transmitted by this MAC; probe tracking is also available.",
                    "Monitor entries use previously observed AP/channel pairs.",
                    "Silent devices or changed MACs may not be seen.", ""] + [self.mark(i, name) for i, name in enumerate(self.items(data))]

        system = data.get("system", {})
        network = data.get("network", {})
        if isinstance(self.details, Path):
            info = target_metadata(self.details)
            guidance = target_instructions(info) if info else []
            if self.details.name.startswith("TARGET-CLIENT-"):
                compact = self.details.stem.removeprefix("TARGET-CLIENT-")
                if re.fullmatch(r"[0-9A-Fa-f]{12}",compact):
                    address = ":".join(compact[i:i+2] for i in range(0,12,2)).upper()
                    saved = client_metadata(self.details)
                    identity = identify(address,"Historically observed client",**{k:v for k,v in saved.get("identity",{}).items() if k in ("hostname","model","advertised_vendor")})
                    guidance += ["Advertised name: " + str(identity.get("name") or "Not supplied"), "Advertised model: " + str(identity.get("model") or "Not supplied"), "Last capture channel: " + str(saved.get("channel") or "Unknown")]
                    guidance += ["MAC: " + address, "Vendor: " + identity['vendor'],
                                 "Type: " + identity['device_type'], identity['address_kind'],
                                 *["Evidence: " + clue for clue in identity['evidence']]]
            if self.details.name == "ethernet.sh":
                guidance = ["Live Ethernet test on eth0; passive L2 discovery.",
                            "Link/speed/duplex, switch/port/VLANs, traffic and adapter details.",
                            "No IPv4 required for switch discovery; wait for advertisements.",
                            "Observed VLANs and inferred mode are not a full switch config.",
                            "Up/Down scroll details; Centre stops; Back keeps it running."]
            return [function_name(self.details), "", *guidance, "Output appears live in Tasks.",
                    "Long-running tasks can be stopped there.", ""] + [
                        self.mark(i, action) for i, action in enumerate(self.items(data))]
        if isinstance(self.details, str) and self.details in CONTROLS:
            status = data.get("controls", {}).get(self.details, "Checking status...")
            lines = [self.details, "", *status.splitlines(), ""] + [self.mark(i, action) for i, action in enumerate(self.items(data))]
            if self.details == "Console":
                lines += console_preview(data.get("controls", {}).get("serial"), max(0, capacity-len(lines)), cols)
            return lines
        if self.page in FUNCTION_PAGES:
            return [self.mark(i, function_name(p) if isinstance(p, Path) else p) for i, p in enumerate(self.items(data))] or ["No functions available"]
        if self.page == "PC Recovery":
            return ["PC recovery is unavailable: pc-recovery.sh was not found.", "Back: return to Home"]
        if self.page == "Home":
            temperature = system.get("temperature")
            temp = f"{temperature:.0f} C" if temperature is not None else "--"
            return [f"Temperature {temp}     Memory {system.get('memory', 0):.0f}%",
                    f"Uptime {system.get('uptime', 0) / 60:.0f} min     Storage {system.get('disk', 0):.0f}%",
                    ""] + [self.mark(i, item) for i, item in enumerate(self.HOME)]
        if self.page == "System":
            result = ["OVERVIEW", f"Host: {system.get('hostname', '--')}",
                      f"Kernel: {system.get('kernel', '--')}",
                      f"Uptime: {system.get('uptime', 0) / 3600:.1f} hours  |  Memory: {system.get('memory', 0):.0f}%",
                      f"Load: {' / '.join(f'{x:.2f}' for x in system.get('load', (0, 0, 0)))}",
                      f"Memory: {system.get('memory_used_mb', 0):.0f} / {system.get('memory_total_mb', 0):.0f} MB",
                      "", "NETWORK"]
            result += [f"{d['device']}  {d['state']}  IPv4 {d.get('ip', '--')} | {d.get('connection', '--')}"
                       for d in network.get("devices", [])] or ["No interface data"]
            result += ["", "STORAGE", f"Root used: {system.get('disk', 0):.0f}%  |  Free: {system.get('disk_free_gb', 0):.2f} GB",
                       f"Games: {self.rom_dir}", "", "HARDWARE",
                       f"Temperature: {system.get('temperature') if system.get('temperature') is not None else '--'} C  |  CPU: {os.cpu_count()} cores",
                       f"Machine: {os.uname().machine}  Game input: {'Available' if Path('/dev/uinput').exists() else 'Unavailable'}"]
            actions = self.items(data)
            if actions:
                result += ["", "SYSTEM ACTIONS"] + [self.mark(i, function_name(item) if isinstance(item, Path) else item) for i, item in enumerate(actions)]
            return result
        if self.page == "Wi-Fi hardware status":
            if self.details is None:
                return [self.mark(i, function_name(d) if isinstance(d, Path) else f"{d['device']}  {d['state']}\n   {d['connection']}  {d['ip']}")
                        for i, d in enumerate(self.items(data))] or ["No Wi-Fi interfaces found"]
            name = self.details["device"]
            device = next((d for d in network.get("devices", []) if d["device"] == name), self.details)
            rows = [f"Interface  {name}", f"State      {device['state']}",
                    f"Connection {device['connection']}", f"IPv4       {device['ip']}", "", "Nearby networks"]
            rows += [f"{'*' if n['active'] == '*' else ' '} {n['ssid'] or '(hidden)'}  {n['signal']}%  {n['security']}"
                     for n in network.get("networks", []) if n["device"] == name]
            # Actions stay visible even when there are many cached networks.
            return rows[:18] + [""] + [self.mark(i, function_name(name) if isinstance(name, Path) else name) for i, name in enumerate(self.items(data))]
        if self.page == "Services":
            if self.details is None:
                return [self.mark(i, function_name(name) if isinstance(name, Path) else name) for i, name in enumerate(self.items(data))]
            status = data.get("controls", {}).get(self.details, "Checking status...")
            return [self.details, "", *status.splitlines()[:18], ""] + [self.mark(i, action)
                    for i, action in enumerate(self.items(data))]
        if self.page == "Security Results":
            if self.details is None:
                return ["Select a device for findings and recommended actions.", ""] + [
                    self.mark(i, f"{host.get('transport','LAN')} {host.get('address') or host.get('ip','--')} {host.get('hostname') or host.get('ssid') or host.get('name') or ''}  {len(host.get('findings', []))} findings")
                    for i, host in enumerate(self.items(data))]
            rows = security_host_lines(self.details)
            wrapped = [part for row in rows for part in (textwrap.wrap(safe_text(row), width=max(20, cols-1)) or [""])]
            space = max(1, capacity-1)
            self.ethernet_scroll = min(self.ethernet_scroll, max(0, len(wrapped)-space))
            offset = self.ethernet_scroll
            return [f"Details {offset+1}-{min(offset+space, len(wrapped))}/{len(wrapped)} | Up/Down: scroll"] + wrapped[offset:offset+space]
        if self.page == "Tasks":
            task = self.task.snapshot()
            if (task["metadata"] or {}).get("kind") == "direct-ethernet":
                from direct_ethernet_view import view as direct_view
                return direct_view(task, self.task_end, capacity, cols)
            prefix = [task["title"], f"{task['state']}   {task['elapsed']:.0f}s",
                      "> Centre: stop task" if task["state"] == "RUNNING" else "Task finished; Centre/Right: latest output"]
            info, finder = task["metadata"], task["finder"]
            if info and info.get("kind") == "wifi-health":
                self.wifi_navigation = getattr(self, "wifi_navigation", wifi_new_navigation())
                return wifi_report(task, self.wifi_navigation, max(1, cols - 1), capacity)
            if info and info["kind"] in STRUCTURED_KINDS:
                rows = (ethernet_lines(task) if info["kind"] == "ethernet" else
                        packet_lines(task, width=max(20, cols - 1)) if info["kind"] == "packet" else security_lines(task))
                if finder.get("values", {}).get("mode") == "peers" and task["state"] != "RUNNING" and task["devices"]:
                    prefix[2] = "> Centre: select client   Right: top"
                if info["kind"] == "security" and task["state"] != "RUNNING" and finder.get("report"):
                    prefix[2] = "> Centre: select device   Right: top"
                wrapped = []
                for line in rows:
                    wrapped.extend(textwrap.wrap(safe_text(line), width=max(20, cols - 1)) or [""])
                space = max(1, capacity - len(prefix) - 1)
                self.ethernet_scroll = min(self.ethernet_scroll, max(0, len(wrapped) - space))
                offset = self.ethernet_scroll
                return prefix + [f"Details {offset + 1}-{min(offset + space, len(wrapped))}/{len(wrapped)} | Up/Down: scroll"] + wrapped[offset:offset + space]
            if info and info["kind"] == "finder":
                status = finder.get("status", "SEARCHING")
                prefix += [f"Beacon finder | wlan1 | {status}",
                           f"Locked AP: {finder.get('bssid', '--')}  MHz: {finder.get('freq', '--')}",
                           f"Last signal: {finder.get('signal', '--')} dBm  {finder.get('quality', '')}",
                           f"Best observed: {finder.get('best', '--')} dBm  " + ("Until Stop" if info.get("duration") == 0 else f"Remaining: {finder.get('remaining', '--')}s"),
                           f"Trend: {finder.get('trend', '--')} (signal trend, not distance)",
                           "Move slowly; less-negative dBm is stronger.",
                           "NOT-SEEN: check position/radio; rescan Wi-Fi for changed channels."]
                if status != "TRACKING" or task["state"] != "RUNNING":
                    prefix += ["Signal shown is historical, not a current measurement."]
                if task["state"] == "COMPLETE":
                    prefix += ["Search ended: " + ("beacons were observed." if "best" in finder else "no valid target signal observed.")]
                elif task["state"] == "CANCELLED":
                    prefix += ["Stopped by user; observations are partial."]
            elif info and info["kind"] == "discovery":
                prefix += ["Host discovery (not a port scan)",
                           f"Subnet: {finder.get('network', '--')}  Stage: {finder.get('status', '--')}",
                           f"Devices reported: {finder.get('reported', finder.get('found', 0))}",
                           "Next: Home > Targets > Network Hosts > choose IP > Run",
                           "Filtered devices may be missed; scan errors are suppressed."]
                if task["state"] == "CANCELLED":
                    prefix += ["Stopped early; the target list may be incomplete."]
            elif info and info["kind"] == "host":
                prefix += [f"Host: {info['ip']}  Stage: {finder.get('status', '--')}",
                           "Scope: common 1000 TCP ports; service detection / OS guess"]
                for key, label in (("name", "Name"), ("mac", "MAC"), ("os", "OS clue"),
                                   ("web", "Web title"), ("http", "HTTP server"),
                                   ("tls", "TLS name"), ("ssh", "SSH banner")):
                    if key in finder:
                        prefix.append(f"{label}: {finder[key]}")
                ports = finder.get("ports", [])
                prefix += [f"Open TCP ports reported: {len(ports)}"]
                prefix += [f"{port}/tcp  {service}  {version}" for port, service, version in ports[:5]]
                if len(ports) > 5:
                    prefix.append("More ports in scrollable output below.")
                numbers = {p[0] for p in ports}
                if 22 in numbers:
                    prefix.append(f"SSH: ssh <your-user>@{info['ip']} (authorised account required)")
                if 80 in numbers or 443 in numbers:
                    scheme = "https" if 443 in numbers else "http"
                    prefix.append(f"Web: {scheme}://{info['ip']}/")
                if 3389 in numbers:
                    prefix.append(f"RDP: Remote Desktop > {info['ip']} (authorised login)")
                if finder.get("empty_report"):
                    prefix += ["No ports reported: INCONCLUSIVE (timeout/filter/error possible)."]
                if task["state"] == "COMPLETE":
                    prefix.append("Backend ended; completion does not guarantee scan success.")
                elif task["state"] == "CANCELLED":
                    prefix.append("Stopped by user; port results may be incomplete.")
            first = task["count"] - len(task["lines"])
            end = task["count"] if self.task_end is None else max(first + 1, min(task["count"], self.task_end))
            mode = "FOLLOW LIVE" if self.task_end is None else "REVIEW (Right: latest)"
            prefix += [f"{mode} | history through line {end}/{task['count']} (last 2000 retained)"]
            history = task["lines"][:max(0, end - first)]
            wrapped = []
            for line in history:
                line = compact_beacon_line(line) if task["title"] in ("Beacons", "Packet scan") else line
                wrapped.extend(textwrap.wrap(safe_text(line), width=max(20, cols - 1)) or [""])
            space = max(1, capacity - len(prefix))
            return prefix + wrapped[-space:]
        if self.page == "Targets":
            if self.details is not None:
                return [self.details.name, "", "Output appears live in Tasks.",
                        "Long-running tasks can be stopped there.", ""] + [
                            self.mark(i, action) for i, action in enumerate(self.items(data))]
            items = self.items(data)
            if self.script_group is None:
                groups = self.script_groups()
                return [self.mark(i, f"{name} ({len(self.task.snapshot()['devices']) if name == 'Wi-Fi Devices' else len(groups[name])})")
                        for i, name in enumerate(items)] or ["No devices listed. Run Packet Captures > Probe requests; targets last until the panel closes." if self.page == "Targets" and self.script_group == "Wi-Fi Devices" else "No targets generated yet. Run Network > hosts or Wi-Fi scan." if self.page == "Targets" else "No scripts found in " + str(self.script_dir)]
            return [self.mark(i, function_name(p) if isinstance(p, Path) else client_label(p,self.task.snapshot()["devices"].get(p,{}))) for i, p in enumerate(items)] or ["Run Packet Captures > General capture or Probe requests to collect device targets." if self.script_group == "Wi-Fi Devices" else "No functions in this category"]
        if self.page == "Game Boy":
            return [self.mark(i, p.name) for i, p in enumerate(self.items(data))] or ["No games found in /mnt/roms"]
        return []

    def mark(self, index, text):
        row=("> " if index == self.selected else "  ") + text
        if hasattr(self,'_action_rows'): self._action_rows.add(safe_text(row))
        return row


def counter_columns(entries, width):
    """Fit short count entries across the available width without truncation."""
    if not entries:
        return []
    cell = max(len(entry) for entry in entries) + 3
    columns = max(1, min(3, width // cell))
    return ["".join(entry.ljust(cell) for entry in entries[i:i + columns]).rstrip()
            for i in range(0, len(entries), columns)]


def packet_lines(task, width=79):
    values = task["finder"].get("values", {})
    if not values:
        return ["Waiting for capture state...", *task["lines"]]
    final = values.get("state") in ("COMPLETE", "STOPPED", "CANCELLED")
    title = "FINAL RESULTS" if final else "LIVE CAPTURE" if task["state"] == "RUNNING" else "PARTIAL RESULTS (capture stopped)"
    rows = [title + (" | Stopped by user" if values.get("state") in ("STOPPED", "CANCELLED") else ""), f"Radio: {values.get('interface', '--')}  Profile: {values.get('mode', values.get('profile', '--'))}",
            f"Frames: {values.get('frames', 0)}  Rate: {values.get('rate', 0)}/s",
            f"Captured: {values.get('elapsed', 0)}s  " + ("No time limit; Centre: Stop" if values.get("remaining") is None and task["state"] == "RUNNING" else "Stopped; final elapsed time above" if values.get("remaining") is None else f"Remaining: {values.get('remaining')}s")]
    if task["state"] == "RUNNING" and time.monotonic()-task["finder"].get("received", 0) > 3:
        rows += ["Updates stale; counts below are the last received snapshot."]
    for label, field in (("Frame classes", "classes"), ("Frame types", "types"), ("Observed channels", "channels")):
        if values.get(field):
            rows += ["", label] + counter_columns([f"{key}: {count}" for key, count in sorted(values[field].items(), key=lambda pair: -pair[1])], width)
    mode = values.get("mode")
    def device_label(address,role):
        evidence = values.get("identities",{}).get(address,{})
        return identity_summary(address,role,**{k:v for k,v in evidence.items() if k in ("hostname","model","advertised_vendor")})
    if mode == "probes":
        rows += ["", f"Stations: {values.get('stations', 0)}  Requested SSIDs: {values.get('ssids', 0)}",
                 "Probe requests show sought networks, not a confirmed connection.",
                 "Station/SSID collection limit reached; results are partial." if values.get("limited") else "All collected station/SSID pairs." if values.get("full_rows") else "Backend supplies the busiest 12 station/SSID pairs.",
                 "Next: Home > Targets > Wi-Fi Devices > select address > Track probes."]
        for item in values.get("rows", []):
            rows += [f"{item.get('station', '--')}  {item.get('rssi') if item.get('rssi') is not None else '--'} dBm",
                     f"  SSID: {item.get('ssid', '--')}  Probes: {item.get('count', 0)}",
                     "  " + device_label(item.get('station'), 'Probe transmitter')]
    elif mode == "peers":
        rows += ["", f"AP/client traffic overview | {len(values.get('aps',[]))} APs | {len(values.get('rows',[]))} pairs",
                 f"Interaction frames: {values.get('pair_frames',0)} | Saved client targets: {values.get('targets_generated',0)}",
                 "Channel hopping: traffic totals cover only frames heard while visiting each channel."]
        if values.get("warning"):
            rows += ["WARNING: " + values["warning"]]
        if not values.get("rows"):
            rows += ["No client interactions observed; no new client targets can be generated."]
        else:
            rows += ["Centre after capture: select client. Targets > Wi-Fi Devices or Wi-Fi Targets."]
        for ap in values.get("aps",[]):
            rows += [f"AP {ap.get('bssid')} | {ap.get('ssid')} | CH{ap.get('channel')} | {ap.get('rssi') if ap.get('rssi') is not None else '--'} dBm", "  " + device_label(ap.get('bssid'), 'AP')]
        elapsed = max(1,values.get("elapsed",1))
        for item in values.get("rows", []):
            rows += ["", f"AP {item.get('bssid')} <-> Client {item.get('station')} | CH{item.get('channel')}",
                     "  AP: " + device_label(item.get('bssid'), 'AP'),
                     "  Client: " + device_label(item.get('station'), 'Client')]
            for label,key in (("WAP -> CLIENT","ap_to_client"),("CLIENT -> WAP","client_to_ap")):
                direction = item.get("directions",{}).get(key,{})
                retry = round(direction.get('retries',0)*100/direction['retry_known'],1) if direction.get('retry_known') else '--'
                mbps = round(direction.get('data_bytes',0)*8/elapsed/1e6,3)
                rows += [label, f"  Frames {direction.get('frames',0)} | Bytes {direction.get('bytes',0)} | Captured avg {mbps} Mbps",
                         f"  Retry marked {retry}% | Last TX {direction.get('rssi') if direction.get('rssi') is not None else '--'} dBm",
                         "  Types: " + (", ".join(f"{name} {count}" for name,count in direction.get('types',{}).items()) or '--'),
                         "  Data PHY Mbps (frames): " + (", ".join(f"{rate} ({count})" for rate,count in direction.get('phy',{}).items()) or 'Not supplied')]
                if direction.get('missing_lengths'):
                    rows += ["WARNING: Byte totals incomplete; some lengths unavailable."]
        rows += ["", "Captured Mbps includes headers/retries; not download/upload throughput."]
        if values.get("diagnostics"):
            rows += ["Capture diagnostics:", *values['diagnostics']]
    elif mode == "pair":
        rows += ["", f"WAP {values.get('bssid')} | Client {values.get('station')}", f"Locked CH{values.get('channel')}",
                 "AP: " + device_label(values.get('bssid'),'AP'),
                 "Client: " + device_label(values.get('station'),'Client')]
        for label,key in (("WAP -> CLIENT","ap_to_client"),("CLIENT -> WAP","client_to_ap")):
            direction = values.get("directions", {}).get(key,{})
            rows += ["", label, f"Frames {direction.get('frames',0)} | Captured bytes {direction.get('bytes',0)}",
                     f"Observed data Mbps: {direction.get('mbps',0)} live | {direction.get('average_mbps',0)} average",
                     f"Retry marked: {direction.get('retry_percent') if direction.get('retry_percent') is not None else '--'}% | Last TX signal {direction.get('rssi') if direction.get('rssi') is not None else '--'} dBm"]
            rows += counter_columns([f"{name}: {count}" for name,count in direction.get("types",{}).items()],width)
            rows += ["Data PHY Mbps (frames): " + (", ".join(f"{rate} ({count})" for rate,count in direction.get("phy",{}).items()) or "Not supplied by adapter")]
            if direction.get("missing_lengths"):
                rows += ["WARNING: Some frame lengths unavailable; byte totals incomplete."]
        rows += ["", "Observed data includes Wi-Fi headers and retries; not application throughput.",
                 "Encrypted payload/application types remain unknown. Missing frames affect totals.",
                 "ACK/CTS without a transmitter address cannot be assigned to a direction.",
                 "Channel width/PHY support limits what this adapter can capture."]
    elif mode == "client-track":
        rows += ["", f"Client {values.get('station')} | {values.get('tracking','SEARCHING')}",
                 device_label(values.get('station'),'Transmitter'),
                 f"Signal {values.get('signal') if values.get('signal') is not None else '--'} dBm | {values.get('trend','WAITING')}",
                 f"CH{values.get('channel') or '--'} | Best on channel {values.get('best') if values.get('best') is not None else '--'} dBm",
                 f"Last transmitted frame: {values.get('age') if values.get('age') is not None else '--'}s ago",
                 "Follows recently heard channel; searches again when client is quiet.",
                 "Client-transmitted frames only; AP signal never counts as client signal.",
                 "Move slowly; less-negative signal is stronger. Trend compares the same channel.",
                 "Signal is not a distance/location fix. Sleeping or changed-MAC clients may vanish."]
    elif mode == "device-track":
        rows += ["", f"Device: {values.get('station', '--')}  {values.get('tracking', 'SEARCHING')}",
                 device_label(values.get('station'),'Probe transmitter'),
                 f"Current signal: {values.get('signal') if values.get('signal') is not None else '--'} dBm",
                 f"Channel: {values.get('channel', '--')}  Best on channel: {values.get('best') if values.get('best') is not None else '--'} dBm",
                 f"Last probe age: {values.get('age') if values.get('age') is not None else '--'}s",
                 "RSSI uses only probe frames transmitted by this station.",
                 "Move slowly; less-negative dBm is stronger. RSSI is not distance.",
                 "SEARCHING/NOT-SEEN: device is silent, out of range, on another channel, or changed MAC."]
    elif mode == "stations":
        rows += ["", f"Stations: {values.get('stations', 0)}  APs: {values.get('aps', 0)}", "Busiest 12 stations reported by backend."]
        for item in values.get("rows", []):
            rows += [f"{item.get('station', '--')}  Frames: {item.get('frames', 0)}",
                     f"  AP: {item.get('bssid', '--')}  CH: {item.get('channel', '--')}  RSSI: {item.get('rssi', '--')}",
                     "  Client: " + device_label(item.get('station'),'Client'),
                     "  AP: " + device_label(item.get('bssid'),'AP')]
    elif mode == "deauth":
        rows += ["", f"Deauth: {values.get('deauth', 0)}  Disassociation: {values.get('disassoc', 0)}", "Observed frames do not by themselves establish an attack."]
        for item in values.get("rows", []):
            rows += [f"{item.get('kind', '--')}  Count: {item.get('count', 0)}  Reason: {item.get('reason', '--')}",
                     f"  Source: {item.get('source', '--')}  Destination: {item.get('dest', '--')}", f"  AP: {item.get('bssid', '--')}"]
    elif mode == "eapol":
        rows += ["", f"EAPOL: {values.get('eapol', 0)}  Pairs: {values.get('pairs', 0)}  PMKID observations: {values.get('pmkid', 0)}",
                 "Observations do not confirm a complete handshake or credentials."]
        for item in values.get("rows", []):
            rows += [f"AP: {item.get('ap', '--')}  Client: {item.get('client', '--')}", f"  Count: {item.get('count', 0)}  PMKID observed: {item.get('pmkid', False)}"]
    elif mode == "raw":
        rows += ["", f"Capture path: {values.get('path', '--')}", f"Reported size: {values.get('bytes', 0)} bytes", "A path alone does not confirm a successful capture file."]
    if values.get("dropped") or values.get("limited"):
        rows += [f"WARNING: Partial capture; queue drops {values.get('dropped',0)}, collection limit {values.get('limited',False)}"]
    rows += ["", *task["lines"][-6:]]
    return rows


def security_devices(report):
    result=[]
    for transport,key,address in (('LAN','hosts','ip'),('Wi-Fi','wifi_devices','bssid'),('BLE','ble_devices','mac')):
        result.extend(dict(device,transport=transport,address=device.get(address)) for device in report.get(key,[]))
    return result


def security_host_lines(host):
    if host.get('transport') in ('Wi-Fi','BLE'):
        rows=[host['transport']+' security observations',str(host.get('ssid') or host.get('name') or '<unnamed>'),str(host.get('address') or '--')]
        if host.get('frequency'):rows.append('Frequency: '+str(host['frequency'])+' MHz')
        if host.get('signal_dbm') is not None:rows.append('Signal: '+str(host['signal_dbm'])+' dBm')
        for key,value in (host.get('advertised') or {}).items():
            if value is not None:rows.append(key.replace('_',' ')+': '+str(value))
        if host.get('uuids'):rows.append('Advertised services: '+', '.join(host['uuids']))
        for finding in host.get('findings',[]):
            rows+=['',str(finding.get('severity','INFO'))+' '+str(finding.get('title') or finding.get('code') or '')]
            if finding.get('evidence'):rows.append(str(finding['evidence']))
            validation=finding.get('validation') or {}
            if validation:rows.append(str(validation.get('status',''))+' · '+str(validation.get('test','')))
            if finding.get('action'):rows.append('Action: '+str(finding['action']))
        return rows
    identity = identify(host.get('mac'),hostname=host.get('hostname'),model=host.get('model'))
    rows = [f"Device: {host.get('ip', '--')}  {host.get('hostname') or ''}",
            f"MAC: {host.get('mac') or '--'}  Vendor: {host.get('vendor') or identity['vendor']}",
            "Device type: " + identity['device_type'],
            "Advertised model: " + str(identity.get('model') or 'Not supplied')]
    for finding in host.get("findings", []):
        rows += ["", f"{finding.get('severity', '--')} | {finding.get('title') or finding.get('code', '--')}",
                 f"Confidence: {finding.get('confidence') or 'Not supplied'}"]
        validation=finding.get('validation')
        if isinstance(validation,dict):
            rows += ["Validation: "+str(validation.get('status','')), "Test: "+str(validation.get('test',''))]
            if validation.get('reason'): rows.append(str(validation['reason']))
        for key, label in (("cve", "CVE"), ("cvss", "CVSS"), ("code", "Code"), ("validation", "Validation"), ("validation_status", "Validation status"), ("evidence", "Evidence"), ("action", "Recommended action")):
            value = finding.get(key)
            if key=="validation" and isinstance(value,dict): continue
            if value is not None and value != "":
                rows += [f"{label}: {json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else value}"]
        known = {"severity", "title", "confidence", "cve", "cvss", "code", "validation", "validation_status", "evidence", "action"}
        for key, value in finding.items():
            if key not in known and value is not None and value != "":
                rows += [f"{key.replace('_', ' ').capitalize()}: {json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else value}"]
        if not any("validat" in key and value for key, value in finding.items()):
            rows += ["Validation outcome not supplied; a CVE/version match is not proof of exploitability."]
    return rows + (["No findings reported for this device."] if not host.get("findings") else [])


def security_lines(task):
    data = task["finder"]
    summary = data.get("summary")
    stage = data.get("stage", "Starting") if task["state"] == "RUNNING" else task["state"]
    rows = [f"Stage: {stage}"]
    if data.get("error"):
        rows += [f"Error: {data['error']}"]
    if not summary:
        return rows + ["Backend scanning; detailed progress is not emitted by this wrapper.",
                       "Elapsed time is shown above. Results appear when scanning finishes.", *task["lines"][-6:]]
    rows += [f"Network devices: {summary.get('network_devices', 0)}  BLE devices: {summary.get('ble_devices', 0)}",
             "  ".join(f"{sev}: {summary.get('counts', {}).get(sev, 0)}" for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")),
             f"Target: {summary.get('target') or '--'}", "", "DEVICE FINDINGS"]
    for item in data.get("attention", []):
        rows += [f"{item.get('ip', '--')}  {item.get('hostname') or ''}  {item.get('top_severity', '--')}",
                 f"  {item.get('top_title') or item.get('top_code') or '--'}",
                 f"  Action: {item.get('top_action') or 'Not supplied'}"]
    if not data.get("attention"):
        rows += ["No device findings emitted."]
    rows += ["", "Centre after completion: choose device and inspect all findings.", *task["lines"][-6:]]
    return rows


def ethernet_lines(task):
    state = task["finder"]
    values = state.get("values", {})
    def value(key, missing="Unknown"):
        result = values.get(key)
        return str(result) if result is not None and result != "" and result != "--" else missing
    age = time.monotonic() - state["received"] if "received" in state else None
    live = "Waiting for first update" if age is None else f"Last update {max(0, age):.1f}s ago"
    if age is not None and age > 3 and task["state"] == "RUNNING":
        live += " | STALE STREAM"
    if task["state"] != "RUNNING":
        live += " | FINAL SNAPSHOT (not live)"
    link = value("link", "Checking")
    stale = bool(values.get("stale"))
    identity = "LAST SEEN (cable disconnected)" if stale else "Current observations"
    rows = [live,
            f"LINK       {value('interface', 'eth0')} | {link} | {value('speed')} | {value('duplex')} duplex",
            f"IPv4       {value('ip', 'Not assigned')}",
            f"Live rate  RX {value('rx_rate')} | TX {value('tx_rate')}",
            "", f"SWITCH / L2 | {identity}",
            f"Switch     {value('switch', 'Waiting for LLDP/CDP' if link == 'UP' else 'Unknown')}",
            f"Port       {value('port')}",
            f"Description {value('port_desc')}",
            f"Model      {value('platform')}",
            f"Management {value('mgmt')}",
            f"Port mode  {value('mode')} | Native VLAN {value('native_vlan')}",
            f"VLANs seen {value('vlans')}",
            f"Protocols  {value('protocols')}",
            "* Port mode inferred; observed VLAN list may be incomplete.",
            "", "TRAFFIC / ADAPTER",
            f"RX total   {value('rx_total')} | {value('rx_packets')} packets",
            f"TX total   {value('tx_total')} | {value('tx_packets')} packets",
            f"Errors     {value('errors')} | Drops {value('drops')}",
            f"Adapter    {value('adapter')} | Driver {value('driver')}",
            f"Firmware   {value('firmware')}"]
    lacp_keys = ('lacp', 'partner', 'lacp_system', 'lacp_port', 'lacp_key')
    if any(value(key) != "Unknown" for key in lacp_keys):
        rows += [f"LACP       {value('lacp')} | Partner {value('partner')}",
                 f"LACP peer  {value('lacp_system')} | Port {value('lacp_port')} | Key {value('lacp_key')}"]
    else:
        rows += ["LACP       Not observed"]
    rows += [f"Cable TDR  {value('tdr')} | PoE: Not reported",
             "Passive discovery; LLDP/CDP advertisements may take time."]
    if task["state"] == "FAILED" or not values:
        rows += ["", *task["lines"][-5:]]
    return rows


def compact_beacon_line(line):
    """Remove table padding while preserving beacon identifiers and measurements."""
    match = re.fullmatch(
        r"\s*(.*?)((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\s+"
        r"(.+?)\s+(\d+)\s+(-?\d+)\s*dBm\s+Wi-?Fi\s*([4-7])\s*(.*?)\s*",
        str(line), re.IGNORECASE,
    )
    if not match:
        return line
    prefix, bssid, ssid, channel, signal, generation, extra = match.groups()
    fields = [prefix.strip(), bssid, ssid.strip(), f"CH{channel}",
              f"{signal}dBm", f"Wi-Fi{generation}", extra.strip()]
    return " ".join(field for field in fields if field)


def safe_text(text):
    return "".join(c for c in str(text) if c.isprintable() or c == "\n")


def network_header(data):
    devices = data.get("network", {}).get("devices", [])
    physical = [d for d in devices if d.get("type") in ("wifi", "ethernet")]
    connected = [d for d in physical if d.get("state") == "connected"]
    device = next((d for d in connected if d.get("device") == "wlan0"),
                  next(iter(connected), next(iter(physical), None)))
    vpn = any(d.get("type") in ("tun", "wireguard") and d.get("ip", "--") != "--"
              for d in devices)
    if device is None:
        return "Network: checking" if "network" not in data else "Network: no physical interface"
    return (f"{device['device']}  {device['state']}  IPv4 {device.get('ip', '--')}  "
            f"VPN {'ON' if vpn else 'OFF'}", f"Connection: {device.get('connection', '--')}")


# Apply colour only after sanitising, wrapping and clipping visible text.
# The underlying content and layout are unchanged; selection remains legible.
DETAIL_TOKENS = re.compile(
    r"(?P<address>(?:[0-9A-F]{2}:){5}[0-9A-F]{2}|\b(?:\d{1,3}\.){3}\d{1,3}\b|\bCVE-\d{4}-\d+\b|\b(?:Te|Gi|Tw|Fa|Eth)\d+(?:/\d+){1,3}\b)"
    r"|(?P<signal>-?\d+(?:\.\d+)?\s*dBm\b)"
    r"|(?P<error>\b(?:CRITICAL|HIGH|FAILED|ERROR|Traceback)\b)"
    r"|(?P<warning>\b(?:MEDIUM|LOW|WARNING|CANCELLED|PARTIAL|WEAKER|WEAK|SEARCHING|SCANNING|STALE|NOT-SEEN|DISCONNECTED|OFFLINE|MISSING|DISABLED|Disabled|OFF)\b)"
    r"|(?P<healthy>\b(?:COMPLETE|COMPLETED|FINAL|CONNECTED|STRONG|GOOD|STEADY|STRONGER|TRACKING|READY|OK|ON|UP|ENABLED|Enabled)\b)"
    r"|(?P<info>\b(?:INFO|LIVE|RUNNING|ANALYZING)\b)"
    r"|(?P<attention>\b(?:NEEDS ATTENTION|Needs attention|POSSIBLE|Possible|UNCONFIRMED|Unconfirmed|Not supplied|not supplied|Not assigned|Not observed|UNSUPPORTED)\b)"
    r"|(?P<number>\b\d+(?:\.\d+)?(?:%|\s*(?:MB|GB|G|M|C|s|ms))?(?![\w.]))",
)


def console_preview(ports, capacity, cols):
    lines = ["", "SERIAL OUTPUT | Shared session; LCD view only"]
    if ports is None:
        return (lines + ["Serial service unavailable"] )[:capacity]
    if not ports:
        return (lines + ["No attached serial session"] )[:capacity]
    ports = sorted(ports, key=lambda port: not port.get("active"))
    remaining = max(0, capacity-2)
    for index, port in enumerate(ports):
        share = remaining // (len(ports)-index)
        if share<2:
            break
        heading = f"{port['port']} | {port['baud']} baud | Serial sessions: {port['sessions']}"
        state = "LIVE" if port.get("active") else "DETACHED | Last output"
        counts = f"{state} | RX {port['rx']} B | TX {port['tx']} B"
        output = [piece for line in port.get("output", "").splitlines()
                  for piece in textwrap.wrap(line, width=max(1, cols-1), replace_whitespace=False) or [""]]
        if not output:
            output = ["Waiting for serial output" if port.get("active") else "No serial output received"]
        lines += [heading, counts] + (output[-(share-2):] if share>2 else [])
        remaining -= min(share, 2+len(output))
    return lines[:capacity]


def colour_details(text, base="\x1b[0m", quiet_numbers=False):
    ble_confidence = bool(re.match(r'^(?:HIGH \d+ \||(?:HIGH|LIKELY|POSSIBLE|INFO)\s{2,}|TARGET-BLE-)',text))
    field = re.match(r"^(\s*(?:User|Username|Password|SSH(?: RX| TX| links| connections| login)?|Session|Email)\s*:\s*)(.*)$", text)
    if field:
        prefix, value = field.groups()
        label = prefix.strip().split(":", 1)[0].strip()
        code = "1;35" if label == "Password" else "1;36"
        if label in ("Session", "SSH login"):
            code = "1;32" if value.strip() == "ACTIVE" else "1;33"
        if label == "Email":
            code = "1;32" if value.startswith("SENT") else "1;31" if value.startswith("FAILED") else "1;33"
        return prefix + "\x1b[" + code + "m" + value + base
    if text.startswith("SWITCH / L2 |") or text == "TRAFFIC / ADAPTER":
        return "\x1b[1;36m" + text + base
    if text.strip() in ("WAP -> CLIENT", "CLIENT -> WAP"):
        return ("\x1b[1;36m" if text.strip() == "WAP -> CLIENT" else "\x1b[1;35m") + text + base
    def paint(match):
        kind = match.lastgroup
        code = {"address": "1;36", "error": "1;31", "warning": "1;33",
                "healthy": "1;32", "info": "1;36", "number": "1;36", "attention": "1;33"}.get(kind)
        if kind == 'number' and quiet_numbers: code='97'
        if ble_confidence and match.group() in ('HIGH','LIKELY','POSSIBLE','INFO'):
            code={'HIGH':'1;36','LIKELY':'1;35','POSSIBLE':'1;33','INFO':'97'}[match.group()]
        if kind == "signal":
            value = float(re.match(r"-?\d+(?:\.\d+)?", match.group()).group())
            code = "1;32" if value >= -60 else "1;33" if value >= -75 else "1;31"
        return "\x1b[" + code + "m" + match.group() + base
    coloured = DETAIL_TOKENS.sub(paint, text)
    for label in ("Recommended action:", "Action:", "Evidence:", "Validation status:", "Confidence:"):
        if text.lstrip().startswith(label):
            coloured = coloured.replace(label, "\x1b[1;35m" + label + base, 1)
    for label in ('BLE  :','WiFi :','BLE services:'):
        if text.startswith(label): coloured=coloured.replace(label,'\x1b[1;36m'+label+base,1)
    if text.startswith('DEVICE HISTORY:'):
        coloured=coloured.replace('DEVICE HISTORY:','\x1b[1;35mDEVICE HISTORY:'+base,1)
    if text.startswith('History:'):
        coloured=coloured.replace('History:','\x1b[1;35mHistory:'+base,1)
        for phrase,code in (('appeared','1;32'),('not seen in this scan','1;33'),('SSID changed','1;33')):
            if phrase in text: coloured=coloured.replace(phrase,'\x1b['+code+'m'+phrase+base,1)
    return coloured


def render(panel, rows=40, cols=80):
    data = panel.collector.snapshot()
    age = max(0, time.time() - data.get("updated", 0)) if data.get("updated") else None
    state = f"LIVE {age:.0f}s" if age is not None and age < 10 else "CHECKING"
    heading = f"{panel.page} / {panel.script_group}" if panel.page == "Targets" and panel.script_group else panel.page
    header = f"CloverKit {heading}"
    summary = network_header(data)
    if isinstance(summary, str):
        summary = (summary, "")
    # CLOVER_COMPACT_LAYOUT_V1
    import textwrap
    width=max(1,cols-1)
    lines = [header, *summary, "-" * width]
    content = []
    panel._action_rows=set()
    for line in panel.lines(data, max(1, rows - 8), cols):
        content.extend(safe_text(line).splitlines() or [""])
    if panel.details is None and panel.page in ("Services", "Game Boy", "Wi-Fi hardware status", "Targets", "Security Results", *FUNCTION_PAGES):
        per_item = 2 if panel.page == "Wi-Fi hardware status" else 1
        offset = max(0, panel.selected * per_item - (rows - 10))
        content = content[offset:]
    if panel.page == "System" and panel.details is None:
        selected_row = next((i for i, row in enumerate(content) if row.startswith("> ")), 0)
        content = content[max(0, selected_row - max(1, rows - 8) + 1):]
    wrapped=[]
    action_fragments=set()
    report_entries=False
    for line in content:
        if line.startswith('Entries'): report_entries=True
        elif report_entries and line and not line.startswith(('  ','> ')): report_entries=False
        pieces=textwrap.wrap(line,width=width,replace_whitespace=False,
                             break_long_words=True,break_on_hyphens=False) or [""]
        if line in panel._action_rows or (report_entries and line.startswith(('  ','> '))):
            action_fragments.update(pieces)
        wrapped.extend(pieces)
    selected_row=next((i for i,row in enumerate(wrapped) if row.startswith("> ")),None)
    if selected_row is not None and selected_row >= max(1,rows-8):
        wrapped=wrapped[selected_row-max(1,rows-8)+1:]
    lines += wrapped[:max(1,rows-8)]
    while len(lines) < rows - 3:
        lines.append("")
    controls = "Up/Down: scroll   Centre: stop   Right: latest   Back: return" if panel.page == "Tasks" else "Up/Down: choose   Centre/Right: open   Left/Back: return"
    if panel.page == "Tasks" and (panel.task.snapshot()["metadata"] or {}).get("kind") in STRUCTURED_KINDS:
        controls = "Up/Down: scroll   Centre: stop   Right: top   Back: return"
    if panel.page == "Tasks":
        task = panel.task.snapshot()
        if task["state"] != "RUNNING":
            structured = (task["metadata"] or {}).get("kind") in STRUCTURED_KINDS
            security = (task["metadata"] or {}).get("kind") == "security" and task["finder"].get("report")
            centre = "device list" if security else "top" if structured else "latest"
            controls = f"Up/Down: scroll   Centre: {centre}   Right: {'top' if structured else 'latest'}   Back: return"
    if panel.page == "Security Results" and panel.details is not None:
        controls = "Up/Down: scroll   Right: top   Back: device list"
    if panel.page == "Tasks" and (panel.task.snapshot()["metadata"] or {}).get("kind") == "wifi-health":
        controls = wifi_controls(getattr(panel, "wifi_navigation", wifi_new_navigation())) + ("   Centre: stop" if panel.task.snapshot()["state"] == "RUNNING" else "")
    for long,short in (("Up/Down: ","U/D "),("Centre/Right: ","C/R "),
                       ("Centre: ","C "),("Right: ","R "),("Left/Back: ","Back "),
                       ("Back: ","Back "),("   "," | "),("device list","devices")):
        controls=controls.replace(long,short)
    if panel.page=="Tasks" and panel.task.snapshot().get("title")=="Wi-Fi waterfall": controls=("U/D band | " if getattr(panel,"_waterfall_mode","general")=="general" else "")+"L/R channel | Centre pause | Back stop"
    control_rows=textwrap.wrap(controls,width=width,break_long_words=True) or [""]
    if len(control_rows)>1:
        footer_rows=[panel.message or "",*control_rows[:2]]
    else:
        footer_rows=[panel.message or "",control_rows[0],"Hold Back: exit | SSH: WASD Enter Q"]
    lines += footer_rows
    output = []
    for index, line in enumerate(lines[:rows]):
        text = safe_text(line)[:max(1, cols - 1)]
        colour = "\x1b[92m" if index == 0 else "\x1b[1;36m" if index == 1 else "\x1b[97m"
        if text.startswith("> "):
            colour = "\x1b[30;102m"
        elif line in action_fragments:
            colour = "\x1b[92m"
        else:
            health_colour = wifi_health_colour(text, colour) if index >= 5 and panel.page == "Tasks" and (panel.task.snapshot()["metadata"] or {}).get("kind") == "wifi-health" else None
            text = health_colour if health_colour is not None else colour_details(text, colour, quiet_numbers=panel.page == "Tasks" and panel.task.snapshot().get("title") == "Device watch")
        output.append(f"\x1b[{index + 1};1H{colour}{text}\x1b[0m\x1b[K")
    return "".join(output)


def sync_terminal_size():
    try:
        size = fcntl.ioctl(1, termios.TIOCGWINSZ, b"\0" * 8)
        rows, cols, _, _ = struct.unpack("HHHH", size)
        if not rows or not cols:
            size = struct.pack("HHHH", 40, 80, 0, 0)
            rows, cols = 40, 80
        fcntl.ioctl(0, termios.TIOCSWINSZ, size)
        return max(12, rows), max(40, cols)
    except OSError:
        return 40, 80


def console_text_mode():
    """Restore Linux console rendering after a direct framebuffer dashboard."""
    try:
        if os.ttyname(1) != "/dev/tty1":
            return None
        old_mode = struct.unpack("i", fcntl.ioctl(1, 0x4B3B, struct.pack("i", 0)))[0]
        fcntl.ioctl(1, 0x4B3A, 0)
        return old_mode
    except OSError:
        return None


def restore_console_mode(mode):
    if mode is not None:
        try:
            fcntl.ioctl(1, 0x4B3A, mode)
        except OSError:
            pass


def pause_dashboard():
    paused = []
    if not os.isatty(1):
        return paused
    try:
        if os.ttyname(1) != "/dev/tty1":
            return paused
    except OSError:
        return paused
    try:
        record = json.loads(Path("/run/bh-flipper-job/active.json").read_text())
        pid = int(record.get("pid", 0))
        if pid > 1 and os.getpgid(pid) == pid:
            root = Path(f"/proc/{pid}")
            environment = (root / "environ").read_bytes().split(b"\0")
            stats = (root / "stat").read_text().rsplit(")", 1)[1].split()
            if b"BH_FLIPPER_JOB_CHILD=1" in environment and stats[0] not in ("T", "t"):
                os.killpg(pid, signal.SIGSTOP)
                paused.append((pid, stats[19], True))
    except (OSError, ValueError, KeyError):
        pass
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            args = (entry / "cmdline").read_bytes().split(b"\0")
            if b"/usr/local/lib/bh/lcd-system.py" in args and any(b"python" in a for a in args[:1]):
                pid = int(entry.name)
                # Save process start time to avoid signalling a reused PID on exit.
                stats = (entry / "stat").read_text().rsplit(")", 1)[1].split()
                if stats[0] in ("T", "t"):
                    continue
                started = stats[19]
                os.kill(pid, signal.SIGSTOP)
                paused.append((pid, started, False))
        except (OSError, ValueError):
            pass
    return paused


def resume_dashboard(paused):
    for pid, started, group in paused:
        try:
            current = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
            if current == started:
                if group:
                    os.killpg(pid, signal.SIGCONT)
                else:
                    os.kill(pid, signal.SIGCONT)
        except (OSError, ValueError):
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", action="store_true", help="Print read-only system information")
    parser.add_argument("--waterfall", action="store_true", help="Open the standalone Wi-Fi waterfall")
    args = parser.parse_args()
    if args.snapshot:
        print(json.dumps({"system": system_data(), "network": network_data(),
                          "services": service_data()}, indent=2))
        return 0
    if not (os.isatty(0) and os.isatty(1)):
        print("Run bh-panel from a terminal, or use --snapshot.", file=sys.stderr)
        return 2
    rows, cols = sync_terminal_size()
    old = termios.tcgetattr(0)
    collector = Collector()
    panel = Panel(collector)
    if args.waterfall: panel.start_task("Wi-Fi waterfall", ["sudo","-n","/usr/local/bin/wifi-passive-health-panel"], {"kind":"wifi-health"})
    def request_exit(signum, frame):
        panel.running = False
    old_handlers = {sig: signal.signal(sig, request_exit)
                    for sig in (signal.SIGTERM, signal.SIGHUP)}
    keys = Keys()
    paused = []
    collector.thread.start()
    old_console_mode = None
    lcd_panel = None
    # CLOVER_LCD_BACKGROUND_V1
    try:
        paused = pause_dashboard()
        old_console_mode = console_text_mode()
        from clover_lcd_panel import open_local
        lcd_panel = open_local()
        if lcd_panel is not None:
            rows, cols = lcd_panel.rows, lcd_panel.cols
        tty.setraw(0)
        sys.stdout.write("\x1b[2J\x1b[?25l")
        last_task_state = "IDLE"
        while panel.running:
            task_state = panel.task.snapshot()["state"]
            if last_task_state == "RUNNING" and task_state != "RUNNING":
                collector.refresh.set()
            last_task_state = task_state
            frame = render(panel, rows, cols)
            if lcd_panel is not None:
                if not waterfall_draw_local(panel,lcd_panel): lcd_panel.frame(frame)
            else:
                sys.stdout.write(frame)
                sys.stdout.flush()
            ready, _, _ = select.select([0], [], [], 0.2)
            if ready:
                received = os.read(0, 128)
                if not received:
                    break
                events = keys.feed(received)
            else:
                events = keys.tick()
            for event in events:
                panel.handle(event)
            if panel.game_requested:
                rom, panel.game_requested = panel.game_requested, None
                # CLOVER_GAME_RECOVERY_V2
                from clover_game_session import run_game
                had_lcd = lcd_panel is not None
                try:
                    if had_lcd:
                        lcd_panel.close()
                        lcd_panel = None
                    console_text_mode()
                    panel.message = run_game(rom, lambda: panel.running)
                finally:
                    tty.setraw(0)
                    termios.tcflush(0, termios.TCIFLUSH)
                    console_text_mode()
                    if had_lcd and panel.running:
                        lcd_panel = open_local()
                        if lcd_panel is not None:
                            rows, cols = lcd_panel.rows, lcd_panel.cols
                    keys = Keys()
                    sys.stdout.write("\x1b[2J\x1b[?25l")
                    sys.stdout.flush()
        return 0
    finally:
        panel.task.stop()
        # Keep the parent/output stream alive until the backend has restored its radios.
        cleanup_deadline=time.monotonic()+190
        while not panel.task.stop_complete.wait(.2) and time.monotonic()<cleanup_deadline:
            panel.message='Stopping: waiting for adapter cleanup...'
            if lcd_panel is not None:
                try: lcd_panel.frame(render(panel,rows,cols))
                except Exception: pass
        if panel.task.thread is not None:
            panel.task.thread.join(timeout=5)
        if not panel.task.stop_complete.is_set():
            print('Adapter cleanup has not completed; check radio status before another scan.',flush=True)
        if lcd_panel is not None:
            lcd_panel.close()
        collector.stop.set()
        try:
            termios.tcsetattr(0, termios.TCSADRAIN, old)
            sys.stdout.write("\x1b[0m\x1b[?25h\x1b[2J\x1b[H")
            sys.stdout.flush()
        finally:
            restore_console_mode(old_console_mode)
            resume_dashboard(paused)
            for sig, handler in old_handlers.items():
                signal.signal(sig, handler)


# CLOVER_COMPACT_PAGES_V1
from clover_compact_pages import install as install_compact_pages
install_compact_pages(Panel, STRUCTURED_KINDS, globals())


# CLOVER_WIFI_CONSOLE_V1
from wifi_console_menu import install as install_wifi_console
install_wifi_console(Panel)

from cloverkit_panel_features import install as _install_roadmap_panel
_install_roadmap_panel(Panel, globals())

from cloverkit_wifi_waterfall import install_panel as install_waterfall_panel, draw_local as waterfall_draw_local
install_waterfall_panel(Panel,globals())

from cloverkit_radio_menu import install as install_radio_menu
install_radio_menu(Panel)

from cloverkit_network_sections import install as install_network_sections
install_network_sections(Panel,globals())

from cloverkit_release_scope import install as install_release_scope
install_release_scope(Panel,globals())

from cloverkit_vehicle_menu import install as install_vehicle_menu
install_vehicle_menu(Panel,globals())

from cloverkit_vehicle_ssh_menu import install as install_vehicle_ssh_menu
install_vehicle_ssh_menu(Panel)

if __name__ == "__main__":
    raise SystemExit(main())
