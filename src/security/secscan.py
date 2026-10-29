#!/usr/bin/env python3

import argparse
import datetime
import hashlib
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
sys.path.insert(0,'/usr/local/lib/bh-interactive')
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

BASE = Path("/mnt/security")
CACHE = BASE / "cache"
REPORTS = BASE / "reports"
BLE_AUTH_FILE = BASE / "authorized-ble.txt"

KEV_FILE = CACHE / "cisa-kev.json"

# CISA's official GitHub mirror of the KEV catalog.
KEV_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Debian Security Tracker machine-readable database.
# Used only where the locally inspected operating system
# identifies itself as Debian.
DEBIAN_TRACKER_URL = (
    "https://security-tracker.debian.org/tracker/data/json"
)
DEBIAN_TRACKER_FILE = CACHE / "debian-security-tracker.json"

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 137, 138, 139,
    143, 161, 389, 443, 445, 515, 548, 554, 631, 993, 995,
    1433, 1521, 1883, 2049, 2375, 2376, 3000, 3306, 3389,
    5000, 5001, 5353, 5432, 5900, 6379, 8000, 8001, 8008,
    8080, 8081, 8088, 8443, 8554, 8883, 8888, 8899, 9000,
    9090, 9100, 10000, 10250, 27017, 34567, 37777, 37778,
    49152
]

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}

ANSI = {
    "CRITICAL": "\033[1;31m",
    "HIGH": "\033[31m",
    "MEDIUM": "\033[33m",
    "LOW": "\033[36m",
    "INFO": "\033[37m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
}


VERBOSE = False

LCD_PROGRESS = '--lcd-progress' in sys.argv
if LCD_PROGRESS: sys.argv.remove('--lcd-progress')
import threading
_progress_lock = threading.Lock()
def live_progress(stage, **values):
    if LCD_PROGRESS:
        with _progress_lock:
            print('SECSCAN_PROGRESS '+json.dumps(dict(event='progress', stage=stage, **values)), flush=True)




def vprint(*args, **kwargs):
    if VERBOSE:
        print(*args, **kwargs)


def progress_bar(current, total, label="Scanning", width=20):
    if LCD_PROGRESS:
        live_progress(label, completed=current, total=total)
        return
    if VERBOSE:
        return

    total = max(int(total or 0), 1)
    current = max(0, min(int(current or 0), total))

    filled = int(width * current / total)

    bar = (
        "█" * filled
        + "░" * (width - filled)
    )

    suffix = (
        "done"
        if current >= total
        else f"{current}/{total}"
    )

    sys.stdout.write(
        f"\r{label:<18} [{bar}]  {suffix}"
    )
    sys.stdout.flush()

    if current >= total:
        sys.stdout.write("\n")
        sys.stdout.flush()


def colour(sev, text):
    if not sys.stdout.isatty():
        return text
    return f"{ANSI.get(sev, '')}{text}{ANSI['RESET']}"


def run(cmd, timeout=None, input_text=None):
    try:
        p = subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def default_interface():
    rc, out, _ = run(["ip", "-4", "route", "show", "default"])
    if rc != 0:
        return None

    m = re.search(r"\bdev\s+(\S+)", out)
    return m.group(1) if m else None



RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def network_is_rfc1918(network):
    """
    True only when the entire IPv4 network falls inside
    RFC1918 private address space.
    """

    try:
        net = ipaddress.ip_network(
            network,
            strict=False
        )
    except Exception:
        return False

    if net.version != 4:
        return False

    return any(
        net.subnet_of(private_net)
        for private_net in RFC1918_NETWORKS
    )


def network_scan_policy(network):
    """
    Classify a proposed network scan.

    Auto discovery:
      allowed only for RFC1918 /24 or smaller.

    Explicit --network:
      wider/public ranges require deliberate override.
    """

    try:
        net = ipaddress.ip_network(
            network,
            strict=False
        )
    except Exception as e:
        return {
            "valid": False,
            "network": None,
            "private": False,
            "wide": False,
            "addresses": 0,
            "reason": str(e),
        }

    return {
        "valid": True,
        "network": str(net),
        "private": network_is_rfc1918(net),
        "wide": net.prefixlen < 24,
        "addresses": net.num_addresses,
        "prefixlen": net.prefixlen,
        "reason": "",
    }


def local_network():
    iface = default_interface()
    if not iface:
        return None, None

    rc, out, _ = run(
        ["ip", "-4", "-o", "addr", "show", "dev", iface, "scope", "global"]
    )

    if rc != 0:
        return iface, None

    m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)", out)

    if not m:
        return iface, None

    net = ipaddress.ip_interface(m.group(1)).network
    return iface, str(net)


def parse_hosts(xml_text):
    hosts = []

    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return hosts

    for h in root.findall("host"):
        status = h.find("status")
        if status is None or status.attrib.get("state") != "up":
            continue

        ipv4 = None
        mac = None
        vendor = None

        for addr in h.findall("address"):
            if addr.attrib.get("addrtype") == "ipv4":
                ipv4 = addr.attrib.get("addr")
            elif addr.attrib.get("addrtype") == "mac":
                mac = addr.attrib.get("addr")
                vendor = addr.attrib.get("vendor")

        hostname = None
        hn = h.find("./hostnames/hostname")
        if hn is not None:
            hostname = hn.attrib.get("name")

        if ipv4:
            hosts.append({
                "ip": ipv4,
                "mac": mac,
                "vendor": vendor,
                "hostname": hostname,
            })

    return hosts


def discover(target):
    vprint(f"\nDiscovering: {target}")

    cmd = [
        "nmap",
        "-sn",
        "-PR",
        "-T3",
        target,
        "-oX",
        "-"
    ]

    rc, out, err = run(cmd, timeout=180)

    if rc != 0:
        print(f"Discovery failed: {err.strip()}")
        return []

    return parse_hosts(out)


def service_scan(ip, deep=False):
    """
    Two-stage LAN service scan.

    Stage 1:
      Fast open-port discovery.

    Stage 2:
      Version/CPE enrichment against proven-open ports,
      split across two concurrent Nmap workers.

    Stage-2 failure never discards Stage-1 open-port evidence.
    """

    from concurrent.futures import (
        ThreadPoolExecutor,
        as_completed,
    )

    if deep:
        port_spec = (
            "1-1024,1883,2049,2375-2376,3000,3306,3389,"
            "5000-5001,5353,5432,5900,6379,8000-8001,8008,"
            "8080-8081,8088,8443,8554,8883,8888-8899,9000,"
            "9090,9100,10000,10250,27017,34567,37777-37778,49152"
        )

        discovery_host_timeout = "15s"
        discovery_process_timeout = 18

        version_host_timeout = "25s"
        version_process_timeout = 30

    else:
        port_spec = ",".join(
            str(x)
            for x in COMMON_PORTS
        )

        discovery_host_timeout = "7s"
        discovery_process_timeout = 10

        # Applied PER version-identification group.
        version_host_timeout = "12s"
        version_process_timeout = 16


    # ========================================================
    # XML PARSER
    # ========================================================

    def parse_service_xml(xml_text):
        services = []

        if not xml_text.strip():
            return services

        try:
            root = ET.fromstring(
                xml_text
            )
        except Exception:
            return services

        for port in root.findall(".//port"):
            state = port.find("state")

            if (
                state is None
                or state.attrib.get("state") != "open"
            ):
                continue

            svc = port.find("service")

            data = {
                "port": int(
                    port.attrib.get(
                        "portid",
                        0
                    )
                ),
                "protocol": port.attrib.get(
                    "protocol",
                    "tcp"
                ),
                "name": "",
                "product": "",
                "version": "",
                "extrainfo": "",
                "tunnel": "",
                "cpes": [],
                "fingerprint_status": "PORT_ONLY",
            }

            if svc is not None:
                for field in (
                    "name",
                    "product",
                    "version",
                    "extrainfo",
                    "tunnel",
                ):
                    data[field] = (
                        svc.attrib.get(
                            field,
                            ""
                        )
                    )

                for cpe in svc.findall("cpe"):
                    if cpe.text:
                        data["cpes"].append(
                            cpe.text.strip()
                        )

            services.append(data)

        return services


    # ========================================================
    # STAGE 1 - FAST OPEN-PORT DISCOVERY
    # ========================================================

    discovery_cmd = [
        "nmap",
        "-Pn",
        "-sT",
        "--open",
        "-T4",
        "--max-retries", "1",
        "--initial-rtt-timeout", "150ms",
        "--max-rtt-timeout", "600ms",
        "--host-timeout",
        discovery_host_timeout,
        "-p",
        port_spec,
        ip,
        "-oX",
        "-"
    ]

    rc, out, err = run(
        discovery_cmd,
        timeout=discovery_process_timeout
    )

    if rc != 0:
        if rc == 124:
            return [], (
                "open-port discovery exceeded "
                f"{discovery_process_timeout}s budget"
            )

        return [], (
            err.strip()
            or f"open-port discovery exited {rc}"
        )

    services = parse_service_xml(out)

    if not services:
        return [], ""

    service_map = {
        (
            s["protocol"],
            s["port"]
        ): s
        for s in services
    }

    open_ports = sorted(
        {
            s["port"]
            for s in services
        }
    )


    # ========================================================
    # STAGE 2 - PARALLEL VERSION / CPE ENRICHMENT
    # ========================================================

    # Alternating assignment gives reasonably balanced groups.
    # Example:
    #   group 1 = ports 21,23,53,110...
    #   group 2 = ports 22,25,80,445...
    groups = [
        open_ports[0::2],
        open_ports[1::2],
    ]

    groups = [
        g
        for g in groups
        if g
    ]

    def identify_group(group_number, ports):
        cmd = [
            "nmap",
            "-Pn",
            "-sT",
            "-sV",
            "--version-light",
            "--open",
            "-T4",
            "--max-retries", "1",
            "--initial-rtt-timeout", "200ms",
            "--max-rtt-timeout", "800ms",
            "--host-timeout",
            version_host_timeout,
            "-p",
            ",".join(
                str(p)
                for p in ports
            ),
            ip,
            "-oX",
            "-"
        ]

        started = time.monotonic()

        rc, version_out, version_err = run(
            cmd,
            timeout=version_process_timeout
        )

        elapsed = (
            time.monotonic()
            - started
        )

        if rc == 0:
            status = "OK"
            identified = parse_service_xml(
                version_out
            )

        else:
            status = (
                "TIMEOUT"
                if rc == 124
                else "ERROR"
            )

            identified = []

        return {
            "group": group_number,
            "ports": ports,
            "status": status,
            "elapsed": elapsed,
            "services": identified,
            "error": (
                version_err.strip()
                if rc not in (0, 124)
                else ""
            ),
        }


    version_results = []

    with ThreadPoolExecutor(
        max_workers=min(
            2,
            len(groups)
        )
    ) as executor:

        futures = {
            executor.submit(
                identify_group,
                i + 1,
                group
            ): i + 1
            for i, group in enumerate(
                groups
            )
        }

        for future in as_completed(
            futures
        ):
            try:
                version_results.append(
                    future.result()
                )

            except Exception as e:
                version_results.append({
                    "group": futures[future],
                    "ports": [],
                    "status": "ERROR",
                    "elapsed": 0,
                    "services": [],
                    "error": str(e),
                })


    # ========================================================
    # MERGE IDENTIFICATION RESULTS
    # ========================================================

    identified_ports = set()

    for result in version_results:
        if VERBOSE:
            vprint(
                f"  SERVICE ID GROUP "
                f"{result['group']}: "
                f"{result['status']} "
                f"{result['elapsed']:.2f}s "
                f"ports={','.join(str(x) for x in result['ports'])}"
            )

        for enriched in result[
            "services"
        ]:
            key = (
                enriched.get(
                    "protocol",
                    "tcp"
                ),
                enriched["port"]
            )

            existing = service_map.get(
                key
            )

            if existing is None:
                continue

            identified_ports.add(
                enriched["port"]
            )

            for field in (
                "name",
                "product",
                "version",
                "extrainfo",
                "tunnel",
            ):
                value = enriched.get(
                    field,
                    ""
                )

                if value:
                    existing[field] = value

            if enriched.get("cpes"):
                existing["cpes"] = (
                    enriched["cpes"]
                )

            existing[
                "fingerprint_status"
            ] = "IDENTIFIED"


    # Mark only failed-to-identify services as unverified.
    for svc in services:
        if svc["port"] not in identified_ports:
            svc[
                "fingerprint_status"
            ] = "UNVERIFIED"

    # Stage 1 completed successfully, therefore this host is
    # not SCAN_INCOMPLETE simply because enrichment was unable
    # to fingerprint every open service.
    return services, ""

_original_security_argv = tuple(sys.argv)

# Approved automatic checks are explicit functions, never CVE-supplied code.
SAFE_VERIFIER_NAMES = frozenset(('verify_ssh_host','verify_ftp_host','verify_telnet_host',
    'verify_http_host','verify_smb_host','verify_rtsp_host','verify_redis_host'))
LAB_VERIFIERS = {}  # No disruptive executors shipped with the ordinary scanner.

def authorize_lab_override(args, parser):
    if not getattr(args,'lab_override',False): return
    if '--lcd-progress' in _original_security_argv or globals().get('LCD_PROGRESS',False) or not sys.stdin.isatty():
        parser.error('Lab override requires an interactive SSH/terminal session')
    if not args.host or not args.cve or args.network or args.ble_only:
        parser.error('Lab override requires one --host and one --cve; no subnet or BLE mode')
    if args.cve not in LAB_VERIFIERS:
        parser.error('No reviewed lab test is installed for this CVE; no exploit executed')
    # A reviewed lab executor must be integrated explicitly before this gate opens.
    parser.error('Lab execution is not enabled in the ordinary security scanner')

def finding_validation(item):
    if item.get('code')=='SCAN_INCOMPLETE':
        return dict(status='INCONCLUSIVE',test='Incomplete scan',reason='Some checks did not finish')
    if item.get('code') in ('REDIS_PING_RESTRICTED','HTTP_TO_HTTPS','FTP_ANONYMOUS_REJECTED','FTP_AUTH_REQUIRED','SMB_SECURE_BASELINE') and item.get('confirmed'):
        return dict(status='NOT REPRODUCED',test='Specific protocol check',reason='Only the stated condition was not reproduced; this is not a clean-device verdict')
    if item.get('confirmed'):
        return dict(status='CONFIRMED',test='Direct observation',reason='Only the stated observation is confirmed')
    if item.get('vendor_state') in ('AFFECTED','UPDATE_AVAILABLE'):
        return dict(status='VENDOR VERIFIED',test='Vendor/package evidence',reason='Exploit was not reproduced')
    if item.get('code')=='CVE_MATCH' or item.get('cve'):
        text=(str(item.get('title',''))+' '+str(item.get('applicability_reason',''))).lower()
        lab=any(term in text for term in ('rowhammer','row hammer','denial of service','denial-of-service','crash','memory corruption','arbitrary code execution'))
        return dict(status='POSSIBLE',test='Lab only' if lab else 'Not tested',reason='No approved non-disruptive CVE verifier installed')
    return dict(status='INCONCLUSIVE' if str(item.get('code','')).endswith(('_UNKNOWN','_UNVERIFIED')) else 'OBSERVED',
                test='Service/protocol evidence',reason='This does not establish CVE exploitability')

def annotate_security_validation(hosts):
    for host in hosts:
        for item in host.get('findings',[]): item['validation']=finding_validation(item)
        host['verification_policy']={'mode':'SAFE_ONLY','lab_override':'SSH terminal only',
            'scope':'Approved protocol checks; CVE reproduction requires a dedicated reviewed verifier'}

def verify_redis_host(host, service):
    port=int(service.get('port',6379));result=dict(mode='REMOTE_SAFE',port=port,outcome='INCONCLUSIVE',evidence='')
    try:
        with socket.create_connection((host['ip'],port),timeout=3) as connection:
            connection.settimeout(3)
            connection.sendall(b'*1\r\n$4\r\nPING\r\n')
            raw=b''
            while b'\r\n' not in raw and len(raw)<512:
                chunk=connection.recv(min(512-len(raw),512))
                if not chunk: break
                raw+=chunk
        reply=raw.split(b'\r\n',1)[0].decode('utf-8','replace')
        if b'\r\n' not in raw: result['evidence']='No complete Redis response received'
        elif reply=='+PONG': result.update(outcome='PING_ALLOWED',evidence='PING returned PONG without AUTH; data access and administrative rights were not tested')
        elif reply.startswith(('-NOAUTH','-NOPERM','-DENIED')): result.update(outcome='ACCESS_RESTRICTED',evidence='PING was refused: '+reply[:180])
        else: result['evidence']='Unexpected response to PING; no security verdict'
    except (OSError,ValueError) as error: result['evidence']='PING check incomplete: '+str(error)[:160]
    return result

def redis_verification_findings(host):
    result=host.get('verification',{}).get('redis')
    if not result: return []
    outcome=result.get('outcome');evidence=result.get('evidence','')
    if outcome=='PING_ALLOWED':
        return [finding('LOW','REDIS_PING_UNAUTH','Redis accepts unauthenticated PING',evidence,'CONFIRMED',port=result['port'],confirmed=True,action='Review Redis ACLs and network exposure; PING alone does not prove unrestricted access.')]
    if outcome=='ACCESS_RESTRICTED':
        return [finding('INFO','REDIS_PING_RESTRICTED','Redis rejected unauthenticated PING',evidence,'CONFIRMED',port=result['port'],confirmed=True,action='This one check does not establish that the device is free of vulnerabilities.')]
    return [finding('INFO','REDIS_UNKNOWN','Redis access check inconclusive',evidence,'LOW',port=result['port'],action='Review or retry this check; do not treat the device as clean.')]


def finding(
    severity,
    code,
    title,
    evidence,
    confidence,
    port=None,
    cve=None,
    kev=False,
    score=None,
    action=None,
    confirmed=False,
):
    return {
        "severity": severity,
        "code": code,
        "title": title,
        "evidence": evidence,
        "confidence": confidence,
        "port": port,
        "cve": cve,
        "kev": kev,
        "cvss": score,
        "action": action,
        "confirmed": confirmed,
    }


def config_checks(host, services):
    findings = []
    ports = {s["port"]: s for s in services}

    scan_error = (
        host.get("scan_error")
        or ""
    ).strip()

    if scan_error:
        if services:
            title = (
                "Service scan incomplete; partial results were used"
            )
            evidence = (
                f"{scan_error}. "
                f"{len(services)} open service(s) were still recovered."
            )
        else:
            title = (
                "Service scan incomplete; no security verdict was made"
            )
            evidence = (
                f"{scan_error}. "
                "No usable service results were recovered."
            )

        findings.append(
            finding(
                "INFO",
                "SCAN_INCOMPLETE",
                title,
                evidence,
                "HIGH",
                action=(
                    "Retry this host with --verbose before "
                    "treating it as clean."
                ),
                confirmed=False,
            )
        )

    if 23 in ports:
        findings.append(finding(
            "HIGH",
            "TELNET_ENABLED",
            "Telnet remote management/service is enabled",
            "TCP/23 is reachable and identified as an open service.",
            "HIGH",
            23,
            action="Disable Telnet and use SSH or another encrypted management protocol."
        ))

    if 21 in ports:
        findings.append(finding(
            "MEDIUM",
            "FTP_ENABLED",
            "Plain FTP service is exposed",
            "TCP/21 is reachable. FTP normally transmits credentials/data without transport encryption.",
            "HIGH",
            21,
            action="Disable FTP if unnecessary or replace it with SFTP/FTPS."
        ))

    if 2375 in ports:
        # Docker API safe validation.
        try:
            req = urllib.request.Request(
                f"http://{host['ip']}:2375/version",
                headers={"User-Agent": "SecScan/1.0"},
            )

            with urllib.request.urlopen(req, timeout=3) as r:
                body = r.read(8192).decode("utf-8", "ignore")

            if '"ApiVersion"' in body or '"Version"' in body:
                findings.append(finding(
                    "CRITICAL",
                    "DOCKER_API_NO_TLS",
                    "Unauthenticated Docker API confirmed",
                    "HTTP request to TCP/2375 /version returned Docker version data without authentication.",
                    "CONFIRMED",
                    2375,
                    action="Disable TCP/2375 or require authenticated TLS access immediately.",
                    confirmed=True,
                ))
        except Exception:
            findings.append(finding(
                "MEDIUM",
                "DOCKER_API_PORT",
                "Docker-style plaintext API port is reachable",
                "TCP/2375 is open, but unauthenticated Docker access was not confirmed.",
                "MEDIUM",
                2375,
                action="Verify whether this service is required and whether access controls are enabled."
            ))

    if 554 in ports or 8554 in ports:
        findings.extend(
            rtsp_verification_findings(
                host
            )
        )

    if 1883 in ports:
        findings.append(finding(
            "LOW",
            "MQTT_PLAINTEXT",
            "MQTT service detected on plaintext port",
            "TCP/1883 is reachable. This does not prove anonymous broker access.",
            "HIGH",
            1883,
            action="Confirm authentication is required and prefer TLS on TCP/8883 where supported."
        ))

    if 6379 in ports:
        findings.append(finding(
            "MEDIUM",
            "REDIS_REACHABLE",
            "Redis service is reachable",
            "TCP/6379 is open. No commands were issued to determine access level.",
            "HIGH",
            6379,
            action="Restrict Redis to trusted hosts and verify authentication/protected mode."
        ))

    if 27017 in ports:
        findings.append(finding(
            "MEDIUM",
            "MONGODB_REACHABLE",
            "MongoDB service is reachable",
            "TCP/27017 is open. Authentication bypass was not tested.",
            "HIGH",
            27017,
            action="Restrict database exposure and verify authentication."
        ))

    if 10250 in ports:
        findings.append(finding(
            "MEDIUM",
            "KUBELET_REACHABLE",
            "Kubernetes kubelet-style service port is reachable",
            "TCP/10250 is open. Authentication state was not tested.",
            "MEDIUM",
            10250,
            action="Verify kubelet authentication/authorization and network restrictions."
        ))

    web_ports = {
        p for p in ports
        if p in [80, 81, 8000, 8001, 8008, 8080, 8081, 8088, 8888, 9000, 9090, 10000]
    }

    tls_ports = {
        p for p in ports
        if p in [443, 8443]
    }

    if web_ports and not tls_ports:
        product_text = " ".join(
            (
                ports[p].get("product", "") + " " +
                ports[p].get("name", "")
            ).lower()
            for p in web_ports
        )

        sensitive_words = [
            "camera", "router", "nas", "management",
            "admin", "switch", "webcam", "dvr", "nvr"
        ]

        if any(x in product_text for x in sensitive_words):
            findings.append(finding(
                "MEDIUM",
                "PLAINTEXT_WEB_MGMT",
                "Possible management interface available without HTTPS",
                f"HTTP-style service detected on {sorted(web_ports)} and no common HTTPS management port was found.",
                "MEDIUM",
                action="Verify whether credentials are sent over HTTP and enable HTTPS if supported."
            ))
        else:
            findings.append(finding(
                "INFO",
                "HTTP_PRESENT",
                "HTTP service present without a common HTTPS listener",
                f"HTTP-style service detected on {sorted(web_ports)}. This may be normal for the device.",
                "LOW",
                action="Review only if this is a management interface."
            ))

    # Replace generic FTP/Telnet presence warnings with
    # evidence-based verifier results.
    findings = [
        f
        for f in findings
        if f.get("code") not in (
            "TELNET_ENABLED",
            "FTP_ENABLED",
            "HTTP_PRESENT",
            "PLAINTEXT_WEB_MGMT",
        )
    ]

    findings.extend(
        ftp_verification_findings(
            host
        )
    )

    findings.extend(
        telnet_verification_findings(
            host
        )
    )

    findings.extend(
        http_verification_findings(
            host
        )
    )

    findings.extend(
        smb_verification_findings(
            host
        )
    )

    if host.get('verification',{}).get('redis'):
        findings=[f for f in findings if f.get('code')!='REDIS_REACHABLE']
        findings.extend(redis_verification_findings(host))

    return findings


def cpe22_to_23(cpe):
    # Nmap often outputs URI-binding CPE 2.2:
    # cpe:/a:vendor:product:version
    if cpe.startswith("cpe:2.3:"):
        return cpe

    if not cpe.startswith("cpe:/"):
        return None

    body = cpe[5:]
    parts = body.split(":")

    if len(parts) < 3:
        return None

    part = parts[0]
    vendor = parts[1] if len(parts) > 1 else "*"
    product = parts[2] if len(parts) > 2 else "*"
    version = parts[3] if len(parts) > 3 and parts[3] else "*"
    update = parts[4] if len(parts) > 4 and parts[4] else "*"
    edition = parts[5] if len(parts) > 5 and parts[5] else "*"
    language = parts[6] if len(parts) > 6 and parts[6] else "*"

    return (
        f"cpe:2.3:{part}:{vendor}:{product}:{version}:"
        f"{update}:{edition}:{language}:*:*:*:*"
    )


def exact_version_cpe(cpe):
    c23 = cpe22_to_23(cpe)

    if not c23:
        return None

    parts = c23.split(":")

    if len(parts) < 6:
        return None

    version = parts[5]

    if version in ("", "*", "-"):
        return None

    return c23


def load_kev():
    if not KEV_FILE.exists():
        return {}

    try:
        data = json.loads(KEV_FILE.read_text())
    except Exception:
        return {}

    return {
        x.get("cveID"): x
        for x in data.get("vulnerabilities", [])
        if x.get("cveID")
    }


def update_kev():
    print("Updating CISA KEV intelligence...")

    try:
        req = urllib.request.Request(
            KEV_URL,
            headers={"User-Agent": "SecScan/1.0"}
        )

        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read()

        parsed = json.loads(data)

        if "vulnerabilities" not in parsed:
            raise ValueError("invalid KEV structure")

        KEV_FILE.write_bytes(data)

        print(
            f"KEV updated: "
            f"{len(parsed.get('vulnerabilities', []))} entries"
        )

        return True

    except Exception as e:
        print(f"WARNING: KEV update failed: {e}")
        return False


def cache_age_hours(path):
    if not path.exists():
        return None

    return (time.time() - path.stat().st_mtime) / 3600


def get_cvss(cve):
    metrics = cve.get("metrics", {})

    for key in [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ]:
        arr = metrics.get(key) or []

        if not arr:
            continue

        try:
            data = arr[0]["cvssData"]
            return float(data.get("baseScore")), data.get("baseSeverity")
        except Exception:
            pass

    return None, None


def nvd_lookup(cpe, api_key="", max_cache_hours=24):
    key = hashlib.sha256(cpe.encode()).hexdigest()[:24]
    cache_file = CACHE / f"nvd-{key}.json"

    age = cache_age_hours(cache_file)

    if age is not None and age <= max_cache_hours:
        try:
            return json.loads(cache_file.read_text()), True
        except Exception:
            pass

    params = urllib.parse.urlencode({"cpeName": cpe})
    url = f"{NVD_URL}?{params}&isVulnerable"

    headers = {
        "User-Agent": "SecScan/1.0"
    }

    if api_key:
        headers["apiKey"] = api_key

    try:
        req = urllib.request.Request(url, headers=headers)

        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode("utf-8"))

        cache_file.write_text(json.dumps(data))

        # NVD has substantially tighter unauthenticated request limits.
        time.sleep(0.7 if api_key else 6.2)

        return data, False

    except Exception as e:
        return {"_error": str(e), "vulnerabilities": []}, False




# ============================================================
# SSH SAFE VERIFICATION
# ============================================================

def local_ipv4_addresses():
    rc, out, _ = run(
        ["ip", "-4", "-o", "addr", "show", "scope", "global"],
        timeout=10
    )

    addresses = set()

    if rc != 0:
        return addresses

    for line in out.splitlines():
        m = re.search(
            r"\binet\s+(\d+\.\d+\.\d+\.\d+)/",
            line
        )

        if m:
            addresses.add(m.group(1))

    addresses.add("127.0.0.1")

    return addresses


def is_local_target(ip):
    return ip in local_ipv4_addresses()


def parse_nmap_script_output(xml_text):
    result = {}

    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return result

    for script in root.findall(".//script"):
        sid = script.attrib.get("id")
        output = script.attrib.get("output", "")

        if sid:
            result[sid] = output

    return result


def verify_ssh_remote(ip, port=22):
    """
    Non-destructive SSH verification.

    Performs protocol negotiation / metadata discovery only.
    No password attempts.
    No login.
    No exploit payloads.
    """

    result = {
        "mode": "REMOTE_SAFE",
        "reachable": True,
        "host_keys": "",
        "algorithms": "",
        "banner": "",
        "local_config": None,
        "package": None,
        "os": None,
    }

    # --------------------------------------------------------
    # Banner
    # --------------------------------------------------------

    try:
        import socket as _socket

        with _socket.create_connection(
            (ip, int(port)),
            timeout=5
        ) as s:
            s.settimeout(5)
            banner = s.recv(1024).decode(
                "utf-8",
                "ignore"
            ).strip()

        result["banner"] = banner

    except Exception:
        pass

    # --------------------------------------------------------
    # Host keys + algorithm negotiation
    # --------------------------------------------------------

    rc, out, err = run(
        [
            "nmap",
            "-Pn",
            "-T4",
            "--max-retries", "1",
            "--host-timeout", "12s",
            "--script-timeout", "8s",
            "-p",
            str(port),
            "--script",
            "ssh-hostkey,ssh2-enum-algos",
            ip,
            "-oX",
            "-"
        ],
        timeout=15
    )

    if rc == 0:
        scripts = parse_nmap_script_output(out)

        result["host_keys"] = scripts.get(
            "ssh-hostkey",
            ""
        )

        result["algorithms"] = scripts.get(
            "ssh2-enum-algos",
            ""
        )

    else:
        if rc == 124:
            result["nmap_error"] = (
                "SSH metadata verification timed out"
            )
            result["verification_timeout"] = True

            if VERBOSE:
                print(
                    f"  SSH verifier timeout: "
                    f"{ip}:{port}"
                )
        else:
            result["nmap_error"] = err.strip()

    return result


def parse_sshd_t(text):
    cfg = {}

    for raw in text.splitlines():
        raw = raw.strip()

        if not raw or " " not in raw:
            continue

        key, value = raw.split(None, 1)

        cfg[key.lower()] = value.strip()

    return cfg


def local_ssh_details():
    """
    Deep local verification.

    This is used only when sec-scan is examining the machine
    it is running on.
    """

    result = {
        "sshd_config": {},
        "package": "",
        "os": {},
        "pam_opie": False,
    }

    # --------------------------------------------------------
    # Effective sshd configuration
    # --------------------------------------------------------

    for cmd in (
        ["/usr/sbin/sshd", "-T"],
        ["sshd", "-T"],
    ):
        rc, out, _ = run(
            cmd,
            timeout=15
        )

        if rc == 0 and out.strip():
            result["sshd_config"] = parse_sshd_t(out)
            break

    # --------------------------------------------------------
    # Installed Debian package version
    # --------------------------------------------------------

    rc, out, _ = run(
        [
            "dpkg-query",
            "-W",
            "-f=${Package} ${Version}\\n",
            "openssh-server"
        ],
        timeout=10
    )

    if rc == 0:
        result["package"] = out.strip()

    # --------------------------------------------------------
    # OS identification
    # --------------------------------------------------------

    os_release = Path("/etc/os-release")

    if os_release.exists():
        for raw in os_release.read_text().splitlines():
            if "=" not in raw:
                continue

            key, value = raw.split("=", 1)

            result["os"][key] = (
                value.strip()
                .strip('"')
            )

    # --------------------------------------------------------
    # OPIE PAM check
    # --------------------------------------------------------

    pam_paths = [
        Path("/etc/pam.d/sshd"),
        Path("/etc/pam.d/common-auth"),
    ]

    for pam in pam_paths:
        try:
            if pam.exists():
                content = pam.read_text(
                    errors="ignore"
                ).lower()

                if "opie" in content:
                    result["pam_opie"] = True
                    break
        except Exception:
            pass

    return result


def verify_ssh_host(host, service):
    ip = host["ip"]
    port = service.get("port", 22)

    verification = verify_ssh_remote(
        ip,
        port
    )

    if is_local_target(ip):
        verification["mode"] = "LOCAL_DEEP"

        local = local_ssh_details()

        verification["local_config"] = local.get(
            "sshd_config",
            {}
        )

        verification["package"] = local.get(
            "package",
            ""
        )

        verification["os"] = local.get(
            "os",
            {}
        )

        verification["pam_opie"] = local.get(
            "pam_opie",
            False
        )

    return verification



def rtsp_request(ip, port, path, method="DESCRIBE"):
    """
    Send one unauthenticated RTSP request.

    Read-only / non-destructive:
      - no credentials
      - no SETUP
      - no PLAY
      - no recording
      - no configuration changes
    """

    import socket as _socket

    result = {
        "path": path,
        "status": None,
        "status_line": "",
        "headers": {},
        "body": "",
        "error": None,
    }

    target = (
        f"rtsp://{ip}:{port}{path}"
    )

    request = (
        f"{method} {target} RTSP/1.0\r\n"
        f"CSeq: 1\r\n"
        f"User-Agent: SecScan/1.0\r\n"
        f"Accept: application/sdp\r\n"
        f"\r\n"
    )

    try:
        with _socket.create_connection(
            (ip, int(port)),
            timeout=5
        ) as s:
            s.settimeout(5)
            s.sendall(
                request.encode(
                    "ascii",
                    "ignore"
                )
            )

            chunks = []

            while True:
                try:
                    data = s.recv(4096)
                except _socket.timeout:
                    break

                if not data:
                    break

                chunks.append(data)

                if sum(len(x) for x in chunks) >= 16384:
                    break

            raw = b"".join(chunks).decode(
                "utf-8",
                "ignore"
            )

        head, sep, body = raw.partition(
            "\r\n\r\n"
        )

        lines = head.splitlines()

        if lines:
            result["status_line"] = lines[0].strip()

            parts = lines[0].split()

            if len(parts) >= 2:
                try:
                    result["status"] = int(parts[1])
                except Exception:
                    pass

        for line in lines[1:]:
            if ":" not in line:
                continue

            key, value = line.split(
                ":",
                1
            )

            result["headers"][
                key.strip().lower()
            ] = value.strip()

        result["body"] = body[:8192]

    except Exception as e:
        result["error"] = str(e)

    return result


def verify_rtsp_host(host, service):
    ip = host["ip"]
    port = service.get("port", 554)

    vendor = (
        host.get("vendor")
        or ""
    ).lower()

    product_blob = " ".join([
        service.get("product", ""),
        service.get("name", ""),
        vendor,
    ]).lower()

    paths = ["/"]

    if "reolink" in product_blob:
        paths = [
            "/Preview_01_main",
            "/Preview_01_sub",
            "/",
        ]

    checks = []

    for path in paths:
        result = rtsp_request(
            ip,
            port,
            path,
            method="DESCRIBE"
        )

        checks.append(result)

        status = result.get("status")

        # Stop early once we get strong evidence.
        if status in (200, 401, 403):
            break

    outcome = "UNKNOWN"
    evidence = ""

    for item in checks:
        status = item.get("status")
        body = (
            item.get("body")
            or ""
        ).lower()

        if status in (401, 403):
            outcome = "AUTH_REQUIRED"
            evidence = (
                f"Unauthenticated RTSP DESCRIBE to "
                f"{item['path']} returned {status}."
            )
            break

        if (
            status == 200
            and (
                "application/sdp"
                in (
                    item.get("headers", {})
                    .get("content-type", "")
                    .lower()
                )
                or "m=video" in body
                or "v=0" in body
            )
        ):
            outcome = "UNAUTH_DESCRIBE"
            evidence = (
                f"Unauthenticated RTSP DESCRIBE to "
                f"{item['path']} returned SDP metadata."
            )
            break

    if outcome == "UNKNOWN":
        status_list = [
            str(x.get("status"))
            for x in checks
            if x.get("status") is not None
        ]

        if status_list:
            evidence = (
                "RTSP responded, but authentication state "
                "could not be confirmed. Statuses: "
                + ", ".join(status_list)
            )
        else:
            evidence = (
                "RTSP port was reachable but the verifier "
                "could not obtain a usable RTSP response."
            )

    return {
        "mode": "REMOTE_SAFE",
        "port": port,
        "outcome": outcome,
        "evidence": evidence,
        "checks": checks,
    }


def rtsp_verification_findings(host):
    result = (
        host.get("verification", {})
        .get("rtsp")
    )

    if not result:
        return []

    outcome = result.get("outcome")

    if outcome == "UNAUTH_DESCRIBE":
        return [
            finding(
                "MEDIUM",
                "RTSP_UNAUTHENTICATED",
                "RTSP stream metadata accessible without authentication",
                result.get("evidence", ""),
                "CONFIRMED",
                port=result.get("port"),
                action=(
                    "Require RTSP authentication or disable RTSP "
                    "if third-party streaming is not needed."
                ),
                confirmed=True,
            )
        ]

    if outcome == "AUTH_REQUIRED":
        return [
            finding(
                "INFO",
                "RTSP_AUTH_REQUIRED",
                "RTSP authentication is enforced",
                result.get("evidence", ""),
                "CONFIRMED",
                port=result.get("port"),
                action=None,
                confirmed=True,
            )
        ]

    return [
        finding(
            "INFO",
            "RTSP_AUTH_UNKNOWN",
            "RTSP service detected; authentication state not confirmed",
            result.get("evidence", ""),
            "LOW",
            port=result.get("port"),
            action=(
                "Review RTSP configuration if this camera should "
                "not expose third-party streaming."
            ),
        )
    ]



# ============================================================
# FTP / TELNET / HTTP / SMB SAFE VERIFICATION
# ============================================================

def verify_ftp_host(host, service):
    import ftplib
    import socket as _socket

    ip = host["ip"]
    port = int(service.get("port", 21))

    result = {
        "mode": "REMOTE_SAFE",
        "port": port,
        "outcome": "UNKNOWN",
        "banner": "",
        "anonymous_reply": "",
        "evidence": "",
    }

    # Capture greeting first.
    try:
        with _socket.create_connection(
            (ip, port),
            timeout=8
        ) as s:
            s.settimeout(8)

            try:
                raw = s.recv(2048)
            except Exception:
                raw = b""

        result["banner"] = raw.decode(
            "utf-8",
            "replace"
        ).strip()[:500]

    except Exception as e:
        result["evidence"] = (
            "TCP/21 was detected, but the greeting "
            "could not be collected: "
            + str(e)[:180]
        )

    # Standard anonymous-login check only.
    # No LIST, RETR, STOR or other data operations.
    try:
        ftp = ftplib.FTP()

        reply = ftp.connect(
            ip,
            port,
            timeout=8
        )

        if reply and not result["banner"]:
            result["banner"] = str(reply)[:500]

        try:
            login_reply = ftp.login(
                "anonymous",
                "secscan@localhost"
            )

            result["anonymous_reply"] = (
                str(login_reply)[:500]
            )

            result["outcome"] = (
                "ANONYMOUS_ALLOWED"
            )

            result["evidence"] = (
                "FTP accepted the standard anonymous login."
            )

        except ftplib.error_perm as e:
            reply = str(e)

            result["anonymous_reply"] = reply[:500]

            if reply.startswith("530"):
                result["outcome"] = "AUTH_REQUIRED"
                result["evidence"] = (
                    "FTP explicitly rejected anonymous "
                    "authentication with a 530 response."
                )
            else:
                result["outcome"] = "ANONYMOUS_REJECTED"
                result["evidence"] = (
                    "FTP rejected anonymous login: "
                    + reply[:180]
                )

        except ftplib.all_errors as e:
            result["outcome"] = "PROTOCOL_UNCLEAR"
            result["evidence"] = (
                "TCP/21 responded, but a standard FTP "
                "anonymous-login exchange could not complete: "
                + str(e)[:180]
            )

        try:
            ftp.quit()
        except Exception:
            try:
                ftp.close()
            except Exception:
                pass

    except ftplib.all_errors as e:
        if result["banner"]:
            result["outcome"] = "PROTOCOL_UNCLEAR"
            result["evidence"] = (
                "TCP/21 returned a greeting, but did not "
                "complete a standard FTP session: "
                + str(e)[:180]
            )
        else:
            result["outcome"] = "NO_FTP_DIALOGUE"
            result["evidence"] = (
                "TCP/21 was reachable during discovery, "
                "but no usable FTP dialogue was obtained: "
                + str(e)[:180]
            )

    return result


def ftp_verification_findings(host):
    result = (
        host.get("verification", {})
        .get("ftp")
    )

    if not result:
        return []

    outcome = result.get("outcome")

    if outcome == "ANONYMOUS_ALLOWED":
        return [
            finding(
                "MEDIUM",
                "FTP_ANONYMOUS",
                "Anonymous FTP login is allowed",
                result.get("evidence", ""),
                "CONFIRMED",
                port=result.get("port"),
                action=(
                    "Disable anonymous FTP unless it is "
                    "intentionally required."
                ),
                confirmed=True,
            )
        ]

    if outcome == "AUTH_REQUIRED":
        return [
            finding(
                "LOW",
                "FTP_PLAINTEXT_AUTH",
                "FTP authentication is required over plaintext",
                result.get("evidence", ""),
                "CONFIRMED",
                port=result.get("port"),
                action=(
                    "Prefer SFTP or another encrypted "
                    "file-transfer protocol."
                ),
                confirmed=True,
            )
        ]

    if outcome == "ANONYMOUS_REJECTED":
        return [
            finding(
                "LOW",
                "FTP_ANONYMOUS_REJECTED",
                "Anonymous FTP rejected; FTP remains plaintext",
                result.get("evidence", ""),
                "HIGH",
                port=result.get("port"),
                action=(
                    "Prefer an encrypted file-transfer protocol "
                    "if FTP credentials are used."
                ),
            )
        ]

    if outcome == "PROTOCOL_UNCLEAR":
        return [
            finding(
                "INFO",
                "FTP_PROTOCOL_UNCLEAR",
                "TCP/21 responded but normal FTP behaviour was not confirmed",
                result.get("evidence", ""),
                "LOW",
                port=result.get("port"),
                action=(
                    "Identify the service on TCP/21 before "
                    "treating it as a normal FTP server."
                ),
            )
        ]

    return [
        finding(
            "INFO",
            "FTP_AUTH_UNKNOWN",
            "FTP authentication state could not be confirmed",
            result.get("evidence", ""),
            "LOW",
            port=result.get("port"),
            action=(
                "Review the service on TCP/21 if it is expected."
            ),
        )
    ]


def verify_telnet_host(host, service):
    import socket as _socket

    ip = host["ip"]
    port = int(service.get("port", 23))

    result = {
        "mode": "REMOTE_SAFE",
        "port": port,
        "outcome": "UNKNOWN",
        "banner": "",
        "evidence": "",
    }

    try:
        with _socket.create_connection(
            (ip, port),
            timeout=5
        ) as s:
            s.settimeout(5)

            chunks = []

            try:
                chunks.append(
                    s.recv(4096)
                )
            except Exception:
                pass

            # One blank line only, to trigger a normal login prompt.
            try:
                s.sendall(b"\r\n")
            except Exception:
                pass

            try:
                chunks.append(
                    s.recv(4096)
                )
            except Exception:
                pass

        raw = b"".join(chunks)

        # Strip common Telnet IAC negotiation bytes enough for
        # human-readable prompt matching.
        readable = "".join(
            chr(b)
            if 32 <= b <= 126 or b in (10, 13, 9)
            else " "
            for b in raw
        )

        readable = re.sub(
            r"\s+",
            " ",
            readable
        ).strip()

        result["banner"] = readable[:500]

        lower = readable.lower()

        auth_markers = (
            "login:",
            "username:",
            "user:",
            "password:",
        )

        if any(x in lower for x in auth_markers):
            result["outcome"] = "LOGIN_PROMPT"
            result["evidence"] = (
                "Telnet session presented an authentication/login prompt."
            )

        elif readable:
            result["outcome"] = "TELNET_RESPONDED"
            result["evidence"] = (
                "TCP/23 returned Telnet-style interactive data, "
                "but no clear login prompt was identified."
            )

        else:
            result["evidence"] = (
                "TCP/23 was reachable but no readable Telnet "
                "prompt was obtained."
            )

    except Exception as e:
        result["evidence"] = (
            "Telnet verification failed: "
            + str(e)[:180]
        )

    return result


def telnet_verification_findings(host):
    result = (
        host.get("verification", {})
        .get("telnet")
    )

    if not result:
        return []

    outcome = result.get("outcome")

    if outcome == "LOGIN_PROMPT":
        return [
            finding(
                "MEDIUM",
                "TELNET_LOGIN",
                "Telnet login service confirmed",
                result.get("evidence", ""),
                "CONFIRMED",
                port=result.get("port"),
                action=(
                    "Disable Telnet and use SSH or another encrypted "
                    "management protocol."
                ),
                confirmed=True,
            )
        ]

    if outcome == "TELNET_RESPONDED":
        return [
            finding(
                "LOW",
                "TELNET_SERVICE",
                "Interactive service on TCP/23 confirmed",
                result.get("evidence", ""),
                "HIGH",
                port=result.get("port"),
                action=(
                    "Verify whether Telnet is required; prefer encrypted "
                    "remote management."
                ),
            )
        ]

    return [
        finding(
            "INFO",
            "TELNET_UNKNOWN",
            "TCP/23 is open but Telnet authentication was not confirmed",
            result.get("evidence", ""),
            "LOW",
            port=result.get("port"),
            action="Review the service listening on TCP/23.",
        )
    ]


def verify_http_host(host, service):
    ip = host["ip"]
    port = int(service.get("port", 80))

    result = {
        "mode": "REMOTE_SAFE",
        "port": port,
        "outcome": "UNKNOWN",
        "status": None,
        "location": "",
        "title": "",
        "evidence": "",
    }

    try:
        url = f"http://{ip}:{port}/"

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(
                self,
                req,
                fp,
                code,
                msg,
                hdrs,
                newurl
            ):
                return None

        opener = urllib.request.build_opener(
            NoRedirect
        )

        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "SecScan/1.0"
            }
        )

        try:
            response = opener.open(
                req,
                timeout=6
            )

            status = response.getcode()
            headers = response.headers
            body = response.read(
                16384
            ).decode(
                "utf-8",
                "ignore"
            )

        except urllib.error.HTTPError as e:
            status = e.code
            headers = e.headers
            body = e.read(
                16384
            ).decode(
                "utf-8",
                "ignore"
            )

        result["status"] = status

        location = (
            headers.get("Location")
            or ""
        )

        result["location"] = location

        if (
            status in (301, 302, 303, 307, 308)
            and location.lower().startswith("https://")
        ):
            result["outcome"] = "HTTPS_REDIRECT"
            result["evidence"] = (
                f"HTTP returned {status} and redirects to HTTPS."
            )
            return result

        title_match = re.search(
            r"(?is)<title[^>]*>(.*?)</title>",
            body
        )

        if title_match:
            title = re.sub(
                r"\s+",
                " ",
                title_match.group(1)
            ).strip()

            result["title"] = title[:160]

        lower = body.lower()

        login_markers = (
            'type="password"',
            "type='password'",
            "login",
            "sign in",
            "username",
            "administrator",
        )

        if any(x in lower for x in login_markers):
            result["outcome"] = "PLAINTEXT_LOGIN_PAGE"
            result["evidence"] = (
                f"HTTP/{port} returned a page containing login/"
                f"authentication indicators without redirecting to HTTPS."
            )

        elif status is not None:
            result["outcome"] = "HTTP_PRESENT"
            result["evidence"] = (
                f"HTTP/{port} responded with status {status}; "
                "no obvious plaintext login form was identified."
            )

    except Exception as e:
        result["evidence"] = (
            "HTTP verification failed: "
            + str(e)[:180]
        )

    return result


def http_verification_findings(host):
    results = (
        host.get("verification", {})
        .get("http", [])
    )

    findings = []

    for result in results:
        outcome = result.get("outcome")

        if outcome == "PLAINTEXT_LOGIN_PAGE":
            findings.append(
                finding(
                    "LOW",
                    "HTTP_PLAINTEXT_LOGIN",
                    "Possible login/admin interface served over plaintext HTTP",
                    result.get("evidence", ""),
                    "HIGH",
                    port=result.get("port"),
                    action=(
                        "Use HTTPS for authentication or management if "
                        "the device supports it."
                    ),
                )
            )

        elif outcome == "HTTPS_REDIRECT":
            findings.append(
                finding(
                    "INFO",
                    "HTTP_TO_HTTPS",
                    "HTTP redirects to HTTPS",
                    result.get("evidence", ""),
                    "CONFIRMED",
                    port=result.get("port"),
                    confirmed=True,
                )
            )

    return findings


def verify_smb_host(host, service):
    ip = host["ip"]
    port = int(service.get("port", 445))

    result = {
        "mode": "REMOTE_SAFE",
        "port": port,
        "protocols": "",
        "security_mode": "",
        "evidence": "",
    }

    rc, out, err = run(
        [
            "nmap",
            "-Pn",
            "--host-timeout", "12s",
            "--script-timeout", "8s",
            "-p",
            str(port),
            "--script",
            "smb-protocols,smb2-security-mode",
            ip,
            "-oX",
            "-"
        ],
        timeout=15
    )

    if rc != 0:
        result["evidence"] = (
            "SMB verification failed: "
            + err.strip()[:180]
        )
        return result

    scripts = parse_nmap_script_output(
        out
    )

    result["protocols"] = scripts.get(
        "smb-protocols",
        ""
    )

    result["security_mode"] = scripts.get(
        "smb2-security-mode",
        ""
    )

    result["evidence"] = (
        "SMB protocol/security capabilities were enumerated "
        "without authentication."
    )

    return result


def smb_verification_findings(host):
    result = (
        host.get("verification", {})
        .get("smb")
    )

    if not result:
        return []

    findings = []

    protocols_raw = (
        result.get("protocols")
        or ""
    )

    security_raw = (
        result.get("security_mode")
        or ""
    )

    protocols = protocols_raw.lower()
    security = security_raw.lower()

    # Nmap commonly reports SMB1 as "NT LM 0.12".
    smb1 = (
        "nt lm 0.12" in protocols
        or "smbv1" in protocols
        or bool(
            re.search(
                r"(?mi)^\s*1\.0(?:0)?\b",
                protocols_raw
            )
        )
    )

    smb2plus = (
        "smb2" in protocols
        or "smb3" in protocols
        or bool(
            re.search(
                r"(?mi)^\s*[23]\.\d+",
                protocols_raw
            )
        )
    )

    signing_required = (
        "message signing enabled and required"
        in security
        or "signing enabled and required"
        in security
        or "message signing required"
        in security
    )

    signing_not_required = (
        "message signing enabled but not required"
        in security
        or "signing enabled but not required"
        in security
    )

    if smb1:
        findings.append(
            finding(
                "MEDIUM",
                "SMB1_ENABLED",
                "Legacy SMBv1 protocol appears enabled",
                (
                    "SMB protocol enumeration reported "
                    "SMBv1/NT LM 0.12 support."
                ),
                "CONFIRMED",
                port=result.get("port"),
                action=(
                    "Disable SMBv1 unless a documented "
                    "legacy dependency requires it."
                ),
                confirmed=True,
            )
        )

    if signing_not_required:
        findings.append(
            finding(
                "LOW",
                "SMB_SIGNING_NOT_REQUIRED",
                "SMB signing is supported but not required",
                (
                    "SMB security-mode enumeration reports "
                    "that message signing is not mandatory."
                ),
                "CONFIRMED",
                port=result.get("port"),
                action=(
                    "Require SMB signing where practical, "
                    "especially for authentication traffic."
                ),
                confirmed=True,
            )
        )

    if (
        not smb1
        and smb2plus
        and signing_required
    ):
        findings.append(
            finding(
                "INFO",
                "SMB_SECURE_BASELINE",
                "SMBv1 not detected and SMB signing is required",
                (
                    "Modern SMB was detected and "
                    "mandatory signing was reported."
                ),
                "CONFIRMED",
                port=result.get("port"),
                confirmed=True,
            )
        )

    elif (
        not findings
        and smb2plus
    ):
        findings.append(
            finding(
                "INFO",
                "SMB_MODERN",
                "Modern SMB protocol support detected",
                (
                    "SMB2/SMB3 support was observed and "
                    "SMBv1 was not identified."
                ),
                "HIGH",
                port=result.get("port"),
            )
        )

    elif not findings:
        findings.append(
            finding(
                "INFO",
                "SMB_REVIEWED",
                "SMB responded but posture was not fully classified",
                (
                    result.get("evidence")
                    or "SMB verification completed."
                ),
                "LOW",
                port=result.get("port"),
            )
        )

    return findings


def run_safe_verifiers(host):
    """
    Run independent protocol verifiers concurrently.

    Maximum of 4 verifier workers per host.

    Individual verifier failures are recorded and do not
    abort the rest of the host scan.
    """

    from concurrent.futures import (
        ThreadPoolExecutor,
        as_completed,
    )

    verification = {}

    services = host.get(
        "services",
        []
    )

    jobs = []

    # --------------------------------------------------------
    # Helper
    # --------------------------------------------------------

    def add_job(
        key,
        label,
        verifier,
        service
    ):
        if verifier.__name__ not in SAFE_VERIFIER_NAMES:
            raise RuntimeError('Verifier is not approved for automatic safe checks')
        jobs.append({
            "key": key,
            "label": label,
            "verifier": verifier,
            "service": service,
        })

    # --------------------------------------------------------
    # SSH
    # --------------------------------------------------------

    for service in services:
        name = (
            service.get("name")
            or ""
        ).lower()

        product = (
            service.get("product")
            or ""
        ).lower()

        if (
            service.get("port") == 22
            or name == "ssh"
            or "openssh" in product
        ):
            add_job(
                "ssh",
                (
                    f"VERIFY SSH : "
                    f"{host['ip']}:{service.get('port', 22)}"
                ),
                verify_ssh_host,
                service,
            )

            break

    # --------------------------------------------------------
    # RTSP
    # --------------------------------------------------------

    for service in services:
        name = (
            service.get("name")
            or ""
        ).lower()

        if (
            service.get("port") in (
                554,
                8554,
            )
            or name == "rtsp"
        ):
            add_job(
                "rtsp",
                (
                    f"VERIFY RTSP: "
                    f"{host['ip']}:{service.get('port', 554)}"
                ),
                verify_rtsp_host,
                service,
            )

            break

    # --------------------------------------------------------
    # FTP
    # --------------------------------------------------------

    for service in services:
        if (
            service.get("port") == 21
            or (
                service.get("name")
                or ""
            ).lower() == "ftp"
        ):
            add_job(
                "ftp",
                (
                    f"VERIFY FTP : "
                    f"{host['ip']}:{service.get('port', 21)}"
                ),
                verify_ftp_host,
                service,
            )

            break

    # --------------------------------------------------------
    # TELNET
    # --------------------------------------------------------

    for service in services:
        if (
            service.get("port") == 23
            or (
                service.get("name")
                or ""
            ).lower() == "telnet"
        ):
            add_job(
                "telnet",
                (
                    f"VERIFY TELNET: "
                    f"{host['ip']}:{service.get('port', 23)}"
                ),
                verify_telnet_host,
                service,
            )

            break

    # --------------------------------------------------------
    # HTTP
    #
    # Each HTTP port is its own job.
    # Results are collected into verification["http"].
    # --------------------------------------------------------

    for service in services:
        port = service.get(
            "port"
        )

        if port in (
            80,
            81,
            8000,
            8001,
            8008,
            8080,
            8081,
            8088,
            8888,
            9000,
            9090,
            10000,
        ):
            add_job(
                "http",
                (
                    f"VERIFY HTTP: "
                    f"{host['ip']}:{port}"
                ),
                verify_http_host,
                service,
            )

    # --------------------------------------------------------
    # SMB
    # --------------------------------------------------------

    for service in services:
        if service.get("port") == 445:
            add_job(
                "smb",
                (
                    f"VERIFY SMB : "
                    f"{host['ip']}:445"
                ),
                verify_smb_host,
                service,
            )

            break

    for service in services:
        if str(service.get('name','')).lower() == 'redis' or 'redis' in str(service.get('product','')).lower():
            add_job('redis', 'VERIFY REDIS PING', verify_redis_host, service)
            break

    if not jobs:
        host["verification"] = verification
        return verification

    # --------------------------------------------------------
    # Run jobs concurrently
    # --------------------------------------------------------

    worker_count = min(
        4,
        len(jobs)
    )

    if VERBOSE:
        print(
            f"  VERIFIER WORKERS: "
            f"{worker_count} "
            f"({len(jobs)} job(s))"
        )

        for job in jobs:
            print(
                f"  {job['label']}"
            )

    http_results = []

    with ThreadPoolExecutor(
        max_workers=worker_count
    ) as executor:

        future_map = {}

        for job in jobs:
            future = executor.submit(
                job["verifier"],
                host,
                job["service"]
            )

            future_map[
                future
            ] = job

        for future in as_completed(
            future_map
        ):
            job = future_map[
                future
            ]

            key = job[
                "key"
            ]

            try:
                result = future.result()

            except Exception as e:
                result = {
                    "mode": "REMOTE_SAFE",
                    "error": str(e),
                    "evidence": (
                        f"{key.upper()} verifier failed: "
                        f"{str(e)[:180]}"
                    ),
                }

                if VERBOSE:
                    print(
                        f"  VERIFY ERROR "
                        f"{host['ip']} "
                        f"{key.upper()}: {e}"
                    )

            if key == "http":
                http_results.append(
                    result
                )

            else:
                verification[
                    key
                ] = result

    if http_results:
        # Stable order for reports.
        http_results.sort(
            key=lambda r: int(
                r.get(
                    "port",
                    0
                )
                or 0
            )
        )

        verification[
            "http"
        ] = http_results

    host[
        "verification"
    ] = verification

    return verification

def ssh_cfg(host):
    return (
        host.get("verification", {})
        .get("ssh", {})
        .get("local_config")
        or {}
    )


def ssh_is_local_deep(host):
    return (
        host.get("verification", {})
        .get("ssh", {})
        .get("mode")
        == "LOCAL_DEEP"
    )



# ============================================================
# VENDOR / DISTRIBUTION SECURITY VERIFICATION
# ============================================================

def debian_tracker_load(max_age_hours=24):
    """
    Load Debian Security Tracker data.

    The database is cached locally because it is large.
    Failure is non-fatal; scanning falls back to normal
    applicability logic.
    """

    age = cache_age_hours(
        DEBIAN_TRACKER_FILE
    )

    if (
        age is not None
        and age <= max_age_hours
    ):
        try:
            return json.loads(
                DEBIAN_TRACKER_FILE.read_text()
            )
        except Exception:
            pass

    try:
        print(
            "  Vendor intel: refreshing Debian Security Tracker..."
        )

        req = urllib.request.Request(
            DEBIAN_TRACKER_URL,
            headers={
                "User-Agent": "SecScan/1.0"
            }
        )

        with urllib.request.urlopen(
            req,
            timeout=60
        ) as r:
            data = r.read()

        parsed = json.loads(
            data.decode("utf-8")
        )

        DEBIAN_TRACKER_FILE.write_bytes(
            data
        )

        return parsed

    except Exception as e:
        print(
            f"  Vendor intel warning: "
            f"Debian tracker unavailable: {e}"
        )

        # Fall back to stale cache if we have one.
        if DEBIAN_TRACKER_FILE.exists():
            try:
                return json.loads(
                    DEBIAN_TRACKER_FILE.read_text()
                )
            except Exception:
                pass

        return {}


def dpkg_version_ge(installed, fixed):
    """
    Debian package-version comparison.
    """

    if not installed or not fixed:
        return None

    if fixed in (
        "0",
        "",
        "(not affected)",
    ):
        return None

    rc, _, _ = run(
        [
            "dpkg",
            "--compare-versions",
            installed,
            "ge",
            fixed
        ],
        timeout=10
    )

    return rc == 0


def local_package_version(host):
    package = (
        host.get("verification", {})
        .get("ssh", {})
        .get("package", "")
    )

    # Example:
    # openssh-server 1:10.3p1-5

    parts = package.split(
        None,
        1
    )

    if len(parts) == 2:
        return parts[1].strip()

    return ""



def local_os_info(host):
    return (
        host.get("verification", {})
        .get("ssh", {})
        .get("os", {})
        or {}
    )


def local_os_vendor(host):
    return (
        local_os_info(host)
        .get("ID", "")
        .strip()
        .lower()
    )


def local_os_codename(host):
    return (
        local_os_info(host)
        .get("VERSION_CODENAME", "")
        .strip()
        .lower()
    )


def local_os_id_like(host):
    raw = (
        local_os_info(host)
        .get("ID_LIKE", "")
        .strip()
        .lower()
    )

    if not raw:
        return []

    return [
        x.strip()
        for x in raw.split()
        if x.strip()
    ]


def classify_linux(host):
    """
    Classify exact distro, family and package ecosystem.

    Exact distro identity is kept separate from family.
    ID_LIKE influences family only, never vendor authority.
    """

    info = local_os_info(host)

    distro = (
        info.get("ID", "")
        .strip()
        .lower()
    )

    name = (
        info.get("PRETTY_NAME")
        or info.get("NAME")
        or distro
        or "Linux"
    )

    version_id = (
        info.get("VERSION_ID", "")
        .strip()
    )

    codename = (
        info.get("VERSION_CODENAME", "")
        .strip()
        .lower()
    )

    id_like = local_os_id_like(host)

    family = "linux-generic"
    package_system = "unknown"
    package_manager = "unknown"

    debian_ids = {
        "debian",
        "ubuntu",
        "kali",
        "linuxmint",
        "pop",
        "raspbian",
        "elementary",
        "zorin",
        "parrot",
    }

    redhat_ids = {
        "rhel",
        "fedora",
        "centos",
        "rocky",
        "almalinux",
        "ol",
        "oracle",
    }

    suse_ids = {
        "opensuse",
        "opensuse-leap",
        "opensuse-tumbleweed",
        "sles",
        "sled",
    }

    arch_ids = {
        "arch",
        "manjaro",
        "endeavouros",
        "garuda",
    }

    alpine_ids = {
        "alpine",
    }

    if (
        distro in debian_ids
        or "debian" in id_like
        or "ubuntu" in id_like
    ):
        family = "debian"
        package_system = "dpkg"
        package_manager = "apt"

    elif (
        distro in redhat_ids
        or "rhel" in id_like
        or "fedora" in id_like
        or "centos" in id_like
    ):
        family = "redhat"
        package_system = "rpm"
        package_manager = "dnf"

    elif (
        distro in suse_ids
        or "suse" in id_like
        or "opensuse" in id_like
    ):
        family = "suse"
        package_system = "rpm"
        package_manager = "zypper"

    elif (
        distro in arch_ids
        or "arch" in id_like
    ):
        family = "arch"
        package_system = "pacman"
        package_manager = "pacman"

    elif distro in alpine_ids:
        family = "alpine"
        package_system = "apk"
        package_manager = "apk"

    return {
        "distro": distro or "unknown",
        "name": name,
        "version_id": version_id,
        "codename": codename,
        "id_like": id_like,
        "family": family,
        "package_system": package_system,
        "package_manager": package_manager,
    }


_DEBIAN_TRACKER_CACHE = None



def apt_package_policy(package):
    """
    Return installed/candidate versions from local APT metadata.
    No package changes are made.
    """

    result = {
        "installed": "",
        "candidate": "",
    }

    rc, out, _ = run(
        [
            "apt-cache",
            "policy",
            package
        ],
        timeout=15
    )

    if rc != 0:
        return result

    for raw in out.splitlines():
        line = raw.strip()

        if line.startswith("Installed:"):
            result["installed"] = (
                line.split(":", 1)[1].strip()
            )

        elif line.startswith("Candidate:"):
            result["candidate"] = (
                line.split(":", 1)[1].strip()
            )

    return result


def package_version_gt(a, b):
    if not a or not b:
        return None

    if a == "(none)" or b == "(none)":
        return None

    rc, _, _ = run(
        [
            "dpkg",
            "--compare-versions",
            a,
            "gt",
            b
        ],
        timeout=10
    )

    return rc == 0


def openssh_upstream_version(package_version):
    """
    Examples:

      1:10.3p1-5  -> 10.3p1
      10.4p1-4    -> 10.4p1
    """

    if not package_version:
        return ""

    value = package_version

    if ":" in value:
        value = value.split(
            ":",
            1
        )[1]

    # Strip Debian/Kali package revision.
    if "-" in value:
        value = value.split(
            "-",
            1
        )[0]

    return value.strip()


def openssh_numeric_tuple(version):
    """
    Convert 10.4p1 -> (10, 4, 1)
    """

    if not version:
        return None

    m = re.match(
        r"^(\d+)\.(\d+)(?:p(\d+))?",
        version
    )

    if not m:
        return None

    return (
        int(m.group(1)),
        int(m.group(2)),
        int(m.group(3) or 0),
    )


def openssh_advisory_cutoff(description):
    """
    Conservative extraction of phrases such as:

      before 10.4
      before 10.3
      before 9.6

    Returns a tuple suitable for version comparison.
    """

    desc = (
        description
        or ""
    )

    m = re.search(
        r"(?i)\bbefore\s+(\d+\.\d+(?:p\d+)?)",
        desc
    )

    if not m:
        return None

    return openssh_numeric_tuple(
        m.group(1)
    )



def rpm_package_policy(package):
    result = {
        "installed": "",
        "candidate": "",
    }

    rc, out, _ = run(
        [
            "rpm",
            "-q",
            "--qf",
            "%{VERSION}-%{RELEASE}\\n",
            package
        ],
        timeout=10
    )

    if rc == 0:
        result["installed"] = out.strip()

    # Try dnf first.
    rc, out, _ = run(
        [
            "dnf",
            "-q",
            "list",
            "--showduplicates",
            package
        ],
        timeout=20
    )

    if rc == 0:
        versions = []

        for raw in out.splitlines():
            line = raw.strip()

            if not line or line.startswith("Installed Packages"):
                continue

            parts = line.split()

            if len(parts) >= 2:
                versions.append(parts[1])

        if versions:
            result["candidate"] = versions[-1]

    return result


def zypper_package_policy(package):
    result = {
        "installed": "",
        "candidate": "",
    }

    rc, out, _ = run(
        [
            "rpm",
            "-q",
            "--qf",
            "%{VERSION}-%{RELEASE}\\n",
            package
        ],
        timeout=10
    )

    if rc == 0:
        result["installed"] = out.strip()

    rc, out, _ = run(
        [
            "zypper",
            "--non-interactive",
            "search",
            "--details",
            "--match-exact",
            package
        ],
        timeout=20
    )

    if rc == 0:
        for raw in out.splitlines():
            if "|" not in raw:
                continue

            parts = [
                x.strip()
                for x in raw.split("|")
            ]

            if len(parts) >= 4 and parts[1] == package:
                result["candidate"] = parts[3]

    return result


def pacman_package_policy(package):
    result = {
        "installed": "",
        "candidate": "",
    }

    rc, out, _ = run(
        [
            "pacman",
            "-Q",
            package
        ],
        timeout=10
    )

    if rc == 0:
        parts = out.strip().split()

        if len(parts) >= 2:
            result["installed"] = parts[1]

    rc, out, _ = run(
        [
            "pacman",
            "-Si",
            package
        ],
        timeout=15
    )

    if rc == 0:
        for raw in out.splitlines():
            if raw.startswith("Version"):
                result["candidate"] = (
                    raw.split(":", 1)[1].strip()
                )
                break

    return result


def apk_package_policy(package):
    result = {
        "installed": "",
        "candidate": "",
    }

    rc, out, _ = run(
        [
            "apk",
            "info",
            "-e",
            package
        ],
        timeout=10
    )

    if rc == 0:
        rc2, out2, _ = run(
            [
                "apk",
                "info",
                "-v",
                package
            ],
            timeout=10
        )

        if rc2 == 0:
            line = out2.strip().splitlines()[0] if out2.strip() else ""

            if line.startswith(package + "-"):
                result["installed"] = line[len(package) + 1:]

    rc, out, _ = run(
        [
            "apk",
            "policy",
            package
        ],
        timeout=15
    )

    if rc == 0:
        versions = []

        for raw in out.splitlines():
            line = raw.strip()

            if line.startswith(package + "-"):
                versions.append(
                    line[len(package) + 1:].split()[0]
                )

        if versions:
            result["candidate"] = versions[0]

    return result


def generic_package_policy(host, package):
    linux = classify_linux(host)

    family = linux["family"]

    if family == "debian":
        return apt_package_policy(package)

    if family == "redhat":
        return rpm_package_policy(package)

    if family == "suse":
        return zypper_package_policy(package)

    if family == "arch":
        return pacman_package_policy(package)

    if family == "alpine":
        return apk_package_policy(package)

    return {
        "installed": "",
        "candidate": "",
    }


def package_update_available(host, package):
    policy = generic_package_policy(
        host,
        package
    )

    installed = policy.get("installed")
    candidate = policy.get("candidate")

    linux = classify_linux(host)

    if not installed or not candidate:
        return {
            "available": None,
            "installed": installed,
            "candidate": candidate,
        }

    family = linux["family"]

    if family == "debian":
        newer = package_version_gt(
            candidate,
            installed
        )

    else:
        # For non-dpkg ecosystems we don't pretend version ordering
        # is universally comparable without native tooling.
        newer = (
            candidate != installed
        )

    return {
        "available": newer,
        "installed": installed,
        "candidate": candidate,
    }


def kali_openssh_status(host, description):
    result = {
        "vendor": "Kali",
        "state": "UNKNOWN",
        "installed_version": None,
        "candidate_version": None,
        "reason": None,
        "update_available": False,
    }

    policy = apt_package_policy(
        "openssh-server"
    )

    installed = (
        policy.get("installed")
        or local_package_version(host)
    )

    candidate = policy.get(
        "candidate"
    )

    result["installed_version"] = installed
    result["candidate_version"] = candidate

    if not installed:
        result["reason"] = (
            "Unable to determine installed Kali OpenSSH package."
        )
        return result

    installed_upstream = openssh_numeric_tuple(
        openssh_upstream_version(
            installed
        )
    )

    candidate_upstream = openssh_numeric_tuple(
        openssh_upstream_version(
            candidate
        )
    )

    cutoff = openssh_advisory_cutoff(
        description
    )

    newer_available = package_version_gt(
        candidate,
        installed
    )

    if newer_available is True:
        result["update_available"] = True

    # --------------------------------------------------------
    # Advisory gives a clean upstream cutoff.
    # --------------------------------------------------------

    if (
        cutoff is not None
        and installed_upstream is not None
    ):
        if installed_upstream >= cutoff:
            result["state"] = "FIXED"
            result["reason"] = (
                "Installed OpenSSH version is at or above "
                "the advisory's affected-version cutoff."
            )
            return result

        # Installed is below cutoff.
        if (
            candidate_upstream is not None
            and candidate_upstream >= cutoff
            and newer_available is True
        ):
            result["state"] = "UPDATE_AVAILABLE"
            result["reason"] = (
                f"Installed package {installed} is below the "
                f"advisory cutoff; APT candidate {candidate} "
                f"is newer and crosses that cutoff."
            )
            return result

        result["state"] = "AFFECTED"
        result["reason"] = (
            f"Installed package {installed} is below the "
            f"advisory cutoff and no confirmed fixed candidate "
            f"was identified from current APT metadata."
        )
        return result

    # --------------------------------------------------------
    # No safe cutoff extracted.
    # We can say an update exists, but not claim it fixes CVE.
    # --------------------------------------------------------

    if newer_available is True:
        result["state"] = "UPDATE_AVAILABLE_UNVERIFIED"
        result["reason"] = (
            f"APT candidate {candidate} is newer than installed "
            f"{installed}, but this scanner could not prove from "
            f"the advisory text that it fixes this CVE."
        )
        return result

    result["reason"] = (
        "Kali package is installed, but no definitive vendor "
        "CVE verdict could be derived safely."
    )

    return result


def vendor_cve_status(host, cve_id, description=""):
    """
    Distribution-aware vulnerability status.

    Exact vendor authority is kept distinct from family/package logic.

    Debian:
      Debian Security Tracker.

    Kali:
      Local APT metadata + conservative advisory cutoff.

    Ubuntu/RHEL/Fedora/Rocky/Alma/SUSE/Arch/Alpine/etc:
      Package-state awareness + conservative advisory cutoff/fallback.

    Remote systems do not receive local vendor verdicts.
    """

    result = {
        "vendor": None,
        "state": "UNKNOWN",
        "release": None,
        "urgency": None,
        "fixed_version": None,
        "installed_version": None,
        "candidate_version": None,
        "update_available": False,
        "reason": None,
        "linux_family": None,
        "package_system": None,
    }

    if not ssh_is_local_deep(host):
        return result

    linux = classify_linux(host)

    distro = linux["distro"]
    family = linux["family"]

    result["vendor"] = distro
    result["release"] = (
        linux.get("codename")
        or linux.get("version_id")
        or None
    )
    result["linux_family"] = family
    result["package_system"] = linux["package_system"]

    # --------------------------------------------------------
    # Kali
    # --------------------------------------------------------

    if distro == "kali":
        kali = kali_openssh_status(
            host,
            description
        )

        result.update(kali)

        return result

    # --------------------------------------------------------
    # Debian exact vendor authority
    # --------------------------------------------------------

    if distro == "debian":
        codename = local_os_codename(
            host
        )

        installed = local_package_version(
            host
        )

        if not codename or not installed:
            result["reason"] = (
                "Debian detected but release/package "
                "information is incomplete."
            )
            return result

        global _DEBIAN_TRACKER_CACHE

        if _DEBIAN_TRACKER_CACHE is None:
            _DEBIAN_TRACKER_CACHE = (
                debian_tracker_load()
            )

        data = _DEBIAN_TRACKER_CACHE

        package_data = data.get(
            "openssh",
            {}
        )

        cve_data = package_data.get(
            cve_id,
            {}
        )

        release_data = (
            cve_data.get(
                "releases",
                {}
            )
            .get(
                codename,
                {}
            )
        )

        if not release_data:
            result.update({
                "vendor": "Debian",
                "release": codename,
                "installed_version": installed,
                "reason": (
                    "CVE not found for this Debian release "
                    "in the cached vendor record."
                ),
            })

            return result

        status = (
            release_data.get(
                "status",
                ""
            )
            .strip()
            .lower()
        )

        urgency = release_data.get(
            "urgency"
        )

        fixed = (
            release_data.get(
                "fixed_version"
            )
            or ""
        )

        result.update({
            "vendor": "Debian",
            "release": codename,
            "urgency": urgency,
            "fixed_version": fixed,
            "installed_version": installed,
        })

        if fixed == "0":
            result["state"] = "NOT_AFFECTED"
            result["reason"] = (
                "Debian Security Tracker marks "
                "this release as not affected."
            )

            return result

        if status == "resolved":
            if fixed:
                installed_is_fixed = dpkg_version_ge(
                    installed,
                    fixed
                )

                if installed_is_fixed is True:
                    result["state"] = "FIXED"
                    result["reason"] = (
                        f"Installed Debian package {installed} "
                        f"is at or newer than fixed version {fixed}."
                    )

                elif installed_is_fixed is False:
                    result["state"] = "AFFECTED"
                    result["reason"] = (
                        f"Debian fixed version is {fixed}; "
                        f"installed package is {installed}."
                    )

            else:
                result["state"] = "FIXED"
                result["reason"] = (
                    "Debian Security Tracker marks "
                    "this release resolved."
                )

            return result

        if status == "open":
            result["state"] = "AFFECTED"
            result["reason"] = (
                "Debian Security Tracker currently "
                "marks this release vulnerable/open."
            )
            return result

        if status == "undetermined":
            result["state"] = "UNKNOWN"
            result["reason"] = (
                "Debian Security Tracker has not yet "
                "determined release applicability."
            )
            return result

        return result

    # --------------------------------------------------------
    # Other Linux distributions
    # --------------------------------------------------------

    policy = generic_package_policy(
        host,
        "openssh-server"
    )

    installed = (
        policy.get("installed")
        or local_package_version(host)
    )

    candidate = policy.get(
        "candidate"
    )

    result["installed_version"] = installed
    result["candidate_version"] = candidate

    cutoff = openssh_advisory_cutoff(
        description
    )

    installed_upstream = openssh_numeric_tuple(
        openssh_upstream_version(
            installed
        )
    )

    candidate_upstream = openssh_numeric_tuple(
        openssh_upstream_version(
            candidate
        )
    )

    update = package_update_available(
        host,
        "openssh-server"
    )

    if update.get("available") is True:
        result["update_available"] = True

    if (
        cutoff is not None
        and installed_upstream is not None
    ):
        if installed_upstream >= cutoff:
            result["state"] = "FIXED"
            result["reason"] = (
                "Installed OpenSSH version is at or above "
                "the advisory cutoff."
            )
            return result

        if (
            candidate_upstream is not None
            and candidate_upstream >= cutoff
            and update.get("available") is True
        ):
            result["state"] = "UPDATE_AVAILABLE"
            result["reason"] = (
                f"Installed package {installed} is below "
                f"the advisory cutoff; candidate {candidate} "
                f"crosses the cutoff."
            )
            return result

        result["state"] = "AFFECTED"
        result["reason"] = (
            f"Installed OpenSSH {installed} appears below "
            f"the advisory cutoff; vendor-specific CVE authority "
            f"is not yet implemented for {distro}."
        )

        return result

    if update.get("available") is True:
        result["state"] = "UPDATE_AVAILABLE_UNVERIFIED"
        result["reason"] = (
            f"A newer package {candidate} is available, "
            f"but this scanner cannot prove it fixes this CVE."
        )
        return result

    result["reason"] = (
        f"{linux['name']} classified as {family} family; "
        f"no exact vendor CVE verdict is available."
    )

    return result

def vendor_cap_severity(severity, vendor):
    """
    Vendor urgency may LOWER an upstream CVSS-derived severity.

    It never raises severity merely from vendor metadata.
    KEV / confirmed behavioural evidence remains separate.
    """

    urgency = str(
        vendor.get("urgency")
        or ""
    ).lower()

    if urgency in (
        "unimportant",
        "low",
    ):
        return cap_severity(
            severity,
            "LOW"
        )

    if urgency == "medium":
        return cap_severity(
            severity,
            "MEDIUM"
        )

    return severity


def assess_cve_applicability(host, service, cve_id, description):
    """
    Conservative applicability filter.

    Returns:
        {
            "status": "APPLICABLE" | "POSSIBLE" | "NOT_APPLICABLE",
            "reason": "...",
            "severity_cap": None | "INFO" | "LOW"
        }

    Goal:
      Do not promote a CVE just because a product/version string matches.
      Check whether the advisory context makes sense for the observed device
      and the service role we actually discovered.
    """

    desc = (description or "").lower()

    product_blob = " ".join(
        [
            service.get("name", ""),
            service.get("product", ""),
            service.get("version", ""),
            service.get("extrainfo", ""),
            host.get("hostname") or "",
            host.get("vendor") or "",
        ]
    ).lower()

    result = {
        "status": "APPLICABLE",
        "reason": "Versioned product match and reachable service.",
        "severity_cap": None,
    }

    # --------------------------------------------------------
    # Distribution / package-specific issues
    # --------------------------------------------------------

    redhat_terms = (
        "red hat",
        "rhel",
        "red hat enterprise linux",
    )

    if any(term in desc for term in redhat_terms):
        if not any(term in product_blob for term in redhat_terms):
            return {
                "status": "NOT_APPLICABLE",
                "reason": (
                    "Advisory is specific to Red Hat/RHEL packaging, "
                    "but the observed service does not identify as Red Hat/RHEL."
                ),
                "severity_cap": None,
            }

    # --------------------------------------------------------
    # Explicit client-side-only issues
    # --------------------------------------------------------

    client_only_phrases = (
        "only on the client side",
        "client side only",
        "occurs only on the client side",
    )

    if any(x in desc for x in client_only_phrases):
        return {
            "status": "NOT_APPLICABLE",
            "reason": (
                "Advisory explicitly describes client-side behavior, "
                "while this scan discovered a listening server service."
            ),
            "severity_cap": None,
        }

    # --------------------------------------------------------
    # ssh-agent issues are not automatically sshd exposure
    # --------------------------------------------------------

    if "ssh-agent" in desc:
        return {
            "status": "POSSIBLE",
            "reason": (
                "Issue affects ssh-agent behavior. A listening SSH server "
                "does not prove agent forwarding or agent exposure is in use."
            ),
            "severity_cap": "INFO",
        }

    # --------------------------------------------------------
    # SCP / SFTP client workflow issues
    # --------------------------------------------------------

    client_tools = (
        "scp ",
        "sftp ",
        "downloaded by scp",
        "downloaded files",
        "copy occurs between two remote destinations",
        "attacker-controlled server",
    )

    if any(x in desc for x in client_tools):
        return {
            "status": "POSSIBLE",
            "reason": (
                "Issue depends on a specific SCP/SFTP client workflow. "
                "An SSH listener alone does not establish that workflow."
            ),
            "severity_cap": "INFO",
        }

    # --------------------------------------------------------
    # Rowhammer / physical-memory assumptions
    # --------------------------------------------------------

    if "row hammer" in desc or "rowhammer" in desc:
        return {
            "status": "POSSIBLE",
            "reason": (
                "Issue depends on hardware/memory attack conditions and "
                "is not established merely by remote SSH reachability."
            ),
            "severity_cap": "INFO",
        }

    # --------------------------------------------------------
    # OpenSSH ssh client token-expansion injection
    # CVE-2023-51385
    #
    # A listening sshd service does NOT prove that the device
    # is using the vulnerable ssh client workflow/configuration.
    # --------------------------------------------------------

    if str(cve_id).upper() == "CVE-2023-51385":
        return {
            "status": "POSSIBLE",
            "reason": (
                "CVE-2023-51385 affects OpenSSH ssh client token "
                "expansion when attacker-influenced user/host values "
                "containing shell metacharacters are used by certain "
                "client configuration expansions. A reachable SSH "
                "server does not establish that vulnerable client "
                "workflow or configuration."
            ),
            "severity_cap": "INFO",
        }

    # --------------------------------------------------------
    # SSH-specific verified applicability
    # --------------------------------------------------------

    if (
        service.get("port") == 22
        or service.get("name", "").lower() == "ssh"
        or "openssh" in service.get("product", "").lower()
    ):
        local_deep = ssh_is_local_deep(host)
        cfg = ssh_cfg(host)

        # VerifyHostKeyDNS is an SSH CLIENT option.
        # A listening sshd service does not make this remotely applicable.
        if "verifyhostkeydns" in desc:
            return {
                "status": "NOT_APPLICABLE",
                "reason": (
                    "VerifyHostKeyDNS is an SSH client-side setting; "
                    "this finding came from a listening SSH server."
                ),
                "severity_cap": None,
            }

        # OPIE/PAM case can be checked locally.
        if "when using opie" in desc:
            if local_deep:
                pam_opie = (
                    host.get("verification", {})
                    .get("ssh", {})
                    .get("pam_opie", False)
                )

                if not pam_opie:
                    return {
                        "status": "NOT_APPLICABLE",
                        "reason": (
                            "Local PAM configuration was inspected and "
                            "no OPIE module was found."
                        ),
                        "severity_cap": None,
                    }

            return {
                "status": "POSSIBLE",
                "reason": (
                    "Advisory requires OPIE/PAM configuration that has "
                    "not been confirmed remotely."
                ),
                "severity_cap": "INFO",
            }

        # DisableForwarding / PermitTunnel interaction.
        if (
            "disableforwarding" in desc
            or "permitunnel" in desc
        ):
            if local_deep and cfg:
                disable_forwarding = cfg.get(
                    "disableforwarding",
                    ""
                ).lower()

                permit_tunnel = cfg.get(
                    "permittunnel",
                    ""
                ).lower()

                if not (
                    disable_forwarding == "yes"
                    and permit_tunnel not in ("", "no")
                ):
                    return {
                        "status": "NOT_APPLICABLE",
                        "reason": (
                            "Effective sshd configuration does not contain "
                            "the DisableForwarding=yes + PermitTunnel-enabled "
                            "condition required by the advisory."
                        ),
                        "severity_cap": None,
                    }

            return {
                "status": "POSSIBLE",
                "reason": (
                    "Advisory depends on DisableForwarding/PermitTunnel "
                    "configuration that cannot be confirmed remotely."
                ),
                "severity_cap": "INFO",
            }

        # X11 / agent forwarding configuration.
        if (
            "x11 forwarding" in desc
            or "agent forwarding" in desc
            or "disableforwarding directive" in desc
        ):
            if local_deep and cfg:
                x11 = cfg.get(
                    "x11forwarding",
                    ""
                ).lower()

                allow_agent = cfg.get(
                    "allowagentforwarding",
                    ""
                ).lower()

                if (
                    x11 == "no"
                    and allow_agent == "no"
                ):
                    return {
                        "status": "NOT_APPLICABLE",
                        "reason": (
                            "Effective local sshd configuration disables "
                            "both X11 and agent forwarding."
                        ),
                        "severity_cap": None,
                    }

            return {
                "status": "POSSIBLE",
                "reason": (
                    "Advisory depends on forwarding configuration that "
                    "has not been confirmed remotely."
                ),
                "severity_cap": "INFO",
            }

        # GSSAPI / Active Directory condition.
        if "gssapistrictacceptorcheck" in desc:
            if local_deep and cfg:
                gssapi = cfg.get(
                    "gssapiauthentication",
                    ""
                ).lower()

                if gssapi != "yes":
                    return {
                        "status": "NOT_APPLICABLE",
                        "reason": (
                            "Effective sshd configuration does not enable "
                            "GSSAPI authentication."
                        ),
                        "severity_cap": None,
                    }

            return {
                "status": "POSSIBLE",
                "reason": (
                    "Advisory requires a specific GSSAPI/AD configuration "
                    "that is not confirmed."
                ),
                "severity_cap": "INFO",
            }

    # --------------------------------------------------------
    # Other configuration-dependent advisories
    # --------------------------------------------------------

    config_phrases = (
        "when certain non-default configurations are used",
        "when a certificate authority",
        "principals option",
    )

    if any(x in desc for x in config_phrases):
        return {
            "status": "POSSIBLE",
            "reason": (
                "Advisory requires a specific optional configuration or "
                "feature that has not been confirmed by this scan."
            ),
            "severity_cap": "INFO",
        }

    return result


def cap_severity(severity, cap):
    if not cap:
        return severity

    order = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0,
    }

    if order.get(severity, 0) > order.get(cap, 0):
        return cap

    return severity



def filter_findings_for_cve(findings, cve_id):
    """
    Return only findings matching the requested CVE identifier.
    Comparison is case-insensitive.
    """
    if not cve_id:
        return findings

    wanted = str(cve_id).strip().upper()

    out = []

    for finding in findings or []:
        fid = str(
            finding.get("id")
            or finding.get("finding_id")
            or finding.get("name")
            or finding.get("title")
            or ""
        ).strip().upper()

        if fid == wanted:
            out.append(finding)
            continue

        cve = str(
            finding.get("cve")
            or finding.get("cve_id")
            or ""
        ).strip().upper()

        if cve == wanted:
            out.append(finding)

    return out


def cve_findings(
    host,
    service,
    kev,
    api_key,
    cache_hours,
    requested_cve=None
):
    results = []

    if requested_cve:
        requested_cve = str(
            requested_cve
        ).strip().upper()

    exact_cpes = []

    for raw in service.get("cpes", []):
        c = exact_version_cpe(raw)
        if c and c not in exact_cpes:
            exact_cpes.append(c)

    for cpe in exact_cpes:
        data, cached = nvd_lookup(
            cpe,
            api_key=api_key,
            max_cache_hours=cache_hours
        )

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")

            if not cve_id:
                continue

            if (
                requested_cve
                and str(cve_id).strip().upper()
                != requested_cve
            ):
                continue

            score, nvd_severity = get_cvss(cve)
            is_kev = cve_id in kev

            descriptions = cve.get("descriptions", [])
            desc = ""

            for d in descriptions:
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            # Conservative scanner:
            # exact version/CPE + live service = high applicability,
            # but this is NOT called confirmed exploitation.
            if is_kev:
                sev = "HIGH"
            elif score is not None and score >= 9.0:
                sev = "HIGH"
            elif score is not None and score >= 7.0:
                sev = "MEDIUM"
            elif score is not None and score >= 4.0:
                sev = "LOW"
            else:
                sev = "INFO"

            evidence = (
                f"Exact versioned CPE reported by service fingerprint: {cpe}. "
                f"Service TCP/{service['port']} is reachable."
            )

            if cached:
                evidence += " NVD result came from local cache."

            if is_kev:
                evidence += " CVE is present in CISA Known Exploited Vulnerabilities."

            applicability = assess_cve_applicability(
                host,
                service,
                cve_id,
                desc
            )

            if applicability["status"] == "NOT_APPLICABLE":
                continue

            sev = cap_severity(
                sev,
                applicability.get("severity_cap")
            )

            if applicability["status"] == "POSSIBLE":
                confidence = "POSSIBLE"
                evidence += (
                    " Applicability not confirmed: "
                    + applicability["reason"]
                )
            else:
                confidence = "HIGH"

            # ------------------------------------------------
            # Vendor/package verification
            # ------------------------------------------------

            vendor = vendor_cve_status(
                host,
                cve_id,
                desc
            )

            if vendor["state"] in (
                "FIXED",
                "NOT_AFFECTED",
            ):
                # Vendor/local package evidence disproves
                # this upstream version match.
                continue

            if vendor["state"] in (
                "AFFECTED",
                "UPDATE_AVAILABLE",
            ):
                confidence = "VENDOR"
                sev = vendor_cap_severity(
                    sev,
                    vendor
                )

                evidence += (
                    " Vendor verification: "
                    + (
                        vendor.get("reason")
                        or "affected"
                    )
                )

            elif (
                vendor["state"]
                == "UPDATE_AVAILABLE_UNVERIFIED"
            ):
                evidence += (
                    " Package update available, but CVE fix "
                    "status could not be proven from advisory text."
                )

            action = (
                "Review vendor advisory and confirm affected "
                "feature/configuration before remediation."
            )

            if vendor["state"] == "UPDATE_AVAILABLE":
                candidate = vendor.get(
                    "candidate_version"
                )

                action = (
                    f"Update openssh-server"
                    + (
                        f" to {candidate}"
                        if candidate
                        else ""
                    )
                    + "."
                )

            elif vendor["state"] == "AFFECTED":
                fixed = vendor.get(
                    "fixed_version"
                )

                if fixed:
                    action = (
                        f"Update to vendor package {fixed} "
                        f"or newer when available."
                    )
                else:
                    action = (
                        "Vendor currently marks this package affected; "
                        "apply the vendor update when available."
                    )

            if is_kev:
                kev_item = kev[cve_id]
                action = (
                    kev_item.get(
                        "requiredAction"
                    )
                    or action
                )

            item_finding = finding(
                sev,
                "CVE_MATCH",
                desc[:180] if desc else f"{cve_id} applies to detected CPE",
                evidence,
                confidence,
                service["port"],
                cve=cve_id,
                kev=is_kev,
                score=score,
                action=action,
                confirmed=False,
            )

            item_finding["applicability_status"] = (
                applicability.get("status")
            )
            item_finding["applicability_reason"] = (
                applicability.get("reason")
            )
            item_finding["applicability_severity_cap"] = (
                applicability.get("severity_cap")
            )

            item_finding["service_name"] = (
                service.get("name")
            )
            item_finding["service_product"] = (
                service.get("product")
            )
            item_finding["service_version"] = (
                service.get("version")
            )
            item_finding["service_cpe"] = cpe

            item_finding["vendor"] = vendor.get(
                "vendor"
            )
            item_finding["vendor_state"] = vendor.get(
                "state"
            )
            item_finding["vendor_release"] = vendor.get(
                "release"
            )
            item_finding["vendor_urgency"] = vendor.get(
                "urgency"
            )
            item_finding["vendor_fixed_version"] = vendor.get(
                "fixed_version"
            )
            item_finding["installed_version"] = vendor.get(
                "installed_version"
            )
            item_finding["candidate_version"] = vendor.get(
                "candidate_version"
            )
            item_finding["update_available"] = vendor.get(
                "update_available",
                False
            )

            results.append(
                item_finding
            )

    return results


def dedupe_findings(findings):
    seen = set()
    out = []

    for f in findings:
        key = (
            f.get("code"),
            f.get("cve"),
            f.get("port"),
            f.get("title")
        )

        if key in seen:
            continue

        seen.add(key)
        out.append(f)

    return out


def load_config():
    cfg = {
        "NVD_API_KEY": os.environ.get("NVD_API_KEY", ""),
        "NVD_CACHE_HOURS": os.environ.get("NVD_CACHE_HOURS", "24"),
        "BLE_SCAN_SECONDS": os.environ.get("BLE_SCAN_SECONDS", "15"),
    }

    conf = BASE / "secscan.conf"

    if conf.exists():
        for line in conf.read_text().splitlines():
            line = line.strip()

            if not line or line.startswith("#") or "=" not in line:
                continue

            k, v = line.split("=", 1)
            v = v.strip().strip('"').strip("'")

            if k in cfg and not cfg[k]:
                cfg[k] = v
            elif k in ("NVD_CACHE_HOURS", "BLE_SCAN_SECONDS"):
                cfg[k] = v

    try:
        cfg["NVD_CACHE_HOURS"] = int(cfg["NVD_CACHE_HOURS"])
    except Exception:
        cfg["NVD_CACHE_HOURS"] = 24

    try:
        cfg["BLE_SCAN_SECONDS"] = int(cfg["BLE_SCAN_SECONDS"])
    except Exception:
        cfg["BLE_SCAN_SECONDS"] = 15

    return cfg



# ============================================================
# BLE SECURITY
# ============================================================

BLE_MAC_RE = re.compile(
    r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"
)


def load_ble_authorized():
    authorized = {}

    if not BLE_AUTH_FILE.exists():
        return authorized

    for raw in BLE_AUTH_FILE.read_text().splitlines():
        raw = raw.strip()

        if not raw or raw.startswith("#"):
            continue

        parts = raw.split("|", 1)

        mac = parts[0].strip().upper()

        if not BLE_MAC_RE.fullmatch(mac):
            continue

        name = parts[1].strip() if len(parts) > 1 else ""

        authorized[mac] = name

    return authorized


def bluetooth_service_active():
    rc, out, _ = run(
        ["systemctl", "is-active", "bluetooth"],
        timeout=10
    )

    return rc == 0 and out.strip() == "active"


def start_bluetooth_service():
    rc, out, err = run(
        ["systemctl", "start", "bluetooth"],
        timeout=20
    )

    return rc == 0, err.strip()


def stop_bluetooth_service():
    rc, out, err = run(
        ["systemctl", "stop", "bluetooth"],
        timeout=20
    )

    return rc == 0, err.strip()


def bluetooth_available():
    rc, out, _ = run(
        ["bluetoothctl", "list"],
        timeout=10
    )

    return rc == 0 and "Controller" in out


def ble_info(mac):
    rc, out, _ = run(
        ["bluetoothctl", "info", mac],
        timeout=12
    )

    result = {
        "uuids": []
    }

    if rc != 0:
        return result

    for raw in out.splitlines():
        line = raw.strip()

        if line.startswith("UUID:"):
            value = line.split("UUID:", 1)[1].strip()
            if value:
                result["uuids"].append(value)
            continue

        if ":" not in line:
            continue

        key, value = line.split(":", 1)

        key = key.strip()
        value = value.strip()

        if key in {
            "Name",
            "Alias",
            "RSSI",
            "Paired",
            "Bonded",
            "Trusted",
            "Connected",
            "AddressType",
            "ManufacturerData",
            "TxPower"
        }:
            result[key] = value

    return result


def bool_yes(value):
    return str(value or "").strip().lower() == "yes"


def ble_scan(seconds):
    vprint()
    vprint(f"BLE DISCOVERY : {seconds}s passive scan")

    from cloverkit_security_radio import ble_output
    rc, out, err = ble_output(seconds)

    if rc != 0:
        return [], err.strip()

    devices = []
    seen = set()

    for line in out.splitlines():
        match = BLE_MAC_RE.search(line)

        if not match:
            continue

        mac = match.group(0).upper()

        if mac in seen:
            continue

        seen.add(mac)

        discovered_name = line[match.end():].strip()
        info = ble_info(mac)
        from cloverkit_security_radio import BLE_RECORDS
        advertisement=BLE_RECORDS.get(mac,{})
        if advertisement.get('name'):info.setdefault('Name',advertisement['name'])
        info['uuids']=sorted(set(info.get('uuids',[]))|set(advertisement.get('uuids',[])))
        values=advertisement.get('rssis',[])
        if values:info.setdefault('RSSI',round(sum(values)/len(values),1))
        if advertisement.get('tx_power') is not None:info.setdefault('TxPower',advertisement['tx_power'])

        name = (
            info.get("Name")
            or info.get("Alias")
            or discovered_name
            or ""
        )

        device = {
            "mac": mac,
            "name": name,
            "alias": info.get("Alias"),
            "address_type": info.get("AddressType"),
            "rssi": info.get("RSSI"),
            "tx_power": info.get("TxPower"),
            "paired": bool_yes(info.get("Paired")),
            "bonded": bool_yes(info.get("Bonded")),
            "trusted": bool_yes(info.get("Trusted")),
            "connected": bool_yes(info.get("Connected")),
            "uuids": info.get("uuids", []),
            "authorized": False,
            "authorized_name": "",
            "gatt_attributes": [],
            "findings": [],
        }

        devices.append(device)

    return devices, ""


def ble_passive_findings(device):
    findings = [finding('INFO','BLE_ADVERTISEMENT_OBSERVED','BLE advertisements observed; access controls not verified','Advertised presence, name and service UUIDs were inspected without connecting. Pairing/GATT security and exploitability are not established by advertisements.','HIGH',action='Use explicitly authorised read-only inspection for checks requiring a connection.')]

    name = device.get("name") or ""

    if re.search(
        r"(?i)(camera|cam|door|lock|alarm|garage|sensor|nvr|dvr)",
        name
    ):
        findings.append(
            finding(
                "INFO",
                "BLE_SECURITY_IOT",
                "BLE device may be security/IoT related",
                (
                    f"Advertised name '{name}' suggests a security or IoT "
                    "device. This is identification only and is not treated "
                    "as a vulnerability."
                ),
                "LOW",
                action=(
                    "Authorize this BLE address only if it is your device "
                    "and you want read-only active inspection."
                )
            )
        )

    return findings


def ble_gatt_enumerate(mac):
    #
    # Safe active BLE stage:
    #
    #   connect
    #   enumerate GATT attribute database
    #   disconnect
    #
    # Deliberately DOES NOT:
    #
    #   pair
    #   trust
    #   read values
    #   write values
    #   fuzz
    #   exploit
    #

    commands = (
        f"connect {mac}\n"
        "menu gatt\n"
        "list-attributes\n"
        "back\n"
        f"disconnect {mac}\n"
        "quit\n"
    )

    rc, out, err = run(
        ["bluetoothctl"],
        timeout=35,
        input_text=commands
    )

    clean = re.sub(
        r"\x1b\[[0-9;]*[A-Za-z]",
        "",
        out
    )

    attrs = []

    for line in clean.splitlines():
        stripped = line.strip()

        if (
            "/org/bluez/" in stripped
            and (
                "/service" in stripped
                or "/char" in stripped
                or "/desc" in stripped
            )
        ):
            attrs.append(stripped)

    connected = (
        "Connection successful" in clean
        or "Connected: yes" in clean
    )

    return {
        "connected": connected,
        "attributes": attrs,
        "stderr": err.strip(),
        "returncode": rc,
    }


def ble_active_findings(device):
    findings = []

    result = ble_gatt_enumerate(
        device["mac"]
    )

    device["gatt_attributes"] = result["attributes"]

    if result["connected"]:
        findings.append(
            finding(
                "INFO",
                "BLE_CONNECTION",
                "Authorized BLE device accepted a connection",
                (
                    "A BLE connection was established without initiating "
                    "pairing. Connectability alone is not a vulnerability."
                ),
                "CONFIRMED",
                confirmed=True
            )
        )

    if result["attributes"]:
        findings.append(
            finding(
                "INFO",
                "BLE_GATT_ENUM",
                "GATT database enumeration succeeded",
                (
                    f"{len(result['attributes'])} GATT attribute entries "
                    "were enumerated without reading or writing characteristic "
                    "values."
                ),
                "CONFIRMED",
                confirmed=True
            )
        )

    return findings


def print_ble_devices(devices, show_info=False):
    if not VERBOSE:
        return

    print()
    print("BLE DEVICES")
    print("------------------------------------------------------")

    if not devices:
        print("No BLE devices discovered.")
        return

    for dev in devices:
        auth = " AUTHORIZED" if dev.get("authorized") else ""

        title = f"{dev['mac']}"

        if dev.get("name"):
            title += f"  {dev['name']}"

        title += auth

        print()
        print(title)

        if dev.get("rssi") is not None:
            print(f"  RSSI       : {dev['rssi']}")

        if dev.get("address_type"):
            print(f"  Addr type  : {dev['address_type']}")

        if dev.get("paired"):
            print("  Paired     : YES")

        if dev.get("authorized_name"):
            print(f"  Auth name  : {dev['authorized_name']}")

        if dev.get("uuids"):
            print(f"  UUIDs      : {len(dev['uuids'])}")

        if dev.get("gatt_attributes"):
            print(f"  GATT attrs : {len(dev['gatt_attributes'])}")

        visible = [
            f for f in dev.get("findings", [])
            if show_info or f.get("severity") != "INFO"
        ]

        for f in visible:
            print(
                f"  {f['severity']:10s} "
                f"{f['code']} - {f['title']}"
            )



def add_network_identity_findings(hosts):
    """
    Detect one discovered MAC being associated with multiple IPs.

    This is informational, not an accusation of spoofing.
    Legitimate causes include gateways, proxy ARP, virtual
    networking, load balancers and unusual topology.
    """

    mac_hosts = {}

    for host in hosts:
        mac = (
            host.get("mac")
            or ""
        ).strip().upper()

        ip = host.get("ip")

        if not mac or not ip:
            continue

        mac_hosts.setdefault(
            mac,
            []
        ).append(host)

    for mac, members in mac_hosts.items():
        ips = sorted(
            {
                h.get("ip")
                for h in members
                if h.get("ip")
            }
        )

        if len(ips) < 2:
            continue

        evidence = (
            f"MAC {mac} was associated with multiple "
            f"discovered IPv4 addresses: "
            + ", ".join(ips)
            + ". This may be legitimate with proxy ARP, "
            "gateways or virtual networking."
        )

        for host in members:
            host.setdefault(
                "findings",
                []
            )

            host["findings"].append(
                finding(
                    "INFO",
                    "DUPLICATE_MAC",
                    "MAC address is associated with multiple discovered IPs",
                    evidence,
                    "HIGH",
                    action=(
                        "Confirm whether the shared MAC is "
                        "expected for this network topology."
                    ),
                )
            )

            host["findings"] = dedupe_findings(
                host["findings"]
            )


def print_host(host):
    if not VERBOSE:
        return

    title = host["ip"]

    if host.get("hostname"):
        title += f"  {host['hostname']}"

    if host.get("vendor"):
        title += f"  [{host['vendor']}]"

    print(f"\n{ANSI['BOLD'] if sys.stdout.isatty() else ''}{title}{ANSI['RESET'] if sys.stdout.isatty() else ''}")

    if host.get("mac"):
        print(f"  MAC: {host['mac']}")

    for svc in host.get("services", []):
        desc = " ".join(
            x for x in [
                svc.get("name"),
                svc.get("product"),
                svc.get("version"),
                svc.get("extrainfo")
            ]
            if x
        )

        print(f"  OPEN {svc['port']}/{svc['protocol']}  {desc}".rstrip())

    ssh_verify = (
        host.get("verification", {})
        .get("ssh")
    )

    if ssh_verify:
        print(
            f"  SSH VERIFY : "
            f"{ssh_verify.get('mode', 'REMOTE_SAFE')}"
        )

        if ssh_verify.get("banner"):
            print(
                f"  SSH BANNER : "
                f"{ssh_verify['banner']}"
            )

        if ssh_verify.get("package"):
            print(
                f"  SSH PACKAGE: "
                f"{ssh_verify['package']}"
            )

        if ssh_verify.get("mode") == "LOCAL_DEEP":
            linux = classify_linux(host)

            print(
                f"  OS CLASSIFY: "
                f"{linux['distro']} "
                f"(family={linux['family']}, "
                f"pkg={linux['package_system']})"
            )


def print_findings_detailed(all_hosts, ble_devices=None, show_info=False):
    if ble_devices is None:
        ble_devices = []

    findings = []

    host_meta = {}

    for host in all_hosts:
        target = host["ip"]

        host_meta[target] = {
            "hostname": host.get("hostname"),
            "vendor": host.get("vendor"),
            "type": "NETWORK",
        }

        for f in host.get("findings", []):
            row = dict(f)
            row["target"] = target
            row["target_type"] = "NETWORK"
            findings.append(row)

    for dev in ble_devices:
        target = dev["mac"]

        host_meta[target] = {
            "hostname": dev.get("name"),
            "vendor": None,
            "type": "BLE",
        }

        for f in dev.get("findings", []):
            row = dict(f)
            row["target"] = target
            row["target_type"] = "BLE"
            findings.append(row)

    findings.sort(
        key=lambda x: (
            SEVERITY_ORDER.get(x["severity"], 99),
            -float(x.get("cvss") or 0),
            x["target"],
        )
    )

    counts = {
        sev: sum(
            1
            for f in findings
            if f["severity"] == sev
        )
        for sev in SEVERITY_ORDER
    }

    print()
    print("======================================================")
    print(" SECURITY SCAN")
    print("======================================================")

    print(f"Network devices : {len(all_hosts)}")
    print(f"BLE devices     : {len(ble_devices)}")
    print(
        "BLE authorized  : "
        + str(
            sum(
                1
                for d in ble_devices
                if d.get("authorized")
            )
        )
    )

    for sev in [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
    ]:
        print(
            f"{colour(sev, sev):10s}: "
            f"{counts[sev]}"
        )

    visible = [
        f
        for f in findings
        if show_info or f["severity"] != "INFO"
    ]

    if not visible:
        print()
        print(
            "No actionable findings "
            "at the selected display level."
        )
        return

    # --------------------------------------------------------
    # Group findings by device
    # --------------------------------------------------------

    grouped = {}

    for f in visible:
        grouped.setdefault(
            f["target"],
            []
        ).append(f)

    def target_priority(item):
        target, rows = item

        highest = min(
            SEVERITY_ORDER.get(
                row["severity"],
                99
            )
            for row in rows
        )

        max_cvss = max(
            float(
                row.get("cvss")
                or 0
            )
            for row in rows
        )

        return (
            highest,
            -max_cvss,
            target
        )

    ordered_targets = sorted(
        grouped.items(),
        key=target_priority
    )

    print()
    print("DEVICE FINDINGS")
    print("======================================================")

    for target, rows in ordered_targets:
        rows.sort(
            key=lambda x: (
                SEVERITY_ORDER.get(
                    x["severity"],
                    99
                ),
                -float(
                    x.get("cvss")
                    or 0
                )
            )
        )

        highest = rows[0]["severity"]

        meta = host_meta.get(
            target,
            {}
        )

        name = meta.get("hostname")
        vendor = meta.get("vendor")

        header = (
            f"{colour(highest, highest):10s} "
            f"{target}"
        )

        if name:
            header += f"  {name}"

        if vendor:
            header += f"  [{vendor}]"

        print()
        print(header)
        print("------------------------------------------------------")

        print(
            f"Type     : "
            f"{meta.get('type', rows[0]['target_type'])}"
        )

        print(
            f"Findings : {len(rows)}"
        )

        print()

        # ----------------------------------------------------
        # Compact finding list
        # ----------------------------------------------------

        for f in rows:
            ident = (
                f.get("cve")
                or f.get("code")
                or "UNKNOWN"
            )

            line = (
                f"  {f['severity']:8s} "
                f"{ident}"
            )

            if (
                f.get("cve")
                and f.get("cvss") is not None
            ):
                line += (
                    f"  CVSS {f['cvss']}"
                )

            if f.get("port"):
                line += (
                    f"  port {f['port']}"
                )

            if f.get("kev"):
                line += "  KEV"

            if f.get("confirmed"):
                line += "  CONFIRMED"

            print(line)

            print(
                f"           "
                f"{f['title']}"
            )

        # ----------------------------------------------------
        # Consolidated advice
        # ----------------------------------------------------

        advice = []

        for f in rows:
            action = (
                f.get("action")
                or ""
            ).strip()

            if (
                action
                and action not in advice
            ):
                advice.append(action)

        if advice:
            print()
            print("ADVICE")

            for action in advice:
                print(
                    f"  - {action}"
                )

        # ----------------------------------------------------
        # Evidence summary
        # ----------------------------------------------------

        confirmed_count = sum(
            1
            for f in rows
            if f.get("confirmed")
        )

        kev_count = sum(
            1
            for f in rows
            if f.get("kev")
        )

        print()
        print("EVIDENCE SUMMARY")
        print(
            f"  Confirmed findings : "
            f"{confirmed_count}"
        )
        print(
            f"  CISA KEV findings  : "
            f"{kev_count}"
        )

        confidences = []

        for f in rows:
            c = f.get("confidence")

            if c and c not in confidences:
                confidences.append(c)

        if confidences:
            print(
                "  Confidence levels   : "
                + ", ".join(confidences)
            )

        print()
        print("======================================================")


def finding_plain_reason(f):
    """
    Short human-readable reason for executive output.
    """

    code = f.get("code")


    if code == "SCAN_INCOMPLETE":
        return (
            "Service inspection did not complete; "
            "do not treat this device as clean."
        )
    cve = f.get("cve")

    if code == "TELNET_LOGIN":
        return "Telnet login service confirmed."

    if code == "TELNET_SERVICE":
        return "Interactive service on TCP/23 confirmed."

    if code == "TELNET_UNKNOWN":
        return "TCP/23 open; Telnet login not confirmed."

    if code == "DUPLICATE_MAC":
        return "One MAC address is associated with multiple discovered IPs."

    if code == "SMB_SECURE_BASELINE":
        return "SMBv1 not detected; SMB signing is required."

    if code == "SMB_MODERN":
        return "Modern SMB detected; SMBv1 was not identified."

    if code == "FTP_PROTOCOL_UNCLEAR":
        return "TCP/21 responded, but normal FTP behaviour was not confirmed."

    if code == "FTP_ANONYMOUS_REJECTED":
        return "Anonymous FTP rejected; FTP transport remains plaintext."

    if code == "FTP_ANONYMOUS":
        return "Anonymous FTP login is allowed."

    if code == "FTP_PLAINTEXT_AUTH":
        return "FTP authentication required, but transport is plaintext."

    if code == "FTP_AUTH_UNKNOWN":
        return "FTP detected; authentication state unclear."

    if code == "HTTP_PLAINTEXT_LOGIN":
        return "Possible login/admin page is served over plaintext HTTP."

    if code == "HTTP_TO_HTTPS":
        return "HTTP redirects to HTTPS."

    if code == "SMB1_ENABLED":
        return "SMBv1 appears enabled."

    if code == "SMB_SIGNING_NOT_REQUIRED":
        return "SMB signing is not required."

    if code == "SMB_REVIEWED":
        return "SMB security capabilities were checked."

    if code == "TELNET_ENABLED":
        return "Telnet management is reachable."

    if code == "FTP_ENABLED":
        return "Plain FTP is reachable."

    if code == "RTSP_UNAUTHENTICATED":
        return "RTSP responds without authentication."

    if code == "RTSP_AUTH_REQUIRED":
        return "RTSP authentication is enforced."

    if code == "RTSP_AUTH_UNKNOWN":
        return "RTSP detected; authentication state is unclear."

    if code == "RTSP_PRESENT":
        return "Camera/video streaming service detected."

    if code == "MQTT_PLAINTEXT":
        return "Plaintext MQTT service detected."

    if code == "REDIS_REACHABLE":
        return "Redis service is reachable."

    if code == "MONGODB_REACHABLE":
        return "MongoDB service is reachable."

    if code == "PLAINTEXT_WEB_MGMT":
        return "Possible management interface is HTTP-only."

    if code == "HTTP_PRESENT":
        return "HTTP service detected without common HTTPS listener."

    if cve:
        vendor_state = f.get(
            "vendor_state"
        )

        if vendor_state == "UPDATE_AVAILABLE":
            installed = (
                f.get("installed_version")
                or "installed package"
            )

            candidate = (
                f.get("candidate_version")
                or "newer package"
            )

            return (
                f"Installed {installed}; "
                f"fixed/newer candidate {candidate} is available."
            )

        if vendor_state == "AFFECTED":
            vendor = (
                f.get("vendor")
                or "Vendor"
            )

            return (
                f"{vendor} confirms the installed "
                f"package/release is affected."
            )

        if f.get("confidence") == "POSSIBLE":
            return (
                "Version matches, but required "
                "conditions are not confirmed."
            )

        return (
            "Applicable software vulnerability "
            "match on a reachable service."
        )

    return f.get(
        "title",
        "Security finding"
    )


def finding_status_label(f):
    if f.get("code") == "SCAN_INCOMPLETE":
        return "INCOMPLETE"

    if f.get("confirmed"):
        return "CONFIRMED"

    if f.get("kev"):
        return "KEV"

    if f.get("vendor_state") == "UPDATE_AVAILABLE":
        return "UPDATE AVAILABLE"

    if f.get("vendor_state") == "AFFECTED":
        return "VENDOR"

    if f.get("confidence") == "POSSIBLE":
        return "POSSIBLE"

    return ""


def executive_visible(
    f,
    show_info=False,
    show_possible=False
):
    # An incomplete scan is operationally important even though
    # it is not itself a vulnerability severity.
    if f.get("code") == "SCAN_INCOMPLETE":
        return True
    # Speculative items do not clutter the normal report.
    if (
        f.get("confidence") == "POSSIBLE"
        and not show_possible
    ):
        return False

    if f.get("severity") != "INFO":
        return True

    if show_info:
        return True

    # A few INFO findings are still useful enough to show
    # in the executive view.
    if f.get("code") in (
        "RTSP_PRESENT",
        "RTSP_UNAUTHENTICATED",
    ):
        return True

    if f.get("confirmed"):
        return True

    if f.get("kev"):
        return True

    return False


def print_findings_executive(
    all_hosts,
    ble_devices=None,
    show_info=False,
    show_possible=False
):
    if ble_devices is None:
        ble_devices = []

    rows = []
    meta = {}

    for host in all_hosts:
        target = host["ip"]

        meta[target] = {
            "name": host.get(
                "hostname"
            ),
            "vendor": host.get(
                "vendor"
            ),
            "type": "NETWORK",
        }

        for f in host.get(
            "findings",
            []
        ):
            row = dict(f)
            row["target"] = target
            row["target_type"] = "NETWORK"
            rows.append(row)

    for dev in ble_devices:
        target = dev["mac"]

        meta[target] = {
            "name": dev.get(
                "name"
            ),
            "vendor": None,
            "type": "BLE",
        }

        for f in dev.get(
            "findings",
            []
        ):
            row = dict(f)
            row["target"] = target
            row["target_type"] = "BLE"
            rows.append(row)

    hidden_possible = sum(
        1
        for f in rows
        if (
            f.get("confidence")
            == "POSSIBLE"
        )
    )

    visible = [
        f
        for f in rows
        if executive_visible(
            f,
            show_info=show_info,
            show_possible=show_possible
        )
    ]

    visible.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(
                f["severity"],
                99
            ),
            -float(
                f.get("cvss")
                or 0
            ),
            f["target"],
        )
    )

    counts = {
        sev: sum(
            1
            for f in visible
            if f["severity"] == sev
        )
        for sev in SEVERITY_ORDER
    }

    print()
    print(
        "======================================================"
    )
    print(
        " SECURITY SCAN"
    )
    print(
        "======================================================"
    )

    print(
        f"Network : {len(all_hosts)} devices"
    )
    print(
        f"BLE     : {len(ble_devices)} devices"
    )

    print()

    for sev in (
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
    ):
        print(
            f"{colour(sev, sev):10s} "
            f"{counts[sev]}"
        )

    if show_info:
        print(
            f"{colour('INFO', 'INFO'):10s} "
            f"{counts['INFO']}"
        )

    if (
        hidden_possible
        and not show_possible
    ):
        print(
            f"POSSIBLE   {hidden_possible} hidden"
        )

    if not visible:
        print()
        print(
            "No actionable findings."
        )

        if hidden_possible:
            print(
                "Use --show-possible to review "
                "unverified matches."
            )

        return

    grouped = {}

    for f in visible:
        grouped.setdefault(
            f["target"],
            []
        ).append(f)

    def group_order(item):
        target, findings = item

        highest = min(
            SEVERITY_ORDER.get(
                f["severity"],
                99
            )
            for f in findings
        )

        return (
            highest,
            target
        )

    print()
    print(
        "NEEDS ATTENTION"
    )
    print(
        "------------------------------------------------------"
    )

    for target, findings in sorted(
        grouped.items(),
        key=group_order
    ):
        findings.sort(
            key=lambda f: (
                SEVERITY_ORDER.get(
                    f["severity"],
                    99
                ),
                -float(
                    f.get("cvss")
                    or 0
                )
            )
        )

        highest = findings[0][
            "severity"
        ]

        info = meta.get(
            target,
            {}
        )

        name = info.get(
            "name"
        )

        header = (
            f"{colour(highest, highest):10s} "
            f"{target}"
        )

        if name and name != target:
            header += f"  {name}"

        print()
        print(header)

        # Executive mode deliberately limits verbosity.
        # Three findings is enough to know whether to investigate.
        shown = findings[:3]

        for f in shown:
            ident = (
                f.get("cve")
                or f.get("code")
                or "UNKNOWN"
            )

            status = finding_status_label(
                f
            )

            line = (
                f"  {f['severity']:8s} "
                f"{ident}"
            )

            if (
                f.get("cve")
                and f.get("cvss") is not None
            ):
                line += (
                    f"  CVSS {f['cvss']}"
                )

            if status:
                line += (
                    f"  [{status}]"
                )

            print(line)

            print(
                "           "
                + finding_plain_reason(f)
            )

        remaining = (
            len(findings)
            - len(shown)
        )

        if remaining > 0:
            print(
                f"           +{remaining} more "
                f"(use --details)"
            )

        # Consolidate actions.
        actions = []

        for f in findings:
            action = (
                f.get("action")
                or ""
            ).strip()

            if (
                action
                and action not in actions
            ):
                actions.append(
                    action
                )

        if actions:
            print(
                "  Action : "
                + actions[0]
            )

            if len(actions) > 1:
                print(
                    f"           +{len(actions)-1} "
                    f"additional action(s) in --details"
                )

    print()
    print(
        "------------------------------------------------------"
    )

    if (
        hidden_possible
        and not show_possible
    ):
        print(
            f"{hidden_possible} speculative finding(s) hidden. "
            f"Use --show-possible if needed."
        )

    print(
        "Use --details for full evidence."
    )



def print_cve_validation(all_hosts, cve_id):
    """
    Focused one-CVE validation report.

    This is an applicability/evidence assessment only.
    It does not execute exploit code.
    """

    wanted = str(cve_id or "").strip().upper()

    host = None
    row = None

    for h in all_hosts or []:
        if host is None:
            host = h

        for f in h.get("findings", []):
            found = str(
                f.get("cve") or ""
            ).strip().upper()

            if found == wanted:
                host = h
                row = f
                break

        if row is not None:
            break

    print()
    print("======================================================")
    print(" CVE VALIDATION")
    print("======================================================")

    target = (
        host.get("ip")
        if host
        else "-"
    )

    hostname = (
        host.get("hostname")
        if host
        else None
    )

    print(f"Target      : {target}")

    if hostname:
        print(f"Hostname    : {hostname}")

    print(f"CVE         : {wanted}")

    if row is None:
        print()
        print("ASSESSMENT")
        print("------------------------------------------------------")
        print("Status      : NOT CONFIRMED")
        print(
            "Reason      : The requested CVE was not retained "
            "after service, version and applicability analysis."
        )
        print()
        print("No exploit executed.")
        return

    service_name = (
        row.get("service_name")
        or "unknown"
    )

    service_product = (
        row.get("service_product")
        or "-"
    )

    service_version = (
        row.get("service_version")
        or "-"
    )

    service_cpe = (
        row.get("service_cpe")
        or "-"
    )

    app_status = (
        row.get("applicability_status")
        or row.get("confidence")
        or "UNKNOWN"
    )

    app_reason = (
        row.get("applicability_reason")
        or row.get("evidence")
        or "-"
    )

    confidence = (
        row.get("confidence")
        or "UNKNOWN"
    )

    vendor_state = (
        row.get("vendor_state")
        or "UNKNOWN"
    )

    print(f"Service     : {service_name}")
    print(f"Port        : {row.get('port') or '-'}")

    if row.get("cvss") is not None:
        print(f"CVSS        : {row['cvss']}")

    print()
    print("SERVICE EVIDENCE")
    print("------------------------------------------------------")
    print(f"Product     : {service_product}")
    print(f"Version     : {service_version}")
    print(f"CPE         : {service_cpe}")
    print("Reachable   : YES")

    print()
    print("APPLICABILITY")
    print("------------------------------------------------------")
    print(f"Status      : {app_status}")
    print(f"Confidence  : {confidence}")
    print(f"Reason      : {app_reason}")

    print()
    print("VULNERABILITY")
    print("------------------------------------------------------")

    title = (
        row.get("title")
        or "-"
    )

    print(f"Description : {title}")
    print(
        f"CISA KEV    : "
        f"{'YES' if row.get('kev') else 'NO'}"
    )
    print(f"Vendor      : {vendor_state}")

    evidence = (
        row.get("evidence")
        or "-"
    )

    print()
    print("EVIDENCE")
    print("------------------------------------------------------")
    print(evidence)

    action = (
        row.get("action")
        or "No specific remediation action generated."
    )

    print()
    print("ACTION")
    print("------------------------------------------------------")
    print(action)

    print()
    print("ASSESSMENT")
    print("------------------------------------------------------")

    if app_status == "POSSIBLE":
        assessment = "POSSIBLE"
    elif app_status == "NOT_APPLICABLE":
        assessment = "NOT APPLICABLE"
    elif row.get("confirmed"):
        assessment = "CONFIRMED"
    elif confidence == "VENDOR":
        assessment = "VENDOR CONFIRMED"
    else:
        assessment = app_status

    print(f"Result      : {assessment}")

    if app_status == "POSSIBLE":
        print(
            "Meaning     : Product/service evidence exists, "
            "but required vulnerability conditions have not "
            "been confirmed."
        )

    print()
    print("Safe validation only. No exploit executed.")


def print_findings(
    all_hosts,
    ble_devices=None,
    show_info=False,
    details=False,
    show_possible=False
):
    focused_cve = next(
        (
            h.get("_focused_cve")
            for h in all_hosts
            if h.get("_focused_cve")
        ),
        None
    )

    if focused_cve:
        return print_cve_validation(
            all_hosts,
            focused_cve
        )

    if details:
        return print_findings_detailed(
            all_hosts,
            ble_devices=ble_devices,
            show_info=True
        )

    return print_findings_executive(
        all_hosts,
        ble_devices=ble_devices,
        show_info=show_info,
        show_possible=show_possible
    )


def security_housekeeping(
    report_keep=30,
    report_max_age_days=30,
    backup_keep=5,
):
    """
    Maintain sec-scan generated files.

    Reports:
      - latest.json is never touched
      - newest report_keep timestamped reports are always retained
      - reports beyond that count are removed only when older
        than report_max_age_days

    Source backups:
      - newest backup_keep secscan.py.before-* files retained
      - older backups removed

    Vulnerability intelligence caches are intentionally untouched.
    """

    removed_reports = []
    removed_backups = []
    freed_bytes = 0

    now = time.time()

    # --------------------------------------------------------
    # Timestamped reports
    # --------------------------------------------------------

    try:
        reports = sorted(
            REPORTS.glob(
                "secscan-*.json"
            ),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )

        protected = set(
            reports[:report_keep]
        )

        max_age_seconds = (
            report_max_age_days
            * 86400
        )

        for report in reports:
            if report in protected:
                continue

            try:
                age = (
                    now
                    - report.stat().st_mtime
                )

                if age <= max_age_seconds:
                    continue

                size = report.stat().st_size

                report.unlink()

                removed_reports.append(
                    report.name
                )

                freed_bytes += size

            except Exception as e:
                vprint(
                    f"Housekeeping warning: "
                    f"unable to remove report "
                    f"{report}: {e}"
                )

    except Exception as e:
        vprint(
            f"Housekeeping warning: "
            f"report cleanup failed: {e}"
        )

    # --------------------------------------------------------
    # Source-code backups
    # --------------------------------------------------------

    try:
        backups = sorted(
            BASE.glob(
                "secscan.py.before-*"
            ),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )

        for old_backup in backups[
            backup_keep:
        ]:
            try:
                size = (
                    old_backup.stat().st_size
                )

                old_backup.unlink()

                removed_backups.append(
                    old_backup.name
                )

                freed_bytes += size

            except Exception as e:
                vprint(
                    f"Housekeeping warning: "
                    f"unable to remove backup "
                    f"{old_backup}: {e}"
                )

    except Exception as e:
        vprint(
            f"Housekeeping warning: "
            f"backup cleanup failed: {e}"
        )

    if VERBOSE:
        print()
        print("HOUSEKEEPING")
        print(
            f"  Reports removed : "
            f"{len(removed_reports)}"
        )
        print(
            f"  Backups removed : "
            f"{len(removed_backups)}"
        )
        print(
            f"  Space reclaimed : "
            f"{freed_bytes / 1024:.1f} KiB"
        )

    return {
        "reports_removed": len(
            removed_reports
        ),
        "backups_removed": len(
            removed_backups
        ),
        "bytes_freed": freed_bytes,
    }


def save_report(hosts, target, ble_devices=None):
    if ble_devices is None:
        ble_devices = []

    REPORTS.mkdir(
        parents=True,
        exist_ok=True
    )

    ts = datetime.datetime.now().strftime(
        "%Y%m%d-%H%M%S"
    )

    path = (
        REPORTS
        / f"secscan-{ts}.json"
    )

    report = {
        "timestamp": (
            datetime.datetime.now()
            .astimezone()
            .isoformat()
        ),
        "target": target,
        "hosts": hosts,
        "ble_devices": ble_devices,
        "ble_coverage": __import__('cloverkit_security_radio').BLE_STATUS,
    }

    payload = json.dumps(
        report,
        indent=2
    )

    path.write_text(
        payload
    )

    latest = (
        REPORTS
        / "latest.json"
    )

    latest.write_text(
        payload
    )

    # Cleanup is deliberately after successful report writes.
    security_housekeeping()

    return path

def main():
    parser = argparse.ArgumentParser(
        description="Low-noise local network and BLE security scanner"
    )

    parser.add_argument(
        "--host",
        "--target",
        help="Scan one IP/hostname instead of the local subnet"
    )

    parser.add_argument(
        "--network",
        help="Explicit CIDR to scan, e.g. 192.0.2.0/24"
    )

    parser.add_argument(
        "--allow-wide-network",
        action="store_true",
        help=(
            "Explicitly allow a public or larger-than-/24 "
            "network supplied with --network"
        )
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Concurrent network host workers, 1-8 (default: 4)"
    )

    parser.add_argument(
        "--deep",
        action="store_true",
        help="Scan TCP 1-1024 plus selected infrastructure/IoT ports"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show live discovery, service and verifier diagnostics"
    )

    parser.add_argument(
        "--show-info",
        action="store_true",
        help="Include informational findings in executive output"
    )

    parser.add_argument(
        "--details",
        action="store_true",
        help="Show full technical findings, evidence and CVE details"
    )

    parser.add_argument(
        "--show-possible",
        action="store_true",
        help="Include speculative/unverified vulnerability matches"
    )

    parser.add_argument(
        "--cve",
        metavar="CVE-ID",
        help=(
            "Focus validation on one CVE. "
            "Use with --host/--target for a single device."
        ),
    )

    parser.add_argument(
        "--no-cve",
        action="store_true",
        help="Skip live/cached NVD correlation"
    )

    parser.add_argument(
        "--no-ble",
        action="store_true",
        help="Skip BLE discovery completely"
    )

    parser.add_argument(
        "--ble-only",
        action="store_true",
        help="Scan nearby BLE devices only; skip IP network scanning"
    )

    parser.add_argument(
        "--ble-active",
        action="store_true",
        help=(
            "Connect and enumerate GATT only for explicitly authorized "
            "BLE devices; no pairing, reads, writes, fuzzing or exploitation"
        )
    )

    parser.add_argument(
        "--ble-seconds",
        type=int,
        help="BLE passive scan duration in seconds"
    )

    parser.add_argument(
        "--update",
        action="store_true",
        help="Update vulnerability intelligence and exit"
    )

    parser.add_argument('--lab-override',action='store_true',help='SSH terminal only: request a reviewed lab test for a single --host and --cve; unsupported tests are refused')
    args = parser.parse_args()

    if args.cve:
        args.cve = args.cve.strip().upper()

        if not re.match(r"^CVE-\d{4}-\d{4,}$", args.cve):
            parser.error(
                "--cve must look like CVE-YYYY-NNNN"
            )

        if not args.host:
            parser.error(
                "--cve currently requires --host or --target"
            )

        if args.no_cve:
            parser.error(
                "--cve cannot be combined with --no-cve"
            )


    authorize_lab_override(args, parser)

    global VERBOSE
    VERBOSE = args.verbose

    cfg = load_config()

    CACHE.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)

    BLE_AUTH_FILE.touch(exist_ok=True)

    if args.update:
        ok = update_kev()
        sys.exit(0 if ok else 1)

    # Refresh KEV if absent or older than 24 hours.
    kev_age = cache_age_hours(KEV_FILE)

    if kev_age is None or kev_age > 24:
        update_kev()

    live_progress('Loading advisory data')
    kev = load_kev()

    completed = []
    ble_devices = []
    target = None

    # --------------------------------------------------------
    # IP NETWORK
    # --------------------------------------------------------

    if not args.ble_only:
        iface, auto_net = local_network()

        if args.host:
            # =================================================
            # TARGET DEVICE MODE
            #
            # Exactly one host.
            # No subnet discovery is performed.
            # =================================================

            target = args.host

            try:
                target_ip = socket.gethostbyname(
                    args.host
                )
            except Exception as e:
                print(
                    f"Unable to resolve target "
                    f"{args.host}: {e}"
                )
                return

            hosts = [{
                "ip": target_ip,
                "hostname": (
                    args.host
                    if not re.match(
                        r"^\d+\.",
                        args.host
                    )
                    else None
                ),
                "mac": None,
                "vendor": None,
            }]

            vprint("Mode      : TARGET DEVICE")
            vprint(f"Target    : {target_ip}")
            if args.cve:
                vprint("Mode      : CVE VALIDATION")
                vprint(f"CVE       : {args.cve}")

        else:
            # =================================================
            # NETWORK MODE
            # =================================================

            explicit_network = (
                args.network is not None
            )

            target = (
                args.network
                if explicit_network
                else auto_net
            )

            if not target:
                print(
                    "Unable to determine local IPv4 network."
                )
                print(
                    "Use: sec-scan --network 192.0.2.0/24"
                )
                return

            policy = network_scan_policy(
                target
            )

            if not policy["valid"]:
                print()
                print(
                    "SECURITY SCAN REFUSED"
                )
                print(
                    "------------------------------------------------------"
                )
                print(
                    f"Invalid network: {target}"
                )
                print(
                    f"Reason         : {policy['reason']}"
                )
                return

            target = policy[
                "network"
            ]

            # ---------------------------------------------
            # Automatic discovery is deliberately narrow.
            # ---------------------------------------------

            if not explicit_network:
                if (
                    not policy["private"]
                    or policy["wide"]
                ):
                    print()
                    print(
                        "SECURITY SCAN REFUSED"
                    )
                    print(
                        "------------------------------------------------------"
                    )
                    print(
                        f"Detected network : {target}"
                    )
                    print(
                        f"Addresses        : {policy['addresses']}"
                    )
                    print(
                        "Type             : "
                        + (
                            "RFC1918 PRIVATE"
                            if policy["private"]
                            else "PUBLIC / NON-RFC1918"
                        )
                    )
                    print()
                    print(
                        "Automatic discovery is limited to "
                        "RFC1918 networks of /24 or smaller."
                    )
                    print()
                    print(
                        "For a single device:"
                    )
                    print(
                        "  sec-scan --host <IP> --deep"
                    )
                    print()
                    print(
                        "For an explicitly authorised network:"
                    )
                    print(
                        "  sec-scan --network <CIDR>"
                    )

                    if (
                        not policy["private"]
                        or policy["wide"]
                    ):
                        print(
                            "  add --allow-wide-network "
                            "for public or larger-than-/24 ranges"
                        )

                    return

            # ---------------------------------------------
            # Explicit networks still get a safety gate.
            # ---------------------------------------------

            elif (
                (
                    not policy["private"]
                    or policy["wide"]
                )
                and not args.allow_wide_network
            ):
                print()
                print(
                    "SECURITY SCAN REFUSED"
                )
                print(
                    "------------------------------------------------------"
                )
                print(
                    f"Requested network: {target}"
                )
                print(
                    f"Addresses        : {policy['addresses']}"
                )
                print(
                    "Type             : "
                    + (
                        "RFC1918 PRIVATE"
                        if policy["private"]
                        else "PUBLIC / NON-RFC1918"
                    )
                )
                print()
                print(
                    "This range is public or larger than /24."
                )
                print(
                    "If you are authorised to scan it, rerun with:"
                )
                print()
                print(
                    f"  sec-scan --network {target} "
                    "--allow-wide-network"
                )
                return

            vprint(f"Interface : {iface}")
            vprint(
                "Mode      : "
                + (
                    "EXPLICIT NETWORK"
                    if explicit_network
                    else "AUTO LAN"
                )
            )
            vprint(f"Network   : {target}")

            live_progress('Discovering devices', target=target)
            hosts = discover(target)
            live_progress('Devices discovered', target=target, discovered=len(hosts))

        if hosts:
            vprint(f"Devices   : {len(hosts)}")
            vprint(f"CISA KEV  : {len(kev)} entries loaded")

        # ----------------------------------------------------
        # PHASE 1
        # Service scan + safe protocol verification
        # ----------------------------------------------------

        from concurrent.futures import (
            ThreadPoolExecutor,
            as_completed,
        )

        workers = max(
            1,
            min(
                int(args.workers or 4),
                8
            )
        )

        if VERBOSE:
            print(f"Network workers : {workers}")

        def scan_network_host(host):
            ip = host["ip"]

            _t_stage = time.monotonic()

            live_progress('Checking services', host=ip)
            services, err = service_scan(
                ip,
                deep=args.deep
            )

            vprint(
                f"  TIMING service_scan       "
                f"{time.monotonic() - _t_stage:.2f}s"
            )

            host["services"] = services
            host["scan_error"] = err

            # Safe verification only.
            # CVE/vendor work is intentionally NOT threaded.
            _t_stage = time.monotonic()

            live_progress('Verifying protocols', host=ip)
            run_safe_verifiers(host)

            vprint(
                f"  TIMING safe_verifiers     "
                f"{time.monotonic() - _t_stage:.2f}s"
            )

            _t_stage = time.monotonic()

            host["findings"] = config_checks(
                host,
                services
            )

            vprint(
                f"  TIMING config_checks      "
                f"{time.monotonic() - _t_stage:.2f}s"
            )

            return host

        scanned_hosts = []
        scan_complete = 0
        interrupted = False

        if hosts:
            if not VERBOSE:
                progress_bar(
                    0,
                    len(hosts),
                    "Scanning network"
                )

            executor = ThreadPoolExecutor(
                max_workers=workers
            )

            futures = {
                executor.submit(
                    scan_network_host,
                    host
                ): host
                for host in hosts
            }

            try:
                for future in as_completed(futures):
                    original = futures[future]

                    try:
                        host = future.result()

                    except Exception as e:
                        host = original

                        host.setdefault(
                            "services",
                            []
                        )

                        host["scan_error"] = (
                            "worker error: "
                            + str(e)
                        )

                        host["findings"] = config_checks(
                            host,
                            host.get("services", [])
                        )

                        if VERBOSE:
                            print(
                                f"Host worker error "
                                f"{host.get('ip')}: {e}"
                            )

                    scanned_hosts.append(host)

                    scan_complete += 1
                    live_progress('Device checked', host=host.get('ip'), completed=scan_complete, total=len(hosts), findings=len(host.get('findings', [])), error=host.get('scan_error'))

                    if not VERBOSE:
                        progress_bar(
                            scan_complete,
                            len(hosts),
                            "Scanning network"
                        )

            except KeyboardInterrupt:
                interrupted = True

                print()
                print(
                    "Scan cancelled - stopping queued host scans..."
                )

                for future in futures:
                    future.cancel()

            finally:
                executor.shutdown(
                    wait=not interrupted,
                    cancel_futures=True
                )

            if interrupted:
                return

        # Stable IP order after concurrent scanning.
        def host_ip_sort(host):
            try:
                return tuple(
                    int(part)
                    for part in host["ip"].split(".")
                )
            except Exception:
                return (
                    999,
                    999,
                    999,
                    999,
                )

        scanned_hosts.sort(
            key=host_ip_sort
        )

        # ----------------------------------------------------
        # PHASE 2
        # CVE / applicability / vendor analysis
        #
        # Deliberately sequential:
        #   - respects NVD throttling
        #   - preserves vendor cache behaviour
        #   - avoids concurrent external intelligence calls
        # ----------------------------------------------------

        total_analysis = len(scanned_hosts)

        if (
            total_analysis
            and not VERBOSE
        ):
            progress_bar(
                0,
                total_analysis,
                "Analysing"
            )

        try:
            for index, host in enumerate(
                scanned_hosts,
                1
            ):
                live_progress('Analysing advisories', host=host.get('ip'), completed=index-1, total=total_analysis)
                services = host.get(
                    "services",
                    []
                )

                if not args.no_cve:
                    unique_cpes = set()

                    for svc in services:
                        for raw in svc.get(
                            "cpes",
                            []
                        ):
                            c = exact_version_cpe(
                                raw
                            )

                            if (
                                not c
                                or c in unique_cpes
                            ):
                                continue

                            unique_cpes.add(c)

                            host["findings"].extend(
                                cve_findings(
                                    host,
                                    svc,
                                    kev,
                                    cfg["NVD_API_KEY"],
                                    cfg["NVD_CACHE_HOURS"],
                                    requested_cve=args.cve,
                                )
                            )

                host["findings"] = dedupe_findings(
                    host.get(
                        "findings",
                        []
                    )
                )

                # Focused CVE validation mode:
                # retain only the specifically requested CVE.
                if args.cve:
                    host["findings"] = (
                        filter_findings_for_cve(
                            host["findings"],
                            args.cve
                        )
                    )

                    host["_focused_cve"] = args.cve

                completed.append(host)
                live_progress('Analysis complete for device', host=host.get('ip'), completed=index, total=total_analysis, findings=len(host.get('findings', [])))

                if VERBOSE:
                    print_host(host)

                else:
                    progress_bar(
                        index,
                        total_analysis,
                        "Analysing"
                    )

        except KeyboardInterrupt:
            print()
            print(
                "Analysis cancelled - partial results retained."
            )

            # Keep anything already analysed rather than traceback.
            pass

    # --------------------------------------------------------
    # BLE
    # --------------------------------------------------------

    bt_started_by_secscan = False

    if not args.no_ble and not args.cve:
        was_active = bluetooth_service_active()

        if not was_active:
            vprint()
            vprint("BLE: starting Bluetooth service temporarily...")

            ok, err = start_bluetooth_service()

            if not ok:
                print(f"BLE: unable to start Bluetooth service: {err}")
            else:
                bt_started_by_secscan = True
                time.sleep(1)

        if bluetooth_service_active():
            if not bluetooth_available():
                print()
                print("BLE: Bluetooth service is active but no controller is available")

            else:
                seconds = (
                    args.ble_seconds
                    if args.ble_seconds is not None
                    else cfg["BLE_SCAN_SECONDS"]
                )

                if seconds < 3:
                    seconds = 3

                if not VERBOSE:
                    progress_bar(
                        0,
                        1,
                        "Scanning BLE"
                    )

                ble_devices, ble_error = ble_scan(seconds)

                if ble_error:
                    print(f"BLE warning: {ble_error}")

                authorized = load_ble_authorized()

                for dev in ble_devices:
                    mac = dev["mac"].upper()

                    if mac in authorized:
                        dev["authorized"] = True
                        dev["authorized_name"] = authorized[mac]

                    dev["findings"].extend(
                        ble_passive_findings(dev)
                    )

                    if (
                        args.ble_active
                        and dev["authorized"]
                    ):
                        print(
                            f"[BLE ACTIVE] {mac} "
                            f"{dev.get('authorized_name') or dev.get('name') or ''}"
                        )

                        dev["findings"].extend(
                            ble_active_findings(dev)
                        )

                    dev["findings"] = dedupe_findings(
                        dev["findings"]
                    )

                print_ble_devices(
                    ble_devices,
                    show_info=args.show_info
                )

                if not VERBOSE:
                    progress_bar(
                        1,
                        1,
                        "Scanning BLE"
                    )

        if bt_started_by_secscan:
            vprint()
            vprint("BLE: stopping temporary Bluetooth service...")

            ok, err = stop_bluetooth_service()

            if not ok:
                print(f"BLE warning: unable to stop Bluetooth service: {err}")

    add_network_identity_findings(completed)
    annotate_security_validation(completed)
    report = save_report(completed, target, ble_devices)

    print_findings(
        completed,
        ble_devices=ble_devices,
        show_info=args.show_info,
        details=args.details,
        show_possible=args.show_possible
    )

    print()
    print("------------------------------------------------------")
    print(f"Report: {report}")
    print(f"Latest: {REPORTS / 'latest.json'}")

    if args.details:
        print()
        print("Interpretation:")
        print("  CONFIRMED = safe behavioural validation succeeded")
        print("  VENDOR = package/vendor applicability confirmed")
        print("  UPDATE AVAILABLE = local package manager has a newer applicable package")
        print("  POSSIBLE = required condition has not been confirmed")
        print("  CVE match alone is NOT treated as proof of exploitability")
        print("  Unknown BLE devices = passive observation only")
        print("  Authorized BLE = connect/GATT enumeration only with --ble-active")


if __name__ == "__main__":
    main()
