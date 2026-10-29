#!/usr/bin/env python3

import argparse
import datetime
import ipaddress
import json
import os
import re
import socket
import statistics
import sys
import time
from pathlib import Path


BASE = Path("/mnt/security")
SCAN_REPORT = BASE / "reports" / "latest.json"
VALIDATOR_DIR = BASE / "validators"
VALIDATION_REPORTS = BASE / "validation-reports"
REGISTRY_FILE = VALIDATOR_DIR / "registry.json"
PATTERN_FILE = VALIDATOR_DIR / "patterns.json"
PROFILE_DIR = VALIDATOR_DIR / "profiles"

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)

RISK_ORDER = {
    "SAFE": 0,
    "ACTIVE": 1,
    "LAB_ONLY": 2,
}


# ============================================================
# BASIC HELPERS
# ============================================================

def load_json(path, default):
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def save_json(path, data):
    path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    path.write_text(
        json.dumps(
            data,
            indent=2
        )
    )


def validate_target(value):
    """
    Target validation deliberately accepts ONE literal IP only.

    No:
      CIDR
      hostnames
      ranges
      wildcard expansion
    """

    if "/" in value:
        raise ValueError(
            "CIDR/range targets are not allowed."
        )

    try:
        ip = ipaddress.ip_address(
            value
        )
    except Exception:
        raise ValueError(
            "Target must be one literal IPv4/IPv6 address."
        )

    return str(ip)


def validate_cve(value):
    value = value.upper().strip()

    if not CVE_RE.match(value):
        raise ValueError(
            "Invalid CVE format."
        )

    return value


# ============================================================
# PATTERN CATALOG / CVE PROFILES
# ============================================================

def load_pattern_catalog():
    data = load_json(
        PATTERN_FILE,
        {}
    )

    result = {}

    for item in data.get(
        "patterns",
        []
    ):
        pattern_id = item.get(
            "id"
        )

        if pattern_id:
            result[
                pattern_id
            ] = item

    return result


def load_cve_profile(cve):
    path = (
        PROFILE_DIR
        / f"{cve.upper()}.json"
    )

    if not path.exists():
        return None

    data = load_json(
        path,
        None
    )

    if not isinstance(
        data,
        dict
    ):
        return None

    return data


def validate_cve_profile(profile):
    errors = []

    if not isinstance(
        profile,
        dict
    ):
        return [
            "Profile is not a JSON object."
        ]

    required = (
        "cve",
        "pattern",
        "risk",
        "enabled",
        "description",
        "parameters",
    )

    for field in required:
        if field not in profile:
            errors.append(
                f"Missing field: {field}"
            )

    if errors:
        return errors

    try:
        validate_cve(
            profile["cve"]
        )
    except Exception as e:
        errors.append(
            f"Invalid CVE: {e}"
        )

    catalog = load_pattern_catalog()

    pattern = profile.get(
        "pattern"
    )

    if pattern not in catalog:
        errors.append(
            f"Unknown validation pattern: {pattern}"
        )

    risk = str(
        profile.get(
            "risk",
            ""
        )
    ).upper()

    if risk not in (
        "SAFE",
        "ACTIVE",
        "LAB_ONLY",
    ):
        errors.append(
            f"Invalid risk class: {risk}"
        )

    # A profile may only make a pattern MORE restrictive,
    # never less restrictive.
    if pattern in catalog:
        pattern_risk = (
            catalog[
                pattern
            ]
            .get(
                "risk",
                "LAB_ONLY"
            )
            .upper()
        )

        if (
            RISK_ORDER.get(
                risk,
                999
            )
            < RISK_ORDER.get(
                pattern_risk,
                999
            )
        ):
            errors.append(
                "Profile attempts to lower the catalog "
                f"safety class from {pattern_risk} to {risk}."
            )

    params = profile.get(
        "parameters"
    )

    if not isinstance(
        params,
        dict
    ):
        errors.append(
            "parameters must be a JSON object."
        )

    return errors


def print_patterns():
    catalog = load_pattern_catalog()

    families = {}

    for pattern in catalog.values():
        families.setdefault(
            pattern.get(
                "family",
                "OTHER"
            ),
            []
        ).append(
            pattern
        )

    print()
    print(
        "======================================================"
    )
    print(
        " CVE VALIDATION PATTERNS"
    )
    print(
        "======================================================"
    )
    print(
        f"Patterns : {len(catalog)}"
    )

    for family in sorted(
        families
    ):
        print()
        print(family)
        print(
            "------------------------------------------------------"
        )

        for pattern in sorted(
            families[family],
            key=lambda x: x["id"]
        ):
            status = (
                "READY"
                if pattern.get(
                    "implemented"
                )
                else "REGISTERED"
            )

            print(
                f"  {pattern['id']:<30s} "
                f"{pattern.get('risk','?'):<8s} "
                f"{status}"
            )


def print_profile(cve):
    profile = load_cve_profile(
        cve
    )

    print()
    print(
        "======================================================"
    )
    print(
        " CVE VALIDATION PROFILE"
    )
    print(
        "======================================================"
    )
    print(
        f"CVE : {cve}"
    )

    if profile is None:
        print()
        print(
            "Profile : NOT FOUND"
        )
        return

    errors = validate_cve_profile(
        profile
    )

    print(
        f"Pattern : "
        f"{profile.get('pattern')}"
    )
    print(
        f"Risk    : "
        f"{profile.get('risk')}"
    )
    print(
        f"Enabled : "
        f"{profile.get('enabled')}"
    )

    if errors:
        print()
        print("PROFILE ERRORS")

        for error in errors:
            print(
                f"  - {error}"
            )

    else:
        print()
        print(
            "Profile validation: PASS"
        )


# ============================================================
# REGISTRY
# ============================================================

def load_registry():
    data = load_json(
        REGISTRY_FILE,
        {}
    )

    if not isinstance(data, dict):
        return {}

    return data


def validator_for(cve):
    registry = load_registry()

    entry = registry.get(
        cve.upper()
    )

    if not isinstance(entry, dict):
        return None

    return entry


# ============================================================
# SECSCAN EVIDENCE
# ============================================================

def latest_scan_host(target):
    data = load_json(
        SCAN_REPORT,
        {}
    )

    for host in data.get(
        "hosts",
        []
    ):
        if host.get("ip") == target:
            return host

    return None


def latest_scan_cve(target, cve):
    host = latest_scan_host(
        target
    )

    if not host:
        return None

    for finding in host.get(
        "findings",
        []
    ):
        if (
            str(finding.get("cve") or "")
            .upper()
            == cve.upper()
        ):
            return finding

    return None


# ============================================================
# HEALTH MONITORING
# ============================================================

def candidate_health_ports(target):
    host = latest_scan_host(
        target
    )

    if not host:
        return []

    ports = []

    for service in host.get(
        "services",
        []
    ):
        try:
            port = int(
                service.get("port")
            )
        except Exception:
            continue

        if port not in ports:
            ports.append(port)

    # Three is enough for health monitoring.
    return ports[:3]


def tcp_health_once(target, port, timeout=1.5):
    started = time.monotonic()

    try:
        with socket.create_connection(
            (target, int(port)),
            timeout=timeout
        ):
            elapsed = (
                time.monotonic()
                - started
            )

            return {
                "port": int(port),
                "reachable": True,
                "latency_ms": round(
                    elapsed * 1000,
                    2
                ),
                "error": None,
            }

    except Exception as e:
        elapsed = (
            time.monotonic()
            - started
        )

        return {
            "port": int(port),
            "reachable": False,
            "latency_ms": round(
                elapsed * 1000,
                2
            ),
            "error": str(e)[:160],
        }


def health_snapshot(target, ports):
    results = [
        tcp_health_once(
            target,
            port
        )
        for port in ports
    ]

    reachable = [
        r
        for r in results
        if r["reachable"]
    ]

    latencies = [
        r["latency_ms"]
        for r in reachable
    ]

    return {
        "timestamp": (
            datetime.datetime.now()
            .astimezone()
            .isoformat()
        ),
        "ports": results,
        "reachable_count": len(
            reachable
        ),
        "median_latency_ms": (
            round(
                statistics.median(
                    latencies
                ),
                2
            )
            if latencies
            else None
        ),
    }


def health_degraded(before, after):
    """
    Conservative health degradation check.

    A validator must not interpret degradation as proof of
    vulnerability.
    """

    if (
        after["reachable_count"]
        < before["reachable_count"]
    ):
        return True, (
            "One or more baseline services "
            "became unreachable."
        )

    b = before.get(
        "median_latency_ms"
    )

    a = after.get(
        "median_latency_ms"
    )

    if (
        b is not None
        and a is not None
        and b >= 1
        and a > max(
            b * 4,
            b + 1000
        )
    ):
        return True, (
            "Target latency increased materially "
            "during validation."
        )

    return False, ""


# ============================================================
# VALIDATOR IMPLEMENTATIONS
#
# IMPORTANT:
#
# Validators are explicitly registered here.
# There is intentionally NO arbitrary script/module loader.
#
# That prevents sec-validate becoming a generic exploit runner.
# ============================================================

def validator_not_implemented(
    target,
    cve,
    context
):
    return {
        "result": "INCONCLUSIVE",
        "confidence": "NONE",
        "evidence": (
            "No CVE-specific validator has been "
            "implemented."
        ),
    }


VALIDATORS = {
    # Added deliberately, one CVE at a time.
    #
    # Example later:
    #
    # "CVE-2026-12345": validate_cve_2026_12345,
}


# ============================================================
# SAFETY GATES
# ============================================================

def execution_confirmation(
    target,
    cve,
    risk,
    lab_requested=False
):
    """
    Per-run interactive authorization gate.

    SAFE / BOUNDED:
        Exact RUN phrase required.

    LAB_ONLY:
        --lab must have been explicitly requested.
        Exact LAB authorization phrase required.
        Fresh sudo authentication is then required separately.
    """

    print()
    print(
        "======================================================"
    )

    if risk == "LAB_ONLY":
        print(" LAB VALIDATION AUTHORIZATION")
    else:
        print(" ACTIVE CVE VALIDATION")

    print(
        "======================================================"
    )
    print(f"Target : {target}")
    print(f"CVE    : {cve}")
    print(f"Risk   : {risk}")
    print()

    if not sys.stdin.isatty():
        print(
            "REFUSED: active validation requires "
            "an interactive terminal."
        )
        return False

    if risk == "LAB_ONLY":
        if not lab_requested:
            print(
                "REFUSED: this validator is LAB_ONLY."
            )
            print(
                "Explicit --lab activation is required."
            )
            return False

        phrase = (
            f"AUTHORISE LAB TEST {target} {cve}"
        )

        print(
            "This validator is outside normal SAFE/BOUNDED "
            "validation."
        )
        print()
        print(
            "The test remains restricted to exactly this "
            "target, CVE and registered validator."
        )
        print()
        print(
            "Type the following exact phrase to continue:"
        )
        print()
        print(f"  {phrase}")
        print()

        entered = input("> ").strip()

        return entered == phrase

    phrase = (
        f"RUN {cve} ON {target}"
    )

    print(
        "This will perform one bounded CVE-specific "
        "validation against exactly this IP."
    )
    print()
    print(
        "Type the following exact phrase to continue:"
    )
    print()
    print(f"  {phrase}")
    print()

    entered = input("> ").strip()

    return entered == phrase


# ============================================================
# REPORTING
# ============================================================

def save_validation_report(report):
    VALIDATION_REPORTS.mkdir(
        parents=True,
        exist_ok=True
    )

    stamp = (
        datetime.datetime.now()
        .strftime("%Y%m%d-%H%M%S")
    )

    path = (
        VALIDATION_REPORTS
        / f"validation-{stamp}.json"
    )

    save_json(
        path,
        report
    )

    save_json(
        VALIDATION_REPORTS / "latest.json",
        report
    )

    return path


# ============================================================
# PLAN
# ============================================================

def print_plan(target, cve):
    finding = latest_scan_cve(
        target,
        cve
    )

    validator = validator_for(
        cve
    )

    print()
    print(
        "======================================================"
    )
    print(
        " CVE VALIDATION PLAN"
    )
    print(
        "======================================================"
    )
    print(f"Target : {target}")
    print(f"CVE    : {cve}")

    print()

    if finding:
        print("SECSCAN EVIDENCE")

        if finding.get(
            "severity"
        ):
            print(
                f"  Context severity : "
                f"{finding['severity']}"
            )

        if finding.get(
            "cvss"
        ) is not None:
            print(
                f"  CVSS             : "
                f"{finding['cvss']}"
            )

        if finding.get(
            "confidence"
        ):
            print(
                f"  Confidence       : "
                f"{finding['confidence']}"
            )

        if finding.get(
            "vendor_state"
        ):
            print(
                f"  Vendor state     : "
                f"{finding['vendor_state']}"
            )

    else:
        print(
            "SECSCAN EVIDENCE"
        )
        print(
            "  No matching CVE finding was found "
            "in latest.json."
        )

    print()
    print("VALIDATOR")

    if not validator:
        print(
            "  Status : NOT IMPLEMENTED"
        )
        print(
            "  Action : Add a CVE-specific validator "
            "before active testing."
        )
        return

    print(
        f"  Status : AVAILABLE"
    )
    print(
        f"  Risk   : "
        f"{validator.get('risk', 'UNKNOWN')}"
    )
    print(
        f"  Method : "
        f"{validator.get('description', '')}"
    )

    if validator.get(
        "notes"
    ):
        print(
            f"  Notes  : "
            f"{validator['notes']}"
        )


# ============================================================
# EXECUTION
# ============================================================

def execute_validation(
    target,
    cve,
    authorized,
    lab_requested=False
):
    validator_meta = validator_for(
        cve
    )

    if not validator_meta:
        print(
            "No validator is registered for this CVE."
        )
        return 2

    risk = (
        validator_meta.get(
            "risk",
            ""
        )
        .upper()
    )

    if risk not in RISK_ORDER:
        print(
            "Validator has an invalid risk classification."
        )
        return 2

    if risk == "LAB_ONLY" and not lab_requested:
        print(
            "REFUSED: validator is LAB_ONLY."
        )
        print(
            "Explicit --lab activation is required."
        )
        return 2

    if lab_requested and risk != "LAB_ONLY":
        print(
            "REFUSED: --lab may only be used with a "
            "registered LAB_ONLY validator."
        )
        return 2

    if not authorized:
        print(
            "REFUSED: --ack-authorized is required."
        )
        return 2

    implementation = VALIDATORS.get(
        cve
    )

    if implementation is None:
        print(
            "Validator metadata exists, but no implementation "
            "is loaded."
        )
        return 2

    if not execution_confirmation(
        target,
        cve,
        risk,
        lab_requested=lab_requested
    ):
        print(
            "Validation cancelled."
        )
        return 2

    sudo_reauthenticated = False

    if risk == "LAB_ONLY":
        import subprocess

        print()
        print(
            "Written LAB authorization : ACCEPTED"
        )
        print(
            "Fresh sudo authentication : REQUIRED"
        )
        print()

        # Deliberately invalidate any cached sudo timestamp.
        subprocess.run(
            ["sudo", "-K"],
            check=False
        )

        auth = subprocess.run(
            ["sudo", "-v"],
            check=False
        )

        if auth.returncode != 0:
            print()
            print(
                "REFUSED: fresh sudo authentication failed."
            )
            return 2

        sudo_reauthenticated = True

        print()
        print(
            "Fresh sudo authentication : ACCEPTED"
        )

    health_ports = candidate_health_ports(
        target
    )

    if not health_ports:
        print(
            "Unable to establish baseline health ports."
        )
        print(
            "Active validation will not run without "
            "a health baseline."
        )
        return 2

    print()
    print(
        "Pre-validation health check..."
    )

    before = health_snapshot(
        target,
        health_ports
    )

    if before[
        "reachable_count"
    ] == 0:
        print(
            "REFUSED: target health baseline could not "
            "be established."
        )
        return 2

    context = {
        "latest_scan": latest_scan_host(
            target
        ),
        "validator": validator_meta,
        "pre_health": before,
    }

    started = time.monotonic()

    try:
        result = implementation(
            target,
            cve,
            context
        )

    except Exception as e:
        result = {
            "result": "INCONCLUSIVE",
            "confidence": "NONE",
            "evidence": (
                "Validator raised an exception: "
                + str(e)[:250]
            ),
        }

    elapsed = (
        time.monotonic()
        - started
    )

    # Absolute framework-level execution cap.
    if elapsed > 30:
        result = {
            "result": "INCONCLUSIVE",
            "confidence": "NONE",
            "evidence": (
                "Validator exceeded the framework's "
                "30-second execution budget."
            ),
        }

    print(
        "Post-validation health check..."
    )

    after = health_snapshot(
        target,
        health_ports
    )

    degraded, reason = health_degraded(
        before,
        after
    )

    if degraded:
        result = {
            "result": (
                "ABORTED_HEALTH_DEGRADATION"
            ),
            "confidence": "NONE",
            "evidence": reason,
        }

    report = {
        "timestamp": (
            datetime.datetime.now()
            .astimezone()
            .isoformat()
        ),
        "target": target,
        "cve": cve,
        "risk": risk,
        "authorization": {
            "authorized_target": bool(authorized),
            "lab_requested": bool(lab_requested),
            "written_override": (
                True
                if risk == "LAB_ONLY"
                else False
            ),
            "sudo_reauthenticated": bool(
                sudo_reauthenticated
            ),
        },
        "pre_health": before,
        "post_health": after,
        "validator_result": result,
        "duration_seconds": round(
            elapsed,
            3
        ),
    }

    report_path = save_validation_report(
        report
    )

    print()
    print(
        "======================================================"
    )
    print(
        " CVE VALIDATION RESULT"
    )
    print(
        "======================================================"
    )
    print(
        f"Result     : "
        f"{result.get('result', 'INCONCLUSIVE')}"
    )
    print(
        f"Confidence : "
        f"{result.get('confidence', 'NONE')}"
    )
    print(
        f"Health     : "
        + (
            "DEGRADED"
            if degraded
            else "UNCHANGED"
        )
    )

    if result.get(
        "evidence"
    ):
        print(
            f"Evidence   : "
            f"{result['evidence']}"
        )

    print()
    print(
        f"Report     : {report_path}"
    )

    return 0


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Explicit single-target CVE validation framework"
        )
    )

    parser.add_argument(
        "--host",
        required=False,
        help=(
            "Exactly one literal target IP address"
        )
    )

    parser.add_argument(
        "--cve",
        required=False,
        help="One CVE identifier"
    )

    mode = parser.add_mutually_exclusive_group(
        required=False
    )

    mode.add_argument(
        "--plan",
        action="store_true",
        help=(
            "Show validation availability and safety "
            "classification without executing anything"
        )
    )

    mode.add_argument(
        "--execute",
        action="store_true",
        help=(
            "Run the explicitly registered validator"
        )
    )

    parser.add_argument(
        "--ack-authorized",
        action="store_true",
        help=(
            "Confirm that you are authorized to assess "
            "the target device"
        )
    )

    parser.add_argument(
        "--lab",
        action="store_true",
        help=(
            "Explicitly request a registered LAB_ONLY "
            "validator. Requires written authorization "
            "and fresh sudo authentication."
        )
    )

    parser.add_argument(
        "--patterns",
        action="store_true",
        help="List the 60 registered validation patterns"
    )

    parser.add_argument(
        "--profile",
        metavar="CVE",
        help="Show and validate a CVE profile"
    )

    args = parser.parse_args()

    if args.patterns:
        print_patterns()
        return 0

    if args.profile:
        try:
            profile_cve = validate_cve(
                args.profile
            )
        except ValueError as e:
            print(
                f"REFUSED: {e}"
            )
            return 2

        print_profile(
            profile_cve
        )
        return 0

    if not args.host or not args.cve:
        parser.error(
            "--host and --cve are required for --plan/--execute"
        )

    if not args.plan and not args.execute:
        parser.error(
            "one of --plan or --execute is required"
        )

    try:
        target = validate_target(
            args.host
        )

        cve = validate_cve(
            args.cve
        )

    except ValueError as e:
        print(
            f"REFUSED: {e}"
        )
        return 2

    if args.plan:
        print_plan(
            target,
            cve
        )
        return 0

    return execute_validation(
        target,
        cve,
        args.ack_authorized,
        lab_requested=args.lab
    )


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
