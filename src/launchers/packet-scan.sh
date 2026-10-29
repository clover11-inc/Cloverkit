#!/bin/bash
# BH_LCD_DISPATCH_V1

if [ "${BH_LCD_DISPATCHED:-0}" != "1" ]; then
    exec /usr/local/bin/lcd-run "$0" "$@"
fi

PROFILE="${1:-beacon}"
SECONDS="${2:-20}"

TMP="$(mktemp /tmp/bh-packet-scan.XXXXXX)"
trap 'rm -f "$TMP"' EXIT

# Run the existing scanner unchanged.
# tee preserves the normal output for the LCD renderer.
set -o pipefail

/usr/local/bin/packet-scan \
    "$PROFILE" \
    "$SECONDS" \
    | tee "$TMP"

RC=${PIPESTATUS[0]}

# ------------------------------------------------------------
# BEACON AP-NAME TARGET GENERATION
# ------------------------------------------------------------

if [ "$RC" -eq 0 ] && [ "$PROFILE" = "beacon" ]; then

    python3 - "$TMP" <<'PY'
import os
import re
import sys
from collections import defaultdict

source = sys.argv[1]
target_dir = "/mnt/scripts"

# Actual Beacon table format:
#
# AP NAME                BSSID              SSID ...
# wap-hostname            AA:BB:CC:DD:EE:FF  Example-Network ...
#
row_re = re.compile(
    r'^\s*(.*?)\s+'
    r'((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\s+'
    r'(.+?)\s+'
    r'(\d+)\s+'
    r'(-?\d+)\s+dBm\s+'
    r'(\S+)\s+'
    r'(\S+)\s*$'
)

aps = defaultdict(set)

with open(source, encoding="utf-8", errors="ignore") as f:
    for line in f:
        m = row_re.match(line)

        if not m:
            continue

        ap_name = m.group(1).strip()
        bssid = m.group(2).upper()

        # "-" means Beacon did not provide an AP identity.
        if not ap_name or ap_name == "-":
            continue

        aps[ap_name].add(bssid)


def safe_name(value):
    value = value.strip()
    value = re.sub(r'[^A-Za-z0-9._-]+', '-', value)
    value = value.strip('-._')
    return value or "UNKNOWN"


created = 0

for ap_name, bssids in sorted(aps.items()):

    safe = safe_name(ap_name)

    path = os.path.join(
        target_dir,
        f"TARGET-APNAME-{safe}.sh"
    )

    quoted = " ".join(
        f'"{mac}"'
        for mac in sorted(bssids)
    )

    body = (
        "#!/bin/bash\n"
        f"# Beacon identified AP: {ap_name}\n"
        "exec /usr/local/bin/ap-find-compact "
        f"60 {quoted}\n"
    )

    with open(path, "w", encoding="utf-8") as f:
        f.write(body)

    os.chmod(path, 0o755)

    created += 1

if created:
    print(f"Beacon named targets : {created}")
else:
    print("Beacon named targets : 0")
PY

/usr/local/bin/lcd-wrap-targets
fi

exit "$RC"
