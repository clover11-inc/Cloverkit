#!/bin/bash
# BH_LCD_DISPATCH_V1
if [ "${BH_LCD_DISPATCHED:-0}" != "1" ]; then
    exec /usr/local/bin/lcd-run "$0" "$@"
fi


MODE="${1:-flipper}"

# Remove stale WiFi targets first.
sudo -n /usr/local/bin/target-clean wifi >/dev/null 2>&1

# Run the real scan.
# It also refreshes wifi-groups.json and rebuilds targets.
if [ "$MODE" = "bh" ]; then
    /usr/local/bin/wifi-scan
else
    /usr/local/bin/wifi-scan >/dev/null
fi

MANIFEST="/run/cloverkit/wifi-groups.json"

if [ ! -s "$MANIFEST" ]; then
    echo "WiFi scan failed."
    exit 1
fi

# Compact Flipper summary only.
if [ "$MODE" != "bh" ]; then
    python3 - "$MANIFEST" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)

rows = data.get("rows", [])
groups = data.get("groups", [])

hidden = sum(
    1 for r in rows
    if r.get("ssid") == "<hidden>"
)

print(f"APs {len(groups)}")
print(f"BSSIDs {len(rows)}")
print(f"Hidden {hidden}")
print()

for n, g in enumerate(groups, 1):
    members = g.get("members", [])
    if not members:
        continue

    best = max(members, key=lambda r: r.get("sig", -999))
    sig = int(best.get("sig", -999))

    if sig >= -49:
        q = "Excellent"
    elif sig >= -59:
        q = "Good"
    elif sig >= -69:
        q = "Fair"
    elif sig >= -79:
        q = "Weak"
    else:
        q = "Poor"

    ssids = sorted({
        r.get("ssid")
        for r in members
        if r.get("ssid")
        and r.get("ssid") != "<hidden>"
    })

    if len(ssids) == 1:
        name = ssids[0]
    elif len(ssids) > 1:
        name = "Multi-SSID"
    else:
        name = "Hidden"

    print(f"{n}: {sig} {q}")
    print(f"   {name[:15]}")

print()
print("Targets updated")
PY

    exit 0
fi

# BH / SSH copy-paste target list.
echo
echo "RUN TARGET:"

FOUND=0

for FILE in \
    /mnt/scripts/TARGET-AP-* \
    /mnt/scripts/TARGET-HIDDEN-* \
    /mnt/scripts/TARGET-SSID-*; do

    [ -e "$FILE" ] || continue

    echo "$FILE"
    FOUND=1
done

if [ "$FOUND" -eq 0 ]; then
    echo "No WiFi targets created."
fi
