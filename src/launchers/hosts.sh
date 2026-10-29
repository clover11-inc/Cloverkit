#!/bin/bash
# BH_LCD_DISPATCH_V1
if [ "${BH_LCD_DISPATCHED:-0}" != "1" ]; then
    exec /usr/local/bin/lcd-run "$0" "$@"
fi


# Network host discovery.
# Normal mode = compact Flipper output.
# "bh" mode = BH/SSH output with copy/paste target commands.

MODE="${1:-flipper}"

CIDR=$(ip -4 -o addr show wlan0 2>/dev/null |
       awk '{print $4; exit}')

if [ -z "$CIDR" ]; then
    echo "HOSTS:NO IP"
    exit 0
fi

NET=$(python3 - "$CIDR" <<'PY'
import ipaddress, sys
print(ipaddress.ip_interface(sys.argv[1]).network)
PY
)

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

# TARGET-NET files are temporary scan results.
sudo -n rm -f /mnt/scripts/TARGET-NET-* 2>/dev/null

echo "NETWORK $NET"
echo "STATE SCANNING"

sudo -n nmap -sn "$NET" -oG - 2>/dev/null |
awk '
/Status: Up/ {
    print $2
    fflush()
}
' |
while IFS= read -r IP; do
    [ -n "$IP" ] || continue

    printf '%s\n' "$IP" >> "$TMP"
    echo "FOUND $IP"
done

COUNT=$(wc -l < "$TMP")

echo "HOSTS $COUNT"
echo "STATE COMPLETE"
echo

# Keep Flipper output short.
if [ "$MODE" = "bh" ]; then
    cat "$TMP"
else
    head -8 "$TMP"
fi

# Build target launchers.
while read -r IP; do
    [ -n "$IP" ] || continue

    SAFE=$(printf '%s' "$IP" | tr '.' '-')
    FILE="/mnt/scripts/TARGET-NET-${SAFE}.sh"

    sudo -n tee "$FILE" >/dev/null <<SCRIPT
#!/bin/bash
exec /usr/local/bin/host-profile "$IP"
SCRIPT

    sudo -n chmod 755 "$FILE"

done < "$TMP"

# Ensure newly generated TARGET-NET launchers enter the normal
# LCD dispatch path. TARGET-NET is then routed to HOST TARGET,
# while Wi-Fi/BLE targets retain TARGET FINDER.
sudo -n /usr/local/bin/lcd-wrap-targets >/dev/null 2>&1 || true

# BH/SSH convenience output.
if [ "$MODE" = "bh" ] && [ "$COUNT" -gt 0 ]; then
    echo
    echo "RUN TARGET:"

    while read -r IP; do
        [ -n "$IP" ] || continue
        SAFE=$(printf '%s' "$IP" | tr '.' '-')
        echo "/mnt/scripts/TARGET-NET-${SAFE}.sh"
    done < "$TMP"
fi
