#!/bin/bash
# BH_LCD_DISPATCH_V1
if [ "${BH_LCD_DISPATCHED:-0}" != "1" ]; then
    exec /usr/local/bin/lcd-run "$0" "$@"
fi


BASE="/tmp/bh-monitor"
PIDFILE="$BASE/tshark.pid"
HOPPID="$BASE/hopper.pid"
IFFILE="$BASE/interface"
STARTFILE="$BASE/start"
CAPFILE="$BASE/capture.pcapng"

IW="/usr/sbin/iw"

# ==================================================
# STOP / REPORT
# ==================================================

if [ -f "$PIDFILE" ] && [ -f "$IFFILE" ]; then

    PID=$(cat "$PIDFILE" 2>/dev/null)
    HOP=$(cat "$HOPPID" 2>/dev/null)
    IF=$(cat "$IFFILE" 2>/dev/null)
    START=$(cat "$STARTFILE" 2>/dev/null)

    # Absolute safety rule
    if [ "$IF" = "wlan0" ]; then
        echo "MON:SAFETY"
        echo "WLAN0 BLOCKED"
        rm -rf "$BASE"
        exit 1
    fi

    [ -n "$HOP" ] && kill "$HOP" 2>/dev/null
    [ -n "$PID" ] && kill "$PID" 2>/dev/null

    sleep 1

    NOW=$(date +%s)

    if [ -n "$START" ]; then
        SECS=$((NOW - START))
        MINS=$((SECS / 60))
        [ "$MINS" -lt 1 ] && MINS="<1"
    else
        MINS="?"
    fi

    APS=0
    FRAMES=0
    DENSE="--"
    STRONG="--"

    if [ -s "$CAPFILE" ]; then

        # Total captured frames
        FRAMES=$(tshark -r "$CAPFILE" \
            -T fields \
            -e frame.number 2>/dev/null |
            wc -l)

        # Unique physical APs seen
        APS=$(tshark -r "$CAPFILE" \
            -Y "wlan.fc.type_subtype == 8" \
            -T fields \
            -e wlan.bssid 2>/dev/null |
            grep -v '^$' |
            sort -u |
            wc -l)

        # Channel containing the most distinct APs
        DENSE=$(tshark -r "$CAPFILE" \
            -Y "wlan.fc.type_subtype == 8" \
            -T fields \
            -e wlan_radio.channel \
            -e wlan.bssid 2>/dev/null |
            awk 'NF>=2 && $1!="" {print $1,$2}' |
            sort -u |
            awk '{count[$1]++}
                 END {
                    max=0
                    best=""
                    for (ch in count)
                        if (count[ch] > max) {
                            max=count[ch]
                            best=ch
                        }
                    if (best!="")
                        print "C"best"("max")"
                 }')

        [ -z "$DENSE" ] && DENSE="--"

        # Strongest received Wi-Fi frame
        STRONG=$(tshark -r "$CAPFILE" \
            -T fields \
            -e radiotap.dbm_antsignal 2>/dev/null |
            tr ',' '\n' |
            grep -E '^-?[0-9]+$' |
            sort -nr |
            head -1)

        [ -z "$STRONG" ] && STRONG="--"
    fi

    # Restore ONLY the external radio
    ip link set "$IF" down >/dev/null 2>&1
    "$IW" dev "$IF" set type managed >/dev/null 2>&1
    ip link set "$IF" up >/dev/null 2>&1
    nmcli device set "$IF" managed yes >/dev/null 2>&1

    # Compact Flipper output
    echo "MON:STOPPED"
    echo "TIME:${MINS}m AP:$APS"
    echo "DENSE:$DENSE"
    echo "STRONG:${STRONG}dBm"
    echo "FRAMES:$FRAMES"
    echo "DISCARD:OK"

    rm -rf "$BASE"
    exit 0
fi


# ==================================================
# CHECK TOOLS
# ==================================================

if ! command -v tshark >/dev/null 2>&1; then
    echo "MON:ERROR"
    echo "TSHARK MISSING"
    exit 1
fi

if [ ! -x "$IW" ]; then
    echo "MON:ERROR"
    echo "IW MISSING"
    exit 1
fi


# ==================================================
# FIND ONE EXTERNAL WIFI RADIO
# wlan0 is NEVER eligible
# ==================================================

IF=""

for DEVPATH in /sys/class/net/wlan*; do

    [ -e "$DEVPATH" ] || continue

    DEV=$(basename "$DEVPATH")

    [ "$DEV" = "wlan0" ] && continue

    if [ -d "$DEVPATH/wireless" ]; then
        IF="$DEV"
        break
    fi
done

if [ -z "$IF" ]; then
    echo "MON:READY"
    echo "NO EXT WIFI"
    echo "PLUG ADAPTER"
    echo "RUN AGAIN"
    exit 0
fi

if [ "$IF" = "wlan0" ]; then
    echo "MON:SAFETY"
    echo "WLAN0 BLOCKED"
    exit 1
fi


# ==================================================
# CHECK MONITOR SUPPORT
# ==================================================

PHY=$("$IW" dev "$IF" info 2>/dev/null |
    awk '/wiphy/ {print "phy"$2; exit}')

if [ -z "$PHY" ]; then
    echo "MON:ERROR"
    echo "RADIO:$IF"
    echo "NO PHY"
    exit 1
fi

if ! "$IW" phy "$PHY" info 2>/dev/null |
    sed -n '/Supported interface modes:/,/Band /p' |
    grep -q 'monitor'; then

    echo "MON:ERROR"
    echo "RADIO:$IF"
    echo "NO MON MODE"
    exit 1
fi


# ==================================================
# PREPARE
# ==================================================

rm -rf "$BASE"
mkdir -p "$BASE"

echo "$IF" > "$IFFILE"
date +%s > "$STARTFILE"

nmcli device set "$IF" managed no >/dev/null 2>&1

ip link set "$IF" down >/dev/null 2>&1

if ! "$IW" dev "$IF" set type monitor >/dev/null 2>&1; then

    nmcli device set "$IF" managed yes >/dev/null 2>&1
    rm -rf "$BASE"

    echo "MON:FAILED"
    echo "RADIO:$IF"
    echo "MODE CHANGE"
    exit 1
fi

ip link set "$IF" up >/dev/null 2>&1


# ==================================================
# CHANNEL HOPPER
# ==================================================

(
    CHANNELS="1 6 11 36 40 44 48 149 153 157 161"

    while true; do
        for CH in $CHANNELS; do
            "$IW" dev "$IF" set channel "$CH" >/dev/null 2>&1
            sleep 1
        done
    done
) &

HOP=$!
echo "$HOP" > "$HOPPID"


# ==================================================
# CAPTURE
# ==================================================

tshark \
    -i "$IF" \
    -w "$CAPFILE" \
    >/dev/null 2>&1 &

PID=$!
echo "$PID" > "$PIDFILE"

sleep 3


# ==================================================
# VERIFY
# ==================================================

if kill -0 "$PID" 2>/dev/null; then

    echo "MON:STARTED"
    echo "RADIO:$IF"
    echo "MODE:HOP"
    echo "SAVE:TEMP"

else

    kill "$HOP" 2>/dev/null

    ip link set "$IF" down >/dev/null 2>&1
    "$IW" dev "$IF" set type managed >/dev/null 2>&1
    ip link set "$IF" up >/dev/null 2>&1
    nmcli device set "$IF" managed yes >/dev/null 2>&1

    rm -rf "$BASE"

    echo "MON:FAILED"
    echo "RADIO:$IF"
    echo "CAPTURE FAIL"
fi
