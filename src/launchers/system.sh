#!/bin/bash

# BH_LCD_DISPATCH_V1
if [ "${BH_LCD_DISPATCHED:-0}" != "1" ]; then
    exec /usr/local/bin/lcd-run "$0" "$@"
fi

set -u

REFRESH=2
PC_REFRESH=30

RUNNING=1
PC_STATE="CHECKING"
LAST_PC_CHECK="$(date +%s)"
PC_STATE_FILE="/tmp/bh-system-pc-state.$$"
PC_CHECK_PID=""

cleanup() {
    RUNNING=0

    if [ -n "${PC_CHECK_PID:-}" ] &&
       kill -0 "$PC_CHECK_PID" 2>/dev/null; then
        kill "$PC_CHECK_PID" 2>/dev/null || true
        wait "$PC_CHECK_PID" 2>/dev/null || true
    fi

    rm -f "${PC_STATE_FILE:-}"
}

trap cleanup TERM INT HUP


get_pc_state() {
    local tmp state

    tmp="$(mktemp /tmp/bh-pc-test.XXXXXX)" || exit 1
    state="ISSUE"

    if timeout -k 1s 6s /usr/local/bin/pc-test \
        >"$tmp" 2>&1 </dev/null; then

        if grep -q 'Network/SSH[[:space:]]*:[[:space:]]*REACHABLE' "$tmp" &&
           grep -q 'SSH key[[:space:]]*:[[:space:]]*WORKING' "$tmp"; then
            state="READY"
        else
            state="ISSUE"
        fi
    else
        state="OFFLINE"
    fi

    rm -f "$tmp"

    printf '%s\n' "$state" > "$PC_STATE_FILE"
}


start_pc_check() {
    if [ -n "${PC_CHECK_PID:-}" ] &&
       kill -0 "$PC_CHECK_PID" 2>/dev/null; then
        return
    fi

    get_pc_state &
    PC_CHECK_PID=$!
}


collect_pc_state() {
    if [ -s "$PC_STATE_FILE" ]; then
        PC_STATE="$(head -1 "$PC_STATE_FILE")"
        rm -f "$PC_STATE_FILE"
    fi
}


emit_system_state() {
    local IF HOST UP NET IP SIG GW DNS LINK DNSOK INET
    local W1 W2
    local USB_WIFI USB_SERIAL USB_ETH USB_STORAGE USB_TOTAL
    local DEV REAL NAME
    local MEM ROOT_USE TEMP T V
    local VPNDEV VPN
    local VPN_STATUS VPN_STATE
    local CONSOLE_STATUS CONSOLE_STATE
    local IPERF_STATUS IPERF_STATE
    local NOW

    # --------------------------------------------------------
    # MANAGEMENT / NETWORK
    # --------------------------------------------------------

    IF="$(
        ip -4 route show default 2>/dev/null |
        awk '/^default / {
            for (i=1;i<=NF;i++)
                if ($i=="dev") {
                    print $(i+1)
                    exit
                }
        }'
    )"

    [ -n "$IF" ] || IF="wlan0"

    HOST="$(hostname)"

    UP="$(
        uptime -p 2>/dev/null |
        sed 's/^up //;s/ hours*/h/;s/ minutes*/m/;s/,//g'
    )"

    NET="$(
        nmcli -t -f NAME,DEVICE con show --active 2>/dev/null |
        awk -F: -v dev="$IF" '$2==dev {print $1; exit}'
    )"

    IP="$(
        ip -4 route show default dev "$IF" 2>/dev/null |
        awk '/^default / {
            for (i=1;i<=NF;i++) {
                if ($i=="src") {
                    print $(i+1)
                    exit
                }
            }
        }'
    )"

    if [ -z "$IP" ]; then
        IP="$(
            ip -4 -o addr show dev "$IF" scope global 2>/dev/null |
            awk '{print $4}' |
            cut -d/ -f1 |
            head -1
        )"
    fi

    SIG="$(
        /usr/sbin/iw dev "$IF" link 2>/dev/null |
        awk '/signal:/ {print $2; exit}'
    )"

    GW="$(
        ip -4 route show default 2>/dev/null |
        awk -v dev="$IF" '
            /^default / {
                found=0
                for (i=1;i<=NF;i++)
                    if ($i=="dev" && $(i+1)==dev)
                        found=1

                if (found) {
                    for (i=1;i<=NF;i++)
                        if ($i=="via") {
                            print $(i+1)
                            exit
                        }
                }
            }
        '
    )"

    DNS="$(
        nmcli -g IP4.DNS dev show "$IF" 2>/dev/null |
        head -1
    )"

    if /usr/sbin/iw dev "$IF" link 2>/dev/null |
        grep -q '^Connected'; then
        LINK="OK"
    else
        LINK="FAIL"
    fi

    if timeout 2s getent hosts example.com >/dev/null 2>&1; then
        DNSOK="OK"
    else
        DNSOK="FAIL"
    fi

    if curl -s --max-time 2 -I https://example.com >/dev/null 2>&1; then
        INET="OK"
    else
        INET="FAIL"
    fi


    # --------------------------------------------------------
    # RADIOS
    # --------------------------------------------------------

    W1="READY"
    W2="READY"

    [ -e /sys/class/net/wlan1 ] || W1="MISS"
    [ -e /sys/class/net/wlan2 ] || W2="MISS"


    # --------------------------------------------------------
    # USB INVENTORY
    # --------------------------------------------------------

    USB_WIFI=0
    USB_SERIAL=0
    USB_ETH=0
    USB_STORAGE=0

    for DEV in /sys/class/net/wlan*; do
        [ -e "$DEV" ] || continue

        REAL="$(readlink -f "$DEV/device" 2>/dev/null)"

        if echo "$REAL" | grep -q '/usb'; then
            USB_WIFI=$((USB_WIFI + 1))
        fi
    done

    USB_SERIAL="$(
        ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null |
        wc -l
    )"

    for DEV in /sys/class/net/*; do
        [ -e "$DEV" ] || continue

        NAME="$(basename "$DEV")"

        case "$NAME" in
            lo|wlan*|wl*)
                continue
                ;;
        esac

        if [ "$(cat "$DEV/type" 2>/dev/null)" = "1" ]; then
            USB_ETH=$((USB_ETH + 1))
        fi
    done

    if lsblk -ndo TRAN 2>/dev/null | grep -q '^usb$'; then
        USB_STORAGE=1
    fi

    USB_TOTAL=$((USB_WIFI + USB_SERIAL + USB_ETH + USB_STORAGE))


    # --------------------------------------------------------
    # RESOURCES
    # --------------------------------------------------------

    MEM="$(
        free 2>/dev/null |
        awk '/Mem:/ {
            if ($2 > 0)
                printf "%.0f%%", ($3/$2)*100
        }'
    )"

    ROOT_USE="$(
        df -P / 2>/dev/null |
        awk 'NR==2 {print $5}'
    )"

    TEMP="--"

    for T in /sys/class/thermal/thermal_zone*/temp; do
        [ -r "$T" ] || continue

        V="$(cat "$T" 2>/dev/null)"

        if [ -n "$V" ]; then
            TEMP="$((V / 1000))C"
            break
        fi
    done


    # --------------------------------------------------------
    # VPN PATH
    # --------------------------------------------------------

    VPNDEV="$(
        ip route get 1.1.1.1 2>/dev/null |
        awk '{
            for(i=1;i<=NF;i++)
                if($i=="dev") {
                    print $(i+1)
                    exit
                }
        }'
    )"

    case "$VPNDEV" in
        tun*|wg*)
            VPN="ON"
            ;;
        *)
            VPN="OFF"
            ;;
    esac


    # --------------------------------------------------------
    # SERVICE STATES
    # --------------------------------------------------------

    VPN_STATUS="$(
        sudo -n /usr/local/bin/bh-vpn status 2>/dev/null
    )"

    if echo "$VPN_STATUS" |
        grep -q 'Status[[:space:]]*:[[:space:]]*CONNECTED'; then
        VPN_STATE="ON"
    else
        VPN_STATE="OFF"
    fi

    CONSOLE_STATUS="$(
        /usr/local/bin/console-status 2>/dev/null
    )"

    if echo "$CONSOLE_STATUS" |
        grep -q 'Console[[:space:]]*:[[:space:]]*DISABLED'; then
        CONSOLE_STATE="OFF"
    else
        CONSOLE_STATE="ON"
    fi

    IPERF_STATUS="$(
        sudo -n /usr/local/bin/iperf-server status 2>/dev/null
    )"

    if echo "$IPERF_STATUS" |
        grep -q 'Status[[:space:]]*:[[:space:]]*OFF'; then
        IPERF_STATE="OFF"
    else
        IPERF_STATE="ON"
    fi


    # --------------------------------------------------------
    # PC - SLOW CHECK, ONLY EVERY 30 SECONDS
    # --------------------------------------------------------

    NOW="$(date +%s)"

    collect_pc_state

    if [ $((NOW - LAST_PC_CHECK)) -ge "$PC_REFRESH" ]; then
        start_pc_check
        LAST_PC_CHECK="$NOW"
    fi


    # --------------------------------------------------------
    # EMIT ONE COMPLETE SNAPSHOT
    # --------------------------------------------------------

    echo "HOST:$HOST"
    echo "UPTIME:${UP:---}"

    echo "NETWORK:${NET:---}"
    echo "IP:${IP:---}"

    if [ -n "$SIG" ]; then
        echo "SIGNAL:${SIG}dBm"
    else
        echo "SIGNAL:--"
    fi

    echo "LINK:$LINK"
    echo "GATEWAY:${GW:---}"
    echo "DNS:$DNSOK"
    echo "INTERNET:$INET"

    echo "WLAN1:$W1"
    echo "WLAN2:$W2"

    echo "VPN:$VPN"

    echo "MEMORY:${MEM:---}"
    echo "STORAGE:${ROOT_USE:---}"
    echo "TEMP:$TEMP"

    echo "CONSOLE:$CONSOLE_STATE"
    echo "IPERF:$IPERF_STATE"
    echo "PC:$PC_STATE"

    echo "USB:$USB_TOTAL"
}


# ============================================================
# LIVE SYSTEM LOOP
# ============================================================

# Paint SYSTEM immediately before starting any slow background checks.
emit_system_state

# PC recovery health is deliberately asynchronous so it can never
# hold up the live SYSTEM dashboard.
start_pc_check
LAST_PC_CHECK="$(date +%s)"

while [ "$RUNNING" -eq 1 ]; do
    sleep "$REFRESH" &
    wait $!

    [ "$RUNNING" -eq 1 ] || break

    emit_system_state
done

exit 0
