#!/bin/bash

# BH_LCD_DISPATCH_V1
if [ "${BH_LCD_DISPATCHED:-0}" != "1" ]; then
    exec /usr/local/bin/lcd-run "$0" "$@"
fi

STATUS="$(sudo -n /usr/local/bin/iperf-server status 2>&1)"

if echo "$STATUS" | grep -q 'Status[[:space:]]*:[[:space:]]*OFF'; then
    echo "IPERF:OFF"
    echo "ACTION:STARTING"

    sudo -n /usr/local/bin/iperf-server start
    RC=$?
else
    echo "IPERF:ON"
    echo "ACTION:STOPPING"

    sudo -n /usr/local/bin/iperf-server stop
    RC=$?
fi

echo
sudo -n /usr/local/bin/iperf-server status

exit "$RC"
