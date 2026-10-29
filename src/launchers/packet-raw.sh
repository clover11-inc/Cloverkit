#!/bin/bash
# BH_LCD_DISPATCH_V1

if [ "${BH_LCD_DISPATCHED:-0}" != "1" ]; then
    exec /usr/local/bin/lcd-run "$0" "$@"
fi

SECONDS="${1:-60}"

exec sudo -n     /usr/local/bin/packet-live     raw     "$SECONDS"
