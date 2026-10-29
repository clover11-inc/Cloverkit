#!/bin/bash
# BH_LCD_DISPATCH_V1
if [ "${BH_LCD_DISPATCHED:-0}" != "1" ] && [ -x /usr/local/bin/lcd-run ]; then
    exec /usr/local/bin/lcd-run "$0" "$@"
fi
exec /usr/local/bin/wifi-health "$@"
