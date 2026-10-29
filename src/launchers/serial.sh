#!/bin/bash
# BH_LCD_DISPATCH_V1
if [ "${BH_LCD_DISPATCHED:-0}" != "1" ]; then
    exec /usr/local/bin/lcd-run "$0" "$@"
fi


DEV=$(ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null |
      head -1)

if [ -z "$DEV" ]; then
    echo "SERIAL:NONE"
    exit 0
fi

MODEL=$(udevadm info -q property -n "$DEV" 2>/dev/null |
        awk -F= '/^ID_MODEL=/ {print $2; exit}')

echo "DEV:$(basename "$DEV")"
echo "MODEL:${MODEL:---}"
echo "9600:picocom"
echo "115200:picocom"
