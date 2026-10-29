#!/bin/bash

if [ "${BH_LCD_DISPATCHED:-0}" != "1" ]; then
    exec /usr/local/bin/lcd-run "$0" "$@"
fi

exec /usr/local/bin/secscan-lcd-run "$@"
