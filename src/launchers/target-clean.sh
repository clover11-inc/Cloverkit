#!/bin/bash

echo
echo "========================================"
echo " TARGET CLEAN"
echo "========================================"
echo

COUNT=$(find /mnt/scripts \
    -maxdepth 1 \
    -type f \
    -name 'TARGET-*.sh' \
    2>/dev/null | wc -l)

echo "Targets : $COUNT"
echo
sudo -n /usr/local/bin/target-clean all
