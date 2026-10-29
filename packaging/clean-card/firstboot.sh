#!/bin/bash
set -Eeuo pipefail
cd /boot/bh/cloverkit-clean
exec 9>/run/cloverkit-clean-install.lock
flock -n 9 || exit 1
log=/boot/bh/cloverkit-clean/install.log
exec > >(tee -a "$log" /dev/tty1 /dev/ttyS0) 2>&1
echo 'CloverKit clean-card installation — keep power connected.'
echo 'Installation is offline. Existing CloverKit cards are not accessed.'
if ! /usr/bin/python3 /boot/bh/cloverkit-clean/firstboot.py; then
    echo 'INSTALLATION STOPPED. See /boot/bh/cloverkit-clean/install.log'
    echo 'No normal network services have been enabled. Use the local recovery console.'
    echo 'Physical serial recovery shell follows. Power-cycle to retry after repairs.'
    setsid -c /bin/bash -i </dev/ttyS0 >/dev/ttyS0 2>&1 || true
    exit 1
fi
echo 'CloverKit installation complete. Rebooting into the interaction panel.'
sync
