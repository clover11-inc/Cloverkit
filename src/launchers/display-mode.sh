#!/bin/bash

MODE_FILE="$HOME/.config/bh/lcd-mode"

mkdir -p "$(dirname "$MODE_FILE")"

MODE="$(cat "$MODE_FILE" 2>/dev/null || echo graphical)"

case "$MODE" in
    graphical)
        NEW="cli"
        ;;
    cli)
        NEW="graphical"
        ;;
    *)
        NEW="graphical"
        ;;
esac

if ! printf '%s\n' "$NEW" > "$MODE_FILE"; then
    echo "DISPLAY MODE: ERROR"
    exit 1
fi

if [ "$NEW" = "cli" ]; then
    # Clear the graphical framebuffer ONCE when entering CLI mode.
    # After this, CLI scripts append/scroll normally.
    sudo -n /usr/local/bin/lcd-cli-reset
fi

# BH_DISPLAY_OWNER_V1
case "$NEW" in
    graphical)
        sudo -n /usr/local/bin/lcd-display-owner graphical
        ;;
    cli)
        sudo -n /usr/local/bin/lcd-display-owner text
        ;;
esac

echo "DISPLAY MODE: ${NEW^^}"
