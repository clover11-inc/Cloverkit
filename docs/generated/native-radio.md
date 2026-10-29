# Protected uplink radio

Status: alpha-software-validation
Access: System > Device Network Controls

## What it does
Verifies registered radio identity and bus before allowing USB capture/reset workflows.

## When to use it
Keep the native management uplink separate from development radios.

## Why it is useful
Reduces accidental loss of management access during radio work.

## Limits and effects
Requires real device registration; USB naming/order and firmware still need device-specific testing.

## Source
- src/panel/cloverkit_radio_identity.py | SHA256 ce41ec0784b51eed776979e9c3f427f90ff477ee1ce0273cb9d58bd44ac46c74
- src/commands/cloverkit-name-radios | SHA256 61bddf0292e284437a00fae78db35efe4ab08b9585cf1f12249a7b805f7f2fe9
