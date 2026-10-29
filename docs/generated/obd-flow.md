# OBD traffic and keyboard access

Status: alpha-software-validation
Access: Vehicle Diagnostics > Remote access & data flow

## What it does
Displays actual ELM serial TX/RX and queues read-only typed requests through the shared owner.

## When to use it
Understand adapter responses or drive diagnostics from a PC keyboard.

## Why it is useful
Links decoded readings to real adapter traffic without a second serial reader.

## Limits and effects
Not a passive raw CAN monitor. Optional conveh provisioning is opt-in; physical adapter/vehicle testing pending.

## Source
- src/vehicle/cloverkit_vehicle/traffic.py | SHA256 1d2e757465555a07169ebcef63b5f74b8fb2d81e469e666d1236264cdaece3da
- src/vehicle/cloverkit_vehicle/ssh_console.py | SHA256 36d12f9b727f2b3a96c12c22f98e9f2f59174915b4ecb5db2d909bb24dd3d2d6
