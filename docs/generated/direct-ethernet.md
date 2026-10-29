# Direct Ethernet

Status: alpha-hardware-validation-pending
Access: Network > ETHERNET

## What it does
Provides passive, temporary static and diagnostic DHCP modes.

## When to use it
Inspect directly connected equipment.

## Why it is useful
Field diagnostics without its normal network.

## Limits and effects
Active modes temporarily configure eth0; dual-adapter use is not implemented.

## Source
- src/commands/clover-direct-ethernet | SHA256 737c2daa33fd13f60eac7a3b3fe5b22ca4e7df6fac48c17ea6a60a0e4e9b2548
