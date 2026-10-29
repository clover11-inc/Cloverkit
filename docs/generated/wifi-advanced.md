# Advanced Wi-Fi scan

Status: alpha-hardware-validation-pending
Access: Network > WI-FI

## What it does
Collects passive AP/client metadata, directional retries and activity.

## When to use it
Investigate reception and captured delivery evidence.

## Why it is useful
Evidence includes sample counts, ages and limits.

## Limits and effects
Hopping misses frames; retries are not end-to-end loss.

## Source
- src/commands/wifi-passive-health | SHA256 b84ebd28ce6ab42d1674ea58e19f8d37e74013a3119bec04f6284b9580007135
