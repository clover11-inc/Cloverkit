# BLE target tracking

Status: alpha-hardware-validation-pending
Access: Targets > BLE Targets

## What it does
Tracks an advertised MAC with signal/freshness states.

## When to use it
Follow an eligible discovered BLE device.

## Why it is useful
Continuous fresh/stale/searching feedback.

## Limits and effects
Randomised MACs and quiet advertising affect continuity.

## Source
- src/commands/device-track | SHA256 9df009601593a0c536a938a39250e0b342c19068cdd7f5def626757364e04b58
