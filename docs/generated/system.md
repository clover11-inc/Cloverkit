# System and hardware status

Status: alpha-software-validation
Access: System

## What it does
Shows temperature, memory, storage, uptime, interfaces and hardware/service status.

## When to use it
Check field readiness and resource pressure.

## Why it is useful
Quickly separates a resource or link problem from a diagnostic result.

## Limits and effects
Readings describe the local board; platform sensors may be absent.

## Source
- src/commands/system | SHA256 7d9f22c67baa7168665d558f9846e411eac57adf610ecfb31c33d4e34b1204d0
- src/panel/bh_panel.py | SHA256 2c81cef7dafa22492b3c4d9b25227983f1278b59bef70472cf016869bb1a1473
