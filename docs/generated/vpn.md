# VPN setup

Status: alpha-hardware-validation-pending
Access: System > VPN setup

## What it does
Imports a self-contained OpenVPN profile and offers explicit On/Off.

## When to use it
Use your chosen VPN provider when configured.

## Why it is useful
No provider lock-in and no connection before configuration.

## Limits and effects
Conservative import rejects unsupported profile directives; account/service activation gated.

## Source
- src/panel/cloverkit_optional_setup.py | SHA256 02f08024bb4f66a72a826f8b5a495e4414c4db82416228491a6b8c6715af6cfb
