# Recovery hotspot

Status: alpha-hardware-validation-pending
Access: System > Recovery hotspot

## What it does
Configures a phone/router hotspot name and password for management override.

## When to use it
Regain control through a known reachable hotspot.

## Why it is useful
Provides an owner-configured recovery path without a preconfigured hotspot.

## Limits and effects
Opt-in; can switch wlan0. WPA personal hotspot only; no enterprise/captive-portal setup.

## Source
- src/panel/cloverkit_recovery_hotspot.py | SHA256 e60b1f1a97b5f85ebafdda07b36eaad90ef22ac59cbe67309401b62ce0211c68
