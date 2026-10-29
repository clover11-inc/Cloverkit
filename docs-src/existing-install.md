# Installing CloverKit beside an existing Blackhat setup

The intended primary release is a standalone application package on Blackhat OS. A full SD image can remain an optional fresh-install route.

- Keep Blackhat's current apps and settings.
- Store versioned CloverKit application files under /opt/cloverkit/releases; keep configuration, reports and logs in CloverKit-owned directories.
- Launch CloverKit manually. Offer System → Startup → On/Off; startup is off until the owner enables it.
- Use the existing owner login. Do not create, rename, lock or delete accounts during installation.
- Discover and protect the built-in SDIO Wi-Fi radio by hardware identity. Do not rename interfaces or assume its existing name is wlan0.
- Do not change kernel, drivers, boot files, fstab, hostname, existing Wi-Fi profiles, SSH configuration or Blackhat's serial gateway.
- Put optional email, VPN, recovery hotspot and restricted-console setup behind explicit user choices; detect conflicts and preserve existing configuration.
- Check compatibility before installing. Report unsupported dependencies instead of upgrading the whole OS or forcing a driver change.
- Record every installed file and checksum. Refuse to overwrite files CloverKit does not own.
- Upgrade by adding a new version; keep the last version for rollback.
- Uninstall only unchanged CloverKit-owned application files. Keep user reports/configuration by default.

## Current state

The read-only preflight is implemented: `python3 packaging/existing_install_plan.py`. It reads only hardware/model, interface bus identity and file-existence checks; it does not read credentials, network profiles or account contents, and does not activate anything.

Full alongside activation is not ready. The existing clean-card firstboot flow is destructive provisioning code and must never be used for this installation route. Runtime relocation, account/console integration and optional startup still require implementation and regression testing.
