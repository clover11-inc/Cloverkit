# Installing CloverKit

This release preserves the tested **first-version fresh-card flow**. CloverKit is an application toolkit on Blackhat OS, not an OS or firmware.

Use the tools only on devices and networks you own, or have explicit written permission to assess.

## Fresh spare SD card

1. Read the [hardware requirements](hardware/README.md). A Flipper companion app is not bundled; use PC serial or SSH for this release.
2. Build the image on a computer as described below. Downloads are checked against pinned SHA-256 values.
3. Use a normal image-writing tool to write the generated `.img` to a **spare SD card**. This erases that card. Check the selected drive carefully.
4. Put the card in Blackhat and connect stable power. First boot expands the card and installs dependencies offline. Allow several minutes; it may reboot during expansion. Keep power connected until CloverKit Home appears.
5. Use a PC serial terminal at **115200 baud, 8 data bits, no parity, 1 stop bit, no flow control**. Ctrl-C leaves the panel for its recovery shell.
6. Run `cloverkit-owner-setup`. Choose a username (default `admin`), a password of at least 12 characters, and whether to enable SSH and add Wi-Fi.
7. Optional: `sudo cloverkit-setup email`, `sudo cloverkit-setup vpn` and `sudo cloverkit-setup recovery-hotspot`. Run each separately.

Recovery hotspot means a phone/router hotspot that CloverKit **joins**, not a hotspot hosted by Blackhat. Supply your own SSID and password. Email and VPN are unused until configured. There is no saved owner network, active owner login, VPN or Flipper pairing.

LCD panel: `bh-screen`. Terminal panel: `bh-panel`. Docs: `cloverkit docs`. Restricted `console`, `conwifi` and `conveh` sessions are enabled through their corresponding tools with temporary credentials. Owner SSH is separate.

## Build the image

Use Python **3.14** on the build computer in a virtual environment. On Windows use the environment's `Scripts/python.exe`; on Linux/macOS use `bin/python`.

```sh
python -m venv .venv
# Activate the environment using your shell's normal command.
python -m pip install -r packaging/clean-card/build-requirements.txt
python tools/verify_package.py
python packaging/clean-card/build_sd.py --work .build/sd
```

The work folder receives upstream downloads, offline payload, final image and checksums. Do not commit it. Building needs internet and several gigabytes of free space. The builder never opens a physical drive.

To reuse verified downloads: `--base-archive /path/to/blackhat-os-armbian-v1_4.zip` and `--offline-cache /path/to/offline-repo`. Files are hash-checked; package versions cannot silently change. `--prepare-only` checks the payload without creating the large image.

This repository distributes source and pinned upstream download instructions. Generated OS images include third-party software under its own terms. Anyone redistributing those images must also satisfy the corresponding source/notice obligations; CloverKit's licence does not replace them.

## Existing installations

Do **not** run `packaging/clean-card/firstboot.py` over an existing installation. It provisions a new card and removes stock credentials. It is guarded for the marked clean-image boot flow.

`packaging/installer.py` stages isolated source for development; it does not activate the full panel on an existing system. **Coming soon:** a standalone installer that adds CloverKit to an existing Blackhat setup without starting fresh.

## Offline vehicle demo

Run `python tools/vehicle.py serve`, then `python tools/vehicle.py access` in another terminal. Open `http://127.0.0.1:8767`, enter the local token and choose Demo. No vehicle is opened until an adapter is deliberately selected. Demo operation does not prove physical vehicle compatibility.

## If installation stops

Use physical serial access. Logs: `/boot/bh/cloverkit-clean/`. Status: `/var/lib/cloverkit/clean-install.json`. Report the last error, board/kernel and adapter details after removing identifying information. Do not re-run provisioning over an owner-configured card.
