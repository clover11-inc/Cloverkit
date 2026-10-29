# CloverKit

**Portable network troubleshooting tools for Flipper Blackhat.**

CloverKit is a set of tools running on Blackhat OS. It is **not an operating system or firmware**. It brings useful checks into one menu, controlled from a Flipper Zero, a PC serial terminal or SSH.

I started it to learn more about the hardware and build tools I wanted to use myself. The aim is simple: find a device or a problem, look into it, and save useful information for later.

**0.1.0-alpha.2 — first public alpha.** The fresh-card build has been tested on development hardware. This is still a personal project under development, not a certified test instrument. See [test status](release-notes/CLEAN-CARD-STATUS.md) and [hardware](hardware/README.md).

## Responsible use

Use CloverKit only on devices and networks you own, or have explicit written permission to assess. Follow applicable laws. Provided as-is, without warranty; use at your own risk.

## What can it do?

- **Scan Wi-Fi:** see nearby APs, network names, channels and signal levels. Related radios can be grouped into an estimated physical AP.
- **Watch Wi-Fi live:** explore networks, clients, signal trends, retries, traffic, roaming observations and capture health as packets arrive.
- **Show a Wi-Fi waterfall:** follow channel and signal history in General, 2.4 GHz, 5 GHz or supported 6 GHz modes. This shows Wi-Fi packet signal, not true RF spectrum energy.
- **Follow a target:** use live AP or BLE signal readings while walking around. Signal trends are clues, not distance measurements.
- **Check nearby devices:** Device Watch combines Wi-Fi and BLE observations; Device History records appearances and changes. Selected findings become targets for closer inspection.
- **Run security checks:** inspect advertised wireless settings, discover LAN services when connected, and compare relevant findings with CVE information. Results distinguish possible matches from implemented checks and direct evidence.
- **Troubleshoot Ethernet:** check link and switch information, listen without an IP address, or use temporary static addressing and an isolated DHCP server for bench work.
- **Investigate a network:** discover hosts, view observed connections, test routes, latency, loss and throughput, and save or inspect packet captures.
- **Share an equipment console:** connect a compatible USB serial adapter to equipment, then use its console locally or through a restricted remote session.
- **Use vehicle diagnostics:** an experimental offline-capable standard OBD2 interface with fault-code references, live values, recordings and reports. Vehicle hardware testing is pending.
- **Stay accessible:** built-in Wi-Fi is reserved for the uplink; USB radios handle scans. Optional email, VPN and a phone/router recovery-hotspot profile use your own settings.

There are also live task controls, hardware status and radio recovery, local documentation, display/startup integration and optional Game Boy launch support. Emulator software and ROMs are not bundled.

The full list is in [features](docs/generated/features.md). Each feature's local documentation explains what it does, when to use it and why it is useful. [Processes](docs/generated/processes.md) maps the scripts behind the menus.

## Access and controls

| Access | Purpose |
|---|---|
| Flipper + Blackhat screen | Local menu controls; leave/re-enter the tested BH app without stopping a scan. |
| PC serial, 115200 8N1 | Keyboard navigation and a recovery shell without Wi-Fi. |
| Owner SSH | Administration, setup and saved reports. Fresh-card setup defaults to `admin` and lets you choose another username. |
| `console` | Restricted shared access to external equipment through a USB serial adapter. |
| `conwifi` | Restricted access to the live Advanced Wi-Fi report. |
| `conveh` | Restricted vehicle-diagnostics access. |

Temporary credentials can be shown locally or sent through optional email. Owner SSH uses its own password. No personal settings or shared default SSH password are included. A configured phone hotspot can also be the main management uplink.

## Install

Start with [INSTALL.md](INSTALL.md). The supported route is a **fresh spare SD card**. The included builder obtains hash-pinned upstream Blackhat OS and dependencies, then creates the first-version installation flow. Downloads happen on the build computer; first-boot installation is offline.

**Coming soon:** install CloverKit alongside your existing Blackhat setup, without starting fresh. This release uses a fresh spare SD card.

### Flipper controls

A compatible Flipper companion app is required for Flipper controls and is **not included in this release**. Use PC serial or SSH to get started.

## Current limits

- Vehicle support initially covers standard OBD2 engine/emissions diagnostics, not universal ABS, airbags, coding or ECU programming. Vehicle hardware and 6 GHz testing remain pending.
- Passive capture sees only what the radios receive. Device identity and AP grouping may be inferred. Missing data is not proof that a device is absent or RF is quiet.
- A CVE/version match is not proof of a vulnerability. Automatic validation is limited to implemented checks; missing validators stay labelled. Intrusive tests require manual/lab controls.
- Local reports and OBD references work offline. Online advisory updates, internet tests and optional email need connectivity.
- Compatibility depends on board, adapter chipset, driver, firmware, cables and power. See the [hardware guide](hardware/README.md).

## Contribute and inspect

Source, licences, reference-data provenance, tests and local documentation are included. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Remove passwords, network identifiers, MACs and VINs from issue reports.

ChatGPT was used while developing this project, as part of learning and exploring what could be built. That does not replace testing or review; the source is available for inspection and improvement.

CloverKit-authored code is **GPL-2.0-or-later**. Third-party work keeps its own terms and credits. See [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md).

Thanks to o7-machinehum / Rootkit Labs, the Blackhat and Flipper communities, Armbian, and the developers of the tools and libraries CloverKit builds on. [Third-party credits](THIRD-PARTY.md).
