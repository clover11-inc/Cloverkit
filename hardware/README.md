# Recreating the CloverKit hardware

Match **chipset + hardware revision + kernel driver + firmware**, not just a retail name or a Wi-Fi generation printed on a box. The source includes a fresh-card image builder; it does not write a physical drive or alter an existing installation.

## Hardware used in development

Flipper Zero and Blackhat with its 480 × 480 display, two compact TP-Link USB Wi-Fi/Bluetooth adapters, a PC USB serial connection, USB Ethernet/console cables as required, and spare SD media were used. Two EDUP EP-AX1678 adapters were ordered for later work; they are not part of the validated baseline. Retail names alone do not establish a chipset or supported band.

The original working-card kernel was 6.16.8-edge-sunxi; the fresh-card Blackhat OS v1.4 image uses 7.1.13-edge-sunxi. Do not copy modules between them.

## Observed development baseline

The following was collected read-only for this release. MAC addresses, USB serial numbers, network details and machine names were deliberately not recorded. See observed-baseline.json for machine-readable facts.

| Component | Observed baseline | Reproduction notes |
|---|---|---|
| Board | Flipper Blackhat, ARMv7 Linux | Follow the board vendor's hardware/OS documentation. This package is an application/toolkit layer, not the base OS. |
| Kernel | 6.16.8-edge-sunxi | Driver behaviour is kernel-dependent. No kernel upgrade or replacement is performed by the package. |
| Display | 480 × 480 framebuffer | The LCD renderer assumes the Blackhat framebuffer/rotation layout; a different panel needs explicit adaptation. |
| Native Wi-Fi | SDIO, rtw88_8723ds | This is the protected management/uplink radio. Identify it by hardware/bus; do not trust enumeration order. Never install the sample MACs. |
| USB Wi-Fi | Two units, USB VID:PID 0bda:c820, reported Realtek 802.11ac NIC, rtw88_8821cu | Retail name/revision was not independently confirmed. The driver's successful bind is recorded; this is not a new exhaustive band/monitor-mode test. |
| USB Bluetooth functions | btusb on those combo USB devices | HCI indices can change. Controller readiness can fail independently of Wi-Fi. Prefer explicit selection/fallback. |
| USB hosts | USB 2.0, EHCI and MUSB paths | Different host paths have behaved differently in development. A successful hot-plug is not proof of reliable warm reboot behaviour. |
| OS tools | Python 3.14.6, BlueZ 5.87, iw 6.17, tcpdump 4.99.6, TShark 4.6.6 | These versions describe the observed baseline, not minimum versions or guaranteed compatibility. |

Exact dongle retail SKUs, USB Ethernet chipset, USB serial chipset and vehicle adapter were not established by this inventory. They are **unknown here**, not silently recommended substitutes.

## Hardware and cables by workflow

| Workflow | Required pieces | Important distinction |
|---|---|---|
| Local panel | Blackhat + compatible display + its supported Flipper/board connection | Use the vendor connection/pinout; do not improvise power wiring from a software guide. |
| Flipper controls | Flipper Zero with compatible FAP/firmware and the board's supported UART/GPIO connection | Requires a separately supplied compatible app; no companion FAP is bundled. |
| PC recovery console | A data-capable USB connection to a suitable USB-to-UART console interface, appropriate wiring/ground, and a PC terminal | A charge-only cable cannot carry serial data. TTL UART is not RS-232 voltage signalling. |
| USB-radio capture | One compatible USB radio for single-radio modes; two for General's parallel 2.4/5 GHz or focused channel splitting | Built-in uplink Wi-Fi is not a spare capture adapter. Antenna/LED appearance is not capability evidence. |
| Ethernet | A Linux-supported USB-to-Ethernet adapter + RJ45 Ethernet cable | Verify actual driver binding/link. A small direct-plug USB-A-to-RJ45 dongle is physically convenient; no particular SKU is certified here. |
| Console sharing / OOB | A supported USB serial/console adapter + the target equipment's correct console cable/pinout | RJ45 console and Ethernet connectors can look alike but are not interchangeable. Supported shared-console baud choices are 9600/115200; match the target. |
| More ports | A USB data hub compatible with the host/power arrangement, plus suitable short data leads/extensions if needed | A hub adds ports, not power budget or another independent capture radio. No hub model has been certified by this alpha. |
| OBD over USB | A supported ELM-style serial OBD interface, matching USB data lead and vehicle OBD connector | The adapter, not raw GPIO wiring, interfaces to the vehicle. Baud/protocol/support vary. No physical adapter/vehicle validation has been claimed. |
| OBD over Bluetooth | An ELM-compatible **Classic Bluetooth SPP** interface and working Linux Bluetooth controller | BLE-only OBD devices need a different transport; being discoverable over BLE is not sufficient for this implementation. |
| Real RF spectrum | A separately supported RF measurement device | Wi-Fi radios/Flipper control hardware do not turn packet RSSI into a calibrated spectrum analyser. No RF-spectrum hardware backend is included. |

Flipper GPIO I/O is 3.3 V-tolerant; use its official pinout and module/power guidance. Do not connect vehicle supply or RS-232 levels directly to GPIO. [Official Flipper GPIO guide](https://docs.flipper.net/zero/gpio-and-modules).

## Power and reliability

Record the power source and cable/hub arrangement in hardware bug reports. Multiple USB radios, Bluetooth functions, Ethernet and a display consume the same system budget. This release does not provide a measured current budget, battery-runtime claim or approved back-powering arrangement. Follow the board/module vendor's guidance; do not assume two power inputs can be joined safely.

USB LEDs are not a reliable health indicator. Inspect driver binding, fresh frame counters and capture timestamps. Warm reboot, cold boot, unplug/replug and simultaneous radio load are separate tests. Kernel USB protocol/allocation errors or repeated controller resets need to be resolved before trusting a scan.

The bound kernel modules declare `rtw88/rtw8821c_fw.bin` and `rtw88/rtw8723d_fw.bin`; those files were present in the development image, with `armbian-firmware 26.02.0-trunk` installed. This records module requirements/presence, not a firmware reflash or proof of runtime blob identity.

The package does not bundle a kernel, firmware blobs or DKMS modules. Use matching OS firmware/driver packages. A module built for another architecture or kernel is not a drop-in fix. Check driver and firmware availability on the exact image before going offline.

## 6 GHz / alternate radios

The 6 GHz menu is a capture mode, not a compatibility promise. It needs a radio, driver, firmware, regulatory configuration and capture path that actually support the band on the chosen kernel. This baseline's attached USB radios are described as 802.11ac; no 6 GHz capability is claimed. Likewise, a Wi-Fi 7 product label does not establish the required Linux/ARM monitor-mode support.

## Direct Ethernet setup

Static target/local addresses must be supplied by the operator; no author-specific office subnet is preconfigured. Configure them deliberately with `clover-direct-ethernet configure --target 192.0.2.2 --local 192.0.2.1/24` after replacing documentation addresses with your isolated test network. The configure command stores settings without changing an interface. Direct DHCP uses a separate private test subnet and refuses overlapping routes.

## Record a useful compatibility result

Start with `python3 tools/doctor.py`. Add board revision, OS/kernel, chipset and USB VID:PID, driver/firmware names, supported bands/widths, monitor-mode behaviour, power/hub/cable arrangement and cold/warm-start results. Record whether both radios collected **fresh** frames during the same interval. Do not post MACs, SSIDs, USB serial numbers, tokens or saved connection profiles.

Upstream references: [Blackhat hardware](https://github.com/o7-machinehum/flipper-blackhat), [Blackhat OS](https://github.com/o7-machinehum/flipper-blackhat-os), [Linux USB serial documentation](https://docs.kernel.org/usb/usb-serial.html). Hardware designs, OS images, SDKs and third-party drivers are not relicensed or redistributed as part of this source alpha.
