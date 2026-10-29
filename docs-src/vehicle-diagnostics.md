# CloverKit Vehicle Diagnostics

Status: isolated release candidate; no live CloverKit installation replaced. Physical adapter and vehicle validation is pending.

## What it does

Connects to an explicitly selected USB ELM-compatible adapter or paired Bluetooth Classic SPP adapter. Detects the protocol and supported parameters; reads engine/emissions codes, readiness, freeze frame 0, vehicle information and supported CAN Mode 06 monitors. Provides live readings, bounded history, CSV recording, saved scans, comparisons and HTML/JSON exports. All ordinary use is offline.

## When to use it

Investigate a check-engine condition, preserve the conditions recorded with a fault, see changing readings, check readiness after repairs, or take a readable report to a technician. Use the code library without a car or internet. Use Demo to learn the controls with no adapter attached.

## Why it is useful

The small CloverKit display, Flipper controls, SSH/serial console and optional phone browser share the same session. One worker owns the selected adapter. A failed Bluetooth controller does not block USB, saved reports or Demo. Evidence keeps timestamps, ECU identities, units and response states; a missing response cannot become a measured zero.

## Included features

- Explicit USB discovery and stable USB identity; no probing of the Flipper/native UART.
- Bluetooth Classic controller status, explicit discovery, PIN pairing and SPP binding; only owned bindings are released. BlueZ tools and controller hardware are needed. Unsupported BLE is explained.
- Automatic ELM protocol selection; explicit baud selection (38400 default, 9600/115200 alternatives).
- Stored, pending and permanent codes retain distinct status and responding ECU.
- Readiness/MIL, freeze frame 0, VIN when available, calibration IDs, calibration verification numbers and adapter supply voltage.
- Supported standard Mode 01 parameters, including an additional sourced PID table beyond the pinned library's command table; encoded fields are labelled raw rather than guessed.
- Supported CAN Mode 06 monitor results retain their returned values/limits and the library's experimental status.
- Selectable live values and graphs, 120 samples per series; up to 24 selected parameters per cycle to keep the small device responsive. This selection limit does not cap the available parameter catalog.
- Recording to local SQLite; CSV export; finalization on stop/disconnect/service exit. Interrupted recordings are marked ended when the owner restarts.
- Up to 500 saved scans; explicit same-vehicle comparison; VIN absence creates a distinct vehicle identity, never a shared anonymous vehicle.
- Complete JSON exports and self-contained HTML with coverage, limitations and evidence. Browser export is local and deliberate.
- Offline searchable generic/manufacturer reference database, with source/licence and conflicting descriptions preserved.
- Optional bounded raw-response logs (2 MB plus one previous file); VIN/identifiers stay local.
- Engine code clearing only after a saved fresh pre-clear scan and a separate explicit confirmation. No automatic clearing; disabled in Demo. Positive ECU acknowledgment required, followed by rescan. Permanent codes cannot be erased on demand.
- Authenticated offline browser, no external JavaScript/fonts/CDNs; loopback by default. LAN binding is explicit. Use only on a trusted local network or via SSH tunnel; HTTP itself is not encrypted.
- Cancellable subprocess for adapter communication; failed or hung adapters release the worker. Reconnection is explicit, using the chosen adapter, never a nearby substitute.
- Read-only profile schema/formula validation, source/licence/applicability metadata and a sourced standard RPM reference. Manufacturer profiles are not automatically activated or brute-forced.

## Offline reference data

The bundled database currently contains **28,172 source-specific definitions for 12,316 distinct codes** and 33 non-generic manufacturer labels. These are reference counts, not 33 validated vehicle integrations. `OTHER` is an upstream ambiguous label and should not be treated as a vehicle manufacturer. See `src/vehicle/cloverkit_vehicle/data/provenance.json` for exact pinned revisions, licences and database hash.

OBDex supplies independently authored CC0 text, descriptions and possible causes. The MIT-labelled dtc-database supplies an additional generic/manufacturer lookup. All eligible rows are bundled; malformed or questionable generic/manufacturer-range rows are excluded from automatic lookup (168 input rows). No paid API/account/download is needed in the field. Upstream claims of completeness are not repeated as verified facts. Conflicting text stays visible. Manufacturer descriptions require explicit matching manufacturer context.

OBDb SAEJ1979 definitions are included as an offline attributed CC-BY-SA reference, with a clearly identified adapted example. They are not treated as directly executable python-OBD commands. No proprietary manufacturer database, commercial app content or paid standard document is copied. A project's declared licence does not independently prove the provenance of every community contribution; release review should retain that distinction.

Bundled upstream repair prices, likelihood ranks and drive-safety flags are not used as diagnoses or presented as reliable repair instructions. A detected condition does not establish a failed component. Unknown codes remain visible with an unknown description.

## Use in the eventual installed release

Home → Vehicle Diagnostics → Connect to vehicle / Scan engine / emissions / Live dashboard / Saved vehicles & reports / Adapter setup / diagnostics / Demo.

The display uses the existing CloverKit header/footer, green actions, black selected text and faded clover renderer. The Flipper uses its existing panel navigation; no new UART protocol or FAP is required for these menus. Actual physical navigation still needs testing.

Console examples (after a validated installation):

```sh
cloverkit-vehicle adapters
cloverkit-vehicle connect '0403:6001:SERIAL'
cloverkit-vehicle connect '0403:6001:SERIAL' --baud 115200
cloverkit-vehicle scan
cloverkit-vehicle status
cloverkit-vehicle live RPM SPEED COOLANT_TEMP
cloverkit-vehicle record start
cloverkit-vehicle record stop
cloverkit-vehicle saved
cloverkit-vehicle export SCAN_ID --format html > vehicle-report.html
cloverkit-vehicle export RECORDING_ID --format csv > readings.csv
cloverkit-vehicle compare PREVIOUS_SCAN_ID CURRENT_SCAN_ID
cloverkit-vehicle lookup P0301
cloverkit-vehicle lookup P1690 --make FORD
cloverkit-vehicle vehicle --nickname 'Workshop vehicle' --make FORD
cloverkit-vehicle vehicle --vehicle-id SAVED_VEHICLE_ID
cloverkit-vehicle bluetooth discover
cloverkit-vehicle bluetooth pair --address AA:BB:CC:DD:EE:FF --pin 1234
cloverkit-vehicle connect AA:BB:CC:DD:EE:FF --transport bluetooth
cloverkit-vehicle cancel
cloverkit-vehicle disconnect
```

`scan` and connection actions enqueue work and return immediately; `status` shows progress/results. `lookup` does not start the service. `clear` waits for pre-clear evidence then asks for the exact confirmation phrase. No diagnostic command is sent by simply listing USB adapters.

For private browser access, keep the service on loopback and use an SSH tunnel: `ssh -L 8767:127.0.0.1:8767 clover@DEVICE`. Open `http://127.0.0.1:8767` and use the token from `cloverkit-vehicle access`. To serve a phone directly, stop the existing owner deliberately and start `cloverkit-vehicle serve --bind DEVICE_LAN_IP`; no firewall/router exposure is configured automatically. The same private data directory enforces one owner regardless of bind address.

## Test the separate candidate without installing

From the candidate directory, set a separate private data directory and module path. This is the only candidate subsystem approved for direct staged execution; inherited network/game launchers still use live absolute paths.

```sh
export CLOVERKIT_VEHICLE_HOME="$PWD/build/vehicle-demo"
export PYTHONPATH="$PWD/src/vehicle:$PWD/src/vehicle/vendor"
python3 -m cloverkit_vehicle serve
```

Use a second SSH shell with the same two environment variables:

```sh
python3 -m cloverkit_vehicle demo
python3 -m cloverkit_vehicle scan
python3 -m cloverkit_vehicle status
python3 -m cloverkit_vehicle access
```

No root, internet or physical adapter is needed for Demo. Stop this test service with Ctrl+C when finished. Real USB access may require an appropriate device group/root; Classic RFCOMM setup requires the BlueZ tools and sufficient permissions. No new broad sudo policy is installed by this candidate.

## Coverage limits

This is standard engine/emissions diagnostics, not a full vehicle scan or a guarantee of health. ELM firmware strings do not establish authenticity, protocol completeness or adapter quality. Readings depend on the vehicle, adapter and physical networks; no guarantee covers all cars, EVs or proprietary modules. Other freeze-frame indices, proprietary ABS/airbag/body access, actuator tests, coding, ECU flashing, immobiliser functions and forced DPF regeneration are not implemented. Read-only profile validation is an extension point, not an advertised manufacturer scan integration. No active unknown-service probing occurs.

## Developer structure and dependencies

`adapters.py`: inventory and Classic management; `backend.py`: isolated GPL-2.0-only python-OBD worker; `engine.py`: one shared owner and state machine; `storage.py`: local evidence; `reference.py`: offline SQLite lookup; `profiles.py`: constrained read-only mapping validation; `service.py`: local authenticated API; `web/`: static offline client; `cloverkit_vehicle_menu.py`: existing Panel adapter.

Vendored pure-Python wheels include python-OBD 0.7.3, pyserial 3.5, Pint 0.24.4 and exact transitive versions. Hashes are recorded in `vendor/vehicle/dependencies.json`; sources/licences accompany the unpacked packages. No pip, compilation or downloads are required at runtime. GPL notices/source must remain with the communication worker and dependency when distributing; other data licences remain separate. OS prerequisites: Python 3.14 validated on the target (other versions need dependency checks), Linux USB serial drivers (FTDI/CH34x/CP210x as appropriate); optional BlueZ `bluetoothctl`, `rfcomm`, `sdptool`. The existing panel/LCD dependencies remain unchanged.

Build the offline database with `tools/build_vehicle_data.py SOURCE_SNAPSHOTS` (build-only PyYAML), then run `tools/build.py`, `tools/check.py` and the tests. Upstream updates are explicit build-time imports, not background downloads. Build guards and normal distribution staging include the entire feature and licences. Live full-release activation retains its existing unresolved release gates.

## Hardware acceptance still required

1. Inspect the delivered USB VID/PID, driver and actual ELM response; select it deliberately.
2. With ignition on, connect and compare stored/pending/permanent code statuses, readiness and VIN against a trusted tool.
3. Confirm freeze-frame RPM/temperature, live values/units and supported parameter list; test ignition-off/no-response states.
4. Unplug the selected adapter during scan and recording; verify prompt navigation, error state, finalized recording and explicit reconnect.
5. Pair the actual Classic adapter with its correct PIN; test controller absence, incorrect PIN and reconnect; confirm BLE-only devices are rejected clearly.
6. Use the Flipper/local panel and browser together; verify shared state and unaffected PC serial/Wi-Fi.
7. Export/open JSON, CSV and HTML completely offline; compare two scans of the same selected vehicle.
8. Test code clearing only when intentionally authorised for a suitable test vehicle; confirm pre-clear report, warning, acknowledgment and post-clear readiness state. Never use a test to erase needed real diagnostic evidence.

Software simulation results are recorded separately from physical checks in the validation report.

Quick isolated candidate launcher: `python3 tools/vehicle.py` starts the loopback server. In a second shell, `python3 tools/vehicle.py demo`, then `python3 tools/vehicle.py scan`, `python3 tools/vehicle.py status` or `python3 tools/vehicle.py access`. It automatically uses candidate-private data under build/vehicle-demo.
