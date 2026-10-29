# CloverKit complete feature map

Source availability and validation are separate. Alpha is not hardware certification.

| Feature | Access | What / value | Status |
|---|---|---|---|
| Interactive Panel | Home | Presents menus, controls and reports. A consistent interface across tools. | alpha-hardware-validation-pending |
| Task management | Home > Tasks | Streams output and manages owned task cancellation. Visible progress and controlled tool handover. | alpha-hardware-validation-pending |
| Basic Wi-Fi scan | Network > WI-FI | Discovers APs, signal, channels and names; creates targets. Discovery feeds focused follow-up actions. | alpha-hardware-validation-pending |
| Advanced Wi-Fi scan | Network > WI-FI | Collects passive AP/client metadata, directional retries and activity. Evidence includes sample counts, ages and limits. | alpha-hardware-validation-pending |
| Wi-Fi waterfall | Network > WI-FI | Shows AP packet RSSI by channel and over time. Readable live channel history. | alpha-hardware-validation-pending |
| Connected client health | Network > WI-FI | Tests a connected external client, reachability and throughput. Combines measured checks and evidence coverage. | alpha-hardware-validation-pending |
| Wi-Fi target tracking | Targets > Wi-Fi Targets | Tracks selected APs, observed clients and probes. Continuous signal and freshness feedback. | alpha-hardware-validation-pending |
| Ethernet link and switch | Network > ETHERNET | Shows link, counters and observed LLDP/CDP/VLAN/LACP evidence. Combines port identity with live link status. | alpha-hardware-validation-pending |
| Direct Ethernet | Network > ETHERNET | Provides passive, temporary static and diagnostic DHCP modes. Field diagnostics without its normal network. | alpha-hardware-validation-pending |
| Host discovery and profiles | Network > DISCOVERY & MONITORING | Discovers responding hosts and profiles common services. Subnet overview leads to focused host targets. | alpha-hardware-validation-pending |
| Observed topology | Network > DISCOVERY & MONITORING | Builds evidence-labelled neighbour and wireless relationships. Avoids inventing wired links from names or addresses. | alpha-hardware-validation-pending |
| Network monitor | Network > DISCOVERY & MONITORING | Preserves the inherited monitoring/report workflow. A fallback alongside focused capture tools. | alpha-hardware-validation-pending |
| Packet capture | Network > Packet Captures | Captures general, probe, station, EAPOL, deauthentication or raw observations. Different views of captured traffic. | alpha-hardware-validation-pending |
| Saved-capture analysis | Network > Packet Captures | Analyses DNS, DHCP, TCP retransmission, ARP and broadcast evidence. Turns packets into bounded diagnostic findings. | alpha-hardware-validation-pending |
| Route and connectivity | Network > DIAGNOSTICS & CAPTURE | Inspects addresses, routes and reachability. Helps separate routing faults from radio symptoms. | alpha-hardware-validation-pending |
| iperf tools | Network > DIAGNOSTICS & CAPTURE | Provides server controls and client/interface helpers. Local testing independent of Internet speed servers. | alpha-hardware-validation-pending |
| Security scan | Security > Security scan | Collects service findings, CVE applicability and vendor evidence. Separates possible, observed and vendor-supported findings. | alpha-hardware-validation-pending |
| Device Watch | Security > Device watch | Collects BLE advertisements and Wi-Fi observations with confidence labels. Selected targets avoid targeting all observations. | alpha-hardware-validation-pending |
| BLE target tracking | Targets > BLE Targets | Tracks an advertised MAC with signal/freshness states. Continuous fresh/stale/searching feedback. | alpha-hardware-validation-pending |
| Device history | Security > Device history | Retains bounded appearance and change events. Adds context beyond a single run. | alpha-hardware-validation-pending |
| Site survey reports | CLI report tools | Records location-tagged readings and exports floor-plan HTML. Portable offline measured-point reporting. | alpha-hardware-validation-pending |
| Wi-Fi recovery | System > Device Network Controls | Reports adapter state and restores permitted development radios. Controlled recovery with built-in radio protection. | alpha-hardware-validation-pending |
| Shared serial console | CLI: console | Provides one serial owner shared by local/remote terminal clients. Portable console-server workflow. | alpha-hardware-validation-pending |
| Remote report viewing | Optional; activation deferred | Retains an independent restricted scan-report browser. Two-person troubleshooting without shared navigation. | alpha-hardware-validation-pending |
| Display and startup | System / startup | Renders the local LCD and manages display handover. Consistent portable presentation and terminal fallback. | alpha-hardware-validation-pending |
| Game controls | Optional module | Preserves ROM discovery and bhtui control integration. Secondary use without a core dependency. | optional-unvalidated |
| Uplink Auto-Connect | Deferred | Connects to saved uplink profiles according to user preferences. Convenient management connectivity. | deferred |
| Email setup | System > Email setup | Guides SMTP setup and shares one sender across access notifications. Access works without email; failure retains local details. | alpha-hardware-validation-pending |
| VPN setup | System > VPN setup | Imports a self-contained OpenVPN profile and offers explicit On/Off. No provider lock-in and no connection before configuration. | alpha-hardware-validation-pending |
| Recovery hotspot | System > Recovery hotspot | Configures a phone/router hotspot name and password for management override. Provides an owner-configured recovery path without a preconfigured hotspot. | alpha-hardware-validation-pending |
| Vehicle Diagnostics | Home > Vehicle Diagnostics | Reads standard engine/emissions codes, readiness, freeze frames and live values; records and exports evidence with an offline DTC library. Local display, console and authenticated browser share one cancellable adapter owner and source-aware explanations. | software-validated-hardware-pending |
| System and hardware status | System | Shows temperature, memory, storage, uptime, interfaces and hardware/service status. Quickly separates a resource or link problem from a diagnostic result. | alpha-software-validation |
| USB device inventory | System | Enumerates connected USB hardware and available adapters. Makes adapter availability visible before starting a workflow. | alpha-software-validation |
| Generated target workflows | Targets | Groups discovered hosts, APs, BLE devices and security findings into follow-up actions. Connects discovery, evidence and tracking in one interface. | alpha-software-validation |
| Protected uplink radio | System > Device Network Controls | Verifies registered radio identity and bus before allowing USB capture/reset workflows. Reduces accidental loss of management access during radio work. | alpha-software-validation |
| Flipper control and power | Flipper companion | The board accepts menu controls from a compatible separately supplied Flipper app. Supports local field operation when a compatible companion is available. | not-included |
| Locally generated documentation | SSH / serial | Generates feature and process guides from source/catalog hashes. Documentation travels with the tools and can be reviewed alongside the implementation. | alpha-software-validation |
| OBD traffic and keyboard access | Vehicle Diagnostics > Remote access & data flow | Displays actual ELM serial TX/RX and queues read-only typed requests through the shared owner. Links decoded readings to real adapter traffic without a second serial reader. | alpha-software-validation |
| PC Recovery | Deferred | Private development recovery workflows are not packaged for activation. Keeps personal recovery media and setup out of the public source package. | deferred |
