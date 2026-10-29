# Security and data handling

CloverKit is experimental diagnostic software, distributed without warranty. Use only on devices and networks you own, or have explicit written permission to assess. Follow applicable laws. Direct Ethernet DHCP, device control, radio reset and DTC clearing can change state; choose them deliberately. OBD clearing keeps the existing fresh evidence and confirmation workflow. No ECU flashing/coding feature is claimed.

The local OBD API binds to loopback by default and requires a token. Prefer an SSH tunnel to exposing it on a LAN. A general SSH account and restricted report-only accounts are different access models. Optional `conveh` uses a forced Vehicle Diagnostics view, no shell/file transfer/forwarding, temporary passwords, expiry and boot locking; fresh-card guest logins stay locked until their corresponding local feature enables access.

Passwords, VPN profiles, SMTP settings, access tokens, saved connections, captures, reports, VINs, MACs and SSIDs do not belong in a release archive. Runtime files are excluded by the package allowlist. The release audit inspects selected files, binary strings and members of bundled dependency archives. It cannot guarantee that a user's later modifications or shared reports contain no sensitive data.

Do not report secrets or raw personal captures in a public issue. Share a minimal redacted reproduction and the relevant source version. No private security contact has been configured yet; avoid publicly disclosing exploit details or identifiers while arranging a suitable reporting channel.
