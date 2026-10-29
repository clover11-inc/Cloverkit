# CloverKit Vehicle SSH

Local screen: Home > Vehicle Diagnostics > Remote access & data flow > Enable / renew SSH console.
The screen shows username conveh and a fresh two-word passphrase such as river-Clover. Existing configured email transport is reused; the passphrase remains visible if email is absent or fails.

PC: ssh -t conveh@CLOVERKIT_IP
Use arrows/WASD and Enter for the same Vehicle Diagnostics menus. T opens the read-only OBD terminal; Escape returns. Q or Ctrl-C closes your SSH session without stopping the local report. Navigation is independent, adapter/data are shared.

Scope: Vehicle Diagnostics only. No OS shell, SCP/SFTP, port forwarding or unrelated CloverKit menus. Account credentials are renewed on Enable; existing sessions then close. Disable SSH console, an explicit OBD Disconnect, normal OBD service shutdown or reboot revokes access. Maximum credential lifetime is eight hours; expiry is checked for every login and throughout an open session. Boot locks the account before SSH starts. Local navigation away from Vehicle Diagnostics does not stop a running report or revoke access.

Enabling access does not connect to a vehicle or start a scan. Select an adapter deliberately. Standard engine/emissions coverage still applies. This console is not a raw CAN bridge. Clearing codes still requires the existing pre-clear evidence and confirmation workflow.

Why use it: work directly on CloverKit, then join from a PC keyboard without granting a general system login or opening a second adapter connection.
