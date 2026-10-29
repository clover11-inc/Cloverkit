# Clean-card activation source

These files contain the activation logic and exact runtime configuration used by the clean SD candidate. The install manifest maps source files to destinations; runtime hashes are checked before installation. Do not run firstboot.py on an existing installation: it is intended only for the marked fresh-card provisioning flow.

Owner setup defaults to admin and accepts a custom management username. Guest accounts console, conwifi and conveh remain restricted. Optional services start unconfigured. No shared SSH password, saved network, email account, VPN configuration or recovery-hotspot credentials are supplied.

The source staging installer remains isolated; these files are not an alongside-install command. See release-notes/CLEAN-CARD-STATUS.md for current validation limits.
