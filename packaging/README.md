# Packaging

`plan` verifies the checksummed compatibility payload and lists targets. `stage --root /new/absolute/path` materialises it atomically without activation. `install --prefix /separate/path` installs a versioned source copy and never writes those compatibility paths. `uninstall --prefix ...` checks tracked hashes before removing package files; changed/untracked files and user data are preserved.

No account, SSH, boot, service or interface setup is automatically activated. Rootfs/systemd and restricted-account files are review templates. Full host activation remains gated. Never execute staged capture commands as though staging were a sandbox.

`tools/package.py` uses an explicit input allowlist and privacy audit, includes pinned corresponding dependency sources, and creates deterministic ZIP/tar.gz archives with inner manifests and outer SHA256SUMS. Debug files, caches, developer paths, captures, runtime databases and private configuration are excluded. Read INSTALL.md and NOTICE.md before adapting activation.
