# CloverKit process/source reference

Static source relationships, not a running-process list. Literal references do not establish complete dependency closure.

## src/commands/ap-find-compact
Workflow: wifi-targets
Purpose: Entry point / helper for ap find compact. See referenced backends for effects.
SHA256: 9a686c8f955757c7bb96a860f423c5d0d7c1ea854bbfe4ca2c77baa8f2795d55
Referenced helpers: /usr/local/bin/ap-find-compact, /usr/local/lib/bh-interactive

## src/commands/ap-find-group
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for ap find group. See referenced backends for effects.
SHA256: e837a57bd667e20a02e070a89cde58a087fec4be0bcb99d8425ea59ac8e5d6d3
Referenced helpers: No literal local helper references.

## src/commands/bh-flipper-job
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for bh flipper job. See referenced backends for effects.
SHA256: b6747801ded0fb7391040c8c9755deb010b5dd75442e75349e5da14e41706405
Referenced helpers: /usr/local/bin/lcd-run

## src/commands/bh-panel
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for bh panel. See referenced backends for effects.
SHA256: b4891c2778eaa695876fa34a3708f847e1c05b0e4a8eba0c463f51316dfd01fb
Referenced helpers: /usr/local/lib/bh-interactive/bh_panel.py

## src/commands/bh-panel-ap-find
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for bh panel ap find. See referenced backends for effects.
SHA256: 73b3446243b8d33ee4f047bbe2b6df50f5f3bd54476c83c8082a8a110fcdf7d3
Referenced helpers: /usr/local/bin/bh-panel-ap-find, /usr/local/lib/bh-interactive

## src/commands/bh-panel-packet-general
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for bh panel packet general. See referenced backends for effects.
SHA256: be46b2e005cfb5c2c65a217c29b6ca0165369a64a3585d3705e915cc423ac829
Referenced helpers: /usr/local/bin/bh-panel-packet-general

## src/commands/bh-panel-packet-live
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for bh panel packet live. See referenced backends for effects.
SHA256: 2893c451e9e12d903a02a963a33402aa3d4184a8604765e8d8d73de0e9baafe8
Referenced helpers: /usr/local/bin/bh-panel-packet-live, /usr/local/lib/bh-interactive

## src/commands/bh-panel-packet-scan
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for bh panel packet scan. See referenced backends for effects.
SHA256: 83fe81aa3c8d1f0e63c026d0bb7158d9935804fddc56550da5e9b1a65fae2739
Referenced helpers: /usr/local/bin/bh-panel-packet-scan, /usr/local/lib/bh-interactive

## src/commands/bh-probe-reader
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for bh probe reader. See referenced backends for effects.
SHA256: 3e4a3fe45bc45903bc90bcefc342de92938ee996944424719f84f552c13be027
Referenced helpers: /usr/local/bin/bh-probe-reader, /usr/local/lib/bh-interactive

## src/commands/bh-screen
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for bh screen. See referenced backends for effects.
SHA256: 948f39ea270a16b684d754caea2f3335e1adcf09c9d18b5912362a13af187cab
Referenced helpers: /usr/local/bin/bh-panel

## src/commands/bh-serial-gateway
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for bh serial gateway. See referenced backends for effects.
SHA256: 3921aed082677215fb5d18f14c2ff6acd42abd8076b4c540f0add7ceaf5b0cc2
Referenced helpers: /usr/local/bin/bh-panel, /usr/local/lib/bh-interactive/bh_panel.py

## src/commands/bh-wifi-peer
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for bh wifi peer. See referenced backends for effects.
SHA256: c50c0e328b5411413a24f5dc9bca8736a0075fbaf1bec756a09169ab5f8b6a2a
Referenced helpers: /usr/local/lib/bh-interactive, /usr/local/lib/bh-interactive/wifi_peer.py

## src/commands/clover-direct-ethernet
Workflow: direct-ethernet
Purpose: Direct-cable diagnostics. No DNS, gateway, forwarding or persistent leases.
SHA256: 737c2daa33fd13f60eac7a3b3fe5b22ca4e7df6fac48c17ea6a60a0e4e9b2548
Referenced helpers: /usr/local/lib/bh-interactive

## src/commands/cloverkit
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for cloverkit. See referenced backends for effects.
SHA256: 7260e0b22665a6b4ee736300c1b224b82396d7bbb559411e980cb5a5074641a4
Referenced helpers: No literal local helper references.

## src/commands/cloverkit-name-radios
Workflow: native-radio
Purpose: Cold-boot native naming before NetworkManager; no fixed USB MACs or port labels.
SHA256: 61bddf0292e284437a00fae78db35efe4ab08b9585cf1f12249a7b805f7f2fe9
Referenced helpers: /usr/local/lib/bh-interactive

## src/commands/cloverkit-packet-insights
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for cloverkit packet insights. See referenced backends for effects.
SHA256: 199eae5a98341e0bc407089e70ad5bcdf2302044dcff0a5deab19cf1576ec711
Referenced helpers: /usr/local/lib/bh-interactive

## src/commands/cloverkit-radio-reset
Workflow: radio-reset
Purpose: Explicit recovery of independent development radios; wlan0 is never modified.
SHA256: acedc2c6ed17b81ff93bd4011bfa8b2d7d272064bc358a69153833cfd1b5a9c3
Referenced helpers: /usr/local/lib/bh-interactive

## src/commands/cloverkit-recovery-watch
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for cloverkit recovery watch. See referenced backends for effects.
SHA256: 512bd3dee945aa636a9197105e55107397563b5dd16ab7053fd19c99a28f31e5
Referenced helpers: /usr/local/lib/bh-interactive

## src/commands/cloverkit-report
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for cloverkit report. See referenced backends for effects.
SHA256: f029438daf38bb04cf36b94c127d06e9866108b6118ff6871cc52c2da7d2d4f9
Referenced helpers: /usr/local/lib/bh-interactive

## src/commands/cloverkit-setup
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for cloverkit setup. See referenced backends for effects.
SHA256: 1fbe38597d4d79573ac6707b6154c6731edbdba56b483b04cab9f94a28384c28
Referenced helpers: /usr/local/lib/bh-interactive

## src/commands/cloverkit-survey-store
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for cloverkit survey store. See referenced backends for effects.
SHA256: b593a3cc5ce8218ef4a603e9cbd058d7521bed5cee8bf52b34452033a3db97c7
Referenced helpers: /usr/local/lib/bh-interactive

## src/commands/cloverkit-vehicle
Workflow: Support helper; individual purpose review pending
Purpose: CloverKit offline vehicle CLI; bundled dependencies require no runtime downloads.
SHA256: 73eb9d4401c970442166090e92aee0b5cad3eb4bb0d20c40f110f6d0bb69f440
Referenced helpers: /usr/local/lib/cloverkit/vehicle

## src/commands/cloverkit-vpn
Workflow: Support helper; individual purpose review pending
Purpose: Explicit optional VPN control. Never connects if not configured.
SHA256: 1b2a77c33609859b48a22708024574ff81c71f7033a25bdd41787dc38e52eed7
Referenced helpers: /usr/local/lib/bh-interactive

## src/commands/console
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for console. See referenced backends for effects.
SHA256: b9381f8714b4a10d6f656163085705d200e779443d86d635f4e7bdd9365a52b0
Referenced helpers: /usr/local/lib/bh-interactive/shared_console.py

## src/commands/conwifi-run
Workflow: Support helper; individual purpose review pending
Purpose: Root-owned no-argument launchers for local or restricted remote scan viewing.
SHA256: c004b870edcc28831aab5c46d995907ee3d77eeae8252926d0b49bf6dd4ac151
Referenced helpers: /usr/local/bin/wifi-passive-health-panel, /usr/local/lib/bh-interactive

## src/commands/device-track
Workflow: ble-targets
Purpose: Entry point / helper for device track. See referenced backends for effects.
SHA256: 9df009601593a0c536a938a39250e0b342c19068cdd7f5def626757364e04b58
Referenced helpers: /usr/local/bin/device-track

## src/commands/device-watch
Workflow: device-watch
Purpose: Entry point / helper for device watch. See referenced backends for effects.
SHA256: 5a16ec96fbd1c69daf59997a3ed2dacda6ed1c05f6766807e985eeb6b000694a
Referenced helpers: /usr/local/bin/cloverkit-device-watch-wifi, /usr/local/bin/device-track, /usr/local/bin/device-watch, /usr/local/lib/bh-interactive

## src/commands/eth-info
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for eth info. See referenced backends for effects.
SHA256: d3407f7ad475994857e6cf49d82f8f763775b522af880188c1ff0b5061544ac8
Referenced helpers: No literal local helper references.

## src/commands/ethernet-l2-capture
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for ethernet l2 capture. See referenced backends for effects.
SHA256: b114461fa0c9bc2a8a1bcc5d6deaee0e523ad2ff2d8125402204fdd897da9cf1
Referenced helpers: No literal local helper references.

## src/commands/ethernet-live
Workflow: ethernet
Purpose: Entry point / helper for ethernet live. See referenced backends for effects.
SHA256: 590970e7a4e28cc71cdd39870730a131c430f8e7a008a47a964ca570fd0ec4c3
Referenced helpers: /usr/local/bin/ethernet-l2-capture, /usr/local/lib/bh-interactive

## src/commands/ethernet-neighbor-capture
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for ethernet neighbor capture. See referenced backends for effects.
SHA256: 225584b7062084c16dad4924cf94b1024a05464b707a0dca55a3f86bfaa18854
Referenced helpers: No literal local helper references.

## src/commands/host-profile
Workflow: hosts
Purpose: Entry point / helper for host profile. See referenced backends for effects.
SHA256: 2a426f00f5677a08846b8fadc9c848f1fce65fbd310ce65f1298fad9ca71fcaf
Referenced helpers: No literal local helper references.

## src/commands/hosts
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for hosts. See referenced backends for effects.
SHA256: 37888847f0ea2d7fe401e2cc4cad5f85df58a9d50318e3e93618769759fd002b
Referenced helpers: No literal local helper references.

## src/commands/iperf-client
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for iperf client. See referenced backends for effects.
SHA256: 828f884ab3b4211f43aeae43804ee5b7ad83e907c0a5f3850fcf6e6ab3c62d9b
Referenced helpers: No literal local helper references.

## src/commands/iperf-select-if
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for iperf select if. See referenced backends for effects.
SHA256: 4e9da0b0cae36e88385ec5dff2c4535fd50600f88dc6b5cb3361f42b415723a4
Referenced helpers: No literal local helper references.

## src/commands/iperf-server
Workflow: iperf
Purpose: Entry point / helper for iperf server. See referenced backends for effects.
SHA256: 5c2c1f70a88d9b042f81b6b60d766ff5736d7ade6c7112526b50d4295d6b1dde
Referenced helpers: /usr/local/bin/iperf-select-if, /usr/local/bin/iperf-server

## src/commands/lcd-cli-reset
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for lcd cli reset. See referenced backends for effects.
SHA256: f51f1e64a055afd7c964fe1f309416bba9117af719b416b0edb1c810009af274
Referenced helpers: No literal local helper references.

## src/commands/lcd-display-owner
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for lcd display owner. See referenced backends for effects.
SHA256: a18cb7997cee5f455571f02de0462c3742e1c955f32795cf0d1e3c835fe260be
Referenced helpers: No literal local helper references.

## src/commands/lcd-mode
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for lcd mode. See referenced backends for effects.
SHA256: 9ead1f2b4350fd7efa09a87f934a7a4614fad51715811bd1497bd395ae03f5f3
Referenced helpers: No literal local helper references.

## src/commands/lcd-run
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for lcd run. See referenced backends for effects.
SHA256: 4e32c369670d3e3b587172e0fcf04ec5b8def584a91faf76b94af81948feecb6
Referenced helpers: /usr/local/bin/bh-flipper-job, /usr/local/bin/lcd-display-owner, /usr/local/lib/bh/lcd-cli.sh, /usr/local/lib/bh/lcd-device-watch.py, /usr/local/lib/bh/lcd-ethernet.py, /usr/local/lib/bh/lcd-gui.py, /usr/local/lib/bh/lcd-host-target.py, /usr/local/lib/bh/lcd-hosts.py, /usr/local/lib/bh/lcd-packet-live.py, /usr/local/lib/bh/lcd-packet.py, /usr/local/lib/bh/lcd-security.py, /usr/local/lib/bh/lcd-system.py, /usr/local/lib/bh/lcd-target.py, /usr/local/lib/bh/lcd-wifi.py

## src/commands/lcd-wrap-targets
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for lcd wrap targets. See referenced backends for effects.
SHA256: f7b7b8d832f5a6a05ac6852c93b46408f1cac85afc7d1304a1b01d77212063f9
Referenced helpers: /usr/local/bin/lcd-run

## src/commands/packet-general-live
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for packet general live. See referenced backends for effects.
SHA256: c383283ecb411bb7db1abcaf9ea6aa37f4f91900d1f7db3ac5c4d18684cb2e90
Referenced helpers: /usr/local/bin/packet-general-live, /usr/local/lib/bh-interactive

## src/commands/packet-live
Workflow: packets
Purpose: Entry point / helper for packet live. See referenced backends for effects.
SHA256: 5c8a18b5762c5cc123c4d54168de26b2be008730f37fa5c9b3a9a58e423e31ee
Referenced helpers: /usr/local/bin/packet-live, /usr/local/lib/bh-interactive

## src/commands/packet-raw-clean
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for packet raw clean. See referenced backends for effects.
SHA256: d9f621842f14b655042eb5869ebd39f82be99915410b903a4412f57188d0cc3b
Referenced helpers: No literal local helper references.

## src/commands/path-test
Workflow: routes
Purpose: Entry point / helper for path test. See referenced backends for effects.
SHA256: bcbbd1254fc9aeefe2634e261c3869100b54ef35e50996d979e4744190ac0b2f
Referenced helpers: /usr/local/bin/path-test

## src/commands/route-check
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for route check. See referenced backends for effects.
SHA256: 303f00a3de559b37148e249e8d83d9303ad0e510ce6629e4795d6030552c383d
Referenced helpers: No literal local helper references.

## src/commands/sec-ble-authorize
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for sec ble authorize. See referenced backends for effects.
SHA256: baaef2884caa56752e0f0e18d6978d842b76cb490155010c5ff888cc1b6cc0fe
Referenced helpers: No literal local helper references.

## src/commands/sec-ble-list
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for sec ble list. See referenced backends for effects.
SHA256: 2980deabd24b120d61b8d0ea453d69d9ca997ff9a443efb0268545136721dd2f
Referenced helpers: No literal local helper references.

## src/commands/sec-ble-remove
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for sec ble remove. See referenced backends for effects.
SHA256: 75260f760ddbc9b9274873878e49f9a98e659b537c0f28c6f7dc340b05ba14eb
Referenced helpers: No literal local helper references.

## src/commands/sec-detail
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for sec detail. See referenced backends for effects.
SHA256: 3dc1c23e0283ca6368077de6282ab16b87dceb7716ac8b940a0e768ce093e5dc
Referenced helpers: No literal local helper references.

## src/commands/sec-last
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for sec last. See referenced backends for effects.
SHA256: 454c5ee9b6f291df23011d9a23ed8a6e4aa2e311f744f4143121a305cbc4b905
Referenced helpers: No literal local helper references.

## src/commands/sec-scan
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for sec scan. See referenced backends for effects.
SHA256: 64f69ab80bbe0eb3c3ee8d83a943b3edc5f272d8c147b98a4ffa1e5585636f3d
Referenced helpers: No literal local helper references.

## src/commands/sec-update
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for sec update. See referenced backends for effects.
SHA256: fe2ec0164b0f8dd49471ed214b0d43b000a73c554ea58ff169d3028bdb5f5bfc
Referenced helpers: No literal local helper references.

## src/commands/sec-validate
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for sec validate. See referenced backends for effects.
SHA256: 5183ef1e209cf44d598845c53ee88f77be7a2ff8e50d56b8f558f3499361c05c
Referenced helpers: No literal local helper references.

## src/commands/secscan-events
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for secscan events. See referenced backends for effects.
SHA256: 17bc8a5de99d22c28531f09a9dc27710fc7bd667367033a9cd6e0c90aa4c772c
Referenced helpers: No literal local helper references.

## src/commands/secscan-lcd-run
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for secscan lcd run. See referenced backends for effects.
SHA256: e581c0dd8fe8d53d6c028038c6c689a6090c1f445663a4b35519dde4a3b0432d
Referenced helpers: /usr/local/bin/secscan-events, /usr/local/bin/secscan-targets, /usr/local/lib/bh-interactive

## src/commands/secscan-targets
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for secscan targets. See referenced backends for effects.
SHA256: 88756df0640d2c7cc324aa47649ee1aee3f438f73e503efe8760f96da11e5bbb
Referenced helpers: /usr/local/bin/lcd-wrap-targets, /usr/local/bin/sec-detail

## src/commands/security-status
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for security status. See referenced backends for effects.
SHA256: 75fd2fe8a4f8c5b3da6fa21ab1ff5356c715a99ecd32c6431c9e463156e59ac1
Referenced helpers: No literal local helper references.

## src/commands/system
Workflow: system
Purpose: Entry point / helper for system. See referenced backends for effects.
SHA256: 7d9f22c67baa7168665d558f9846e411eac57adf610ecfb31c33d4e34b1204d0
Referenced helpers: No literal local helper references.

## src/commands/target-build-wifi
Workflow: target-workflows
Purpose: Entry point / helper for target build wifi. See referenced backends for effects.
SHA256: 876cd9f0a88153aea1047064fa945f0f2e8bdbbd6ce39b09084839fa06ad3246
Referenced helpers: /usr/local/bin/ap-find-compact, /usr/local/bin/lcd-wrap-targets, /usr/local/bin/target-build-wifi

## src/commands/target-clean
Workflow: target-workflows
Purpose: Entry point / helper for target clean. See referenced backends for effects.
SHA256: e6040dd8a4e43263959e825cae100b0a53b7e06491a45dda5ccb7deba75a966d
Referenced helpers: /usr/local/bin/target-clean

## src/commands/usb-scan
Workflow: usb
Purpose: Entry point / helper for usb scan. See referenced backends for effects.
SHA256: 9659e796c62abeb6f273ddc58381057d6c69caa04e5fcb4d3a934ed0770bf3e2
Referenced helpers: No literal local helper references.

## src/commands/wifi-apnames
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for wifi apnames. See referenced backends for effects.
SHA256: 98a971b4063585f71ade7155efd091cf65e3e993fb8cc54b64e495242fb08e24
Referenced helpers: No literal local helper references.

## src/commands/wifi-health
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for wifi health. See referenced backends for effects.
SHA256: 41ddc38c8b4df76170e0ce20dd5c112df80ab9ea6d9ae6d718e262d18530c081
Referenced helpers: /usr/local/bin/wifi-health-connected, /usr/local/bin/wifi-passive-health, /usr/local/lib/bh-interactive

## src/commands/wifi-health-ap-map
Workflow: Support helper; individual purpose review pending
Purpose: Scoped, no-argument writer for a user-confirmed AP/BSSID mapping.
SHA256: 7ad83b0ba4a79f1cdcdd1ab80f3cc614d542a1566a25ad9910c03b946cb6ac8e
Referenced helpers: No literal local helper references.

## src/commands/wifi-health-connected
Workflow: client-health
Purpose: Cloverkit client health: read-only radio observations and bounded active tests.
SHA256: af57baadc34c361ceb4cbae5a81f45768b1c51ac4cf330b203c341606ae6eb34
Referenced helpers: /usr/local/lib/bh-interactive

## src/commands/wifi-monitor
Workflow: monitor
Purpose: Entry point / helper for wifi monitor. See referenced backends for effects.
SHA256: 72eab5b42192832fb48fee6c7c93607985739d764fd3fb5f3c40416ba5978a17
Referenced helpers: No literal local helper references.

## src/commands/wifi-passive-health
Workflow: wifi-advanced
Purpose: Automatic passive Wi-Fi observations; no association, credentials or payload decryption.
SHA256: b84ebd28ce6ab42d1674ea58e19f8d37e74013a3119bec04f6284b9580007135
Referenced helpers: /usr/local/lib/bh-interactive

## src/commands/wifi-passive-health-panel
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for wifi passive health panel. See referenced backends for effects.
SHA256: 157ad8ac48d06dc706578b6101a2d571966196dca8d42f5a0ac599fee16dd81c
Referenced helpers: /usr/local/bin/wifi-passive-health, /usr/local/lib/bh-interactive

## src/commands/wifi-scan
Workflow: wifi-basic
Purpose: Entry point / helper for wifi scan. See referenced backends for effects.
SHA256: b370106e262a10243e3cd1fde5ed5f881cba32b132ebf2f33184f58abc8f1845
Referenced helpers: /usr/local/bin/target-build-wifi, /usr/local/bin/wifi-apnames, /usr/local/bin/wifi-scan, /usr/local/lib/bh-interactive

## src/commands/wifi-waterfall
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for wifi waterfall. See referenced backends for effects.
SHA256: 3b610e8de506ea0fcf15a40ff2fb89c685d1710b43b6bf1ba15cccc7361c19eb
Referenced helpers: /usr/local/bin/bh-panel

## src/commands/wifi-waterfall-capture
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for wifi waterfall capture. See referenced backends for effects.
SHA256: 9a40021131148a30b505e79dfcfae31fcba8230cdc904a6381f5e09ca870f10d
Referenced helpers: /usr/local/bin/wifi-passive-health

## src/panel/bh_panel.py
Workflow: panel, tasks, system, target-workflows
Purpose: Standalone BlackHat panel; existing toolkit scripts are never edited.
SHA256: 2c81cef7dafa22492b3c4d9b25227983f1278b59bef70472cf016869bb1a1473
Referenced helpers: /usr/local/bin/ap-find-compact, /usr/local/bin/bh-panel-ap-find, /usr/local/bin/bh-panel-packet-general, /usr/local/bin/bh-panel-packet-live, /usr/local/bin/bh-panel-packet-scan, /usr/local/bin/bh-probe-reader, /usr/local/bin/bh-vpn, /usr/local/bin/bh-wifi-peer, /usr/local/bin/clover-direct-ethernet, /usr/local/bin/console-off, /usr/local/bin/console-on, /usr/local/bin/console-status, /usr/local/bin/conwifi-run, /usr/local/bin/conwifi-run-local, /usr/local/bin/ethernet-live, /usr/local/bin/host-profile, /usr/local/bin/iperf-server, /usr/local/bin/lcd-run, /usr/local/bin/wifi-passive-health-panel, /usr/local/lib/bh/lcd-system.py

## src/panel/clover_boot_splash.py
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for clover boot splash. See referenced backends for effects.
SHA256: 27fe0a5ebbe841445eb30d68e561dc716f3af7895a7ddbea6515a63b4ac2a88e
Referenced helpers: /usr/local/lib/bh-interactive/clover-boot.png

## src/panel/clover_compact_pages.py
Workflow: Support helper; individual purpose review pending
Purpose: Small-screen task results; preserve the specialised diagnostic views.
SHA256: 6b5a45a6ca3f2595c47017f52ec6ccd97aca1b87528f2ca22d69821f2bdd5c07
Referenced helpers: No literal local helper references.

## src/panel/clover_game_session.py
Workflow: games
Purpose: Cloverkit game lifecycle: input proxy, VT handoff, scoped cleanup.
SHA256: 2a03a8b6ac78040f1146870aaf56e96ad5ed991f332179c3c55fcb35838f90de
Referenced helpers: /usr/local/bin/bhtui

## src/panel/clover_lcd_panel.py
Workflow: display
Purpose: Render existing ANSI panel frames over a faint clover on the local LCD only.
SHA256: 7f86ea2e5125812c6790f87c8114ec74ae6e0673e532a5d33d035f76c9852743
Referenced helpers: /usr/local/lib/bh-interactive/clover-boot.png

## src/panel/cloverkit_device_history.py
Workflow: history
Purpose: Device Watch history and advertisement enrichment using its existing scanners.
SHA256: 183d376e667e51831ce88ab398c0b64d09154ba1cc57c570189cd3fa42cc7878
Referenced helpers: No literal local helper references.

## src/panel/cloverkit_direct_neighbors.py
Workflow: Support helper; individual purpose review pending
Purpose: Reuse Ethernet's existing passive L2 helper inside Direct Ethernet sessions.
SHA256: 9a659d38df4ca19114e1860303aa01b8b4a17bf2ee92c4db6f72455cbd5b9523
Referenced helpers: /usr/local/bin/ethernet-l2-capture

## src/panel/cloverkit_insights.py
Workflow: Support helper; individual purpose review pending
Purpose: Evidence-based CloverKit analysis. This module never changes interfaces.
SHA256: 538046d360d0fa168d65817764706fabc03c59ac4644628d8918a0e03ac894d8
Referenced helpers: No literal local helper references.

## src/panel/cloverkit_network_sections.py
Workflow: Support helper; individual purpose review pending
Purpose: Display-only Network sections; tools keep their existing launch handlers.
SHA256: d630b249f1e99b15665abe5bfc471ad4580829b645daca17cb23e5b7fb80e18f
Referenced helpers: No literal local helper references.

## src/panel/cloverkit_optional_setup.py
Workflow: email, vpn
Purpose: Optional CloverKit email/VPN setup; nothing sends or connects on import.
SHA256: 02f08024bb4f66a72a826f8b5a495e4414c4db82416228491a6b8c6715af6cfb
Referenced helpers: No literal local helper references.

## src/panel/cloverkit_panel_features.py
Workflow: Support helper; individual purpose review pending
Purpose: Small integrations for the established CloverKit panel.
SHA256: f32eb7fdc0d375be72790bbe5b09c457767e55fc2cdee46a16f1f4be0d40fc87
Referenced helpers: /usr/local/bin/wifi-health-connected

## src/panel/cloverkit_radio_identity.py
Workflow: native-radio
Purpose: Protect the native SDIO radio; discover USB radios without saved USB identities.
SHA256: ce41ec0784b51eed776979e9c3f427f90ff477ee1ce0273cb9d58bd44ac46c74
Referenced helpers: No literal local helper references.

## src/panel/cloverkit_radio_menu.py
Workflow: Support helper; individual purpose review pending
Purpose: One Wi-Fi adapters status and recovery page under Device Network Controls.
SHA256: 632331410065cfbf44c601ced1d1bfc0af563caf5be937c6bb7a6a1e8be2c486
Referenced helpers: /usr/local/bin/cloverkit-radio-reset

## src/panel/cloverkit_radio_recovery.py
Workflow: Support helper; individual purpose review pending
Purpose: Journal and recover only the external radios owned by Advanced Scan.
SHA256: afe071bd2a70d2d5240ced65d3f98afe7d967692d15a840bf92ea74a261e49dd
Referenced helpers: No literal local helper references.

## src/panel/cloverkit_recovery_hotspot.py
Workflow: recovery-hotspot
Purpose: Optional saved recovery-hotspot override; no personal profile defaults.
SHA256: e60b1f1a97b5f85ebafdda07b36eaad90ef22ac59cbe67309401b62ce0211c68
Referenced helpers: No literal local helper references.

## src/panel/cloverkit_release_scope.py
Workflow: Support helper; individual purpose review pending
Purpose: Keep deferred integrations out of the candidate panel; retain independent serial CLI.
SHA256: 2d1ef05709728eddc5e8f7c0c4fa01258267459579de08f70d3a4a9172ca70d7
Referenced helpers: /usr/local/bin/cloverkit-vpn

## src/panel/cloverkit_report.py
Workflow: topology, packet-analysis, survey
Purpose: Report tools for existing CloverKit captures and measurements; no new capture engine.
SHA256: 492c0215de71f51ae2781646701e3c3e8bf1e805b74b660fd875c39395608e85
Referenced helpers: /usr/local/bin/cloverkit-survey-store

## src/panel/cloverkit_vehicle_menu.py
Workflow: vehicle-diagnostics
Purpose: CloverKit menu integration. Slow adapter work never runs on the panel thread.
SHA256: 13c6c98d5af7b33908449ceda35f2b810310f0e74ddcdf09b4b6eaa9ef1b61b1
Referenced helpers: /usr/local/lib/cloverkit/vehicle

## src/panel/cloverkit_vehicle_readable.py
Workflow: Support helper; individual purpose review pending
Purpose: Readable vehicle summaries. Presentation only; no diagnostic operations.
SHA256: 6fbb04f3f8ec33f8b39e8585cad7110e2301debd87631d0e8f799cf5aae84ae2
Referenced helpers: No literal local helper references.

## src/panel/cloverkit_vehicle_ssh_menu.py
Workflow: Support helper; individual purpose review pending
Purpose: Optional restricted Vehicle SSH controls layered over the readable OBD menus.
SHA256: ab8964e44085df7a2ede89265a4d64d683349780170f61935fc1db46831e783e
Referenced helpers: No literal local helper references.

## src/panel/cloverkit_wifi_waterfall.py
Workflow: waterfall
Purpose: AP packet RSSI waterfall. This is not an RF spectrum measurement.
SHA256: 8603d7157f078525e91cde5268abc3952ac5a05e77521d15c1644044d02b9a48
Referenced helpers: /usr/local/bin/wifi-waterfall-capture, /usr/local/lib/bh-interactive/clover-boot.png

## src/panel/cloverkit_wireless.py
Workflow: Support helper; individual purpose review pending
Purpose: Live capabilities, roaming, topology and site-survey pages for Advanced Scan.
SHA256: dc85795c1481e1b054b713d2a34bfdae1070b7ba15b1b21359702a571193d6d3
Referenced helpers: /usr/local/bin/cloverkit-survey-store

## src/panel/console_email.py
Workflow: Support helper; individual purpose review pending
Purpose: Compatibility notification entrypoint; uses the single CloverKit email configuration.
SHA256: dbc488f2e2ae2172e43d4e2e0555c349553798da97af7060431cc5d222e742fa
Referenced helpers: No literal local helper references.

## src/panel/console_password.py
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for console password. See referenced backends for effects.
SHA256: 00cc90ef1209f5910a56ab74532cb8a619186f63477a324017f26ff294489227
Referenced helpers: No literal local helper references.

## src/panel/console_traffic.py
Workflow: Support helper; individual purpose review pending
Purpose: Observe TCP counters for sockets held by the restricted Console account.
SHA256: 1721b61b536dbe618728387e17048b5911026b3cf4c1c81717ca810e0cd8027d
Referenced helpers: No literal local helper references.

## src/panel/conwifi_report.py
Workflow: report-sharing
Purpose: Forced SSH command: browse only the published Advanced scan snapshot.
SHA256: bc5ec65f0b76605ac2d45c461fdc9d7e6b1b5162faaaf9db62b7584a57165cb6
Referenced helpers: /usr/local/lib/bh-interactive

## src/panel/device_identity.py
Workflow: Support helper; individual purpose review pending
Purpose: Offline MAC attribution. Registered vendor is not a device-model identity.
SHA256: ba10e08939fed79468c7262af6bd3656bebc4be7ba7ec98b6774979d25e98428
Referenced helpers: /usr/local/lib/bh-interactive/identity-fields.json, /usr/local/lib/bh-interactive/manuf

## src/panel/direct_ethernet_view.py
Workflow: Support helper; individual purpose review pending
Purpose: Fixed evidence summary above a scrollable, timestamped task history.
SHA256: b63feb2237da5c75666707350402205547b17722c7fa2273a8b74b502218fc76
Referenced helpers: No literal local helper references.

## src/panel/identity-fields.json
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for identity fields. See referenced backends for effects.
SHA256: 807476292502550dd17377bc7b353b63d49c9017f65f77e60cef6b00d628bf34
Referenced helpers: No literal local helper references.

## src/panel/probe_reader.py
Workflow: Support helper; individual purpose review pending
Purpose: Passive probe collection/tracking on an external radio; no frame injection.
SHA256: 720fdda3197bc39a196bc771408355e1d748297622ae195ef82e19c7a35e802e
Referenced helpers: /usr/local/bin/bh-probe-reader

## src/panel/shared_console.py
Workflow: serial
Purpose: One serial reader per adapter, shared terminal clients and an LCD snapshot.
SHA256: b6961ea1dbb24266f64839f559886eafc0fd32dd04984b4d60f2c357f4218397
Referenced helpers: No literal local helper references.

## src/panel/wifi_console_menu.py
Workflow: Support helper; individual purpose review pending
Purpose: Local Advanced capture entry; account/email integration is deferred.
SHA256: c89936c0a652cb139b3a2b519e52de241ba394dc2cc31015a80905a9d01db3c2
Referenced helpers: /usr/local/bin/conwifi-run, /usr/local/bin/wifi-passive-health-panel

## src/panel/wifi_health_browser.py
Workflow: Support helper; individual purpose review pending
Purpose: H23 live network browser. Navigation holds identities, never volatile row indexes.
SHA256: a8c2f0000cb6350c65829828c9bdba52991509178ee1e2e1cc80e9195ef30aad
Referenced helpers: /usr/local/bin/wifi-health-ap-map

## src/panel/wifi_health_engineer.py
Workflow: Support helper; individual purpose review pending
Purpose: Receiver evidence and display context; no radio or scan policy changes.
SHA256: 2968f67622f012aad2705fd76dcf09932007711272fe3de50e0a0972aed8dbe7
Referenced helpers: No literal local helper references.

## src/panel/wifi_health_presentation.py
Workflow: Support helper; individual purpose review pending
Purpose: Concise, evidence-led Advanced report pages shared by LCD and SSH.
SHA256: 9d62cebaf154a74f38e0f90fd1c4e0f5f6677899aa0ea5bcc9cee5af8d789945
Referenced helpers: No literal local helper references.

## src/panel/wifi_health_view.py
Workflow: Support helper; individual purpose review pending
Purpose: Fixed, selectable Wi-Fi dashboard. Each render replaces its previous state.
SHA256: 86ab8b0f9376e16517764c3aec78448d59d64f7a8f359ddc33d69c52c7878921
Referenced helpers: No literal local helper references.

## src/panel/wifi_peer.py
Workflow: Support helper; individual purpose review pending
Purpose: Passive infrastructure pair discovery, direction monitoring and client finding.
SHA256: 9e8f0db57dab91a27a297a0b64011dac0d9efa048b9eac56e96ec9248ad74f07
Referenced helpers: /usr/local/bin/bh-wifi-peer

## src/security/secscan.py
Workflow: security
Purpose: Entry point / helper for secscan. See referenced backends for effects.
SHA256: 1c1fc8e86f1ccaf01a399c0e9c226b7598e948b7774548290fbc44e309b200e5
Referenced helpers: /usr/local/lib/bh-interactive

## src/security/secvalidate.py
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for secvalidate. See referenced backends for effects.
SHA256: 970c71860902701753a040a9f0d36e6248838e3a28879f369bd5d7768e328366
Referenced helpers: No literal local helper references.

## src/security/validators/patterns.json
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for patterns. See referenced backends for effects.
SHA256: 06b2093febc0a47be756ed23443840631a208d8c19532e11759b7f7488b036bc
Referenced helpers: No literal local helper references.

## src/security/validators/profile-schema.json
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for profile schema. See referenced backends for effects.
SHA256: 3db959d8270a1f46915d36bbbb0cb4f5b7e013474b7398af6eafc17aac74adb9
Referenced helpers: No literal local helper references.

## src/security/validators/profiles/EXAMPLE.json
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for EXAMPLE. See referenced backends for effects.
SHA256: 542211676d4fcf3c49a24dd8c9cc174165661934c20566e181d16b6345d1007e
Referenced helpers: No literal local helper references.

## src/security/validators/registry.json
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for registry. See referenced backends for effects.
SHA256: ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356
Referenced helpers: No literal local helper references.

## src/launchers/device-history.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for device history. See referenced backends for effects.
SHA256: fba97a3a1dc90dd1d6e0fea0ddeffe19277c4bdc9c6a4aa6e0e07775b4c40be5
Referenced helpers: /usr/local/bin/cloverkit-report

## src/launchers/device-watch.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for device watch. See referenced backends for effects.
SHA256: da7dc230ff8f0b011af8f38066019bb8e0224b157e162b6619c9d5a0f03c06ca
Referenced helpers: /usr/local/bin/device-watch, /usr/local/bin/lcd-run, /usr/local/bin/lcd-wrap-targets

## src/launchers/display-mode.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for display mode. See referenced backends for effects.
SHA256: 584f261d5f3a7f1166b5bfcc48b6e2878de658f3880e0f9fc7a627939d4e2fd4
Referenced helpers: /usr/local/bin/lcd-cli-reset, /usr/local/bin/lcd-display-owner

## src/launchers/ethernet.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for ethernet. See referenced backends for effects.
SHA256: 7c678ef03173d8ee30622922a01ef4a20e49279695c30fa37bc57a0a80a55d62
Referenced helpers: /usr/local/bin/eth-info, /usr/local/bin/ethernet-live, /usr/local/bin/lcd-run

## src/launchers/hosts.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for hosts. See referenced backends for effects.
SHA256: 0251fe6cde06743b5a7f3e4bfddbd8c2543a7e2cc2a90b34ba680116c48852ad
Referenced helpers: /usr/local/bin/host-profile, /usr/local/bin/lcd-run, /usr/local/bin/lcd-wrap-targets

## src/launchers/iperf-toggle.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for iperf toggle. See referenced backends for effects.
SHA256: 5a784ed1d7dc5cb1584c95bc7740703fb9b00587870f0f245af865eeba4b62c2
Referenced helpers: /usr/local/bin/iperf-server, /usr/local/bin/lcd-run

## src/launchers/monitor.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for monitor. See referenced backends for effects.
SHA256: 3b11ce56d02509a96f4664c641940d93212e3fe4d5243ec5ad0f1c3987120506
Referenced helpers: /usr/local/bin/lcd-run

## src/launchers/net-direct-passive.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for net direct passive. See referenced backends for effects.
SHA256: e776f513d2c681a3928526fb24ff23869dc92e422348b474361cc74bbc027e57
Referenced helpers: /usr/local/bin/clover-direct-ethernet

## src/launchers/net-direct-static.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for net direct static. See referenced backends for effects.
SHA256: 9521b1e3bf5b55c2b6d6da5a9a911cb180669bcea350c01b796e1d390e511e3f
Referenced helpers: /usr/local/bin/clover-direct-ethernet

## src/launchers/net-direct-test.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for net direct test. See referenced backends for effects.
SHA256: 5bca6299a81e8adf9f175e738d427ffbedf093aeb8064afcaa49aa2f65de0c3f
Referenced helpers: /usr/local/bin/clover-direct-ethernet

## src/launchers/net-topology.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for net topology. See referenced backends for effects.
SHA256: 7a68ea34092e5f5ffa82ffbcc559dd9a96784327d60cf4463505442e38e7a188
Referenced helpers: /usr/local/bin/cloverkit-report

## src/launchers/packet-beacon.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for packet beacon. See referenced backends for effects.
SHA256: b494579f57790b2886b14ff2ca4f6a959c8f1c8dac2af66859b8e278ece0c7b5
Referenced helpers: No literal local helper references.

## src/launchers/packet-deauth.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for packet deauth. See referenced backends for effects.
SHA256: f655c9f0a16b6419743fc1ee51a47f12760d53f6260f8fa0681d7a0fcda7a9c8
Referenced helpers: /usr/local/bin/lcd-run, /usr/local/bin/packet-live

## src/launchers/packet-eapol.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for packet eapol. See referenced backends for effects.
SHA256: 6cc9c3040624c63174708218227203d821d04c2a3b9c75062fa4395cf5c0b332
Referenced helpers: /usr/local/bin/lcd-run, /usr/local/bin/packet-live

## src/launchers/packet-general.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for packet general. See referenced backends for effects.
SHA256: b1dca71de7d54fb4571d0c619486c054cae4efa13a5b18d072ef1a5f44a355c0
Referenced helpers: /usr/local/bin/lcd-run, /usr/local/bin/packet-general-live

## src/launchers/packet-insights.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for packet insights. See referenced backends for effects.
SHA256: 6c88980513cd009e8a559074c0e2d92241b387865d157bca5cc99e8b8b33d9a2
Referenced helpers: /usr/local/bin/cloverkit-packet-insights

## src/launchers/packet-ndp.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for packet ndp. See referenced backends for effects.
SHA256: 87c10341f095da094a5624e266ed7621f97ca44590b88669f9f44fff37bf73e0
Referenced helpers: No literal local helper references.

## src/launchers/packet-probes.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for packet probes. See referenced backends for effects.
SHA256: 4f9b705ced4da77f90932a1410624efcbada9bc8c285a9d113b1d93d0a40f187
Referenced helpers: /usr/local/bin/lcd-run, /usr/local/bin/packet-live

## src/launchers/packet-raw.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for packet raw. See referenced backends for effects.
SHA256: 609dda53fb9a8d5abd268a2eaf9d1815f1e8d8bd76e6cabb7d7f69de3c46b42b
Referenced helpers: /usr/local/bin/lcd-run, /usr/local/bin/packet-live

## src/launchers/packet-scan.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for packet scan. See referenced backends for effects.
SHA256: b8509502b3a34fe9f2d4da9e86a386cda87d79c51ce0213531271c167633d759
Referenced helpers: /usr/local/bin/ap-find-compact, /usr/local/bin/lcd-run, /usr/local/bin/lcd-wrap-targets, /usr/local/bin/packet-scan

## src/launchers/packet-stations.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for packet stations. See referenced backends for effects.
SHA256: 5ae3bbb534020c9be14974b3440191bd41a8a68044e8b066c8c2b1ff06eeaa77
Referenced helpers: /usr/local/bin/lcd-run, /usr/local/bin/packet-live

## src/launchers/path-test.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for path test. See referenced backends for effects.
SHA256: d2ed64328585151103deac8c7c8fd686adf3d0c056edafa0ea628a394dd92170
Referenced helpers: /usr/local/bin/lcd-run, /usr/local/bin/path-test

## src/launchers/security-scan.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for security scan. See referenced backends for effects.
SHA256: b846de96c05d9f8e7f25fa6627f41492d4bab38198505f9549713fa0b65025c1
Referenced helpers: /usr/local/bin/lcd-run, /usr/local/bin/secscan-lcd-run

## src/launchers/serial.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for serial. See referenced backends for effects.
SHA256: b73fa0d092c56e07d4a73a4954bb2891cd830fe7da9aae4a771367e8ba595919
Referenced helpers: /usr/local/bin/lcd-run

## src/launchers/system.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for system. See referenced backends for effects.
SHA256: 6f57840dd525ba2fda4d16ea3d2cceeabedf001cab748548b5e600253c23d3f2
Referenced helpers: /usr/local/bin/bh-vpn, /usr/local/bin/console-status, /usr/local/bin/iperf-server, /usr/local/bin/lcd-run, /usr/local/bin/pc-test

## src/launchers/target-clean.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for target clean. See referenced backends for effects.
SHA256: 527f1fae8abec1da808d3a43c92f1e9889616857cb329a937926c69654aade26
Referenced helpers: /usr/local/bin/target-clean

## src/launchers/wifi-client-health.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for wifi client health. See referenced backends for effects.
SHA256: fdd97140ef2110c9d9ba6d81971ae419e1fbbd957f8099cb5b7f2511d3487192
Referenced helpers: /usr/local/bin/wifi-health-connected

## src/launchers/wifi-health.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for wifi health. See referenced backends for effects.
SHA256: b0014cb2516834969002553ccc9301b034c1949a88c920939f36b60a701eec8f
Referenced helpers: /usr/local/bin/lcd-run, /usr/local/bin/wifi-health

## src/launchers/wifi-waterfall.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for wifi waterfall. See referenced backends for effects.
SHA256: 1b490ab9d120d75e402502764f9f42fd04879dd7bd85988da8fa1f76198b2a88
Referenced helpers: /usr/local/bin/wifi-waterfall

## src/launchers/wifi.sh
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for wifi. See referenced backends for effects.
SHA256: 94cecf8f7bc37cf8e3093ce95511f7abd35528cdc8f8e81fcc0448bc33f6f016
Referenced helpers: /usr/local/bin/lcd-run, /usr/local/bin/target-clean, /usr/local/bin/wifi-scan

## src/vehicle/cloverkit_vehicle/__init__.py
Workflow: Support helper; individual purpose review pending
Purpose: CloverKit offline vehicle diagnostics. Hardware coverage is discovered, never assumed.
SHA256: 008a6e34c14d6e5def173dbeb99cd4412d89e4bce901639d31a77d1e20606829
Referenced helpers: No literal local helper references.

## src/vehicle/cloverkit_vehicle/__main__.py
Workflow: Support helper; individual purpose review pending
Purpose: CloverKit console entry point; ordinary use is fully offline.
SHA256: 720809b7dc5f47b8d10380994a067b7e7bdd3a9d85285a9d4173e0b69c8188f9
Referenced helpers: No literal local helper references.

## src/vehicle/cloverkit_vehicle/adapters.py
Workflow: Support helper; individual purpose review pending
Purpose: Explicit USB/Classic selection. Discovery never probes serial ports.
SHA256: ff4a75237d05fa8671b3b56c312f1c4532bdf77d4e352b80c06c21d4d3e3c1a1
Referenced helpers: No literal local helper references.

## src/vehicle/cloverkit_vehicle/backend.py
Workflow: vehicle-diagnostics
Purpose: Isolated python-OBD worker. All ELM traffic is owned by this one process.
SHA256: 55a3f7ddcd3bde452381bd3617a05e9abe21531459b388c51daeb2476489335b
Referenced helpers: No literal local helper references.

## src/vehicle/cloverkit_vehicle/client.py
Workflow: Support helper; individual purpose review pending
Purpose: Local/console client. UI clients share the service instead of opening adapters.
SHA256: d98137bed037b67b07a65933bf2be53d97c2286a5c7038e1e93bd96d41ab17cb
Referenced helpers: No literal local helper references.

## src/vehicle/cloverkit_vehicle/data/pids.json
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for pids. See referenced backends for effects.
SHA256: b5a5a257c3b184d6327181c9bc241b99d21364d833b9832e4fe28f6ac52e8cb2
Referenced helpers: No literal local helper references.

## src/vehicle/cloverkit_vehicle/data/profiles/saej1979-rpm.json
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for saej1979 rpm. See referenced backends for effects.
SHA256: 21093bce2eaf3cc2df2a76c6511e8176ed9e289b8eb4f343d94b2b90ca270496
Referenced helpers: No literal local helper references.

## src/vehicle/cloverkit_vehicle/data/provenance.json
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for provenance. See referenced backends for effects.
SHA256: e896e4bc0f047213a43a2d3897006b4db8ca425dfd1dc18fbb357a3603cdeb50
Referenced helpers: No literal local helper references.

## src/vehicle/cloverkit_vehicle/engine.py
Workflow: vehicle-diagnostics
Purpose: One cancellable adapter owner, shared state, scan evidence and bounded live data.
SHA256: d8e6a71418d0160950351a00ad7e3c9b38d60691443638e540ba155d23f3f6a1
Referenced helpers: No literal local helper references.

## src/vehicle/cloverkit_vehicle/presentation.py
Workflow: Support helper; individual purpose review pending
Purpose: Compact shared unit labels; original values/units remain in saved evidence.
SHA256: a0896a9b0b150f63a9cb944973e18a0a0db30f99a75bd57a7969a9993b515c66
Referenced helpers: No literal local helper references.

## src/vehicle/cloverkit_vehicle/profiles.py
Workflow: Support helper; individual purpose review pending
Purpose: Validated read-only profile extension points; no eval, write services or scripts.
SHA256: df437f3304cdc612eca87a8f117f18863e6b7b99b67a84a276cdb04b31589f1c
Referenced helpers: No literal local helper references.

## src/vehicle/cloverkit_vehicle/reference.py
Workflow: vehicle-diagnostics
Purpose: Offline, source-aware DTC reference; unknown codes never acquire guessed meanings.
SHA256: bf95826625856533304a119c33ab67e237c3ae331c047489a21d8f8c5a853bc3
Referenced helpers: No literal local helper references.

## src/vehicle/cloverkit_vehicle/service.py
Workflow: vehicle-diagnostics
Purpose: Local authenticated API and offline browser. No cloud, CDN, telemetry or auto-probing.
SHA256: 94d07d8dd7e25f968646891235f767452d35db6d367572cf99f00e739b36e53c
Referenced helpers: No literal local helper references.

## src/vehicle/cloverkit_vehicle/ssh_access.py
Workflow: Support helper; individual purpose review pending
Purpose: Temporary SSH account controls; no passwords in process arguments.
SHA256: 32e1114792747ee4a2b6e9221c5e5799a27b7ff46ad10a477f2d26ece2240bf6
Referenced helpers: /usr/local/lib/cloverkit/vehicle/conveh_access.py

## src/vehicle/cloverkit_vehicle/ssh_console.py
Workflow: obd-flow
Purpose: Forced SSH view: Vehicle Diagnostics only, independent navigation, shared adapter.
SHA256: 36d12f9b727f2b3a96c12c22f98e9f2f59174915b4ecb5db2d909bb24dd3d2d6
Referenced helpers: No literal local helper references.

## src/vehicle/cloverkit_vehicle/storage.py
Workflow: Support helper; individual purpose review pending
Purpose: Private, bounded local session/recording storage and self-contained exports.
SHA256: 259012b66e160f9ed65367b15fbec8af3ef6f1c4a00552a70fadb456d195907c
Referenced helpers: No literal local helper references.

## src/vehicle/cloverkit_vehicle/traffic.py
Workflow: obd-flow
Purpose: Bounded actual serial traffic capture and shared-owner terminal command policy.
SHA256: 1d2e757465555a07169ebcef63b5f74b8fb2d81e469e666d1236264cdaece3da
Referenced helpers: No literal local helper references.

## src/vehicle/cloverkit_vehicle/web/app.js
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for app. See referenced backends for effects.
SHA256: 39eace6ad8bc24f54f9fc744283b4d7d17921c472702c7462ee32c5386c96717
Referenced helpers: No literal local helper references.

## src/vehicle/cloverkit_vehicle/web/index.html
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for index. See referenced backends for effects.
SHA256: b7b35d8e6bfd3c46e7072e8815ea9e8b5ff2a5668a6f96c179af7f2d0f4d53d4
Referenced helpers: No literal local helper references.

## src/vehicle/cloverkit_vehicle/web/remote.js
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for remote. See referenced backends for effects.
SHA256: 3f438a8f4abc68b6b97239160640af0f7d2c3c0647d553ddacbf6c3ad6b43f6b
Referenced helpers: No literal local helper references.

## src/vehicle/cloverkit_vehicle/web/style.css
Workflow: Support helper; individual purpose review pending
Purpose: Entry point / helper for style. See referenced backends for effects.
SHA256: 0c28428f5495cebde07be8f54b0684bd2a1e53f245751ffcde9b08956b357774
Referenced helpers: No literal local helper references.

