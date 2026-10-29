# OBD tool research — CloverKit decisions

Reviewed 19 October 2026. Primary vendor documentation, upstream source and dataset licences informed the implementation. No commercial database is scraped.

| What makes a useful tool | CloverKit implementation / decision | Primary reference |
|---|---|---|
| Evidence beyond a fault number | Distinct stored/pending/permanent states, freeze frame, readiness and supported monitors | [OBDLink diagnostics guide](https://support.obdlink.com/support/solutions/articles/43000711154-get-started-with-diagnostics), [python-OBD commands](https://python-obd.readthedocs.io/en/latest/Command%20Tables/) |
| Readings that explain changing behaviour | Selectable live values, history, charts and recording | [OBDLink app](https://www.obdlink.com/obd-apps/obdlink-app/), [OBDwiz](https://www.scantool.net/obdwiz) |
| Field use without mobile data or subscriptions | Bundled definitions/dependencies; self-contained reports; no remote lookups at runtime | [OBDex](https://github.com/foerbsnavi/obdex), [dtc-database](https://github.com/Wal33D/dtc-database) |
| Broad coverage without false confidence | Discover vehicle capabilities; keep unknowns and per-ECU results; label experimental decoders | [python-OBD connections](https://python-obd.readthedocs.io/en/latest/Connections/), [responses](https://python-obd.readthedocs.io/en/latest/Responses/) |
| Connection diagnosis and dependable cancellation | Explicit adapter/baud, one worker, bounded operations, readable failure states | [ELM327 datasheet](https://www.elmelectronics.com/wp-content/uploads/2016/07/ELM327DS.pdf) |
| Preserve evidence around repairs | Save/compare/export and deliberate pre-clear report; readiness warning | [OBDLink diagnostics guide](https://support.obdlink.com/support/solutions/articles/43000711154-get-started-with-diagnostics), [BAR OBD reference](https://www.bar.ca.gov/obd-test-reference) |
| Extend coverage responsibly | Source/licence/applicability-aware profiles; no automatic execution of imported manufacturer commands | [OBDb](https://github.com/OBDb), [SAEJ1979 definitions](https://github.com/OBDb/SAEJ1979) |

## Library and data choices

- **python-OBD 0.7.3 (GPL-2.0-only):** reused in an explicitly labelled communication worker; pyserial/Pint dependencies are pinned and bundled. Existing protocol parsers remain upstream. Focused extensions handle permanent codes, strict short-frame checks, freeze-frame index normalization, per-ECU preservation, actual VIN/calibration lengths and an additional sourced PID catalog. Source and licence travel with the release.
- **OBDex (CC0 data / MIT tooling):** all eligible generic definitions, explanations and possible causes included. Original bilingual/reference metadata retained in SQLite. Upstream repair-price, likelihood and driving-safety fields are not adopted as reliable advice. Project completeness claims are not independent validation.
- **dtc-database (declared MIT):** eligible generic and manufacturer definitions included separately, preserving make and source. Community provenance is labelled unverified; malformed/range-conflicting input is excluded from automatic generic lookup. No overwrite of conflicting descriptions.
- **OBDb SAEJ1979 (CC-BY-SA-4.0):** complete standard reference snapshot retained, alongside an attributed adapted RPM profile. OBDb signal definitions are not directly compatible with python-OBD and are not automatically installed as executable manufacturer integrations.
- **Commercial scan databases and opaque extracted ECU databases:** not copied. A large row count is not evidence of accuracy, permission to redistribute or validated vehicle access.

The code database contains 28,172 definitions and 12,316 distinct codes after validation, with 33 non-generic upstream labels (including ambiguous OTHER). Manufacturer text is only selected with matching user context. This is not a claim to cover 33 tested makes or every module.

## Hardware and protocol boundary

An ELM-compatible device is a protocol bridge, not universal access to every network/module. The purchased cable has not been physically inspected. USB chipset identity, adapter firmware claims and a matching vehicle connector are insufficient proof of supported commands. Classic SPP and BLE are distinct transports.

Modern **OBDonUDS / SAE J1979-2**, CAN FD, DoIP, EV-specific diagnostics and proprietary module access need separate coverage and adapter validation. This candidate does not implement them. [SAE J1979-2](https://saemobilus.sae.org/standards/j1979-2_202104-e-e-diagnostic-test-modes-obdonuds), [Vector overview](https://www.vector.com/en/business-unit/testing-validation-diagnostics/diagnostics/standards-knowhow/obdonuds/).

No universal "all codes / all cars / all functions" promise is technically supportable from a generic ELM cable and an offline text database. CloverKit includes broad available reference material and an extensible structure; it reports actual measured coverage instead of using a vehicle-specific whitelist.
