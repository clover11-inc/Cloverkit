# Third-party source and attribution

- Blackhat OS-derived code: Rootkit Labs, MIT; https://github.com/o7-machinehum/flipper-blackhat-os. Notice preserved in LICENSES/BlackhatOS-MIT.txt.
- python-OBD 0.7.3: GPL-2.0-only; source, metadata and licence retained. The backend worker is marked GPL-2.0-only.
- pyserial, Pint, flexcache, flexparser, platformdirs and typing_extensions: exact versions, notices and source archive hashes are listed in THIRD-PARTY.json. Runtime source is bundled under src/vehicle/vendor; original wheels and source distributions are under vendor/vehicle.
- Diagnostic data: LICENSES/vehicle, src/vehicle/cloverkit_vehicle/data/provenance.json and the database's provenance records retain each dataset's source and licence. Community descriptions can be incomplete, contradictory or wrong for a particular vehicle. Counts describe bundled entries, not verified vehicle coverage.
- The Blackhat hardware repository uses a different licence; no hardware designs are redistributed here. The upstream Flipper app repository has no published licence as checked for this alpha, so its code and icon are excluded. No companion application is bundled.
- The inherited unannotated manufacturer database is excluded. Vendor attribution can use the target OS's licensed Wireshark/IEEE data instead; attribution can be absent when those datasets are not installed.
- Linux, firmware SDK, capture tools, system packages, emulator executables and game ROMs are not redistributed in the source archive. Install applicable OS dependencies separately under their respective terms.
