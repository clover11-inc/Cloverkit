import json
import sys
from collections import defaultdict

path = sys.argv[1]
iface = sys.argv[2]
json_path = sys.argv[3]
apnames_path = sys.argv[4]


AP_NAME_CACHE = "/run/cloverkit/ap-names.json"

apnames = {}

try:
    with open(
        AP_NAME_CACHE,
        encoding="utf-8",
    ) as f:

        cache = json.load(f)

    entries = cache.get(
        "entries",
        {},
    )

    if isinstance(entries, dict):

        for bssid, item in entries.items():

            if not isinstance(item, dict):
                continue

            name = item.get("name")

            if name:
                apnames[
                    bssid.upper()
                ] = str(name)

except Exception:
    pass


# Preserve cached exact-BSSID names; enrich from recent passive AP observations.
import time,re
try:
    with open('/var/lib/cloverkit/wifi-passive-health/latest.json',encoding='utf-8') as history_file:
        history=json.load(history_file)
    history_age=time.time()-float(history.get('updated_at',0))
    if history.get('schema')==1 and 0<=history_age<=3600:
        observed={}
        for ap in history.get('aps',[]):
            bssid=str(ap.get('bssid','')).upper()
            if not re.fullmatch(r'(?:[0-9A-F]{2}:){5}[0-9A-F]{2}',bssid):continue
            # Prefer an advertised AP name, then an advertised device name.
            device=ap.get('advertised_device') or {}
            name=ap.get('beacon_ap_name') or device.get('name')
            if not isinstance(name,str):continue
            name=''.join(c for c in name if c.isprintable()).strip()[:120]
            if not name or name.upper() in ('CONFLICT','UNKNOWN','N/A'):continue
            observed.setdefault(bssid,set()).add(name)
        for bssid,names in observed.items():
            if len(names)==1:apnames[bssid]=next(iter(names))
            else:apnames.pop(bssid,None)
except (OSError,ValueError,TypeError,AttributeError):
    pass

try:
    with open(
        apnames_path,
        encoding="utf-8",
        errors="replace",
    ) as f:

        for line in f:

            line = line.rstrip("\n")

            if "|" not in line:
                continue

            bssid, name = line.split("|", 1)

            bssid = bssid.strip().upper()
            name = name.strip()

            if bssid and name:
                apnames[bssid] = name

except Exception:
    pass


def quality(dbm):
    if dbm >= -49:
        return "Excellent"
    if dbm >= -59:
        return "Good"
    if dbm >= -69:
        return "Fair"
    if dbm >= -79:
        return "Weak"
    if dbm >= -89:
        return "Poor"
    return "Very Poor"


def allocated_candidate(mac):
    """
    Existing enterprise/common allocation heuristic.

    Example:
      ...:63
      ...:67
      ...:6B
      ...:6F
          ↓
      ...:60
    """
    p = mac.split(":")
    last = int(p[-1], 16)
    p[-1] = f"{last & 0xF0:02X}"
    return ":".join(p)


def virtual_radio_key(row):
    """
    Virtual BSSID family on ONE radio.

    Ignore first MAC octet because some AP platforms alter it
    between virtual BSSIDs/SSIDs.

    Example:
      02:11:22:33:44:50
      06:11:22:33:44:50
      0A:11:22:33:44:50
      0E:11:22:33:44:50

    becomes:
      11:22:33:44:50
    """
    p = row["bssid"].split(":")

    return (
        ":".join(p[1:]),
        row["band"],
        row["ch"],
    )


def physical_virtual_key(radio_group):
    """
    Correlate different radios belonging to the same physical AP.

    Known pattern:
      xx:11:22:32:44:50  → 2.4 GHz radio
      xx:11:22:33:44:50  → 5 GHz radio

    Here:
      first octet = virtual BSSID variation
      middle radio byte = radio identity
      stable remainder identifies the physical AP.

    Stable key:
      11:22:44:50
    """
    p = radio_group["tail"].split(":")

    if len(p) != 5:
        return radio_group["tail"]

    return ":".join([
        p[0],
        p[1],
        p[3],
        p[4],
    ])


# ============================================================
# Parse observations
# ============================================================

rows = []

with open(path, encoding="utf-8", errors="replace") as f:
    for line in f:
        p = line.rstrip("\n").split("|")

        if len(p) != 6:
            continue

        signal, channel, freq, ssid, bssid, security = p

        try:
            signal = float(signal)
            freq = float(freq)
        except ValueError:
            continue

        if freq < 3000:
            band = "2.4G"
        elif freq < 5925:
            band = "5G"
        else:
            band = "6G"

        rows.append({
            "sig": signal,
            "ch": channel or "?",
            "freq": freq,
            "band": band,
            "ssid": ssid if ssid else "<hidden>",
            "bssid": bssid.upper(),
            "security": security,
        })


# ============================================================
# STAGE 1
# Detect virtual BSSIDs belonging to one radio.
#
# Important fix:
# RSSI spread is NOT used to reject a MAC family.
# ============================================================

virtual_candidates = defaultdict(list)

for row in rows:
    virtual_candidates[virtual_radio_key(row)].append(row)

virtual_radios = []
virtual_member_bssids = set()

for key, members in virtual_candidates.items():

    first_octets = {
        r["bssid"].split(":")[0]
        for r in members
    }

    unique_ssids = {
        r["ssid"]
        for r in members
    }

    if (
        len(members) >= 2
        and len(first_octets) >= 2
        and len(unique_ssids) >= 2
    ):
        tail, band, channel = key

        group = {
            "tail": tail,
            "band": band,
            "channel": channel,
            "members": members,
        }

        virtual_radios.append(group)

        virtual_member_bssids.update(
            r["bssid"]
            for r in members
        )


# ============================================================
# AP NAME ENRICHMENT
#
# Names come only from previously observed Beacon evidence.
# A name is attached to the exact BSSID that advertised it.
# A unique name may then be promoted to the physical AP group.
# ============================================================

for row in rows:

    row["ap_name"] = apnames.get(
        row["bssid"].upper()
    )


def apply_group_ap_name(group):

    names = {
        row.get("ap_name")
        for row in group["members"]
        if row.get("ap_name")
    }

    if len(names) == 1:

        group["ap_name"] = next(
            iter(names)
        )

        group["ap_name_conflict"] = False

    elif len(names) > 1:

        # Never silently choose between conflicting names.
        group["ap_name"] = None
        group["ap_name_conflict"] = True

    else:

        group["ap_name"] = None
        group["ap_name_conflict"] = False


# ============================================================
# STAGE 2
# Correlate virtual radio groups into physical APs.
#
# REQUIRE:
#   same physical MAC pattern
#   different bands
#   at least 2 common visible SSIDs
#
# That prevents blindly combining unrelated radios merely
# because some MAC bytes happen to match.
# ============================================================

physical_candidates = defaultdict(list)

for radio in virtual_radios:
    physical_candidates[
        physical_virtual_key(radio)
    ].append(radio)


groups = []
consumed_virtual_ids = set()

for physical_key, radios in physical_candidates.items():

    bands = {
        radio["band"]
        for radio in radios
    }

    if len(radios) < 2 or len(bands) < 2:
        continue

    visible_sets = []

    for radio in radios:
        visible_sets.append({
            r["ssid"]
            for r in radio["members"]
            if r["ssid"] != "<hidden>"
        })

    # Compare all radio SSID sets.
    common = set(visible_sets[0])

    for s in visible_sets[1:]:
        common &= s

    # Need real evidence they're the same AP.
    if len(common) < 2:
        continue

    members = []

    for radio in radios:
        members.extend(radio["members"])
        consumed_virtual_ids.add(id(radio))

    groups.append({
        "type": "virtual-physical",
        "id": f"XX:{physical_key}",
        "pattern": "Virtual multi-radio",
        "confidence": "HIGH",
        "members": members,
    })


# ============================================================
# STAGE 3
# Virtual radio groups that cannot be correlated across bands.
# Still represent ONE radio/AP estimate, not individual BSSIDs.
# ============================================================

for radio in virtual_radios:

    if id(radio) in consumed_virtual_ids:
        continue

    groups.append({
        "type": "virtual-radio",
        "id": f"XX:{radio['tail']}",
        "pattern": "Virtual-BSSID",
        "confidence": "HIGH",
        "members": radio["members"],
    })


already_grouped = {
    r["bssid"]
    for group in groups
    for r in group["members"]
}


# ============================================================
# STAGE 4
# Existing allocated/common enterprise BSSID pattern.
# ============================================================

allocated_candidates = defaultdict(list)

for row in rows:

    if row["bssid"] in already_grouped:
        continue

    allocated_candidates[
        allocated_candidate(row["bssid"])
    ].append(row)


for candidate, members in allocated_candidates.items():

    if len(members) < 2:
        continue

    groups.append({
        "type": "allocated",
        "id": candidate,
        "pattern": "Allocated-BSSID",
        "confidence": "EST",
        "members": members,
    })

    already_grouped.update(
        r["bssid"]
        for r in members
    )


# ============================================================
# STAGE 5
# Standalone observations remain unchanged.
# ============================================================

for row in rows:

    if row["bssid"] in already_grouped:
        continue

    groups.append({
        "type": "single",
        "id": row["bssid"],
        "pattern": "Standalone",
        "confidence": "-",
        "members": [row],
    })


for group in groups:
    apply_group_ap_name(group)


groups.sort(
    key=lambda g: max(
        r["sig"]
        for r in g["members"]
    ),
    reverse=True
)


# ============================================================
# Save EXACT grouping for target-build-wifi
# ============================================================

json_data = {
    "interface": iface,
    "rows": rows,
    "groups": groups,
}

with open(json_path, "w", encoding="utf-8") as f:
    json.dump(json_data, f)


# ============================================================
# Counts / display
# ============================================================

count24 = sum(r["band"] == "2.4G" for r in rows)
count5 = sum(r["band"] == "5G" for r in rows)
count6 = sum(r["band"] == "6G" for r in rows)
hidden = sum(r["ssid"] == "<hidden>" for r in rows)



print("WIFI NEARBY")
print(f"Interface : {iface}")
print(f"BSSIDs    : {len(rows)}")
print(f"EST APs   : {len(groups)}")
print(f"2.4G      : {count24}")
print(f"5G        : {count5}")

if count6:
    print(f"6G        : {count6}")

print(f"Hidden    : {hidden}")
print()


print()

for group in groups:

    members = group["members"]

    best = max(
        r["sig"]
        for r in members
    )

    if group["type"] == "single":
        print(f"AP/BSSID : {group['id']}")
    else:
        print(f"AP EST   : {group['id']}")

    if group.get("ap_name"):
        print(f"AP Name  : {group['ap_name']}")

    elif group.get("ap_name_conflict"):
        print("AP Name  : CONFLICT")

    print(f"Pattern  : {group['pattern']}")

    if group["confidence"] != "-":
        print(f"Confidence: {group['confidence']}")

    print(
        f"Signal   : {int(best)} dBm "
        f"({quality(best)})"
    )

    radios = defaultdict(list)

    for r in members:
        radios[
            (r["band"], r["ch"])
        ].append(r)


    def radio_sort(item):

        (band, channel), _ = item

        order = {
            "2.4G": 0,
            "5G": 1,
            "6G": 2,
        }

        try:
            channel_num = int(channel)
        except ValueError:
            channel_num = 999

        return (
            order.get(band, 9),
            channel_num
        )


    for number, ((band, channel), ads) in enumerate(
        sorted(
            radios.items(),
            key=radio_sort
        ),
        start=1
    ):

        strongest = max(
            r["sig"]
            for r in ads
        )

        print()
        print(
            f"  Radio {number}: "
            f"{band}  Channel {channel}  "
            f"{int(strongest)} dBm "
            f"({quality(strongest)})"
        )

        for r in sorted(
            ads,
            key=lambda x: x["sig"],
            reverse=True
        ):

            print(
                f"    {r['ssid']:<22} "
                f"{r['bssid']} "
                f"{int(r['sig'])}dBm"
            )

    print()


print()
print()

print(
    f"{'SIG':<5} "
    f"{'QUALITY':<9} "
    f"{'CH':<4} "
    f"{'BAND':<5} "
    f"{'SSID':<24} "
    f"{'BSSID':<18} "
    f"SECURITY"
)

print(
    f"{'-----':<5} "
    f"{'---------':<9} "
    f"{'----':<4} "
    f"{'-----':<5} "
    f"{'------------------------':<24} "
    f"{'------------------':<18} "
    f"--------"
)

for r in sorted(
    rows,
    key=lambda x: x["sig"],
    reverse=True
):

    print(
        f"{int(r['sig']):<5} "
        f"{quality(r['sig']):<9} "
        f"{r['ch']:<4} "
        f"{r['band']:<5} "
        f"{r['ssid'][:24]:<24} "
        f"{r['bssid']:<18} "
        f"{r['security']}"
    )


print()
print()