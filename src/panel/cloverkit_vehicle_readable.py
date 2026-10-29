"""Readable vehicle summaries. Presentation only; no diagnostic operations."""
import textwrap

LABELS = {'RPM':'Engine speed', 'SPEED':'Road speed', 'COOLANT_TEMP':'Coolant temperature',
          'THROTTLE_POS':'Throttle position', 'VIN':'Vehicle identification number',
          'CALIBRATION_ID':'Calibration identifier', 'CVN':'Calibration verification number',
          'ELM_VOLTAGE':'Adapter voltage', 'STATUS':'Emissions readiness',
          'GET_DTC':'Stored fault codes', 'GET_CURRENT_DTC':'Pending fault codes',
          'PERMANENT_DTC':'Permanent fault codes', 'MIL':'Engine warning light',
          'DTC_count':'Fault code count', 'ignition_type':'Ignition type'}
SECTIONS = [('Emissions readiness','readiness'), ('Readings when a fault occurred','freeze_frames'),
            ('Vehicle information','vehicle_info'), ('On-board monitor results','monitors'),
            ('Checks completed / unavailable','coverage')]

def label(name):
    return LABELS.get(name, str(name).removeprefix('DTC_').replace('_',' ').capitalize()) if not str(name).startswith('DTC_') else LABELS.get(str(name)[4:], str(name)[4:].replace('_',' ').capitalize())

def readable(value, unit=''):
    from cloverkit_vehicle.presentation import compact
    if isinstance(value,dict):
        if 'available' in value and 'complete' in value:
            return ['Not supported' if not value['available'] else 'Complete' if value['complete'] else 'Incomplete']
        return [label(k)+': '+line for k,v in value.items() for line in readable(v)] or ['No values reported']
    if isinstance(value,(list,tuple)):
        return [line for v in value for line in readable(v,unit)] or ['None reported']
    if value is None:return ['Not available']
    if isinstance(value,bool):return ['Yes' if value else 'No']
    return [compact(value,unit).strip()]

def entries(scan,section):
    raw=scan.get(section) or ([] if section=='readiness' else {})
    if section=='readiness':
        result=[]
        for r in raw:
            ecu=r.get('ecu','unknown')
            for key,value in (r.get('value') or {}).items():
                if key=='MIL':value='ON' if value else 'OFF'
                result.append((label(key),readable(value),ecu))
        return result
    result=[]
    for name,readings in raw.items():
        for r in readings:
            lines=readable(r.get('value'),r.get('unit','')) if r.get('state')=='measured' else [label(r.get('state','unavailable'))]
            if r.get('detail'):lines.append(str(r['detail']))
            result.append((label(name),lines,r.get('ecu','unknown')))
    return result

def code_detail(code,section):
    from cloverkit_vehicle.reference import advice
    rows=[]
    if section=='What this code means':rows=[code.get('description','Definition unavailable'),code.get('caution','')]
    for definition in code.get('definitions',[]):
        a=advice(definition)
        if section=='What this code means' and a['explanation']:rows += [a['explanation']]
        elif section=='Possible causes':rows += a['possible_causes']
        elif section=='What to check next':rows += a['next_checks']
        elif section=='Definition sources':rows += [definition['source']+' / '+definition['license'],definition.get('title','')]
    return list(dict.fromkeys(r for r in rows if r)) or ['No additional information in the offline reference.']

def page(panel,rows,detail,capacity,cols):
    wrapped=[part for line in detail for part in (textwrap.wrap(str(line),max(20,cols-2)) or [''])]
    room=max(1,capacity-len(rows)-1)
    offset=min(max(0,getattr(panel,'_vehicle_scroll',0)),max(0,len(wrapped)-room))
    panel._vehicle_scroll=offset
    return rows+wrapped[offset:offset+room]+[f'{offset+1 if wrapped else 0}-{min(offset+room,len(wrapped))} of {len(wrapped)} | Up/Down scroll | Back']
