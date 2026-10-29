"""H23 live network browser. Navigation holds identities, never volatile row indexes."""
import time
import textwrap
import json, subprocess, re
from collections import defaultdict
from wifi_health_view import band, channel, fmt, source_name, signal_assessment

def values(task): return task.get('finder',{}).get('values',{})
def fresh(d,a): return a.get('last_seen_seconds',999)<=d.get('measurement_window_seconds',60)
def network_key(a):
    name=a.get('ssid')
    return ('ssid',name) if name and name!='Unknown/hidden' else ('unnamed',a['bssid'])
def network_name(key): return key[1] if key[0]=='ssid' else 'Unnamed BSSID '+key[1]
def new_navigation(): return {'stack':[{'page':'summary','key':None,'selected':None,'offset':0}], 'scope':None}
def entry(key,label,page=None,target=None): return {'id':key,'label':label,'page':page,'target':target}
def ap_id(a): return (a['bssid'],a['frequency'])
def link_id(c): return (c['ap'],c['client'],c['frequency'])
def trend_id(t): return tuple(t.get('identity',[]))+(t['metric'],)
def scoped(d,scope):
    aps=d.get('aps',[])
    if scope is None: return aps,d.get('clients',[])
    aps=[a for a in aps if network_key(a)==scope]
    addresses={a['bssid'] for a in aps}
    return aps,[c for c in d.get('clients',[]) if c['ap'] in addresses]
def risky(c): return any(x.get('frames',0)>=100 and (x.get('retry_percent') or 0)>=20 for x in c.get('directions',{}).values())
def reception(a):
    return signal_assessment(a.get('signal_dbm')) if a.get('signal_samples',0)>=3 and a.get('signal_dbm') is not None else 'COLLECTING: fewer than 3 signal samples'
def coverage_lines(d,aps):
    rows=[]
    for label in ('2.4 GHz','5 GHz','6 GHz'):
        observed=[a for a in aps if band(a['frequency'])==label and fresh(d,a) and a.get('signal_dbm') is not None and a.get('signal_samples',0)>=3]
        configured=[f for r in d.get('radios',{}).values() for f in r.get('channels',[])]
        if configured and not any(band(f)==label for f in configured):
            rows.append(label+': no capture channel configured');continue
        if observed:
            best=max(observed,key=lambda a:a['signal_dbm'])
            rows.append(f"{label}: strongest {reception(best)} | CH {channel(best['frequency'])}")
        else: rows.append(label+': COLLECTING: no qualified recent signal')
    return rows
def channel_evidence(d,freq):
    rows=[]
    for c in d.get('activity',{}).get('channel_coverage',[]):
        if c['frequency']==freq:
            rows.append(f"{c['radio']}: listened {c['listened_seconds']:g}s / {c['window_seconds']:g}s ({c['listening_share_percent']:g}%), {c['visits']} visits")
            rows.append('Capture width: '+fmt(c.get('capture_width_mhz'),' MHz'))
    return rows or ['Listening duration: no channel evidence available']
def direction_lines(c):
    rows=[]
    for key,label in [('up','CLIENT -> AP'),('down','AP -> CLIENT')]:
        x=c.get('directions',{}).get(key,{})
        count=x.get('frames',0);percent=x.get('retry_percent')
        status='WARNING' if count>=100 and (percent or 0)>=20 else 'OBSERVED OK' if count>=100 else 'LIMITED SAMPLE' if count else 'NO OBSERVATIONS'
        rows.extend([label+': '+status,
                     f"Retry flags: {x.get('retry_frames',0)}/{count} data frames ({fmt(percent,'%')}) | last {fmt(x.get('last_seen_seconds'),'s')} ago"])
        if x.get('window_capped'): rows.append('LIMITED: link window reached its storage cap')
    return rows

def names_for(group):
    return sorted({a['ssid'] for a in group if a.get('ssid') and a['ssid']!='Unknown/hidden'})
def automatic_mac_groups(pending):
    """Basic Scan's five-stage allocation heuristic, evaluated on live data.

    One representative per exact BSSID prevents channel visits manufacturing
    extra members. Return original observations for all drill-down evidence.
    """
    rows=[]
    for address,observations in sorted(pending.items()):
        a=min(observations,key=lambda a:(not bool(a.get('ssid') and a['ssid']!='Unknown/hidden'),a.get('last_seen_seconds',999)))
        parts=address.split(':')
        if len(parts)!=6: continue
        try: octets=[int(p,16) for p in parts]
        except ValueError: continue
        if any(len(p)!=2 for p in parts) or any(x>255 for x in octets): continue
        rows.append(dict(address=address,parts=parts,band=band(a['frequency']),ch=a.get('advertised_primary_channel') or channel(a['frequency']),ssid=a.get('ssid') or 'Unknown/hidden'))
    candidates=defaultdict(list)
    for r in rows: candidates[(':'.join(r['parts'][1:]),r['band'],r['ch'])].append(r)
    radios=[]
    for (tail,radio_band,ch),members in candidates.items():
        if len(members)>=2 and len({r['parts'][0] for r in members})>=2 and len({r['ssid'] for r in members})>=2:
            radios.append(dict(tail=tail,band=radio_band,ch=ch,members=members))
    physical=defaultdict(list)
    for radio in radios:
        p=radio['tail'].split(':');physical[':'.join([p[0],p[1],p[3],p[4]])].append(radio)
    groups={};consumed=set();assigned=set()
    def add(kind,identity,members):
        addresses={r['address'] for r in members};assigned.update(addresses)
        groups[(kind,identity)]=[a for address in sorted(addresses) for a in pending[address]]
    for key,family in physical.items():
        common=set.intersection(*[{r['ssid'] for r in radio['members'] if r['ssid']!='Unknown/hidden'} for radio in family])
        if len(family)>=2 and len({r['band'] for r in family})>=2 and len(common)>=2:
            add('virtual-physical','xx:'+key,[r for radio in family for r in radio['members']]);consumed.update(id(r) for r in family)
    for radio in radios:
        if id(radio) not in consumed:
            add('virtual-radio','xx:'+radio['tail']+'@'+str(radio['band'])+'-ch'+str(radio['ch']),radio['members'])
    allocated=defaultdict(list)
    for r in rows:
        if r['address'] not in assigned:
            p=r['parts'][:];p[-1]=f"{int(p[-1],16)&0xf0:02x}";allocated[':'.join(p)].append(r)
    for key,members in allocated.items():
        if len(members)>=2: add('allocated',key,members)
    for address,observations in pending.items():
        if address not in assigned: groups[('unmapped',address)]=observations
    return groups

def grouping_evidence(kind):
    return {
        'confirmed':['CONFIRMED: saved physical AP mapping'],
        'advertised-mld':['ESTIMATED: shared advertised multi-link device address; identity is unauthenticated'],
        'advertised':['ESTIMATED: shared advertised WPS UUID; no observed model/serial conflict'],
        'virtual-physical':['ESTIMATED: Virtual multi-radio | Basic confidence HIGH',
            'Virtual BSSID families: same last 5 MAC octets, band and primary channel; different first octets and SSIDs.',
            'Cross-band match: stable MAC remainder and at least 2 shared visible SSIDs.'],
        'virtual-radio':['ESTIMATED: Virtual-BSSID | Basic confidence HIGH',
            'Same last 5 MAC octets, band and primary channel; different first octets and SSIDs.',
            'One radio family; other bands have not been linked yet.'],
        'allocated':['ESTIMATED: Allocated-BSSID | Basic confidence EST',
            'Same first 5 MAC octets and same final-octet 16-address allocation block.'],
        'unmapped':['STANDALONE: no grouping pattern or device identity matched']
    }.get(kind,[])

def device_groups(aps):
    groups={};pending={}
    for a in aps:
        if a.get('physical_ap_id'): groups.setdefault(('confirmed',a['physical_ap_id']),[]).append(a)
        else: pending.setdefault(a['bssid'],[]).append(a)
    identities={}
    for address,rows in pending.items():
        hints=[a for a in rows if a.get('advertised_device',{}).get('uuid')]
        if hints:
            latest=min(hints,key=lambda a:a.get('device_identity_age_seconds') or 0)
            identities.setdefault(latest['advertised_device']['uuid'],[]).append(address)
    assigned=set();conflicted=set()
    for uuid,addresses in identities.items():
        rows=[a for address in addresses for a in pending[address]]
        hints=[a.get('advertised_device',{}) for a in rows]
        conflict=any(len({h[k].lower() for h in hints if h.get(k) and h[k].lower() not in ('0','00000000','12345678','unknown','unspecified')})>1 for k in ('manufacturer','model','serial'))
        if not conflict:
            groups[('advertised','wps:'+uuid)]=rows;assigned.update(addresses)
        else: conflicted.update(addresses)
    # Advertised multi-link address is stronger than a MAC allocation pattern.
    mlds={}
    for address,rows in pending.items():
        if address in assigned or address in conflicted:continue
        identities={a.get('advertised_capabilities',{}).get('multi-link device address','').lower() for a in rows}
        identities={m for m in identities if re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',m) and not int(m[:2],16)&1}
        if len(identities)==1:mlds.setdefault(next(iter(identities)),[]).append(address)
    for mld,addresses in mlds.items():
        if len(addresses)>1:
            groups[('advertised-mld',mld)]=[a for address in addresses for a in pending[address]]
            assigned.update(addresses)
    groups.update(automatic_mac_groups({address:rows for address,rows in pending.items() if address not in assigned and address not in conflicted}))
    for address,rows in pending.items():
        if address in conflicted: groups[('unmapped',address)]=rows
    return groups
def inventory_group(aps,kind,identity):
    return device_groups(aps).get((kind,identity),[])
def radio_key(a):
    return 'radio:'+a['physical_radio'] if a.get('physical_radio') else 'band:'+(band(a['frequency']) or 'unknown')
def radio_name(key): return key.split(':',1)[1]+(' (known radio)' if key.startswith('radio:') else ' observations (radio identity unknown)')
def mapping_request(group,identity):
    name=next((a.get('physical_ap_name') or a.get('advertised_device',{}).get('name') or a.get('advertised_device',{}).get('model') for a in group if a.get('physical_ap_name') or a.get('advertised_device',{}).get('name') or a.get('advertised_device',{}).get('model')),None)
    return dict(id=identity.replace('wps:','ap-'),name=name or 'AP '+identity[-17:],bssids=sorted({a['bssid'] for a in group}))
def apply_mapping(nav):
    request=nav.pop('pending_mapping',None)
    if not request: return ''
    try:
        p=subprocess.run(['sudo','-n','/usr/local/bin/wifi-health-ap-map'],input=json.dumps(request),capture_output=True,text=True,timeout=5)
        result=json.loads(p.stdout)
        if p.returncode or result.get('status')!='saved': return 'AP mapping failed: '+result.get('message','writer failed')
        nav['stack']=[dict(page='physical',key=None,selected=('confirmed',request['id']),offset=0)]
        return 'Saved confirmed AP group; capture continues.'
    except (OSError,ValueError,subprocess.TimeoutExpired): return 'AP mapping failed; existing inventory retained.'

def page_data(task,nav):
    d=values(task);frame=nav['stack'][-1];page=frame['page'];key=frame['key']
    aps,clients=scoped(d,nav.get('scope'));all_aps=d.get('aps',[]);all_clients=d.get('clients',[])
    title=page.upper();body=[];items=[]
    if page=='summary':
        title='LIVE OVERVIEW';scope=nav.get('scope')
        body=['Scope: '+(network_name(scope) if scope else 'All observed'),
              f"{len({network_key(a) for a in aps})} detected networks | {len({a['bssid'] for a in aps})} BSSIDs | {len({c['client'] for c in clients})} client MACs",
              'RECEPTION AT THIS DEVICE']+coverage_lines(d,aps)
        counts={'STRONG':0,'MARGINAL':0,'WEAK':0,'COLLECTING':0}
        for a in aps:
            if not fresh(d,a): continue
            counts[reception(a).split(':')[0]]+=1
        body += [f"BSSID/channel readings: {counts['STRONG']} strong, {counts['MARGINAL']} marginal, {counts['WEAK']} weakly heard",
                 'Weak neighbours alone do not indicate a coverage fault.',
                 'DELIVERY FINDINGS',f'{sum(risky(c) and fresh(d,c) for c in clients)} observed links with elevated directional retry flags']
        if not any(c.get('directions') for c in clients): body.append('COLLECTING: no directional link samples yet')
        activity=d.get('activity',{});body.append(f"All-capture traffic: {fmt(activity.get('frames_per_second'),' frames/s')} | {fmt(activity.get('kb_per_second'),' KB/s')} captured, last 60s")
        for name,r in d.get('radios',{}).items():
            body.append(f"{name}: {r.get('band','')} CH {channel(r.get('frequency'))} | round {r.get('sweep_number','?')} {r.get('sweep_position','?')}/{r.get('sweep_channels','?')} | dwell {fmt(r.get('dwell_target_seconds'),'s')}")
            body.append(f"  {r.get('frames',0)} frames | packet age {fmt(r.get('last_frame_seconds'),'s')} | "+('WAITING' if not r.get('frames') else 'RECEIVING' if r.get('last_frame_seconds',999) is not None and r.get('last_frame_seconds',999)<=10 else 'QUIET'))
            if r.get('error') or r.get('tune_error'): body.append('WARNING: '+name+': '+str(r.get('error') or r.get('tune_error')))
        if d.get('notes'): body.append('NOTE: '+str(d['notes'][-1]))
        items=[entry('networks','Networks','networks'),entry('clients','Clients','clients'),entry('findings','Delivery findings','findings'),entry('trends','Trends','trends'),entry('physical','Physical APs','physical'),entry('traffic','Traffic details','traffic'),entry('measurements','Channel measurements','measurements')]
        if not any(s.get('noise_dbm') is not None or s.get('busy_percent') is not None for s in d.get('channel_surveys',[])) and not any(r.get('packet_noise_dbm') is not None for r in d.get('radios',{}).values()):
            items=[x for x in items if x['id']!='measurements']
        if scope: items.insert(0,entry('clear','Show all observed networks','clear_scope'))
    elif page=='networks':
        title='DETECTED NETWORKS';body=['Live network names; same SSID does not confirm one physical AP.']
        networks={network_key(a) for a in all_aps}
        for n in sorted(networks):
            group=[a for a in all_aps if network_key(a)==n]
            items.append(entry(n,f"{network_name(n)} | {len({a['bssid'] for a in group})} BSSIDs",'network',n))
    elif page=='network':
        title='NETWORK: '+network_name(key);group,links=scoped(d,key)
        body=coverage_lines(d,group)+[f"{len({a['bssid'] for a in group})} observed BSSIDs | {len({c['client'] for c in links})} client MACs",
                                    'Band availability is observational; unobserved does not mean absent.']
        items=[entry('focus','Use this network as summary scope','set_scope',key),entry('clients','Clients on this network','network_clients',key)]
        for a in sorted(group,key=lambda a:ap_id(a)):
            items.append(entry(ap_id(a),f"{a['bssid']} | {band(a['frequency'])} CH {channel(a['frequency'])} | {reception(a).split(':')[0]}",'ap',ap_id(a)))
    elif page in ('clients','network_clients','ap_clients'):
        links=all_clients if page=='clients' else scoped(d,key)[1] if page=='network_clients' else [c for c in all_clients if (c['ap'],c['frequency'])==key]
        if page=='clients': links=clients
        title='CLIENTS';body=['One entry per observed client MAC; identities are not authenticated.']
        for mac in sorted({c['client'] for c in links}):
            group=[c for c in links if c['client']==mac]
            # Pin the context addresses to the parent scope, not to later global scope changes.
            contexts=(page, nav.get('scope') if page=='clients' else key)
            items.append(entry(mac,f"{mac} | {len(group)} link observations"+(' | WARNING retries' if any(risky(c) for c in group) else ''),'client',(mac,contexts)))
    elif page=='ap':
        a=next((a for a in all_aps if ap_id(a)==key),None)
        if not a: body=['Source no longer retained in this capture.']
        else:
            group_identity=next((identity for identity,rows in device_groups(all_aps).items() if any(x['bssid']==a['bssid'] for x in rows)),('unmapped',a['bssid']))
            group_label=('CONFIRMED ' if group_identity[0]=='confirmed' else 'STANDALONE ' if group_identity[0]=='unmapped' else 'ESTIMATED ')+group_identity[1]
            title='BSSID: '+a['bssid'];body=['Network: '+source_name(a.get('ssid')),
                'AP group: '+group_label,
                f"Band: {band(a['frequency'])} | CH {channel(a['frequency'])} | {a['frequency']} MHz capture frequency",
                'AP advertised width: '+(a.get('advertised_width') or 'unknown'),
                'AP advertised primary channel: '+str(a.get('advertised_primary_channel') or 'unknown'),
                'Assessment: '+reception(a),f"Signal range {fmt(a.get('min_dbm'),' dBm')} to {fmt(a.get('max_dbm'),' dBm')} | samples {a.get('signal_samples',0)}",
                f"Last signal {fmt(a.get('signal_last_seen_seconds'),'s')} | last frame {fmt(a.get('last_seen_seconds'),'s')}",
                f"Beacons: {a.get('beacons',0)} | last {fmt(a.get('beacon_last_seen_seconds'),'s')}"]
            if a.get('ap_reported_busy_percent') is not None: body.append(f"AP-reported utilisation: {a['ap_reported_busy_percent']:g}%")
            if a.get('snr_db') is not None: body.append('Same-frame AP SNR: '+fmt(a['snr_db'],' dB'))
            body+=channel_evidence(d,a['frequency'])+['Signal is received here; not a measurement at the client.']
            items=[entry('clients','Clients / directional link evidence','ap_clients',key)]
    elif page=='client':
        mac,contexts=key;title='CLIENT: '+mac
        kind,parent=contexts
        candidates=scoped(d,parent)[1] if kind in ('clients','network_clients') else [c for c in all_clients if (c['ap'],c['frequency'])==parent]
        links=[c for c in candidates if c['client']==mac]
        body=['Observed MAC: '+mac, 'Signal is client-origin reception at this device.',
              'Different captured frequencies do not confirm roaming.']
        recent=[c for c in links if fresh(d,c) and c.get('signal_dbm') is not None and c.get('signal_samples',0)>=3]
        if recent:
            best=max(recent,key=lambda c:c['signal_dbm']);body.append('Strongest observation: '+signal_assessment(best['signal_dbm']))
        for c in sorted(links,key=link_id):
            items.append(entry(link_id(c),f"{c['ap']} CH {channel(c['frequency'])} | {reception(c).split(':')[0]}"+(' | WARNING retries' if risky(c) else ''),'link',link_id(c)))
    elif page=='link':
        c=next((c for c in all_clients if link_id(c)==key),None)
        title='CLIENT <-> BSSID LINK'
        if not c: body=['Source no longer retained in this capture.']
        else:
            a=next((a for a in all_aps if ap_id(a)==(c['ap'],c['frequency'])),{})
            body=['Client MAC: '+c['client'],'BSSID: '+c['ap'],'Network: '+source_name(a.get('ssid')),
                  f"Band: {band(c['frequency'])} | CH {channel(c['frequency'])} | {c['frequency']} MHz capture frequency",
                  'AP advertised width: '+(a.get('advertised_width') or 'unknown'),
                  f"Observation window: {d.get('measurement_window_seconds',60):g}s",'DIRECTIONAL RETRIES']+direction_lines(c)
            body+=['RECEPTION AT THIS DEVICE','Client: '+reception(c),
                   f"Client samples {c.get('signal_samples',0)} | range {fmt(c.get('min_dbm'),' dBm')} to {fmt(c.get('max_dbm'),' dBm')} | age {fmt(c.get('signal_last_seen_seconds'),'s')}",
                   'AP: '+reception(a)]
            if a.get('snr_db') is not None: body.append('Same-frame AP SNR: '+fmt(a['snr_db'],' dB'))
            body+=['LISTENING EVIDENCE']+channel_evidence(d,c['frequency'])
            body+=['INTERPRETATION','Warning: >=20% retry flags with >=100 sampled data frames per direction.',
                   'These are captured attempts, not end-to-end packet loss or unique packets.',
                   'Hopping, missing frames and unsupported PHY/width can bias the sample.',
                   'Confirm a concerning link with a capture on its actual channel and width.']
    elif page=='findings':
        title='DELIVERY FINDINGS';body=['All sampled links are retained regardless of signal strength.',
            'WARNING requires >=100 data frames and >=20% retry flags per direction.']
        for c in sorted(clients,key=link_id):
            if risky(c) and fresh(d,c): items.append(entry(link_id(c),f"{c['client']} <-> {c['ap']} CH {channel(c['frequency'])}",'link',link_id(c)))
        if not items: body.append('No qualified elevated directional retry finding in current samples.')
        unattributed=sum(max(0,a.get('recent_data_frames',0)-sum(x.get('frames',0) for c in all_clients if (c['ap'],c['frequency'])==ap_id(a) for x in c.get('directions',{}).values())) for a in aps)
        body.append(f'Unattributed / unmatched data attempts: {unattributed}; not assigned to a client.')
    elif page=='trends':
        title='TRENDS';addresses={a['bssid'] for a in aps}
        for t in d.get('trends',[]):
            if nav.get('scope') is not None and (not t.get('identity') or t['identity'][0] not in addresses): continue
            items.append(entry(trend_id(t),f"{t['status']} {t['metric']} | {t.get('source','')} | {t.get('identity',['?'])[0]}",'trend',trend_id(t)))
        if not items: body=['COLLECTING: need 3 same-source readings spanning 30s, latest within 60s.','Repaints do not add evidence. Channel hopping can delay comparable samples.']
    elif page=='trend':
        trends=d.get('trends',[]);index=next((i for i,t in enumerate(trends) if trend_id(t)==key),None)
        title='TREND EVIDENCE'
        if index is None: body=['Trend no longer has fresh evidence.']
        else:
            t=trends[index];identity=t.get('identity',[]);metric=t['metric']
            freq=next((x for x in identity if isinstance(x,(int,float)) and x>=2400),None)
            unit='dBm' if metric in ('AP signal','client signal','noise') else 'dB' if metric=='SNR' else '%'
            rule={'AP signal':'signal below -75 dBm','client signal':'signal below -75 dBm','SNR':'SNR below 20 dB','retries':'retry flags >=20%, >=100 sampled data frames','link retries':'retry flags >=20%, >=100 sampled data frames per direction','AP load':'AP-reported utilisation >=70%','channel load':'survey utilisation >=70%'}.get(metric,'no warning threshold')
            body=['Assessment: '+t['status']+' '+metric,'Source: '+source_name(t.get('source')),
                  ('Device radio: ' if metric in ('noise','channel load') else 'BSSID: ')+str(identity[0]),
                  f'Channel {channel(freq)} | {freq} MHz']
            if metric in ('client signal','link retries'): body.append('Client MAC: '+str(identity[1]))
            if metric=='link retries': body.append('Direction: '+('CLIENT -> AP' if identity[-1]=='up' else 'AP -> CLIENT'))
            if metric=='retries': body.append('Scope: BSSID/channel aggregate, all captured data attempts.')
            body+=['EVIDENCE',f"{t.get('samples','?')} readings spanning {t.get('span_seconds','?')}s",
                   f"Early median {fmt(t.get('early_median'))} -> late median {fmt(t.get('late_median'))} {unit}",
                   f"Change {t.get('delta',0):+g} "+('percentage points' if unit=='%' else 'dB'),
                   f"Warning readings: {t.get('warning_readings','?')}/{t.get('samples','?')}",
                   'DECISION RULE',f"Worsening/improving: median change >= {t.get('change_threshold',5):g} "+('percentage points' if unit=='%' else 'dB'),
                   'Higher is better.' if t.get('higher_is_better',metric in ('AP signal','client signal','SNR')) else 'Lower is better.',
                   'Persistent: >=60s span, latest reading in warning, >=80% readings in warning.',
                   'Warning condition: '+rule,'Stable: change below threshold and persistence rule not met.',
                   'RECENT READINGS (age, value; last 3)']
            body += [f"{r['age_seconds']:g}s ago: {r['value']:g} {unit}"+(' WARNING' if r.get('warning') else '') for r in t.get('readings',[])[-3:]]
            body+=['CONTEXT','Same source/channel; rolling windows overlap. Trend span is not continuous listening or proof of cause.']

    elif page=='physical':
        title='PHYSICAL AP DISCOVERY';visible={ap_id(a) for a in aps}
        groups={identity:group for identity,group in device_groups(all_aps).items() if any(ap_id(a) in visible for a in group)}
        confirmed=sum(k[0]=='confirmed' for k in groups);estimated=sum(k[0] not in ('confirmed','unmapped') for k in groups);standalone=sum(k[0]=='unmapped' for k in groups)
        body=[f'{confirmed} confirmed | {estimated} estimated AP groups | {standalone} standalone BSSIDs',
              'Automatic grouping uses Basic Scan rules and advertised device identity.',
              'Estimates are not verified hardware counts; unmatched addresses stay visible.']
        for identity,group in sorted(groups.items()):
            names=names_for(group);hint=next((a.get('advertised_device',{}) for a in group if a.get('advertised_device')), {})
            name=group[0].get('physical_ap_name') or hint.get('name') or hint.get('model') or identity[1]
            status='CONFIRMED' if identity[0]=='confirmed' else 'STANDALONE' if identity[0]=='unmapped' else 'ESTIMATED'
            label=name+f" | {len(names)} SSIDs / {len({a['bssid'] for a in group})} BSSIDs | "+status
            items.append(entry(identity,label,'physical_ap',identity))
        if groups: items.append(entry('correction','Optional: correct AP grouping','unresolved'))
    elif page=='unresolved':
        title='AP GROUPING CORRECTION';groups=device_groups(all_aps)
        body=['Automatic estimates remain live; this correction is optional.',
              'Save a verified mapping only when you know the hardware identity.']
        items=[entry('group','Create a confirmed AP group','mapping_builder')]
        for identity,group in sorted(groups.items()):
            if identity[0]=='unmapped': items.append(entry(identity,identity[1]+' | '+(', '.join(names_for(group)) or 'Name not captured'),'physical_ap',identity))
    elif page=='mapping_builder':
        title='SELECT BSSIDs FOR ONE AP';selected=nav.setdefault('mapping_members',[])
        body=['Select only BSSIDs whose physical device identity you have verified.',f'{len(selected)} BSSIDs selected for optional verified override.']
        addresses=sorted({a['bssid'] for a in all_aps if not a.get('physical_ap_id')})
        selected[:]=[x for x in selected if x in addresses]
        if selected: items.append(entry('save','Review and save this physical AP group','review_manual'))
        for address in addresses:
            names=names_for([a for a in all_aps if a['bssid']==address])
            items.append(entry(address,('[x] ' if address in selected else '[ ] ')+address+' | '+(', '.join(names) or 'Name not captured'),'toggle_member',address))
    elif page=='mapping_review':
        title='CONFIRM ONE PHYSICAL AP';request=key
        body=['You are confirming that all listed addresses belong to ONE device.',
              'AP name: '+request['name'],'AP identity: '+request['id'],f"{len(request['bssids'])} BSSIDs in this group",'This persists the mapping and updates the live report.']
        items=[entry('save','Save verified physical AP grouping','save_mapping',request)]
        for address in request['bssids']:
            observations=[a for a in all_aps if a['bssid']==address]
            latest=min(observations,key=lambda a:a.get('last_seen_seconds',999)) if observations else None
            items.append(entry(('member',address),address+' | '+(', '.join(names_for(observations)) or 'Name not captured'),'ap' if latest else None,ap_id(latest) if latest else None))

    elif page=='physical_ap':
        kind,identity=key;group=inventory_group(all_aps,kind,identity);names=names_for(group)
        title=('PHYSICAL AP: ' if kind=='confirmed' else 'STANDALONE BSSID: ' if kind=='unmapped' else 'ESTIMATED AP: ')+identity
        body=grouping_evidence(kind)+[f"{len(names)} observed SSIDs | {len({a['bssid'] for a in group})} distinct BSSIDs"]
        hints=[a for a in group if a.get('advertised_device')]
        if hints:
            h=min(hints,key=lambda a:a.get('device_identity_age_seconds') or 0);device=h['advertised_device']
            body+=['IDENTITY EVIDENCE']+[k.title()+': '+device[k] for k in ('uuid','manufacturer','model','serial','name') if device.get(k)]
            body.append('Identity advertisement age: '+fmt(h.get('device_identity_age_seconds'),'s'))
        if kind=='advertised':
            body+=['Matching UUID with no observed model/serial conflict is a grouping hint.',
                   'Advertised identifiers may be duplicated or spoofed; not chassis proof.']

        elif kind in ('virtual-physical','virtual-radio','allocated'):
            body+=['Live estimate; grouping may change as new evidence arrives.',
                   'Estimated identity is not authenticated chassis proof.']
        for radio in sorted({radio_key(a) for a in group}):
            rows=[a for a in group if radio_key(a)==radio]
            items.append(entry(('radio',radio),radio_name(radio)+f' | {len(names_for(rows))} SSIDs','inventory_radio',(kind,identity,radio)))
    elif page=='inventory_radio':
        kind,identity,radio=key;group=[a for a in inventory_group(all_aps,kind,identity) if radio_key(a)==radio]
        title=radio_name(radio).upper();body=['Parent device: '+identity,f"{len(names_for(group))} observed SSIDs | {len({a['bssid'] for a in group})} BSSIDs"]
        for name in names_for(group):
            rows=[a for a in group if a.get('ssid')==name]
            items.append(entry(('ssid',name),name+f" | {len({a['bssid'] for a in rows})} BSSIDs",'inventory_ssid',(kind,identity,radio,name)))
        if any(not a.get('ssid') or a['ssid']=='Unknown/hidden' for a in group): items.append(entry(('unnamed',None),'Name not captured / unresolved observations','inventory_ssid',(kind,identity,radio,None)))
    elif page=='inventory_ssid':
        kind,identity,radio,name=key;group=[a for a in inventory_group(all_aps,kind,identity) if radio_key(a)==radio]
        group=[a for a in group if (a.get('ssid')==name if name is not None else not a.get('ssid') or a['ssid']=='Unknown/hidden')]
        title='SSID: '+source_name(name);body=['Parent device: '+identity,'Channel numbers below are capture observations.']
        for a in sorted(group,key=ap_id):
            primary=' | AP primary CH '+str(a['advertised_primary_channel']) if a.get('advertised_primary_channel') is not None else ''
            items.append(entry(ap_id(a),f"{a['bssid']} | capture CH {channel(a['frequency'])}"+primary+' | '+(a.get('advertised_width') or 'unknown width'),'ap',ap_id(a)))
    elif page=='traffic':
        title='TRAFFIC';activity=d.get('activity',{});mix=activity.get('frame_types_60s',{})
        body=['Scope: all captured activity (60s), including unnamed/unattributed frames.',
              f"{fmt(activity.get('frames_per_second'),' frames/s')} | {fmt(activity.get('kb_per_second'),' KB/s')}"]
        body += [f'{k}: {mix.get(k,0)}' for k in ('data','management','control','beacons','probes','association','authentication','disconnects','ACK','RTS','CTS')]
        body+=['Capture activity is not usable throughput; encrypted applications are unknown.','Two-radio overlap may count an attempt twice.']
        if activity.get('mix_window_capped'): body.append('LIMITED: frame-mix storage cap reached')
    elif page=='measurements':
        title='CHANNEL MEASUREMENTS';latest={}
        body=['LOCAL RECEIVER MEASUREMENTS']
        for name,r in d.get('radios',{}).items():
            counts=r.get('metadata_samples',{});n=counts.get('frames',0)
            body.append(f"{name}: signal metadata {counts.get('signal',0)}/{n} frames since start")
            if counts.get('noise',0):body.append(f"{name}: noise metadata {counts['noise']}/{n} frames since start")
            elif n:body.append(name+': packet noise not supplied in captured frames')
            else:body.append(name+': collecting packet metadata')
        for sample in sorted(d.get('channel_surveys',[]),key=lambda row:row.get('time',0)):
            latest[(sample.get('radio'),sample.get('frequency'))]=sample
        usable=[(identity,row) for identity,row in latest.items() if row.get('noise_dbm') is not None or row.get('busy_percent') is not None]
        for identity,row in sorted(usable,key=lambda item:str(item[0])):
            items.append(entry(identity,f"Driver measurement: {identity[0]} CH {channel(identity[1])}",'channel_survey',identity))
        if not usable:body.append('Local noise / channel busy: no usable survey data returned by the driver')
        body+=['AP-REPORTED UTILISATION','AP beacon reports are measured by the AP, separately from this receiver.']
        reported=[a for a in d.get('aps',[]) if a.get('ap_reported_busy_percent') is not None]
        for ap in sorted(reported,key=lambda a:a['ap_reported_busy_percent'],reverse=True):
            label=source_name(ap.get('ssid'))+' | '+ap['bssid']+f" | {ap['ap_reported_busy_percent']:g}% busy (AP-reported)"
            if ap.get('ap_reported_stations') is not None:label+=f" | {ap['ap_reported_stations']} stations"
            items.append(entry(('ap-load',ap['bssid'],ap['frequency']),label,'ap',ap_id(ap)))
        if not reported:body.append('No recent AP BSS Load advertisement decoded yet; APs may omit it.')
        body+=['SNR requires measured signal and noise from a matching source.','Captured frame counts cannot substitute for channel busy time.']
    elif page=='channel_survey':
        rows=[s for s in d.get('channel_surveys',[]) if (s.get('radio'),s.get('frequency'))==key]
        title='CHANNEL SURVEY'
        if rows:
            s=max(rows,key=lambda s:s.get('time',0));body=[f'Device radio: {key[0]} | CH {channel(key[1])}',f"Survey interval: {fmt(s.get('observed_seconds'),'s')}"]
            if s.get('noise_dbm') is not None: body.append('Noise: '+fmt(s['noise_dbm'],' dBm'))
            if s.get('busy_percent') is not None: body.append('Channel utilisation: '+fmt(s['busy_percent'],'%'))
            body+=['Driver survey at this device; utilisation is not listening share.']
        else: body=['Survey no longer retained.']
    if not items and page in ('networks','clients','network_clients','ap_clients','client','physical','physical_ap','inventory_ssid'): body.append('COLLECTING: no matching observations yet.')
    return title,body,items

def chosen(frame,items):
    identity=frame.get('selected')
    position=next((i for i,x in enumerate(items) if x['id']==identity),None)
    if position is None and items: position=0;frame['selected']=items[0]['id']
    return position


def open_report_page(nav,page,key):
    def normal(value):
        if isinstance(value,(tuple,list)):return tuple(normal(v) for v in value)
        if isinstance(value,dict):return tuple(sorted((str(k),normal(v)) for k,v in value.items()))
        return value
    identity=(page,normal(key))
    for index,frame in enumerate(nav['stack']):
        if (frame['page'],normal(frame.get('key')))==identity:
            nav['stack']=nav['stack'][:index+1]
            return
    nav['stack'].append({'page':page,'key':key,'selected':None,'offset':0})

def navigate(task,nav,key):
    frame=nav['stack'][-1];_,body,items=page_data(task,nav);position=chosen(frame,items)
    if key in ('back','left'):
        if len(nav['stack'])==1: return False
        nav['stack'].pop();return True
    if key in ('up','down'):
        delta=-1 if key=='up' else 1
        if items:
            frame['selected']=items[(position+delta)%len(items)]['id']
        else: frame['offset']=max(0,frame.get('offset',0)+delta)
        return True
    if key=='right':
        if position is not None:
            x=items[position]
            if x['page']=='toggle_member':
                members=nav.setdefault('mapping_members',[])
                if x['target'] in members: members.remove(x['target'])
                else: members.append(x['target'])
            elif x['page']=='review_manual':
                members=nav.get('mapping_members',[])
                if members:
                    request=mapping_request([a for a in values(task).get('aps',[]) if a['bssid'] in members],'manual-'+sorted(members)[0])
                    nav['stack'].append(dict(page='mapping_review',key=request,selected=None,offset=0))
            elif x['page']=='save_mapping': nav['pending_mapping']=x['target']
            elif x['page'] in ('clear_scope','set_scope'):

                nav['scope']=x['target'] if x['page']=='set_scope' else None
                nav['stack']=[{'page':'summary','key':None,'selected':None,'offset':0}]
            elif x['page']: open_report_page(nav,x['page'],x['target'])
        return True
    return False

def report(task,nav,width=79,capacity=30):
    title,body,items=page_data(task,nav);d=values(task);frame=nav['stack'][-1]
    age=max(0,time.monotonic()-task.get('finder',{}).get('received',time.monotonic()))
    status='STOPPING' if task.get('stopping') else 'FAILED' if task.get('state')=='FAILED' or d.get('state')=='FAILED' else 'FINAL' if task.get('state')!='RUNNING' else 'STALE' if age>10 else d.get('state','STARTING')
    header=[f"{status} H25 | {d.get('frames_observed',0)} frames | updated {age:.0f}s ago",title]
    if status=='STALE': header.append('STALE: readings are not current; assessments paused.')
    if status=='FAILED' and d.get('notes'): header.append('Error: '+d['notes'][-1])
    wrap=lambda texts:[line for text in texts for line in textwrap.wrap(str(text),max(1,width)) or ['']]
    rows=wrap(header);remaining=max(1,capacity-len(rows))
    content=wrap(body)
    position=chosen(frame,items)
    if items:
        # Keep a navigable list visible even on a compact display.
        reserve=min(len(items),max(3,remaining//3));content=content[:max(0,remaining-reserve-1)]
        first=max(0,min(position-reserve//2,len(items)-reserve))
        content.append(f'ENTRIES {first+1}-{min(len(items),first+reserve)}/{len(items)}')
        content += [('> ' if i==position else '  ')+x['label'] for i,x in enumerate(items) if first<=i<first+reserve]
    else:
        offset=min(frame.get('offset',0),max(0,len(content)-remaining+1));frame['offset']=offset
        if len(content)>remaining:
            rows.append(f'EVIDENCE lines {offset+1}-{min(len(content),offset+remaining-1)}/{len(content)}');remaining=max(1,capacity-len(rows))
        content=content[offset:offset+remaining]
    return [r[:width] for r in (rows+content)[:capacity]]

def controls(nav):
    return 'Up/Down: browse   Right: open   Back/Left: '+('menu' if len(nav['stack'])==1 else 'previous')


# WIFI_REPORT_PLAIN_V1
from wifi_health_presentation import install as _install_plain_report
_install_plain_report(globals())

# WIFI_ENGINEER_EVIDENCE_V1
from wifi_health_engineer import install_browser as _install_evidence_pages
_install_evidence_pages(globals())

# CLOVERKIT_ROADMAP_V1
from cloverkit_wireless import install_browser as _install_roadmap_pages
_install_roadmap_pages(globals())

# Local credentials stay above report content and never enter remote published snapshots.
_report_without_access=report
def report(task,nav,width=79,capacity=30):
    access=values(task).get('local_access')
    if not access:return _report_without_access(task,nav,width,capacity)
    prefix=['REPORT ACCESS: ssh -t '+access['username']+'@'+access['host']]
    if access.get('show_password') and access.get('password'):prefix.append('Password: '+access['password'])
    prefix.append('Email: '+access.get('email','NOT CONFIGURED')+' | Valid until scan stops')
    if task.get('state')!='RUNNING':prefix=['REPORT ACCESS ENDED']
    prefix=[part for line in prefix for part in textwrap.wrap(line,max(1,width))]
    return (prefix+_report_without_access(task,nav,width,max(1,capacity-len(prefix))))[:capacity]
