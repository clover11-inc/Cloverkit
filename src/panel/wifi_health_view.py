"""Fixed, selectable Wi-Fi dashboard. Each render replaces its previous state."""
import time
import re
import textwrap

SECTIONS = ('2.4 GHz', '5 GHz', '6 GHz', 'Traffic', 'Retries', 'Noise', 'Channel load', 'SNR', 'Clients', 'Measurements', 'AP inventory', 'Trend')

def available_sections(task):
    d=task.get('finder',{}).get('values',{})
    window=d.get('measurement_window_seconds',60)
    noise=any(s.get('noise_dbm') is not None for s in d.get('channel_surveys',[])) or any(r.get('packet_noise_dbm') is not None for r in d.get('radios',{}).values())
    snr=any(a.get('snr_db') is not None and a.get('last_seen_seconds',999)<=window for a in d.get('aps',[]))
    return [i for i in range(len(SECTIONS)) if (i!=5 or noise) and (i!=7 or snr)]

def fmt(value, unit=''):
    return 'UNAVAILABLE' if value is None else f'{value:g}{unit}'

def band(freq):
    return '2.4 GHz' if 2400 <= freq < 2500 else '5 GHz' if 4900 <= freq < 5925 else '6 GHz' if 5925 <= freq < 7125 else None

def channel(freq):
    if freq == 2484: return 14
    if freq is None: return '?'
    if 2412 <= freq <= 2472: return (freq-2407)//5
    if freq == 5935: return 2
    if 5955 <= freq <= 7115: return (freq-5950)//5
    if 5000 <= freq < 5925: return (freq-5000)//5
    return '?'

def bar(dbm):
    n=max(0,min(8,round((dbm+100)/60*8)))
    return str(n)+'/8'

def source_name(value):
    return 'Name not captured' if not value or value == 'Unknown/hidden' else value

def signal_assessment(value):
    if value is None: return 'UNKNOWN: no signal measurement'
    label='WEAK' if value < -75 else 'MARGINAL' if value < -67 else 'STRONG'
    return f'{label}: {value:g} dBm at this device'

def trend_words(status, metric):
    if status == 'PERSISTENT':
        return {'AP signal':'AP signal remains weak','client signal':'Client signal remains weak',
                'retries':'Frequent retransmissions persist','AP load':'AP utilisation remains high',
                'channel load':'Channel utilisation remains high','SNR':'Signal-to-noise remains low'}.get(metric, metric+' warning persists')
    label={'AP signal':'AP signal','SNR':'Signal-to-noise','AP load':'AP utilisation','channel load':'Channel utilisation','retries':'Retransmissions'}.get(metric,metric.capitalize())
    return label+' '+{'STABLE':'unchanged','WORSENING':'worsening','IMPROVING':'improving'}.get(status,status.lower())

def view(task, selected=0, width=79, capacity=30, detail=False, source_index=0):
    visible=available_sections(task)
    if selected not in visible: selected=9
    state=task.get('finder', {}); d=state.get('values', {})
    now=time.monotonic(); age=max(0,now-state.get('received',now))
    aps=d.get('aps', []); clients=d.get('clients', [])
    measurement_window=d.get('measurement_window_seconds',60)
    current=[a for a in aps if a.get('last_seen_seconds',999)<=measurement_window]
    sig=[a for a in current if a.get('signal_dbm') is not None]
    weak=[a for a in sig if a['signal_dbm'] < -75]
    client_sig=[c for c in clients if c.get('last_seen_seconds',999)<=measurement_window and c.get('signal_dbm') is not None]
    weak_clients=[c for c in client_sig if c['signal_dbm']<-75]
    qualified=[a for a in current if a.get('recent_data_frames',0)>=100 and a.get('recent_retry_percent') is not None]
    retries=[a for a in qualified if a['recent_retry_percent']>=20]
    surveys=d.get('channel_surveys', [])
    survey_noise=[s['noise_dbm'] for s in surveys if s.get('noise_dbm') is not None]
    packet_noise=[r['packet_noise_dbm'] for r in d.get('radios',{}).values() if r.get('packet_noise_dbm') is not None]
    noise=survey_noise or packet_noise
    noise_source='SURVEY' if survey_noise else 'PACKET'
    busy=[s['busy_percent'] for s in surveys if s.get('busy_percent') is not None]
    ap_load=[a for a in current if a.get('ap_reported_busy_percent') is not None]
    ap_busy=[a['ap_reported_busy_percent'] for a in ap_load]
    snr=[a for a in current if a.get('snr_db') is not None]
    bad_snr=[a for a in snr if a['snr_db']<20]
    stopped=task.get('state')!='RUNNING'
    status='FINAL' if stopped else 'STALE' if age>10 else d.get('state','STARTING')
    high_load=(busy and max(busy)>=70) or (ap_busy and max(ap_busy)>=70)
    checks=[('AP signal',bool(sig)),('clients',bool(client_sig)),('retries',bool(qualified)),
            ('noise',bool(noise)),('load',bool(busy or ap_busy)),('SNR',bool(snr))]
    missing=[label for label,available in checks if not available and label not in ('noise','SNR')]
    warnings=[]
    if weak: warnings.append('weak AP signals')
    if weak_clients: warnings.append('weak client signals')
    if retries: warnings.append('frequent retransmissions')
    if high_load: warnings.append('busy channels')
    if bad_snr: warnings.append('low SNR')
    failed=d.get('state')=='FAILED' or task.get('state')=='FAILED'
    if failed:
        verdict='FAILED: capture could not continue'
        advice='Advice: resolve the capture error; no health verdict.'
    elif not stopped and age>10:
        verdict='STALE: live readings stopped updating'
        advice='Advice: check the capture task; readings are out of date.'
    elif not d.get('frames_observed'):
        verdict='COLLECTING: waiting for captured traffic'
        advice='Advice: allow a channel sweep; no assessment yet.'
    elif warnings:
        verdict='Attention: '+', '.join(warnings)
        coverage=bool(weak or weak_clients); delivery=bool(retries or high_load or bad_snr)
        focus='coverage and delivery' if coverage and delivery else 'coverage' if coverage else 'delivery / channel conditions'
        advice='Advice: investigate '+focus+'; cause unconfirmed.'
    else:
        verdict='No warnings in available measurements' if any(available for _,available in checks) else 'Insufficient data for health checks'
        advice='Advice: captured measurements do not certify network health.'
    frame_mix=d.get('activity',{}).get('frame_types_60s',{})
    trends=d.get('trends',[])
    notable=[t for t in trends if t.get('status')!='STABLE']
    candidates=notable or trends
    groups={}
    for t in candidates:
        key=(t['status'],t['metric'])
        groups.setdefault(key,[]).append(t)
    shown=list(groups.items())[:2]
    chosen=[items[0] for _,items in shown]
    def trend_label(key,items):
        count=len({tuple(t.get('identity',[t.get('source','')])) for t in items})
        return trend_words(*key)+(f' ({count} sources)' if count>1 else '')
    trend_line='Trend: '+('; '.join(trend_label(key,items) for key,items in shown) if shown else 'gathering repeat readings')
    if chosen and not failed and (stopped or age<=10):
        lead=chosen[0]
        metric_warning={'AP signal':bool(weak),'client signal':bool(weak_clients),'retries':bool(retries),
                        'SNR':bool(bad_snr),'AP load':bool(high_load),'channel load':bool(high_load)}.get(lead['metric'],False)
        if lead['status']=='WORSENING' and metric_warning:
            advice='Advice: '+lead['metric']+' deteriorating; cause unconfirmed.'
        elif lead['status']=='PERSISTENT' and metric_warning:
            advice='Advice: persistent '+lead['metric']+' warning; investigate this source.'
        elif lead['status']=='IMPROVING' and warnings:
            advice='Advice: '+lead['metric']+' improving; warnings still present.'
    rows=[f"{status} H22 | {d.get('frames_observed',0)} frames | {len({a['bssid'] for a in aps})} BSSIDs / {len({c['client'] for c in clients})} client MACs total",
          verdict + (' | FINAL readings' if stopped else '')]
    details=[]
    for b in SECTIONS[:3]:
        group=[a for a in sig if band(a['frequency'])==b]
        if group:
            best=max(group,key=lambda a:a['signal_dbm']); v=best['signal_dbm']; count=sum(a['signal_dbm']<-75 for a in group)
            label='STRONG' if v>=-67 else 'WEAK' if v<-75 else 'MARGINAL'
            if count and v>=-67: label='MIXED'
            metric=f'{v:.0f} dBm {label}; {count} weak AP readings'
            worst=min(group,key=lambda a:a['signal_dbm'])
            details.append([f"Strongest: {source_name(best['ssid'])} {v:.0f} dBm",f"Weakest: {source_name(worst['ssid'])} {worst['signal_dbm']:.0f} dBm",f"{len(group)} BSSID/channel readings at this device; not AP-to-client signal"])
        else:
            radios=list(d.get('radios',{}).values())
            known=bool(radios) and all('channels' in r for r in radios)
            supported=any(band(f)==b for r in radios for f in r.get('channels',[]))
            if known and not supported:
                metric='UNSUPPORTED: adapter/driver has no usable channels'
                details.append(['No supported capture channels for this band.', 'Adapter / driver / regulatory capability limit.', 'Wi-Fi 6 uses 2.4/5 GHz; Wi-Fi 6E adds 6 GHz.'])
            else:
                metric='WAITING: no recent AP signal reading'
                details.append([f'No AP signal within the {measurement_window:.0f}s observation window.', 'Channel hopping leaves gaps; not proof of an empty band.', 'Wi-Fi 6/7 traffic capture depends on radio PHY support.'])
        rows.append(f'{b}: {metric}')
    activity=d.get('activity', {})
    rows.append(f"Traffic: {fmt(activity.get('frames_per_second'),' frames/s')} {fmt(activity.get('kb_per_second'),' KB/s')} (last 60s)")
    details.append([f"60s frames: data {frame_mix.get('data',0)} | management {frame_mix.get('management',0)} | control {frame_mix.get('control',0)}",
                    f"60s data: AP-to-client {activity.get('down_frames_60s',0)} | client-to-AP {activity.get('up_frames_60s',0)}",
                    f"60s beacons {frame_mix.get('beacons',0)} | probes {frame_mix.get('probes',0)} | auth/association {frame_mix.get('authentication',0)+frame_mix.get('association',0)}",
                    f"60s disconnect frames {frame_mix.get('disconnects',0)}; not confirmed failures",
                    f"60s ACK {frame_mix.get('ACK',0)} RTS {frame_mix.get('RTS',0)} CTS {frame_mix.get('CTS',0)}; speed/loss unverified"])
    rows.append('Retries: '+(f'WARNING: {len(retries)} '+('source' if len(retries)==1 else 'sources')+f' retransmitting often; highest {max(a["recent_retry_percent"] for a in qualified):.1f}%' if retries else f'OBSERVED OK; highest {max(a["recent_retry_percent"] for a in qualified):.1f}%' if qualified else 'WAITING: need 100 data frames per AP/channel'))
    if qualified:
        peak=max(qualified,key=lambda a:a['recent_retry_percent'])
        retry_detail=[f"{source_name(peak['ssid'])} | {peak['bssid']} | CH {channel(peak['frequency'])}",f"{peak['recent_retry_percent']:.1f}% of {peak['recent_data_frames']} sampled data frames marked retransmitted",
                'Sources = AP/channel groups; high = retry flags on >=20% of frames.',
                'Not packet loss; channel hopping may bias this sample.']
    else: retry_detail=['No AP/channel has 100 recent data frames.', 'Retry assessment needs more captured traffic.', 'Missing frames / ACKs do not prove loss.']
    details.append(retry_detail)
    rows.append('Noise: '+(f'{min(noise):g} to {max(noise):g} dBm [{noise_source}]' if noise else 'UNAVAILABLE: adapter not reporting noise'))
    details.append([f'{noise_source} noise at the BH receiver.' if noise else 'Neither driver survey nor packets reported valid noise.',f'{len(noise)} measurements in recent channel visits.','Higher (less negative) = louder; source not identified.'])
    loads=busy or ap_busy
    load_source='BH SURVEY' if busy else 'AP REPORT'
    rows.append('Channel load: '+(f'{max(loads):.0f}% '+('device-measured' if busy else 'AP-reported')+' '+('WARNING' if max(loads)>=70 else 'OBSERVED OK') if loads else 'UNAVAILABLE: no utilisation reading'))
    details.append([f'{len(busy)} BH surveys; {len(ap_load)} AP beacon load reports.',
                    f"AP peak: {max(ap_busy):.0f}% | {max(ap_load,key=lambda a:a['ap_reported_busy_percent'])['ssid']}" if ap_busy else 'No recent AP beacon load report.',
                    'AP reports are measured at AP; survey is measured at BH.'])
    rows.append('SNR: '+(f'{min(a["snr_db"] for a in snr):.0f} dB lowest '+('LOW' if bad_snr else 'OBSERVED OK') if snr else 'UNAVAILABLE: signal or noise reading missing'))
    details.append(['Same-frame captured AP signal minus noise.', f'{len(snr)} AP/channel readings available.', 'Unavailable signal or noise means SNR cannot be assessed.'])
    rows.append('Clients: '+(f"{len(weak_clients)} of {len(client_sig)} readings weak at this device" if client_sig else 'WAITING: no recent client signal reading'))
    details.append([])
    rows.append('Measurements: '+('Unavailable: '+', '.join(missing)+'; missing data is not a fault' if missing else 'Displayed measurement types have data'))
    details.append([])
    inventory={}
    for a in aps:
        key=('confirmed',a['physical_ap_id']) if a.get('physical_ap_id') else ('unmapped',a['bssid'])
        inventory.setdefault(key,[]).append(a)
    confirmed=sum(key[0]=='confirmed' for key in inventory)
    unmapped=sum(key[0]=='unmapped' for key in inventory)
    rows.append(f'AP inventory: {confirmed} confirmed physical APs; {unmapped} unmapped BSSIDs')
    details.append([])
    rows.append(trend_line)
    details.append([])
    for name,r in d.get('radios',{}).items():
        reception='WAITING' if not r.get('frames') else 'RECEIVING' if r.get('last_frame_seconds') is not None and r['last_frame_seconds']<=10 else 'QUIET'
        last=r.get('last_frame_seconds')
        packet_age='none' if last is None else f'{last+age:.0f}s'
        sweep=f"round {r.get('sweep_number','?')} {r.get('sweep_position','?')}/{r.get('sweep_channels',len(r.get('channels',[])) or '?')}"
        dwell=f" listen {r['dwell_target_seconds']:g}s" if r.get('dwell_target_seconds') is not None else ''
        rows.append(f"{name}: {r.get('band','')} CH {channel(r.get('frequency'))} | {sweep}{dwell}")
        reception_text={'WAITING':'WAITING: no packets yet','QUIET':'QUIET: no packets recently','RECEIVING':'RECEIVING'}[reception]
        rows.append(f"  Total {r.get('frames',0)} frames | last packet {packet_age} | {r.get('error') or r.get('tune_error') or reception_text}")
    rows[2 + selected % len(SECTIONS)] = '> ' + rows[2 + selected % len(SECTIONS)]
    total_mix=sum(frame_mix.get(k,0) for k in ('data','management','control','other'))
    if total_mix:
        dominant=max(('data','management','control'),key=lambda k:frame_mix.get(k,0))
        mix_note=f'Traffic: mostly {dominant} ({100*frame_mix.get(dominant,0)/total_mix:.0f}%); {total_mix} frames/60s'
    else:
        mix_note='Traffic: quiet capture window; not a network fault'
    if not warnings and not failed and d.get('frames_observed') and age<=10:
        advice='Advice: available measurements only; not a full network health test.'
    if total_mix:
        traffic_index=next(i for i,r in enumerate(rows) if r.removeprefix('> ').startswith('Traffic:'))
        rows[traffic_index]+=f'; {100*frame_mix.get(dominant,0)/total_mix:.0f}% {dominant}'
    rows[2:2]=[advice]
    selected_index=selected % len(SECTIONS)
    metric_trends=[t for t in trends if t['metric'] in {
        '2.4 GHz':('AP signal',),'5 GHz':('AP signal',),'6 GHz':('AP signal',),
        'Traffic':(),'Retries':('retries',),'Noise':('noise',),
        'Channel load':('AP load','channel load'),'SNR':('SNR',),'Clients':('client signal',),'Measurements':(),'AP inventory':(),'Trend':()}[SECTIONS[selected_index]]]
    if selected_index<3: metric_trends=[t for t in metric_trends if band(t['identity'][1])==SECTIONS[selected_index]]
    if metric_trends:
        source_rows=[]
        for t in metric_trends[:2]:
            identity=t.get('identity',[])
            freq=next((value for value in identity if isinstance(value,(int,float)) and value>=2400),None)
            address=identity[1] if t['metric']=='client signal' and len(identity)>1 else identity[0] if identity else ''
            source=f"{source_name(t['source'])} {str(address)[-8:]}".strip()
            if freq is not None: source+=f' CH {channel(freq)}'
            unit='percentage points' if t['metric'] in ('retries','AP load','channel load') else 'dB'
            source_rows.append(f"{trend_words(t['status'],t['metric'])}: {source}")
            source_rows.append(f"Change {t['delta']:+g} {unit}; readings span {t['span_seconds']}s")
        details[selected_index].extend(source_rows)
    # The summary and evidence screens use the same live snapshot.
    if detail:
        section=SECTIONS[selected_index]
        groups=([a for a in sig if band(a['frequency'])==section] if selected_index<3 else qualified if section=='Retries' else client_sig if section=='Clients' else ap_load if section=='Channel load' and not busy else snr if section=='SNR' else [])
        def identity_key(a): return (a.get('bssid',a.get('ap','')),a.get('client',''),a.get('frequency',0))
        groups=sorted(groups,key=lambda a: ((-a['recent_retry_percent'] if section=='Retries' else a['signal_dbm'] if selected_index<3 or section=='Clients' else -a['ap_reported_busy_percent'] if section=='Channel load' else a.get('snr_db',0)),identity_key(a)))
        evidence=[]
        if section=='Trend':
            if trends:
                t=trends[source_index%len(trends)];identity=t.get('identity',[]);metric=t['metric']
                freq=next((x for x in identity if isinstance(x,(int,float)) and x>=2400),None)
                unit='dBm' if metric in ('AP signal','client signal','noise') else 'dB' if metric=='SNR' else '%'
                threshold=t.get('change_threshold',5 if unit in ('dBm','dB') else 10 if metric=='retries' else 15)
                rule={'AP signal':'signal below -75 dBm','client signal':'signal below -75 dBm','SNR':'SNR below 20 dB','retries':'retry flags >=20% (at least 100 data frames)','AP load':'AP utilisation >=70%','channel load':'survey utilisation >=70%'}.get(metric,'no warning threshold')
                evidence=[f'Trend {source_index%len(trends)+1}/{len(trends)}',
                          'Assessment: '+trend_words(t['status'],metric),
                          'Source: '+source_name(t.get('source')),
                          ('Client MAC: '+str(identity[1]) if metric=='client signal' and len(identity)>1 else 'Metric: '+metric),
                          ('BSSID: ' if metric not in ('channel load','noise') else 'Device radio: ')+str(identity[0] if identity else 'unknown'),
                          f'Channel {channel(freq)} | {freq} MHz',
                          'EVIDENCE',
                          f"{t.get('samples','?')} readings spanning {t['span_seconds']}s",
                          f"Early median {fmt(t.get('early_median'))} -> late median {fmt(t.get('late_median'))} {unit}",
                          f"Change {t['delta']:+g} {'percentage points' if unit=='%' else 'dB'}",
                          f"Warning readings: {t.get('warning_readings','?')}/{t.get('samples','?')}",
                          'DECISION RULE',
                          f'Worsening/improving: median change of at least {threshold:g} '+('percentage points' if unit=='%' else 'dB'),
                          ('Higher is better.' if metric in ('AP signal','client signal','SNR') else 'Lower is better.'),
                          'Persistent: >=60s span, latest reading in warning, >=80% of readings in warning.',
                          'Warning condition: '+rule,
                          'Stable: change below threshold and persistence rule not met.',
                          'RECENT READINGS (age, value; last 3)']
                evidence += [f"{r['age_seconds']:g}s ago: {r['value']:g} {unit}"+(' WARNING' if r.get('warning') else '') for r in t.get('readings',[])[-3:]]
                evidence += ['CONTEXT','Same source/channel; rolling windows overlap. Trend span is not continuous listening or proof of cause.']
            else:
                evidence=['COLLECTING: no qualified trend yet.', 'Need 3 fresh same-source/channel readings spanning at least 30s.',
                          'New evidence is sampled at least 10s apart; redraws do not count.',
                          'Channel hopping may delay comparable observations.']
        elif section=='AP inventory':
            pages=[(key,observations,a) for key,observations in sorted(inventory.items()) for a in sorted(observations,key=lambda a:(a['frequency'],a['bssid']))]
            if pages:
                key,observations,a=pages[source_index%len(pages)]
                frequencies=sorted({x['frequency'] for x in observations})
                bands=sorted({band(f) or 'unknown band' for f in frequencies})
                evidence=[f'Entry {source_index%len(pages)+1}/{len(pages)}',
                          'Physical AP: '+(a.get('physical_ap_name') or key[1] if key[0]=='confirmed' else 'unverified; this BSSID is not a physical count'),
                          'Identity: '+('confirmed inventory mapping' if key[0]=='confirmed' else 'no confirmed mapping supplied'),
                          'Observed bands: '+', '.join(bands),
                          'Observed channels: '+', '.join(str(channel(f)) for f in frequencies),
                          f"Observed BSSIDs: {len({x['bssid'] for x in observations})}",
                          'Bands/channels not observed may still be provided by this AP.',
                          'BSSID: '+a['bssid'], 'SSID: '+source_name(a.get('ssid')),
                          f"Band: {band(a['frequency'])} | CH {channel(a['frequency'])} | {a['frequency']} MHz",
                          'AP advertised width: '+(a.get('advertised_width') or 'unknown'),
                          'Radio identity: '+(a.get('physical_radio') or 'not mapped'),
                          f"Last captured frame: {fmt(a.get('last_seen_seconds'),'s')} ago",
                          f"Beacons: {a.get('beacons',0)} | last {fmt(a.get('beacon_last_seen_seconds'),'s')} ago",
                          f"Signal: {fmt(a.get('signal_dbm'),' dBm')} at this device | {a.get('signal_samples',0)} samples"]
                for c in activity.get('channel_coverage',[]):
                    if c['frequency']==a['frequency']:
                        evidence.append(f"{c['radio']}: listened {c['listened_seconds']:g}s / {c['window_seconds']:g}s ({c['listening_share_percent']:g}%); capture width {fmt(c.get('capture_width_mhz'),' MHz')}")
                evidence.append('Listening share is observation time, not channel utilisation.')
            else: evidence=['No BSSIDs captured yet. Inventory updates live as frames arrive.']
        elif section=='Clients' and client_sig:
            by_client={}
            for c in client_sig: by_client.setdefault(c['client'],[]).append(c)
            sources=sorted(by_client,key=lambda mac:(min(c['signal_dbm'] for c in by_client[mac]),mac))
            mac=sources[source_index%len(sources)]
            observations=sorted(by_client[mac],key=lambda c:(c.get('signal_last_seen_seconds',999),c.get('frequency',0),c.get('ap','')))
            worst=min(observations,key=lambda c:c['signal_dbm'])
            evidence=[f'Client {source_index%len(sources)+1}/{len(sources)}',
                      'Assessment: '+signal_assessment(worst['signal_dbm'])+' (weakest observation)',
                      'Client MAC: '+mac,
                      f'{len(observations)} BSSID/channel observations within {measurement_window:g}s',
                      'Channels are capture frequencies; movement/roaming is unconfirmed.',
                      'CHANNEL OBSERVATIONS (newest signal first)']
            for c in observations[:5]:
                ap=next((a for a in aps if a['bssid']==c.get('ap') and a['frequency']==c.get('frequency')), {})
                evidence.extend([f"BSSID: {c.get('ap','unknown')} | CH {channel(c.get('frequency'))} | {band(c.get('frequency',0))}",
                                 f"{source_name(ap.get('ssid'))} | width {ap.get('advertised_width') or 'unknown'}",
                                 f"{signal_assessment(c['signal_dbm'])} | n={c.get('signal_samples',0)} | age {fmt(c.get('signal_last_seen_seconds'),'s')}"])
            coverage=[x for x in activity.get('channel_coverage',[]) if x['frequency']==worst.get('frequency')]
            for c in coverage[:1]: evidence.append(f"Weakest channel: listened {c['listened_seconds']:g}s / {c['window_seconds']:g}s ({c['listening_share_percent']:g}%)")
            if len(observations)>5: evidence.append(f'{len(observations)-5} additional observations in the saved report.')
            evidence.extend(['CONTEXT', 'Weak threshold: below -75 dBm. Signal is received here, not measured at the AP.',
                             'Same MAC groups observed addresses; physical identity is unverified.'])
        elif groups:
            a=groups[source_index%len(groups)]; frequency=a['frequency']; bssid=a.get('bssid',a.get('ap'))
            ap=next((x for x in aps if x['bssid']==bssid and x['frequency']==frequency),{})
            assessment=signal_assessment(a.get('signal_dbm')) if selected_index<3 else (f"{'WARNING' if a['recent_retry_percent']>=20 else 'OBSERVED OK'}: {a['recent_retry_percent']:g}% retransmission flags" if section=='Retries' else f"{'WARNING' if a['ap_reported_busy_percent']>=70 else 'OBSERVED OK'}: {a['ap_reported_busy_percent']:g}% AP utilisation" if section=='Channel load' else f"{'LOW' if a['snr_db']<20 else 'OBSERVED OK'}: {a['snr_db']:g} dB SNR")
            evidence=[f'Source {source_index%len(groups)+1}/{len(groups)}',
                      'Assessment: '+assessment,
                      'Network: '+source_name(a.get('ssid',ap.get('ssid'))),
                      'BSSID: '+bssid]
            if section=='Clients': evidence.append('Client MAC: '+a['client'])
            evidence.extend([f"Channel {channel(frequency)} | {frequency} MHz | AP advertised width: {ap.get('advertised_width') or 'unknown'}",
                             f"Beacons captured: {ap.get('beacons',0)} total | last {fmt(ap.get('beacon_last_seen_seconds'),'s')} ago"])
            coverage=[x for x in activity.get('channel_coverage',[]) if x['frequency']==frequency]
            for c in coverage:
                evidence.extend([f"{c['radio']} capture width: {fmt(c.get('capture_width_mhz'),' MHz')}",
                                 f"Listened {c['listened_seconds']:g}s of {c['window_seconds']:g}s ({c['listening_share_percent']:g}%); {c['visits']} visits"])
            if not coverage: evidence.append('Capture width/listening duration: no channel observation available')
            if selected_index<3 or section=='Clients':
                evidence.extend([f"Signal mean {fmt(a.get('signal_dbm'),' dBm')} | samples {a.get('signal_samples',0)}",
                                 f"Range {fmt(a.get('min_dbm'),' dBm')} to {fmt(a.get('max_dbm'),' dBm')}",
                                 f"Last signal {fmt(a.get('signal_last_seen_seconds'),'s')} ago | window {measurement_window:g}s",
                                 'Weak threshold: below -75 dBm, measured at this device.',
                                 'This does not measure AP-to-client reception or prove a fault.',
                                 'Distance, walls, antenna position and capture limits may affect reception.'])
            elif section=='Retries':
                evidence.extend([f"{a['recent_retry_percent']:.1f}% of {a['recent_data_frames']} sampled data frames marked retransmitted",
                                 f"Last data {fmt(a.get('data_last_seen_seconds'),'s')} ago | window {measurement_window:g}s",
                                 'Warning threshold: >=20%, with at least 100 sampled data frames.',
                                 'Not packet loss; channel hopping may bias this sample.',
                                 'AP/channel group includes client-to-AP and AP-to-client traffic.',
                                 'Confirm transmitter/client with a fixed-channel capture.'])
            elif section=='Channel load': evidence.append(f"AP reports channel utilisation {a['ap_reported_busy_percent']:g}% (not this device's listening share)")
            elif section=='SNR': evidence.append(f"Signal-to-noise {a['snr_db']:g} dB | low threshold <20 dB")
            matching=[t for t in metric_trends if t.get('identity',[])[:3 if section=='Clients' else 2]==([bssid,a['client'],frequency] if section=='Clients' else [bssid,frequency])]
            for t in matching[:1]:
                unit='percentage points' if t['metric'] in ('retries','AP load','channel load') else 'dB'
                evidence.extend([trend_words(t['status'],t['metric']),f"{t.get('samples','?')} trend readings spanning {t['span_seconds']}s; change {t['delta']:+g} {unit}",
                                 'Trend span is not continuous listening time.'])
        elif section in ('Noise','Channel load') and surveys:
            available=[s for s in surveys if s.get('noise_dbm' if section=='Noise' else 'busy_percent') is not None]
            latest={}
            for s in sorted(available,key=lambda x:x.get('time',0)): latest[(s.get('radio','?'),s.get('frequency'))]=s
            sources=sorted(latest.values(),key=lambda x:(x.get('radio','?'),x.get('frequency') or 0))
            if sources:
                s=sources[source_index%len(sources)]
                evidence=[f'Source {source_index%len(sources)+1}/{len(sources)}',
                          f"Device radio: {s.get('radio','?')} | CH {channel(s.get('frequency'))}",
                          f"Survey listening interval: {fmt(s.get('observed_seconds'),'s')}",
                          f"Noise: {fmt(s.get('noise_dbm'),' dBm')}" if section=='Noise' else f"Channel utilisation: {fmt(s.get('busy_percent'),'%')}",
                          'Driver survey measured at this device, not at an AP.',
                          'Channel utilisation is not the fraction of time we listened.']
            else: evidence=details[selected_index][:3]
        elif section=='Measurements':
            reasons={'AP signal':'no recent AP-origin signal reading','clients':'no recent client-origin signal reading',
                     'retries':'need 100 data frames per BSSID/channel','noise':'adapter/packets did not provide noise',
                     'load':'no valid survey or AP utilisation report','SNR':'requires signal and noise in the same frame'}
            evidence=['Measurement availability, not a health score.']
            evidence += [label+': '+('available' if available else 'unavailable - '+reasons[label]) for label,available in checks if available or label not in ('noise','SNR')]
            evidence += ['Missing data is a measurement limitation, not evidence of a fault.',
                         f'Physical APs observed: {confirmed} confirmed; {unmapped} unmapped BSSIDs. Open AP inventory for details.',
                         'BSSID count = distinct observed network MAC addresses, not SSIDs or physical APs.',
                         f"Distinct captured network names: {len({a['ssid'] for a in aps if a.get('ssid') and a['ssid']!='Unknown/hidden'})} (unnamed BSSIDs excluded)",
                         'Client count = distinct client MACs seen since capture started.',
                         'Signal counts = recent BSSID/client/channel observations.',
                         'Listening share = time tuned to a channel / observation window.',
                         'Listening share is not channel utilisation or packet airtime.']
        else:
            evidence=details[selected_index] or ['No qualifying source measurements yet.']
        evidence=[item.replace('BH receiver','this device').replace('at BH','at this device').replace('BH surveys','device surveys').replace('BH survey','device survey').replace('BH.','this device.') for item in evidence]
        rows=[rows[0], 'DETAILS: '+section, *[line for item in evidence for line in textwrap.wrap(item,width=max(1,width))]]
    else:
        # Show a concrete worst source alongside each warning category.
        examples=[]
        if weak:
            a=min(weak,key=lambda a:a['signal_dbm']); examples.append(f"Weak BSSID {a['bssid']} CH {channel(a['frequency'])}: {a['signal_dbm']:g} dBm")
        if weak_clients:
            c=min(weak_clients,key=lambda c:c['signal_dbm']); examples.append(f"Weak client {c['client']} CH {channel(c.get('frequency'))}: {c['signal_dbm']:g} dBm")
        if retries:
            a=max(retries,key=lambda a:a['recent_retry_percent']); examples.append(f"Retry group {a['bssid']} CH {channel(a['frequency'])}: {a['recent_retry_percent']:g}% / {a['recent_data_frames']} frames")
        rows[3:3]=examples
        if 5 not in visible: rows=[r for r in rows if not r.removeprefix('> ').startswith('Noise:')]
        if 7 not in visible: rows=[r for r in rows if not r.removeprefix('> ').startswith('SNR:')]
    if d.get('notes'): rows += ['NOTE: '+d['notes'][-1]]
    if task.get('stopping'): rows[0]='STOPPING: restoring test adapters / saving report'
    # Always reserve bottom space for selected details. No history is rendered.
    rows=[r[:max(1,width)] for r in rows]
    if len(rows)>capacity:
        rows=rows[:capacity]
    return rows

def colour(text, base):
    if text.startswith('> '): return text
    neutral='\x1b[0m'
    if text.startswith(('DETAILS:', 'CHANNEL OBSERVATIONS', 'CONTEXT', 'EVIDENCE', 'DECISION RULE', 'RECENT READINGS', 'RECEPTION AT', 'DELIVERY FINDINGS', 'DIRECTIONAL RETRIES', 'LISTENING EVIDENCE', 'INTERPRETATION', 'LIVE OVERVIEW', 'DETECTED NETWORKS', 'TRENDS', 'CLIENTS', 'NETWORK:', 'CLIENT:', 'CLIENT <', 'PHYSICAL AP INVENTORY', 'PHYSICAL AP DISCOVERY', 'PHYSICAL AP:', 'IDENTITY EVIDENCE', 'ADVERTISED DEVICE:', 'UNRESOLVED BSSID', 'CONFIRM ONE PHYSICAL AP', 'SELECT BSSIDs', 'CHANNEL MEASUREMENTS', 'TREND EVIDENCE', 'TRAFFIC', 'ENTRIES ')):
        return '\x1b[1;36m'+text+neutral+base
    prefix=text.split(':',1)[0]+':'
    if text.startswith(('BSSID:', 'Client MAC:', 'Network:', 'SSID:', 'Physical AP:', 'Radio identity:', 'Source:')):
        return '\x1b[1;36m'+prefix+neutral+text[len(prefix):]+base
    if text.startswith(('Signal mean', 'Range ', 'Last signal', 'Channel ', 'AP advertised width:', 'Beacons', 'Listened ', 'Weakest channel:', 'Observed bands:', 'Observed channels:')):
        return '\x1b[0;36m'+text+neutral+base
    if text.startswith(('Weak threshold:', 'Warning threshold:', 'This does not', 'Not packet loss', 'Distance,', 'Channels are capture', 'Same MAC', 'Trend span', 'Listening share is')):
        return '\x1b[0;33m'+text+neutral+base
    if text.startswith('    '): return neutral+'\x1b[3m'+text+'\x1b[23m'+base
    # Apply colour to status tokens only; labels, values and explanations stay neutral.
    codes={word:code for words,code in (
        ('FAILED WARNING LOW WEAK WORSENING','1;31'),('UNSUPPORTED','1;35'),
        ('UNAVAILABLE','1;34'),('UNVERIFIED CHECK LIMITED MARGINAL MIXED STOPPING COLLECTING WAITING UNKNOWN STALE PERSISTENT QUIET','1;33'),
        ('STRONG IMPROVING CONFIRMED','1;32'),('RUNNING LISTENING RECEIVING STABLE','1;36')) for word in words.split()}
    codes.update({'OBSERVED OK':'1;32','SIGNAL OK':'1;32','No warnings in available measurements':'1;32','Attention':'1;33','Insufficient data':'1;33','unchanged':'1;36','worsening':'1;31','improving':'1;32','remains weak':'1;33'})
    pattern=r'\b(?:'+ '|'.join(re.escape(word) for word in sorted(codes,key=len,reverse=True))+r')\b'
    return neutral+re.sub(pattern,lambda match:'\x1b['+codes[match[0]]+'m'+match[0]+neutral,text)+base
# CLOVER_REPORT_COLOUR_V2
_original_colour=colour
def colour(text,base=''):
    # Only trusted formatting is generated here; observed text stays printable.
    text=''.join(c if c.isprintable() else ' ' for c in str(text))
    if text.startswith('> '):return '\x1b[1;36m'+text+'\x1b[0m'+base
    if text.startswith('Nav:'):return '\x1b[36m'+text+'\x1b[0m'+base
    codes={'Strong':'1;32','Marginal':'1;33','Weak':'1;31','Elevated':'1;31','Below threshold':'1;32','Limited':'1;33','Receiving':'36','Capture error':'1;31','Estimated':'33','Verified':'32','unavailable':'97','not measured':'97','No recent signal':'97','No signal samples':'97','Old signal':'97','Not assessed':'97','STALE REPORT':'33'}
    pattern=r'\b(?:'+'|'.join(re.escape(x) for x in sorted(codes,key=len,reverse=True))+r')\b'
    if any(x in text for x in codes):return re.sub(pattern,lambda m:'\x1b['+codes[m[0]]+'m'+m[0]+'\x1b[0m'+base,text)+base
    return _original_colour(text,base)

# CLOVERKIT_REPORT_READABILITY_V1
def colour(text,base=''):
    text=''.join(c if c.isprintable() else ' ' for c in str(text))
    reset='\x1b[0m';white='\x1b[97m';cyan='\x1b[36m';grey='\x1b[97m'
    if text.startswith('> '):return '\x1b[1;36m'+text+reset+base
    if text.startswith('Nav:'):return cyan+text+reset+base
    headings=('LOCAL RECEIVER MEASUREMENTS','AP-REPORTED UTILISATION','CHANNEL SURVEY','CAPTURE STATUS','CAPTURE LIMITATIONS','LINK EVIDENCE','LINK MEASUREMENT DETAILS','RECEPTION HERE','RETRY FLAGS','LISTENING COVERAGE','ROAMING TIMELINE','CHANNEL MEASUREMENTS','RETRY EVIDENCE','LIMITS','SIGNAL RECEIVED HERE','OBSERVED TOPOLOGY','WIRELESS DIAGNOSIS','SITE SURVEY')
    if text in headings or text.startswith(('NODE:','BSSID:','CLIENT:','NETWORK:','Entries','Evidence ·')):
        return '\x1b[1;36m'+text+reset+base
    muted=('RSSI is measured','Retry percentage uses','Bytes are captured','Noise/busy fields','Channel hopping','Heuristic thresholds','No packet payload','Configured 20MHz','SSID/BSSID','SNR =','Missing measurements','No channel-survey','Missing capability','Only listened channels','No reassociation','No channel measurements','Captured attempts','Assessment needs','Hopping and','Quiet channels','Measurements below')
    if text.startswith(muted):return grey+text+reset+base
    # Identity labels are highlighted without treating advertised names as states.
    if text.startswith(('SSID:','Client:','BSSID:','Beacon AP name:','Name source:')):
        label,rest=text.split(':',1);return cyan+label+':'+white+rest+reset+base
    codes={'FAILED':'1;31','Capture error':'1;31','Elevated':'1;31','Weak':'1;31',
           'RUNNING':'1;32','Receiving':'1;32','Strong':'1;32','Below threshold':'1;32','Verified':'1;32',
           'STOPPING':'1;33','STALE REPORT':'1;33','Marginal':'1;33','Limited':'1;33','No recent frames':'1;33','No recent signal':'1;33','Old signal':'1;33','Estimated':'1;33',
           'unavailable':'97','not measured':'97','Not assessed':'97','No signal samples':'97','unknown':'97','age unknown':'97','not decoded':'97','No frames yet':'97'}
    token=r'\b(?:'+'|'.join(re.escape(k) for k in sorted(codes,key=len,reverse=True))+r')\b'
    label,sep,rest=text.partition(':')
    lead=('\x1b['+codes[label]+'m'+label+sep+white if label in codes else cyan+label+sep+white) if sep else white
    content=rest if sep else text
    # One combined pass avoids interpreting numbers inside ANSI formatting.
    pattern=token+r'|(?<![A-Za-z0-9])[-+]?\d+(?:\.\d+)?(?:%|\s+(?:dBm|dB|MHz|GHz|frames|samples)|s\b)'
    content=re.sub(pattern,lambda m:'\x1b['+codes.get(m[0],'1;36')+'m'+m[0]+white,content)
    return lead+content+reset+base
