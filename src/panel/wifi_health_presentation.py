"""Concise, evidence-led Advanced report pages shared by LCD and SSH."""
import time,textwrap

def age_text(age):
    if age is None:return 'age unknown'
    age=max(0,float(age))
    return f'{age:.0f}s ago' if age<60 else f'{age/60:.0f}m ago' if age<3600 else f'{age/3600:.1f}h ago'
def ago(row,signal=False):
    return row.get('signal_last_seen_seconds',row.get('last_seen_seconds')) if signal else row.get('last_seen_seconds')
def window(d):return d.get('measurement_window_seconds',60)
def level(number):return 'Weak' if number < -75 else 'Marginal' if number < -67 else 'Strong'
def signal_text(d,row,short=False):
    count=row.get('signal_samples',0);value=row.get('signal_dbm');age=ago(row,True)
    if age is not None and age>window(d):return ('Old signal: '+f'{value:g} dBm' if value is not None else 'No recent signal')+' · last '+age_text(age)
    if value is None or count==0:return 'No recent signal' if age is not None else 'No signal samples'
    if count<3:return f'{count}/3 signal samples · {value:g} dBm (limited)'
    return f'{level(value)}: {value:g} dBm'+(' · age unknown' if age is None else ' · '+age_text(age) if age>10 else '')
def qualified_signal(d,row):
    age=ago(row,True)
    return row.get('signal_samples',0)>=3 and row.get('signal_dbm') is not None and age is not None and age<=window(d)
def best(rows,d,signal=False):
    if not rows:return {}
    qualified=[r for r in rows if qualified_signal(d,r)] if signal else []
    return min(qualified or rows,key=lambda r:(ago(r,signal) is None,ago(r,signal) if ago(r,signal) is not None else 1e12))
def retry_state(d,direction):
    n=direction.get('frames',0);age=direction.get('last_seen_seconds');pct=direction.get('retry_percent')
    if not n:return 'Not assessed · no recent data frames'
    if age is not None and age>window(d):return 'Not assessed · old data · '+age_text(age)
    if n<100 or pct is None:return f'Limited · {n}/100 data frames'
    return f'{"Elevated" if pct>=20 else "Below threshold"}: {pct:g}% · {n} frames'
def assessed(d,c):
    return any(x.get('frames',0)>=100 and x.get('retry_percent') is not None and (x.get('last_seen_seconds') is None or x['last_seen_seconds']<=window(d)) for x in c.get('directions',{}).values())
def elevated(d,c):
    return any(x.get('frames',0)>=100 and (x.get('retry_percent') or 0)>=20 and (x.get('last_seen_seconds') is None or x['last_seen_seconds']<=window(d)) for x in c.get('directions',{}).values())

def install(ns):
    if ns.get('_plain_report_installed'):return
    ns['_plain_report_installed']=True
    original=ns['page_data'];E=ns['entry'];band=ns['band'];channel=ns['channel'];fmt=ns['fmt']
    groups_for=ns['device_groups'];names_for=ns['names_for'];scoped=ns['scoped'];ap_id=ns['ap_id']
    def unique(rows,field):return len({r.get(field) for r in rows if r.get(field)})
    def parent_group(aps,address):
        return next(((identity,rows) for identity,rows in groups_for(aps).items() if any(a['bssid']==address for a in rows)),(('unmapped',address),[]))
    def parent_label(identity):
        kind,name=identity
        return ('Verified AP: ' if kind=='confirmed' else 'Ungrouped BSSID: ' if kind=='unmapped' else 'Estimated parent AP: ')+name
    def group_reason(kind):
        return 'saved verified mapping' if kind=='confirmed' else 'advertised UUID' if kind=='advertised' else 'no grouping evidence' if kind=='unmapped' else 'advertised multi-link address' if kind=='advertised-mld' else 'MAC pattern'
    def coverage(d,aps):
        result=[]
        configured=[f for r in d.get('radios',{}).values() for f in r.get('channels',[])]
        for label in ('2.4 GHz','5 GHz','6 GHz'):
            rows=[a for a in aps if band(a.get('frequency',0))==label]
            current=[a for a in rows if qualified_signal(d,a)]
            if current:
                a=max(current,key=lambda a:a['signal_dbm']);result.append(f'{label}: best heard {signal_text(d,a)} · CH {channel(a["frequency"])}')
            elif configured and not any(band(f)==label for f in configured):result.append(label+': not scanned')
            elif rows:
                ages=[ago(a,True) for a in rows if ago(a,True) is not None]
                result.append(label+': no recent signal'+(' · last '+age_text(min(ages)) if ages else ' samples'))
            else:result.append(label+': no AP signal sampled yet')
        return result
    def radio_lines(d):
        rows=[]
        for name,r in d.get('radios',{}).items():
            error=r.get('error') or r.get('tune_error');age=r.get('last_frame_seconds')
            status='Capture error' if error else 'No frames yet' if not r.get('frames') else 'Receiving' if age is not None and age<=10 else 'No recent frames'
            rows.append(f'{name}: {r.get("band","band unknown")} · capture CH {channel(r.get("frequency"))} · {status}')
            rows.append(f'  {r.get("frames",0)} frames · last '+age_text(age))
            if error:rows.append(str(error))
        return rows
    def ap_rows(d,address):return [a for a in d.get('aps',[]) if a['bssid']==address]
    def capture_label(a,d):return f'{band(a.get("frequency",0)) or "Band unknown"} · capture CH {channel(a.get("frequency"))} · {signal_text(d,a)}'
    def context_links(d,kind,parent,scope):
        links=d.get('clients',[])
        if kind=='clients':return scoped(d,parent)[1]
        if kind=='network_clients':return scoped(d,parent)[1]
        if kind=='bssid_clients':return [c for c in links if c['ap']==parent]
        if kind=='ap_clients':return [c for c in links if (c['ap'],c['frequency'])==parent]
        return links
    def link_observation(d,key):
        address,mac=key[:2]
        rows=[c for c in d.get('clients',[]) if c['ap']==address and c['client']==mac and (len(key)==2 or c['frequency']==key[2])]
        c=best(rows,d)
        a=next((a for a in d.get('aps',[]) if c and ap_id(a)==(address,c['frequency'])),{})
        return c,a,rows
    def hearing(d,freq):
        rows=[]
        for item in d.get('activity',{}).get('channel_coverage',[]):
            if item.get('frequency')==freq:
                rows.append(f'{item.get("radio","Adapter")}: listened {item.get("listened_seconds",0):g}s / {item.get("window_seconds",window(d)):g}s · {item.get("listening_share_percent",0):g}%')
                rows.append('Adapter capture width: '+fmt(item.get('capture_width_mhz'),' MHz').replace('UNAVAILABLE','not reported'))
        return rows or ['Listening duration: not recorded for this channel']
    def noise_lines(d,a):
        rows=[]
        for name,r in d.get('radios',{}).items():
            if r.get('frequency')==a.get('frequency'):
                v=r.get('packet_noise_dbm')
                if v is not None:rows.append(f'Capture noise ({name}): {v:g} dBm · adapter/channel sample')
        if not rows:rows=['Capture noise: unavailable · no packet noise supplied']
        surveys=[x for x in d.get('channel_surveys',[]) if x.get('frequency')==a.get('frequency') and x.get('noise_dbm') is not None]
        if surveys:
            x=surveys[-1];rows.append(f'Driver survey noise: {x["noise_dbm"]:g} dBm · CH {channel(x["frequency"])}')
        else:rows.append('Driver survey noise: unavailable for this channel')
        v=a.get('snr_db')
        rows.append(f'AP SNR here: {v:g} dB · same-frame samples' if v is not None else 'AP SNR: unavailable · no paired signal/noise samples')
        return rows
    def bssid_page(d,address,a=None):
        observations=ap_rows(d,address);a=a or best(observations,d,True)
        if not a:return 'BSSID: '+address,['Observation no longer retained'],[]
        identity,_=parent_group(d.get('aps',[]),address)
        names=sorted({x['ssid'] for x in observations if x.get('ssid') and x['ssid']!='Unknown/hidden'})
        primary=a.get('advertised_primary_channel');width=a.get('advertised_width')
        body=['SSID: '+(', '.join(names) if names else 'not captured'),
              parent_label(identity)+' · '+group_reason(identity[0]),
              'AP radio: '+('CH '+str(primary) if primary is not None else 'primary channel not decoded')+' · '+(width or 'width not decoded'),
              'AP signal here: '+signal_text(d,a),
              'Last signal: '+age_text(ago(a,True)),
              f'{a.get("signal_samples",0)} signal samples · {a.get("beacons",0)} beacons since start']
        if a.get('ap_reported_busy_percent') is not None:body.append(f'AP-reported utilisation: {a["ap_reported_busy_percent"]:g}%')
        body += noise_lines(d,a)
        body.append(f'{len(observations)} capture channel observations · not separate AP radios')
        if ago(a,True) is not None and ago(a,True)>10:body=[line for line in body if not line.startswith('Last signal:')]
        items=[E('clients','Clients on this BSSID','bssid_clients',address),E('channels','Capture observations','bssid_channels',address),E('evidence','Signal / listening evidence','bssid_evidence',(address,a.get('frequency'))),E('related','Possible related APs','related',identity)]
        return 'BSSID: '+address,body,items
    def pages(task,nav):
        # Age retained snapshots without changing the scan's authoritative data.
        elapsed=max(0,time.monotonic()-task.get('finder',{}).get('received',time.monotonic()))
        if elapsed>2:
            original_data=ns['values'](task)
            def aged(row):
                result=dict(row)
                for field in ('last_seen_seconds','signal_last_seen_seconds','beacon_last_seen_seconds','device_identity_age_seconds','last_frame_seconds'):
                    if result.get(field) is not None:result[field]+=elapsed
                return result
            updated=dict(original_data)
            updated['aps']=[aged(a) for a in original_data.get('aps',[])]
            updated['clients']=[]
            for c in original_data.get('clients',[]):
                row=aged(c);row['directions']={k:aged(v) for k,v in c.get('directions',{}).items()};updated['clients'].append(row)
            updated['radios']={k:aged(v) for k,v in original_data.get('radios',{}).items()}
            task=dict(task,finder=dict(task.get('finder',{}),values=updated))
        d=ns['values'](task);f=nav['stack'][-1];page,key=f['page'],f.get('key')
        aps,clients=scoped(d,nav.get('scope'));allaps=d.get('aps',[]);allclients=d.get('clients',[])
        if page=='summary':
            named={a['ssid'] for a in aps if a.get('ssid') and a['ssid']!='Unknown/hidden'}
            named_addresses={a['bssid'] for a in aps if a.get('ssid') and a['ssid']!='Unknown/hidden'}
            unnamed={a['bssid'] for a in aps if a['bssid'] not in named_addresses}
            eligible=[c for c in clients if assessed(d,c)]
            body=['Scope: '+(ns['network_name'](nav['scope']) if nav.get('scope') else 'all observed'),f'{len(named)} named SSIDs · {len(unnamed)} SSID not captured',f'{unique(aps,"bssid")} BSSIDs · {unique(clients,"client")} client MACs since start','SIGNAL RECEIVED HERE',*coverage(d,aps),
                  'Retries: '+(f'{sum(elevated(d,c) for c in eligible)} elevated / {len(eligible)} assessed link observations' if eligible else 'not assessed · no links with enough data')]
            if clients:body.append(f'{len(clients)-len(eligible)} link observations: insufficient recent data')
            body+=radio_lines(d)
            if d.get('notes'):body.append('Capture note: '+str(d['notes'][-1]))
            items=[E('networks','Networks','networks'),E('clients','Clients','clients'),E('findings','Retry findings','findings'),E('trends','Trends','trends'),E('physical','Physical APs','physical'),E('traffic','Traffic','traffic'),E('measurements','Channel measurements','measurements'),E('capture','Capture status / limits','capture_status')]
            if nav.get('scope'):items.insert(0,E('clear','Show all networks','clear_scope'))
            return 'OVERVIEW',body,items
        if page in ('networks','unnamed'):
            names=sorted({a['ssid'] for a in allaps if a.get('ssid') and a['ssid']!='Unknown/hidden'})
            named_addresses={a['bssid'] for a in allaps if a.get('ssid') and a['ssid']!='Unknown/hidden'}
            unnamed=sorted({a['bssid'] for a in allaps if a['bssid'] not in named_addresses})
            if page=='unnamed':return 'SSID NOT CAPTURED',[f'{len(unnamed)} observed addresses · hidden or name not sampled'],[E(x,x,'bssid',x) for x in unnamed]
            entries=[E(('ssid',name),name+f' · {unique([a for a in allaps if a.get("ssid")==name],"bssid")} BSSID'+('' if unique([a for a in allaps if a.get('ssid')==name],'bssid')==1 else 's'),'network',('ssid',name)) for name in names]
            if unnamed:entries.append(E('unnamed',f'SSID not captured · {len(unnamed)} BSSIDs','unnamed'))
            return 'NETWORKS',[f'{len(names)} named SSIDs · {len(unnamed)} unnamed BSSIDs'],entries
        if page=='network':
            group,links=scoped(d,key);addresses=sorted({a['bssid'] for a in group})
            body=[f'{len(addresses)} BSSIDs · {unique(links,"client")} clients observed',*coverage(d,group)]
            entries=[E('focus','Use as overview scope','set_scope',key),E('clients','Clients on this network','network_clients',key)]
            for address in addresses:
                rows=[a for a in group if a['bssid']==address];a=best(rows,d,True)
                entries.append(E(address,address+' · '+capture_label(a,d),'bssid',address))
            return 'NETWORK: '+ns['network_name'](key),body,entries
        if page=='bssid':return bssid_page(d,key)
        if page=='ap':
            a=next((a for a in allaps if ap_id(a)==key),None)
            return bssid_page(d,key[0],a)
        if page=='bssid_channels':
            rows=ap_rows(d,key)
            return 'CAPTURE OBSERVATIONS: '+key,['One BSSID · frequencies heard here, not separate AP radios'],[E(ap_id(a),capture_label(a,d),'ap',ap_id(a)) for a in sorted(rows,key=lambda a:a['frequency'])]
        if page=='bssid_evidence':
            address,freq=key;a=next((a for a in allaps if ap_id(a)==key),{})
            return 'BSSID EVIDENCE: '+address,[capture_label(a,d),f'Signal range: {fmt(a.get("min_dbm")," dBm")} to {fmt(a.get("max_dbm")," dBm")}',f'Signal samples: {a.get("signal_samples",0)} · last '+age_text(ago(a,True)),f'Beacons since start: {a.get("beacons",0)} · last '+age_text(a.get('beacon_last_seen_seconds')),*noise_lines(d,a),*hearing(d,freq),'Reception is measured at Cloverkit, not at a client.'],[]
        if page in ('clients','network_clients','ap_clients','bssid_clients'):
            parent=nav.get('scope') if page=='clients' else key
            links=context_links(d,page,parent,nav.get('scope'))
            title='CLIENTS' if page=='clients' else 'CLIENTS ON NETWORK: '+ns['network_name'](key) if page=='network_clients' else 'CLIENTS ON BSSID: '+(key if page=='bssid_clients' else key[0])
            entries=[]
            for mac in sorted({c['client'] for c in links}):
                rows=[c for c in links if c['client']==mac];a=best(rows,d)
                entries.append(E(mac,mac+f' · {unique(rows,"ap")} BSSID links · last '+age_text(ago(a)),'client',(mac,(page,parent))))
            return title,[f'{unique(links,"client")} observed client MACs · last-seen retained'],entries
        if page=='client':
            mac,(kind,parent)=key;links=[c for c in context_links(d,kind,parent,nav.get('scope')) if c['client']==mac]
            c=best(links,d,True)
            body=['Client signal here: '+signal_text(d,c),'Observed links · addresses are not authenticated identities']
            entries=[]
            for address in sorted({c['ap'] for c in links}):
                rows=[c for c in links if c['ap']==address];c=best(rows,d)
                status='Elevated retries' if any(elevated(d,c) for c in rows) else 'Retries below threshold' if any(assessed(d,c) for c in rows) else 'Retries not assessed'
                entries.append(E((address,mac),address+' · '+status,'link',(address,mac)))
            return 'CLIENT: '+mac,body,entries
        if page in ('link','link_evidence','link_evidence_details','link_observations'):
            c,a,rows=link_observation(d,key)
            if not c:return 'LINK: CLIENT ↔ BSSID',['Link observation no longer retained'],[]
            if page=='link_observations':return 'LINK CAPTURE OBSERVATIONS',[c['client']+' ↔ '+c['ap'],'Channel changes alone do not confirm roaming.'],[E((r['ap'],r['client'],r['frequency']),f'Capture CH {channel(r["frequency"])} · last '+age_text(ago(r)),'link',(r['ap'],r['client'],r['frequency'])) for r in sorted(rows,key=lambda r:r['frequency'])]
            body=['Client: '+c['client'],'BSSID: '+c['ap'],'SSID: '+ns['source_name'](a.get('ssid')).replace('Name not captured','not captured'),
                  'AP radio: '+('CH '+str(a['advertised_primary_channel']) if a.get('advertised_primary_channel') is not None else 'primary channel not decoded')+' · '+(a.get('advertised_width') or 'width not decoded'),
                  'AP signal here: '+signal_text(d,a),'Client signal here: '+signal_text(d,c),
                  'Client → AP: '+retry_state(d,c.get('directions',{}).get('up',{})),
                  'AP → client: '+retry_state(d,c.get('directions',{}).get('down',{})),*hearing(d,c['frequency'])]
            if page in ('link_evidence','link_evidence_details'):
                body += [f'Window: last {window(d):g}s · capture CH {channel(c["frequency"])}',f'Client signal samples: {c.get("signal_samples",0)}','Last client signal: '+age_text(ago(c,True)),f'Range: {fmt(c.get("min_dbm")," dBm")} to {fmt(c.get("max_dbm")," dBm")}',
                         'RETRY EVIDENCE']
                for direction,label in [('up','Client → AP'),('down','AP → client')]:
                    x=c.get('directions',{}).get(direction,{})
                    body.append(f'{label}: {x.get("retry_frames",0)}/{x.get("frames",0)} retry-flagged data frames · last '+age_text(x.get('last_seen_seconds')))
                body+=['Assessment needs 100 data frames per direction; elevated at 20% retries.','Captured attempts, not end-to-end packet loss.','Hopping and 20 MHz capture can miss wider-channel traffic.']
                if page=='link_evidence_details':return 'LINK MEASUREMENT DETAILS',body,[]
                compact=body[:4]+['RECEPTION HERE',*body[4:6],'RETRY FLAGS',*body[6:8],'LISTENING COVERAGE',*hearing(d,c['frequency']),f'Window: last {window(d):g}s','Retry flags are captured attempts, not end-to-end packet loss.']
                return 'LINK EVIDENCE',compact,[E('details','Full measurement details','link_evidence_details',key)]
            entries=[E('evidence','Signal / retry evidence','link_evidence',key)]
            if len(rows)>1:entries.append(E('observations',f'Capture observations · {len(rows)} channels','link_observations',key))
            return 'LINK: CLIENT ↔ BSSID',body,entries
        if page=='findings':
            eligible=[c for c in clients if assessed(d,c)];high=[c for c in eligible if elevated(d,c)]
            body=[f'{len(high)} elevated / {len(eligible)} assessed link observations',f'{len(clients)-len(eligible)} observations: insufficient recent data','Elevated: ≥20% retries with ≥100 data frames per direction.']
            if not eligible:body.insert(0,'Retries not assessed · no links with enough data')
            elif not high:body.append('No elevated retries in assessed samples · not a delivery guarantee')
            return 'RETRY FINDINGS',body,[E(ns['link_id'](c),c['client']+' ↔ '+c['ap']+f' · capture CH {channel(c["frequency"])}','link',ns['link_id'](c)) for c in high]
        if page=='related':
            identity=tuple(key);groups=groups_for(allaps);source=groups.get(identity,[]);names=set(names_for(source))
            body=[parent_label(identity),'Shared SSIDs are context · groups remain separate'];entries=[]
            for other,rows in sorted(groups.items()):
                if other==identity:continue
                common=sorted(names & set(names_for(rows)))
                if len(common)>=2:
                    entries.append(E(other,other[1]+f' · {len(common)} shared SSIDs','relation',(identity,other)))
            if not entries:body.append('No groups share two captured SSIDs with this group')
            return 'POSSIBLE RELATED APs',body,entries
        if page=='relation':
            left,right=map(tuple,key);groups=groups_for(allaps);common=sorted(set(names_for(groups.get(left,[]))) & set(names_for(groups.get(right,[]))))
            return 'SHARED-SSID EVIDENCE',[parent_label(left),parent_label(right),f'{len(common)} shared captured SSIDs',*common,'Possible relation · not a hardware match','SSID names do not merge or rename either AP group'],[E('group','Open other AP group','physical_ap',right)]
        if page=='capture_status':return 'CAPTURE STATUS',radio_lines(d)+['Observation window: '+str(window(d))+'s','Quiet channels and hopping can produce gaps between received frames.','Measurements below show what each adapter actually supplied.'],[E('limits','Capture limitations / interpretation','capture_limits')]
        if page=='capture_limits':return 'CAPTURE LIMITATIONS',d.get('limits',[]) or ['No extra limitations recorded.'],[]
        title,body,items=original(task,nav)
        if page=='physical':
            title='PHYSICAL APs';body=[body[0],'Verified: saved mapping · Estimated: MAC pattern/advertised UUID','Ungrouped: no matching evidence']
            items=[dict(x,label=x['label'].replace('CONFIRMED','Verified').replace('ESTIMATED','Estimated').replace('STANDALONE','Ungrouped').replace('Optional: correct AP grouping','Correct grouping (optional)')) for x in items]
        elif page=='physical_ap':
            title=parent_label(key);kind,identity=key
            body=[group_reason(kind)+' · '+('verified mapping' if kind=='confirmed' else 'physical identity unverified'),*body[1:]]
            items.append(E('related','Possible related APs','related',key))
        elif page=='inventory_radio':title='AP RADIO / BAND';body.insert(0,'CH values below are capture observations')
        elif page=='trends' and not items:body=['Trend not assessed · need 3 readings over 30s','Same source/channel · newest reading within 60s']
        elif page=='traffic':title='CAPTURED TRAFFIC'
        elif page=='measurements' and not items and not body:body=['Driver supplied no noise/utilisation readings']
        replacements={'COLLECTING: no matching observations yet.':'No matching observations yet','UNAVAILABLE':'not measured','Name not captured':'SSID not captured','Source no longer retained in this capture.':'Observation no longer retained'}
        for old,new in replacements.items():body=[str(x).replace(old,new) for x in body]
        return title,body,items
    def breadcrumb(nav):
        labels={'summary':'Overview','networks':'Networks','physical':'Physical APs','findings':'Retry findings','trends':'Trends','traffic':'Traffic','measurements':'Channel measurements','capture_status':'Capture status','capture_limits':'Limitations','link_evidence_details':'Full details','bssid_clients':'Clients','network_clients':'Clients','clients':'Clients','ap_clients':'Clients','link':'Link','link_evidence':'Evidence','bssid_evidence':'Evidence','bssid_channels':'Captures','related':'Related APs'}
        result=[]
        for f in nav['stack']:
            page,key=f['page'],f.get('key')
            label=('BSSID: '+str(key)) if page=='bssid' else ('Client: '+str(key[0] if isinstance(key,(tuple,list)) else key)) if page=='client' else ns['network_name'](key) if page=='network' else labels.get(page,page.replace('_',' ').title())
            result.append(f.get("label",label))
        if len(result)>4:result=[result[0],'…',*result[-2:]]
        return ' > '.join(result)
    def report(task,nav,width=79,capacity=30):
        # Look up dynamically so the restricted remote viewer can filter edit actions.
        title,body,items=ns['page_data'](task,nav);d=ns['values'](task)
        age=max(0,time.monotonic()-task.get('finder',{}).get('received',time.monotonic()))
        state='STOPPING' if task.get('stopping') else 'FAILED' if task.get('state')=='FAILED' or d.get('state')=='FAILED' else 'FINAL' if task.get('state')!='RUNNING' else 'STALE REPORT' if age>10 else d.get('state','STARTING')
        width=max(20,width);capacity=max(5,capacity)
        wrap=lambda line:textwrap.wrap(str(line),width=width,break_long_words=True,break_on_hyphens=False) or ['']
        rows=wrap(f'{state} H25 · {d.get("frames_observed",0)} frames · report {age:.0f}s old')+['Nav: '+x for x in textwrap.wrap(breadcrumb(nav),width=max(15,width-5),break_long_words=True,break_on_hyphens=False)] +wrap(title)
        if state=='STALE REPORT':rows+=wrap('Live updates paused · measurements may be old')
        remaining=max(1,capacity-len(rows));frame=nav['stack'][-1];position=ns['chosen'](frame,items)
        content=[line for x in body for line in wrap(x)]
        if items:
            # Wrap full MACs and context rather than cutting off the selected status.
            reserve=min(max(1,remaining-1),max(3,remaining//3))
            position=position or 0
            start=min(frame.get('menu_start',0),position)
            parts=[wrap(('> ' if i==position else '  ')+x['label']) for i,x in enumerate(items)]
            while start<position and sum(len(x) for x in parts[start:position+1])>reserve:start+=1
            frame['menu_start']=start
            visible=[]
            for part in parts[start:]:
                if len(visible)+len(part)>reserve:break
                visible+=part
            if not visible:visible=parts[position][:reserve]
            allowance=max(0,remaining-len(visible)-1)
            rows+=content[:allowance]+[f'Entries · selected {(position or 0)+1}/{len(items)}']+visible
        else:
            offset=min(frame.get('offset',0),max(0,len(content)-remaining));frame['offset']=offset
            if len(content)>remaining:
                rows+=wrap(f'Evidence · lines {offset+1}-{min(len(content),offset+remaining-1)}/{len(content)}');remaining=max(1,capacity-len(rows))
            rows+=content[offset:offset+remaining]
        return rows[:capacity]
    ns['page_data']=pages;ns['report']=report
