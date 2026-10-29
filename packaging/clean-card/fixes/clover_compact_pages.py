"""Small-screen task results; preserve the specialised diagnostic views."""
import re
import textwrap

MAC=r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}'
AP=re.compile(r'^\s*(-?\d+)\s+(Excellent|Good|Fair|Weak|Poor|Very\s+weak)\s+(\d+)\s+(\S+)\s+(.*?)\s+('+MAC+r')\s*(.*)$',re.I)


def wrap(value,width):
    return textwrap.wrap(str(value),width=max(1,width),replace_whitespace=False,
                         break_long_words=True,break_on_hyphens=False) or ['']


def target_label(value):
    from pathlib import Path
    name=Path(str(value)).name
    name=name[:-3] if name.endswith('.sh') else name
    match=re.match(r'TARGET-AP-(?:\d+-)?(.*)-([0-9A-Fa-f]{12})$',name,re.I)
    if match: return match.group(1)
    match=re.match(r'TARGET-(?:HIDDEN|CLIENT)-([0-9A-Fa-f]{12})$',name,re.I)
    if match:
        mac=':'.join(match.group(1)[i:i+2] for i in range(0,12,2)).upper()
        return ('Hidden ' if 'HIDDEN' in name.upper() else '')+mac
    match=re.match(r'TARGET-(?:SSID|NET|SEC)-(.*)$',name,re.I)
    if match: return match.group(1)
    return name


def tight_packet_rows(rows):
    result=[]
    for row in rows:
        if row.startswith(('Centre after capture:', 'Wi-Fi Devices or Wi-Fi Targets.')): continue
        match=re.match(r'^(AP|STA|CLIENT)\s+('+MAC+r')\s*\|\s*(.*?)\s*\|\s*CH(\d+)\s*\|\s*(-?[\d.]+)\s*dBm$',row,re.I)
        if match:
            role,mac,name,channel,signal=match.groups()
            try: signal=f'{float(signal):g}'
            except ValueError: pass
            result.extend([f'{name} | Ch{channel} {signal}dBm',f'{role} {mac}'])
            continue
        vendor=re.match(r'^\s*(.*?)\s*\|\s*Access point\s*$',row)
        if vendor and result and re.match(r'^AP '+MAC+'$',result[-1]):
            result[-1]+=' | '+vendor.group(1).replace('Private/local MAC','Local MAC')
            continue
        result.append(row.replace('Private/local MAC','Local MAC'))
    return result


def output_rows(lines,width,basic=False):
    result=[]
    for raw in lines:
        line=re.sub(r'\x1b\[[0-9;?]*[A-Za-z]','',str(raw)).strip()
        if '/mnt/scripts/TARGET-' in line:
            line=re.sub(r'/mnt/scripts/TARGET-[^\s]+',lambda m:target_label(m.group(0)),line)
        if not line or re.fullmatch(r'[-= _+|]+',line): continue
        if basic:
            if re.match(r'^SIG\s+QUALITY\s+CH\s+BAND',line): continue
            match=AP.match(line)
            if match:
                signal,quality,channel,band,ssid,mac,security=match.groups()
                result.extend(wrap(ssid or '<hidden SSID>',width))
                result.extend(wrap(f'{signal} dBm | {quality} | Ch {channel} {band}',width))
                result.extend(wrap(f'{mac} {security}',width))
                continue
        result.extend(wrap(line,width))
    return result


# BASIC_AP_GROUPS_RESTORED_V1
def basic_records(task):
    # Use this task's emitted grouping, never a newer scan's shared manifest.
    groups=[];current=None
    for raw in task.get('lines',[]):
        line=re.sub(r'\x1b\[[0-9;?]*[A-Za-z]','',str(raw)).strip()
        start=re.match(r'^AP(?:/BSSID| EST)\s*:\s*(.*)$',line)
        if start:
            current={'id':start.group(1),'name':None,'members':[], 'radios':[], 'confidence':'--','signal':'--'}
            groups.append(current);continue
        if current is None: continue
        if line.startswith('AP Name'):
            name=line.split(':',1)[1].strip()
            current['name']=name if name.upper() not in ('CONFLICT','UNKNOWN','N/A') else None
        elif line.startswith('Confidence:'):
            current['confidence']=line.split(':',1)[1].strip()
        elif line.startswith('Signal'):
            match=re.search(r'(-?\d+)\s*dBm',line)
            if match: current['signal']=match.group(1)
        else:
            radio=re.match(r'^Radio \d+:\s*(\S+)\s+Channel\s+(\S+)',line)
            if radio:
                current['radios'].append((radio.group(1),radio.group(2)));continue
            member=re.match(r'^(.*?)\s+('+MAC+r')\s+(-?\d+)dBm$',line)
            if member: current['members'].append(member.group(1).strip())
    return groups


def basic_page(panel,task,capacity,cols):
    groups=basic_records(task);width=max(1,cols-1)
    # E/H describes the backend's heuristic grouping, not verified inventory.
    name_width=max(7,min(19,width-30))
    channels_width=max(7,min(15,width-name_width-18))
    rows=[]
    for group in groups:
        names=list(dict.fromkeys(x for x in group['members'] if x!='<hidden>'))
        name=group['name'] or (names[0] if len(names)==1 else 'Multi-SSID' if names else '<hidden>')
        # Distinguish otherwise identical estimates without another details menu.
        if not group['name'] and len(names)>1: name+=' '+group['id'].replace(':','')[-4:]
        channels='/'.join(band.replace('G','')+':'+ch for band,ch in dict.fromkeys(group['radios'])) or '--'
        confidence={'HIGH':'High','EST':'Est'}.get(group['confidence'],'--')
        rows.append(f"{short(name,name_width):<{name_width}} {group['signal']:>4} {short(channels,channels_width):<{channels_width}} {len(group['members']):>3} {confidence:<4}")
    if not groups:
        # Old/partial output must never be counted as physical APs.
        for raw in task.get('lines',[]):
            match=AP.match(str(raw))
            if match:
                signal,quality,ch,band,name,mac,security=match.groups()
                rows.append(f'{short(name or "<hidden>",19):<19} {signal:>4} {ch:>3} {band:<4}')
        label='BSSIDs; grouping unavailable'
        header='Network              dBm  Ch Band'
    else:
        counts=[int(m.group(1)) for raw in task.get('lines',[]) if (m:=re.match(r'^BSSIDs\s*:\s*(\d+)',str(raw).strip()))]
        total=counts[-1] if counts else sum(len(x['members']) for x in groups)
        label=f'{len(groups)} AP estimates | {total} BSSIDs'
        header=f'{"AP / Name":<{name_width}}  dBm {"GHz:Ch":<{channels_width}} BSS Conf'
    maximum=max(0,len(rows)-max(1,capacity-2))
    offset=getattr(panel,'_ap_offset',None)
    offset=maximum if offset is None else max(0,min(maximum,offset))
    panel._ap_current=offset;panel._ap_max=maximum
    prefix=f"{task.get('state','IDLE')} {task.get('elapsed',0):.0f}s | {label}"
    if not rows:
        errors=[str(x).strip() for x in task.get('lines',[]) if re.search(r'failed|error|denied|no external',str(x),re.I)]
        return [prefix]+(errors or ['No scan results reported'])
    return [prefix,header]+rows[offset:offset+max(1,capacity-2)]


def short(value,width):
    text=str(value).replace('\n',' ')
    return text if len(text)<=width else text[:max(0,width-1)]+'…'


def compact_security(task):
    data=task.get('finder') or {};summary=data.get('summary') or {}
    rows=[]
    if data.get('error'): rows.append('Error: '+str(data['error']))
    if not summary:
        import time
        p=data.get('progress') or {}
        rows.append('Stage: '+str(p.get('stage') or data.get('stage','Starting')))
        if p.get('target'): rows.append('Target: '+str(p['target']))
        if 'discovered' in p: rows.append(f"Devices found: {p['discovered']}")
        if p.get('total'): rows.append(f"This stage: {p.get('completed',0)}/{p['total']} devices")
        for host,stage in (p.get('active') or {}).items(): rows.append(f'{host} · {stage}')
        age=time.monotonic()-data.get('received',time.monotonic())
        if p: rows.append(f"Update {int(age)}s ago"+(' · no recent scanner update' if age>6 else ' · scan running'))
        if p.get('recent'): rows+=['Recent checks · provisional',*p['recent']]
        return rows

    rows += [f"{summary.get('target','--')} | LAN {summary.get('network_devices',0)} WiFi {summary.get('wifi_devices',0)} BLE {summary.get('ble_devices',0)}",
             ' '.join(f'{label}{summary.get("counts",{}).get(key,0)}' for key,label in [('CRITICAL','C'),('HIGH','H'),('MEDIUM','M'),('LOW','L'),('INFO','I')])]
    coverage=summary.get('coverage') or {}
    for name,label in (('wifi','Wi-Fi'),('ble','BLE'),('lan','LAN')):
        part=coverage.get(name,{})
        if part.get('status') not in (None,'checked','not requested'):
            rows.append(label+': '+str(part['status'])+(' · '+str(part['reason']) if part.get('reason') and name!='lan' else ''))
    for item in data.get('attention',[]):
        rows += [f"{item.get('ip') or item.get('address','--')} {item.get('top_severity','--')} {item.get('hostname') or ''}",
                 str(item.get('top_title') or item.get('top_code') or '--')]
        validation=item.get('top_validation') or {}
        if validation: rows.append(str(validation.get('status',''))+' · '+str(validation.get('test','')))
        if item.get('top_action'): rows.append('Action: '+str(item['top_action']))
    return rows or ['No findings reported']


# STATIONS_TABLE_V1
def station_rows(task,width):
    import time
    v=(task.get('finder') or {}).get('values') or {}
    records=v.get('rows') or []
    aps=list(dict.fromkeys(str(x.get('bssid')) for x in records if x.get('bssid')))
    labels={ap:f'A{i+1}' for i,ap in enumerate(aps)}
    remaining=v.get('remaining')
    rows=[f"{v.get('interface','--')} | {v.get('frames',0)} frames {v.get('rate',0)}/s",
          f"{v.get('stations',len(records))} clients | {v.get('aps',len(aps))} APs | Left {remaining if remaining is not None else '--'}s"]
    if task.get('state')=='RUNNING' and time.monotonic()-(task.get('finder') or {}).get('received',0)>3:
        rows.append('STALE: last received counts')
    rows.append(f"{'Client':<17} {'AP':<3} {'Ch':>3} {'dBm':>4} {'Frames':>6}")
    for item in records:
        rssi=item.get('rssi')
        rssi='--' if rssi is None else str(rssi)
        row=f"{short(item.get('station') or '--',17):<17} {short(labels.get(str(item.get('bssid')),'--'),3):<3} {short(item.get('channel') or '--',3):>3} {short(rssi,4):>4} {short(item.get('frames',0),6):>6}"
        rows.append(row)
    if not records: rows.append('No stations observed')
    if aps:
        rows.append('AP key')
        rows.extend(f'{labels[ap]:<3} {ap}' for ap in aps)
    rows.append('Busiest stations; hopping gives partial totals.')
    if v.get('dropped') or v.get('limited'):
        rows.append(f"Partial: drops {v.get('dropped',0)} limit {v.get('limited',False)}")
    if v.get('warning'): rows.append(brief_warning(v['warning']))
    for line in task.get('lines',[]):
        line=str(line).strip()
        if line.startswith(('Running as user "root"','Capturing on ')) or line.endswith('packets captured'): continue
        if re.search(r'error|failed|warning|denied|not found|no such|dropped',line,re.I):
            if keep_repeats or line not in rows: rows.append(line)
    return rows

def brief_warning(value):
    value=str(value)
    if value.startswith('No frames received from TShark'): return 'No frames received—check adapter/channel.'
    if value.startswith('Frames received, but no addressed'): return 'Frames seen; no AP/client pairs observed.'
    return 'Warning: '+value


def meaningful_diagnostics(lines):
    return [str(x) for x in lines if not str(x).startswith(('Running as user \"root\"','Capturing on ')) and not re.fullmatch(r'\d+ packets captured',str(x).strip())]


def count_rows(label,values,width):
    result=[];line=label+': '
    for key,value in values.items():
        part=f'{key} {value}'
        if len(line)+len(part)+3>width and line!=label+': ':
            result.append(line);line='  '+part
        else: line+=(' | ' if not line.endswith(': ') else '')+part
    if line: result.append(line)
    return result


def compact_packet(task,width,original):
    v=(task.get('finder') or {}).get('values') or {}
    if v.get('mode')=='stations': return station_rows(task,width)
    if v.get('mode') not in ('peers','pair'): return clean_logs(original(task,width=width),task.get('state'),False)
    rows=[f"{v.get('interface','--')} | {v.get('frames',0)} frames {v.get('rate',0)}/s",
          f"{len(v.get('aps',[]))} APs | {len(v.get('rows',[]))} pairs"+(f" | Left {v.get('remaining','--')}s" if task.get('state')=='RUNNING' else '')]
    if task.get('state')=='RUNNING':
        import time
        if time.monotonic()-(task.get('finder') or {}).get('received',0)>3: rows.append('STALE: last received counts')
    if v.get('warning'): rows.append(brief_warning(v['warning']))
    for field,label in [('classes','Classes'),('types','Types'),('channels','Channels')]:
        if v.get(field): rows.extend(count_rows(label,v[field],width))
    name_width=max(7,min(20,max((len(x.get('ssid') or '<hidden>') for x in v.get('aps',[])),default=7)))
    if v.get('aps'): rows.append(f"{'Network':<{name_width}}  Ch  dBm")
    for ap in v.get('aps',[]):
        signal=ap.get('rssi');signal='--' if signal is None else f'{float(signal):g}'
        rows.append(f"{short(ap.get('ssid') or '<hidden>',name_width):<{name_width}} {str(ap.get('channel','--')):>3} {signal:>4}")
    pairs=v.get('rows',[]) if v.get('mode')=='peers' else [v]
    for item in pairs:
        rows += [f"AP {item.get('bssid','--')} Ch{item.get('channel','--')}",f"Client {item.get('station','--')}"]
        for label,key in [('AP→C','ap_to_client'),('C→AP','client_to_ap')]:
            d=item.get('directions',{}).get(key,{})
            retry=d.get('retry_percent')
            if retry is None and d.get('retry_known'): retry=round(d.get('retries',0)*100/d['retry_known'],1)
            rssi=d.get('rssi') if d.get('rssi') is not None else '--'
            rows += [f"{label} {d.get('frames',0)}f {d.get('bytes',0)}B | Retry {retry if retry is not None else '--'}% | {rssi}dBm"]
            avg=d.get('average_mbps',round(d.get('data_bytes',0)*8/max(1,v.get('elapsed',1))/1e6,3))
            rows.append(f"Captured avg {avg}Mbps | PHY "+(', '.join(f'{r}({n})' for r,n in d.get('phy',{}).items()) or '--'))
            if d.get('types'): rows.append('Types: '+' '.join(f'{k}:{n}' for k,n in d['types'].items()))
            if d.get('missing_lengths'): rows.append('Warning: byte totals incomplete')
    rows.append('Hopping: partial totals; Mbps is captured traffic.')
    if v.get('dropped') or v.get('limited'): rows.append(f"Partial: drops {v.get('dropped',0)} limit {v.get('limited',False)}")
    rows.extend(meaningful_diagnostics(v.get('diagnostics') or []))
    return rows


def clean_logs(lines,state,basic=False,keep_repeats=False):
    rows=[];progress=[]
    for raw in lines:
        line=re.sub(r'\x1b\[[0-9;?]*[A-Za-z]','',str(raw)).strip()
        if not line or re.fullmatch(r'[-= _+|]+',line): continue
        if re.search(r'(Scanning|Analysing|Analyzing).*\[',line):
            if state=='RUNNING': progress=[re.sub(r'\[.*?\]','',line).strip()]
            continue
        if line.startswith(('Starting...', 'STATE ', 'Stage: COMPLETE','TARGET WRAP:', 'Temporary captures deleted.', 'Nothing retained.', 'FINAL RESULTS', 'COMPLETE (exit 0)', 'Done', 'RUN TARGET:', 'DEVICE WATCH', '802.11 BEACON ANALYSIS')): continue
        if line in ('DETECTED','BACKGROUND'): continue
        if line.startswith(('AP NAME','BSSID','CH  RSSI')): continue
        line=re.sub(r'/mnt/scripts/TARGET-[^\s]+',lambda m:target_label(m.group(0)),line)
        if line.startswith('TARGET-'): line=target_label(line)
        line=line.replace('VERY STRONG','').replace('Passive observation only.','Passive; identities may be inferred.')
        beacon=re.fullmatch(r'\s*(.*?)('+MAC+r')\s+(.+?)\s+(\d+)\s+(-?\d+)\s*dBm\s+Wi-?Fi\s*([4-7])\s*(.*?)\s*',line,re.I)
        if beacon:
            prefix,mac,name,ch,signal,generation,load=beacon.groups()
            line=f'{short(name,24):<24} {ch:>3} {signal:>4} WiFi{generation} {load}'
        if line not in rows: rows.append(line)
    return progress+rows


def install(Panel,structured_kinds,namespace=None):
    if namespace is not None:
        old_name=namespace.get('function_name')
        if old_name:
            def name(path):
                return target_label(path) if str(path).split('/')[-1].startswith('TARGET-') else old_name(path)
            namespace['function_name']=name
        old_packet=namespace.get('packet_lines')
        if old_packet:
            def packet(task,*args,**kwargs):
                return compact_packet(task,kwargs.get('width',79),old_packet)
            namespace['packet_lines']=packet
    namespace['security_lines']=compact_security
    # DEVICE_NETWORK_CONTROLS_V1
    from pathlib import Path
    device_controls=('net-auto','net-direct','net-off')
    old_category=namespace['script_category']
    def category(path):
        return 'System & Devices' if path.stem.lower() in device_controls else old_category(path)
    namespace['script_category']=category
    old_items=Panel.items
    def items(panel,data):
        result=old_items(panel,data)
        if panel.page=='System' and panel.details is None:
            controls={x.stem:x for x in result if isinstance(x,Path) and x.stem in device_controls}
            return [x for x in result if not (isinstance(x,Path) and x.stem in device_controls)]+[controls[k] for k in device_controls if k in controls]
        return result
    Panel.items=items
    # NETWORK_OVERVIEW_CLEANUP_V2
    namespace['FUNCTION_NAMES'].update({
        'ethernet':'Ethernet - Link & Switch',
        'net-direct-passive':'Ethernet - Direct Listen',
        'net-direct-static':'Ethernet - Direct Static IP',
        'net-direct-test':'Ethernet - Direct DHCP Server'})
    hardware='Wi-Fi hardware status'
    previous_items=Panel.items
    def hardware_items(panel,data):
        result=previous_items(panel,data)
        if panel.page=='Network' and panel.details is None:
            return [x for x in result if x!=hardware]
        if panel.page=='System' and panel.details is None and hardware not in result:
            return result+[hardware]
        return result
    Panel.items=hardware_items
    previous_handle=Panel.handle
    def hardware_handle(panel,key):
        if panel.page=='System' and panel.details is None and key in ('enter','right'):
            items=panel.items(panel.collector.snapshot())
            if items and items[min(panel.selected,len(items)-1)]==hardware:
                panel.page=hardware;panel.details=None;panel.selected=0;return
        if panel.page==hardware and panel.details is None and key in ('left','back'):
            panel.page='System'
            items=panel.items(panel.collector.snapshot())
            panel.selected=items.index(hardware) if hardware in items else 0
            return
        return previous_handle(panel,key)
    Panel.handle=hardware_handle
    namespace['FUNCTION_NAMES']['path-test']='Network - Route & Connectivity'
    old_lines=Panel.lines
    old_handle=Panel.handle
    special=set(structured_kinds)|{'wifi-health','direct-ethernet'}
    def generic(panel):
        if panel.page!='Tasks': return False
        return (panel.task.snapshot().get('metadata') or {}).get('kind') not in special
    def lines(panel,data,capacity=30,cols=80):
        from pathlib import Path
        # Keep the task queue transition even on pages with custom layouts.
        pending=getattr(panel,'pending_task',None)
        if pending and panel.task.snapshot()['state']!='RUNNING' and panel.task.stop_complete.is_set() and not panel.task.thread.is_alive():
            panel.pending_task=None;panel.start_task(*pending)
        if panel.page=='System' and panel.details is None:
            system=data.get('system') or {}; net=data.get('network') or {}
            temp=system.get('temperature');temp=f'{temp:.0f}' if temp is not None else '--'
            rows=[f"{system.get('hostname','--')} | {system.get('kernel','--')}",
                  f"Up {system.get('uptime',0)/60:.0f}m | {temp}°C | Load {system.get('load',[0])[0]:.2f}",
                  f"RAM {system.get('memory_used_mb',0):.0f}/{system.get('memory_total_mb',0):.0f}MB | Disk {system.get('disk',0):.0f}% Free {system.get('disk_free_gb',0):.0f}GB"]
            for d in net.get('devices',[]):
                if d.get('device') in ('lo','wlan0'): continue
                rows.append(f"{d.get('device','--')} {d.get('ip') or '--'} {d.get('state','--').replace(' (externally)','')}")
            items=panel.items(data)
            actions=[]
            for i,x in enumerate(items):
                if (x==hardware or (isinstance(x,Path) and x.stem in device_controls)) and (i==0 or not ((isinstance(items[i-1],Path) and items[i-1].stem in device_controls) or items[i-1]==hardware)):
                    actions.append('Device Network Controls')
                actions.append(panel.mark(i,namespace['function_name'](x) if isinstance(x,Path) else str(x)))
            # Headers are display-only; selection indexes remain real actions.
            available=max(0,capacity-min(len(actions),capacity))
            return rows[:available]+actions
        if isinstance(panel.details,Path):
            info=namespace['target_metadata'](panel.details) or {};kind=info.get('kind')
            guide={
                'discovery':['Find hosts on the Wi-Fi subnet (no port scan).','Replaces saved host targets.','Results: Targets > Network Hosts.','Filtered devices may be missed.'],
                'host':[f"Profile {info.get('ip','--')}: common TCP ports.",'Services, banners and OS clues; not proof of OS.','45s scan timeout; follow-up checks add time.','Empty output may mean filtering or failure.'],
                'security':['Network/BLE checks and findings.','Centre when complete: device findings.','Version matches need validation.'],
                'finder':['Track AP beacon signal until stopped.','Stronger dBm is not distance.','Silent APs may need a rescan.']}.get(kind)
            if guide is None:
                original=old_lines(panel,data,capacity,cols)
                guide=[x for x in original if x and not x.startswith(('> ','  ','Output appears','Long-running'))][1:]
                guide=guide[:3]
            actions=[panel.mark(i,x) for i,x in enumerate(panel.items(data))]
            budget=max(0,capacity-len(actions)-1)
            body=[part for x in guide for part in wrap(x,cols-1)]
            return [namespace['function_name'](panel.details)]+body[:budget]+actions
        if panel.page=='Targets' and isinstance(panel.details,dict):
            d=panel.details
            rows=[d.get('station','--'),f"Last RSSI {d.get('rssi','--')}dBm (historical)",
                  'SSIDs: '+', '.join(d.get('ssids',[])), 'Silent/changed MACs may not be seen.']
            return rows+[panel.mark(i,x.replace(' (until Stop)','').replace(' (60s)','')) for i,x in enumerate(panel.items(data))]
        if not generic(panel):
            kind=(panel.task.snapshot().get('metadata') or {}).get('kind') if panel.page=='Tasks' else None
            compact=kind in set(structured_kinds)
            rows=old_lines(panel,data,capacity+1 if compact else capacity,cols)
            if compact and len(rows)>2 and (rows[2].startswith('> Centre:') or rows[2].startswith('Task finished;')):
                rows=rows[:2]+rows[3:]
            # Existing specialised pages retain their navigation and evidence.
            return [re.sub(r'\s*\| Up/Down: scroll$','',row) for row in rows][:capacity]
        task=panel.task.snapshot();width=max(1,cols-1)
        if task.get('title')=='Scan Wi-Fi - Basic' and task.get('state')!='RUNNING':
            started=getattr(panel.task,'started',None)
            if getattr(panel,'_ap_started','unset')!=started:
                panel._ap_started=started;panel._ap_offset=None
            return basic_page(panel,task,capacity,cols)
        identity=(task.get('title'),getattr(panel.task,'started',task.get('started')),task.get('metadata',{}).__repr__())
        if getattr(panel,'_compact_identity',None)!=identity:
            panel._compact_identity=identity;panel._compact_offset=None
        title=task.get('title','Task')
        final_watch=title=='Device watch' and task.get('state')!='RUNNING'
        raw=clean_logs(task.get('lines',[]),task.get('state'),keep_repeats=(task.get('metadata') or {}).get('kind')=='finder')
        if final_watch:
            summary_start=next((i for i,line in enumerate(raw) if line.startswith('BLE  :')),None)
            if summary_start is not None: raw=raw[summary_start:]
        rows=output_rows(raw,width,basic=title=='Scan Wi-Fi - Basic')
        # Preserve parsed finder/host evidence in the scrollable body rather than
        # pinning a large explanatory block above the actual output.
        info=task.get('metadata') or {};finder=task.get('finder') or {}
        facts=[]
        if info.get('kind') in ('finder','discovery','host'):
            for key,label in (('status','Stage'),('bssid','AP'),('freq','MHz'),
                              ('signal','Signal dBm'),('best','Best dBm'),
                              ('network','Subnet'),('name','Name'),('mac','MAC'),
                              ('os','OS clue'),('web','Web'),('http','HTTP'),
                              ('tls','TLS'),('ssh','SSH')):
                if key in finder: facts.extend(wrap(f'{label}: {finder[key]}',width))
            if info.get('ip'): facts=wrap('Host: '+info['ip'],width)+facts
            if info.get('kind')=='finder':
                facts.extend(wrap('Signal trend is not distance. Values may be historical.',width))
            if info.get('kind')=='host':
                raw=[x for x in raw if not x.startswith(('NAME ','MAC ','HTTP ','TLS ','SSH ','Scanning')) and x!=str(info.get('ip',''))]
                rows=facts+output_rows(raw,width)
            else:
                if info.get('kind')=='finder':
                    import time
                    received=finder.get('signal_received')
                    if received is not None:
                        age=max(0,int(time.monotonic()-received))
                        facts.append(f'Last reading: {age}s ago'+(' · STALE' if age>5 else ' · LIVE' if task.get('state')=='RUNNING' else ' · FINAL'))
                    elif task.get('state')=='RUNNING': facts.append('Waiting for first signal reading')
                    trend=str(finder.get('trend',''))
                    if received is not None and age<=2 and finder.get('status')=='TRACKING':
                        direction='Signal weakening' if trend.startswith('FARTHER') else 'Signal strengthening' if trend.startswith('CLOSER') else 'Signal steady'
                    else: direction='No recent signal' if received is not None else 'Searching for target'
                    facts.append('Current: '+direction)
                    if finder.get('status')=='ACQUIRING' and finder.get('acquisition'):
                        facts.append('Acquiring: '+str(finder['acquisition']))
                    rows=[]
                rows=facts+rows
        panel._compact_rows=len(rows)
        title_rows=wrap(title,width)
        status=f"{task.get('state','IDLE')} | {task.get('elapsed',0):.0f}s"
        # A title of any length is included in the scrollable body in full.
        if len(title_rows)>1: rows=title_rows+rows
        prefix=[title_rows[0],status]
        space=max(1,capacity-len(prefix)-1)
        maximum=max(0,len(rows)-space)
        offset=getattr(panel,'_compact_offset',None)
        offset=(0 if final_watch else maximum) if offset is None else max(0,min(maximum,offset))
        panel._compact_max=maximum;panel._compact_current=offset
        position=(f"{'LIVE' if getattr(panel,'_compact_offset',None) is None and task.get('state')=='RUNNING' else 'Results'} {offset+1}-{min(len(rows),offset+space)}/{len(rows)}" if rows else 'Waiting for output' if task.get('state')=='RUNNING' else 'No output reported')
        return prefix+[position]+rows[offset:offset+space]
    def handle(panel,key):
        task=panel.task.snapshot()
        if panel.page=='Tasks' and task.get('title')=='Scan Wi-Fi - Basic' and task.get('state')!='RUNNING':
            if key in ('up','down'):
                maximum=getattr(panel,'_ap_max',0)
                current=getattr(panel,'_ap_current',maximum)
                panel._ap_offset=max(0,min(maximum,current+(-1 if key=='up' else 1)))
                return
            if key in ('right','enter'): panel._ap_offset=None;return
        if generic(panel):
            if key in ('up','down','right'):
                if key=='right': panel._compact_offset=None
                else:
                    end=getattr(panel,'_compact_max',0)
                    current=getattr(panel,'_compact_current',end)
                    current=max(0,min(end,current+(-3 if key=='up' else 3)))
                    panel._compact_offset=None if key=='down' and current==end else current
                return
            if key=='enter' and panel.task.snapshot().get('state')!='RUNNING':
                panel._compact_offset=None
        return old_handle(panel,key)
    Panel.lines=lines
    Panel.handle=handle
