"""Live capabilities, roaming, topology and site-survey pages for Advanced Scan."""
import json
from pathlib import Path
import subprocess
import time
from cloverkit_insights import WirelessEvidence, integer, text, topology, load_json

CAPABILITY_FIELDS={
    'HT':'wlan.ht.capabilities', 'VHT':'wlan.vht.capabilities',
    'HE':'wlan.ext_tag.he_mac_caps', 'EHT':'wlan.eht.mac_capabilities_info',
    '802.11k neighbor reports':'wlan.rmcap.b1',
    '802.11v BSS transition':'wlan.extcap.b19',
    '802.11r mobility domain':'wlan.mobility_domain.mdid',
    'multi-link device address':'wlan.eht.multi_link.common_info.mld_mac_address',
}
EXTRA_FIELDS=list(CAPABILITY_FIELDS.values())+['wlan.fixed.current_ap','wlan.fixed.status_code','wlan.seq','wlan.frag']

def install_backend(cls):
    if getattr(cls,'_roadmap_installed',False): return
    cls._roadmap_installed=True
    ingest=cls.ingest; snapshot=cls.snapshot
    def incoming(self,line,radio):
        cells=line.rstrip('\n').split('\t')
        ingest(self,line,radio)
        if len(cells)<8 or len(cells)>len(self.fields): return
        d=dict(zip(self.fields,cells))
        with self.lock:
            if not hasattr(self,'_wireless_evidence'): self._wireless_evidence=WirelessEvidence()
            self._wireless_evidence.ingest(d,radio)
            typ=integer(d.get('wlan.fc.type')); sub=integer(d.get('wlan.fc.subtype'))
            bssid=d.get('wlan.bssid','').lower(); freq=integer(d.get('radiotap.channel.freq'))
            row=self.aps.get((bssid,freq))
            if row is not None and typ==0 and sub in (5,8) and d.get('wlan.ta','').lower()==bssid:
                caps=row.setdefault('advertised_capabilities',{})
                for name,field in CAPABILITY_FIELDS.items():
                    raw=d.get(field)
                    if raw not in (None,''):
                        caps[name]=(integer(raw)==1) if name in ('802.11k neighbor reports','802.11v BSS transition') else text(raw,80)
                row['capabilities_seen']=time.monotonic()
    def current(self):
        with self.lock:
            data=snapshot(self); now=time.monotonic()
            for row in data.get('aps',[]):
                raw=self.aps.get((row['bssid'],row['frequency']),{})
                row.pop('capabilities_seen',None)
                row['capabilities_age_seconds']=round(now-raw['capabilities_seen'],1) if raw.get('capabilities_seen') else None
            data['roaming']=self._wireless_evidence.snapshot() if hasattr(self,'_wireless_evidence') else WirelessEvidence().snapshot()
            ethernet=load_json('/var/lib/cloverkit/ethernet-evidence/latest.json')
            if time.time()-ethernet.get('updated_at',0)>10: ethernet=dict(ethernet,stale=True)
            data['topology']=topology(data,ethernet)
            saved=load_json('/var/lib/cloverkit/site-survey/points.json',{'points':[]})
            # Keep the live stream compact; full readings remain in the export.
            points=[dict(p,recorded_ap_count=len(p.get('aps',[])),aps=sorted(p.get('aps',[]),key=lambda a:a.get('signal_dbm',-130),reverse=True)[:8]) for p in saved.get('points',[])[-100:]]
            data['site_survey']=dict(points=points,total_locations=len(saved.get('points',[])))
            return data
    cls.ingest=incoming; cls.snapshot=current

def install_browser(ns):
    if ns.get('_roadmap_installed'): return
    ns['_roadmap_installed']=True
    original=ns['page_data']; navigate=ns['navigate']; E=ns['entry']
    def pages(task,nav):
        data=ns['values'](task); frame=nav['stack'][-1]; page=frame['page']; key=frame.get('key')
        title,body,items=original(task,nav); body=list(body); items=list(items)
        if page=='summary':
            items += [E('roaming','Roaming timeline','roaming'),E('wireless_diagnosis','Wireless diagnosis','wireless_diagnosis'),
                      E('topology','Observed topology','topology'),E('survey','Site survey','survey')]
        elif page in ('bssid','bssid_evidence','ap'):
            address=key[0] if isinstance(key,(tuple,list)) else key
            rows=[r for r in data.get('aps',[]) if r['bssid']==address and r.get('advertised_capabilities')]
            if rows:
                latest=min(rows,key=lambda r:r.get('capabilities_age_seconds') if r.get('capabilities_age_seconds') is not None else 1e12)
                caps=latest['advertised_capabilities']; standards=[k for k in ('HT','VHT','HE','EHT') if caps.get(k)]
                if standards: body.append('Advertised PHY: '+', '.join(standards)+' (capabilities, not negotiated speed)')
                for label in ('802.11k neighbor reports','802.11v BSS transition','802.11r mobility domain','multi-link device address'):
                    if label in caps: body.append(label+': '+('advertised' if caps[label] is True else 'bit unset' if caps[label] is False else str(caps[label])))
                body.append('Missing capability fields mean unknown; not proof of no support.')
        elif page=='roaming':
            title='ROAMING TIMELINE'; events=data.get('roaming',{}).get('events',[])
            body=[f'{len(events)} retained management/transition events','Only listened channels are visible; frame gaps are not service outage measurements.']
            clients=sorted({r['client'] for r in events})
            items=[E(c,c+' | '+str(sum(r['client']==c for r in events))+' events','roaming_client',c) for c in clients]
            if not items: body.append('No reassociation or BSSID transition observed yet')
        elif page=='roaming_client':
            title='ROAM: '+str(key); body=[]; items=[]
            for event in data.get('roaming',{}).get('events',[]):
                if event['client']!=key: continue
                body += [event['event']+' | '+str(event.get('time')),
                         str(event.get('previous_ap') or 'previous AP unknown')+' -> '+event['target_ap'],event['outcome']]
                if event.get('gap_ms') is not None: body += [f"Observed timing {event['gap_ms']:g} ms",event.get('timing','request timestamp only')]
        elif page=='wireless_diagnosis':
            title='WIRELESS DIAGNOSIS'; body=[]; items=[]; evidence=data.get('roaming',{})
            for row in evidence.get('association_failures',[]): body.append(f"{row['bssid']}: status {row['status_code']} | {row['frames']} rejected response frame(s)")
            for row in evidence.get('authentication_failures',[]): body.append(f"{row['bssid']}: authentication status {row['status_code']} | {row['frames']} rejection frame(s)")
            for row in evidence.get('disconnects',[]): body.append(f"{row['bssid']}: reason {row['reason_code']} | {row['frames']} disconnect frame(s)")
            if not body: body=['No rejected association or disconnect frames observed']
            body += ['Counts describe captured frames; they do not establish who initiated an attack.']
        elif page=='topology':
            title='OBSERVED TOPOLOGY'; graph=data.get('topology',{}); body=[f"{len(graph.get('nodes',[]))} nodes | {len(graph.get('edges',[]))} observed relationships",
                'Wireless and ARP observations do not establish switch-to-AP cabling.']
            items=[E(n['id'],n['label']+' | '+n['kind'],'topology_node',n['id']) for n in graph.get('nodes',[])]
        elif page=='topology_node':
            graph=data.get('topology',{}); nodes={n['id']:n for n in graph.get('nodes',[])}; node=nodes.get(key,{})
            edges=[e for e in graph.get('edges',[]) if key in (e['source'],e['target'])]
            title='NODE: '+node.get('label',str(key)); items=[]
            kind=node.get('kind')
            if kind=='observer':
                body=['CloverKit is the receiver, listening to nearby Wi-Fi traffic.',
                      str(sum(e['relation']=='heard wirelessly' for e in edges))+' AP identities heard in this scan.',
                      'Open an AP below to see observed client traffic.',
                      'This is a wireless observation map; it does not show switch-to-AP cables.']
            elif kind=='AP':
                body=['AP BSSID: '+node.get('bssid',str(key).removeprefix('ap:')),
                      'CloverKit captured frames involving this AP.',
                      'Client entries show captured AP/client traffic, not a live association query.']
            elif kind=='client':
                body=['Client MAC: '+str(key).removeprefix('client:'),
                      'AP entries show captured traffic involving this client.',
                      'Multiple AP entries alone do not confirm roaming.']
            else:body=[kind or 'Observation no longer retained','Connections below describe the available evidence.']
            for edge in edges:
                other=edge['target'] if edge['source']==key else edge['source']; related=nodes.get(other,{})
                role='Receiver' if related.get('kind')=='observer' else 'AP' if related.get('kind')=='AP' else 'Client' if related.get('kind')=='client' else 'Neighbor'
                label=role+': '+related.get('label',other)
                if related.get('kind')=='AP' and related.get('label')!=related.get('bssid'):label+=' | '+related.get('bssid',other.removeprefix('ap:'))
                age=edge.get('age_seconds')
                if isinstance(age,(int,float)):label+=' | seen '+str(round(age,1))+'s ago'
                if edge.get('stale'):label+=' | old observation'
                items.append(E(other+'|'+edge['relation'],label,'topology_node',other))
                if edge.get('port'):body.append('Advertised Ethernet port: '+str(edge['port']))
            if not edges:body.append('No related observations currently retained.')
        elif page=='survey':
            title='SITE SURVEY'; points=data.get('site_survey',{}).get('points',[])
            body=[f"{data.get('site_survey',{}).get('total_locations',len(points))} saved locations (newest 100 shown)",'Select a row/column on a 5x5 floor-plan grid. Only fresh qualified readings are saved.',
                  'Export from normal SSH: cloverkit-report survey-export','Floor plan can be added to the exported interactive HTML.']
            items=[E('record','Record current location','survey_row')]+[E(i,p['location']+' | '+str(p.get('recorded_ap_count',len(p['aps'])))+' readings','survey_point',i) for i,p in enumerate(points)]
        elif page=='survey_row':
            title='SURVEY: FLOOR-PLAN ROW'; body=['Top to bottom: rows 1–5']; items=[E(i,'Row '+str(i+1),'survey_column',i) for i in range(5)]
        elif page=='survey_column':
            title='SURVEY: FLOOR-PLAN COLUMN'; body=['Left to right: columns 1–5']; items=[E(i,'Column '+str(i+1),'survey_record',(key,i)) for i in range(5)]
        elif page=='survey_record':
            title='SURVEY RECORD'; body=[nav.get('survey_message','Select Record to save the current readings.')]
            items=[E('save','Record this location','survey_save',key)]
        elif page=='survey_point':
            points=data.get('site_survey',{}).get('points',[]); point=points[key] if isinstance(key,int) and 0<=key<len(points) else {}
            title='SURVEY: '+point.get('location','not retained'); body=[]; items=[]
            if point.get('recorded_ap_count',0)>8: body.append('Strongest 8 readings shown; all readings available in HTML export.')
            for row in point.get('aps',[]): body.append(f"{row.get('beacon_ap_name') or row.get('ssid')} | {row['frequency']} MHz | {row['signal_dbm']} dBm")
        return title,body,items
    ns['page_data']=pages
    def move(task,nav,key):
        if key in ('right','enter'):
            frame=nav['stack'][-1]; _,_,items=ns['page_data'](task,nav); position=ns['chosen'](frame,items)
            if position is not None and items[position]['page']=='topology_node':
                target=items[position]['target']; graph=ns['values'](task).get('topology',{})
                node=next((n for n in graph.get('nodes',[]) if n['id']==target),{})
                roots=[i for i,f in enumerate(nav['stack']) if f['page']=='topology']
                base=nav['stack'][:roots[0]+1] if roots else [dict(page='summary',key=None,selected=None,offset=0),dict(page='topology',key=None,selected=None,offset=0)]
                # Graph links change the inspected node, not the page depth.
                nav['stack']=base+[dict(page='topology_node',key=target,label=node.get('label',target),selected=None,offset=0)]
                return True
            if position is not None and items[position]['page']=='survey_save':
                row,column=items[position]['target']; request=dict(row=row,column=column)
                try:
                    result=subprocess.run(['sudo','-n','/usr/local/bin/cloverkit-survey-store'],input=json.dumps(request),text=True,capture_output=True,timeout=5)
                    response=json.loads(result.stdout); nav['survey_message']=response.get('message','Saved')
                except (OSError,ValueError,subprocess.TimeoutExpired) as error: nav['survey_message']='Unable to record: '+text(error)
                return True
        return navigate(task,nav,key)
    ns['navigate']=move
