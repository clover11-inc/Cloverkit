"""Evidence-based CloverKit analysis. This module never changes interfaces."""
import collections
import hashlib
import json
import math
import os
from pathlib import Path
import re
import statistics
import tempfile
import time

MAC = re.compile(r'^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$')

def number(value):
    try:
        n = float(str(value).split(',')[0])
        return n if math.isfinite(n) else None
    except (ValueError, TypeError): return None

def integer(value):
    try: return int(str(value).split(',')[0], 0)
    except (ValueError, TypeError):
        n=number(value); return int(n) if n is not None else None

def text(value, limit=120):
    return ''.join(c for c in str(value or '') if c.isprintable()).strip()[:limit]

def unicast(value):
    return bool(MAC.fullmatch(value or '')) and not int(value[:2],16)&1

def verify_external(name, root=Path('/sys/class/net')):
    from cloverkit_radio_identity import verify_usb
    verify_usb(name,root)


def atomic_json(path, data):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix='.clover-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as stream:
            json.dump(data,stream,ensure_ascii=True); stream.flush(); os.fsync(stream.fileno())
        os.chmod(name,0o640); os.replace(name,path)
    finally: Path(name).unlink(missing_ok=True)

def load_json(path, default=None):
    try: return json.loads(Path(path).read_text())
    except (OSError,ValueError): return default if default is not None else {}

def health_score(data):
    """Score only measured dimensions; report completeness beside the score."""
    rows=[]
    def add(name, weight, score, detail):
        rows.append(dict(check=name,weight=weight,score=score,detail=detail))
    source=data.get('source_ip'); checks=data.get('checks',{})
    lease=checks.get('addressing',{})
    add('DHCP/addressing',15,100 if lease.get('method')=='auto' and source else 0 if lease.get('method')=='auto' and not source else None,
        'DHCP-configured address present; acquisition time unmeasured' if lease.get('method')=='auto' and source else 'Static or unknown configuration; DHCP not assessed')
    dns=checks.get('dns',{})
    add('DNS',15,100 if dns.get('status')=='resolved' else 0 if dns.get('status')=='failed' else None,
        'System resolver result; resolver path may differ from selected interface' if dns else 'DNS not measured')
    gateway=data.get('gateway',{}); loss=number(gateway.get('loss'))
    add('Gateway response',20,100 if loss is not None and loss<100 else 0 if loss==100 else None,
        'ICMP response received' if loss is not None and loss<100 else 'No ICMP reply; filtering and reachability are not distinguished' if loss==100 else 'Gateway not measured')
    add('Packet loss',25,max(0,100-loss*5) if loss is not None else None,
        f'{loss:g}% local ICMP loss' if loss is not None else 'Loss not measured')
    latency=number(gateway.get('avg_ms')); jitter=number(gateway.get('mdev_ms'))
    add('Latency',15,100 if latency is not None and latency<=10 else max(0,100-(latency-10)*2) if latency is not None else None,
        f'{latency:g} ms gateway average' if latency is not None else 'Latency not measured')
    add('Jitter',10,100 if jitter is not None and jitter<=5 else max(0,100-(jitter-5)*4) if jitter is not None else None,
        f'{jitter:g} ms RTT standard deviation (jitter proxy)' if jitter is not None else 'Jitter not measured')
    measured=[r for r in rows if r['score'] is not None]; weight=sum(r['weight'] for r in measured)
    score=round(sum(r['weight']*r['score'] for r in measured)/weight) if weight else None
    issues=[r['detail'] for r in measured if r['score']<80]
    return dict(score=score,measured_weight_percent=weight,checks=rows,issues=issues,
                interpretation='Troubleshooting heuristic; omitted checks do not count as passes')

def ethernet_findings(data):
    findings=[]
    if data.get('link') not in ('UP',True): findings.append('No Ethernet carrier; check cable, power and switch port')
    if str(data.get('duplex','')).lower()=='half': findings.append('Half duplex reported; check negotiation on both ends')
    errors=number(data.get('errors')); drops=number(data.get('drops'))
    if errors and errors>0: findings.append('Interface errors recorded; compare counter changes and cable diagnostics')
    if drops and drops>0: findings.append('Receive/transmit drops recorded; inspect load and buffers')
    if str(data.get('ip','')).strip() in ('','--','None'): findings.append('No IPv4 address reported; passive L2 discovery can still work')
    if data.get('switch') not in (None,'','--'):
        findings.append('Advertised neighbor: '+text(data['switch'])+' / '+text(data.get('port','unknown port')))
    if data.get('vlans') not in (None,'','--'):
        findings.append('Observed tags: '+text(data['vlans'])+'; unseen VLANs cannot be ruled out')
    if data.get('stale'): findings.append('Neighbor data is retained from an earlier link; not current evidence')
    return findings or ['No fault indicated by available Ethernet observations']

class WirelessEvidence:
    def __init__(self):
        self.events=collections.deque(maxlen=1000)
        self.last_data={}; self.pending={}; self.seen=collections.OrderedDict()
        self.failures=collections.Counter(); self.auth_failures=collections.Counter(); self.disconnects=collections.Counter()
    def ingest(self, d, radio, now=None):
        now=time.monotonic() if now is None else now
        stamp=number(d.get('frame.time_epoch')); typ=integer(d.get('wlan.fc.type')); sub=integer(d.get('wlan.fc.subtype'))
        bssid=d.get('wlan.bssid','').lower(); ta=d.get('wlan.ta','').lower(); ra=d.get('wlan.ra','').lower()
        if not unicast(bssid): return
        # Cross-radio duplicates and wireless retries must not create extra roams.
        key=(stamp,ta,ra,typ,sub,d.get('wlan.seq'),d.get('wlan.frag'))
        if stamp is not None and key in self.seen: return
        if stamp is not None:
            self.seen[key]=now
            while len(self.seen)>4096: self.seen.popitem(last=False)
        for mapping in (self.last_data,self.pending):
            for client in list(mapping):
                if now-mapping[client]['seen']>300: del mapping[client]
            while len(mapping)>5000: mapping.pop(next(iter(mapping)))
        if typ==0 and sub in (0,2) and ta!=bssid and unicast(ta):
            old=d.get('wlan.fixed.current_ap','').lower() if sub==2 else None
            self.pending[ta]=dict(seen=now,stamp=stamp,target=bssid,old=old if unicast(old) else None,kind='reassociation' if sub==2 else 'association')
            if sub==2:
                self.events.append(dict(event='reassociation request',client=ta,previous_ap=old if unicast(old) else None,
                    target_ap=bssid,time=stamp,radio=radio,outcome='response not yet observed',gap_ms=None))
        elif typ==0 and sub in (1,3) and ta==bssid and unicast(ra):
            status=integer(d.get('wlan.fixed.status_code'))
            if status is not None and status!=0: self.failures[(bssid,status)]+=1
            request=self.pending.get(ra)
            if status==0 and request and request['target']==bssid and now-request['seen']<=10:
                elapsed=(stamp-request['stamp'])*1000 if stamp is not None and request['stamp'] is not None and stamp>=request['stamp'] else None
                self.events.append(dict(event=request['kind']+' accepted',client=ra,previous_ap=request['old'],target_ap=bssid,
                    time=stamp,radio=radio,outcome='successful management response',gap_ms=round(elapsed,1) if elapsed is not None else None,
                    timing='request-to-response observation; not end-to-end outage'))
        elif typ==0 and sub in (10,12):
            self.disconnects[(bssid,integer(d.get('wlan.fixed.reason_code')))]+=1
        elif typ==0 and sub==11 and ta==bssid:
            status=integer(d.get('wlan.fixed.status_code'))
            if status is not None and status!=0: self.auth_failures[(bssid,status)]+=1
        elif typ==2:
            to_ds=integer(d.get('wlan.fc.tods')); from_ds=integer(d.get('wlan.fc.fromds'))
            client=ta if to_ds==1 and from_ds==0 and ra==bssid else ra if to_ds==0 and from_ds==1 and ta==bssid else None
            if not unicast(client) or client==bssid: return
            old=self.last_data.get(client)
            if old and old['bssid']!=bssid and stamp is not None and old['stamp'] is not None and stamp>=old['stamp']:
                gap=(stamp-old['stamp'])*1000
                self.events.append(dict(event='BSSID transition observed',client=client,previous_ap=old['bssid'],target_ap=bssid,time=stamp,
                    radio=radio,outcome='possible roam or multi-link activity; not confirmed',gap_ms=round(gap,1),
                    timing='gap between captured data frames; channel hopping/missed frames can inflate it'))
            if not old or stamp is None or old['stamp'] is None or stamp>=old['stamp']:
                self.last_data[client]=dict(seen=now,stamp=stamp,bssid=bssid)
    def snapshot(self):
        # Bound status/reason-code attribution even in a hostile capture.
        for counts in (self.failures,self.auth_failures,self.disconnects):
            if len(counts)>1000:
                retained=counts.most_common(1000); counts.clear(); counts.update(dict(retained))
        return dict(events=list(self.events),association_failures=[dict(bssid=k[0],status_code=k[1],frames=v) for k,v in self.failures.most_common(100)],
                    authentication_failures=[dict(bssid=k[0],status_code=k[1],frames=v) for k,v in self.auth_failures.most_common(100)],
                    disconnects=[dict(bssid=k[0],reason_code=k[1],frames=v) for k,v in self.disconnects.most_common(100)],
                    limitations=['Only frames on listened channels are visible','Data-frame gaps are not measured service outages','BSSID transitions can also reflect multi-link activity'])

class PacketEvidence:
    """Interpret decoded fields from an existing PCAP, without a capture engine."""
    def __init__(self):
        self.frames=0; self.first=None; self.last=None; self.pending_dns={}; self.dns_errors=collections.Counter()
        self.dhcp={}; self.arp={}; self.conflicts=collections.Counter(); self.retransmissions=0; self.tcp_frames=0
        self.broadcast=collections.Counter(); self.wireless=WirelessEvidence(); self.expired_dns=0
    def ingest(self,d):
        self.frames+=1; stamp=number(d.get('frame.time_epoch'))
        if stamp is not None:
            self.first=stamp if self.first is None else min(self.first,stamp); self.last=stamp if self.last is None else max(self.last,stamp)
        ident=d.get('dns.id'); response=integer(d.get('dns.flags.response'))
        src=d.get('ip.src',''); dst=d.get('ip.dst',''); udp=d.get('udp.srcport',''); udp_dst=d.get('udp.dstport','')
        question=d.get('dns.qry.name','')
        if ident and response is not None:
            key=(ident,src,dst,udp,udp_dst,question) if response==0 else (ident,dst,src,udp_dst,udp,question)
            if response==0:
                self.pending_dns[key]=stamp
                if len(self.pending_dns)>10000:
                    self.pending_dns.pop(next(iter(self.pending_dns))); self.expired_dns+=1
            else:
                self.pending_dns.pop(key,None)
                code=integer(d.get('dns.flags.rcode'))
                if code: self.dns_errors[code]+=1
        transaction=d.get('dhcp.id'); message=integer(d.get('dhcp.option.dhcp'))
        if transaction and message is not None:
            client=d.get('dhcp.hw.mac_addr','')
            self.dhcp.setdefault((transaction,client),set()).add(message)
            if len(self.dhcp)>10000: self.dhcp.pop(next(iter(self.dhcp)))
        ip=d.get('arp.src.proto_ipv4'); mac=d.get('arp.src.hw_mac','').lower()
        if ip and ip!='0.0.0.0' and unicast(mac):
            if ip in self.arp and self.arp[ip]!=mac: self.conflicts[ip]+=1
            self.arp[ip]=mac
            if len(self.arp)>10000: self.arp.pop(next(iter(self.arp)))
        if d.get('tcp.stream')!='' and d.get('tcp.stream') is not None:
            self.tcp_frames+=1
            self.retransmissions+=int(any(d.get(k) not in ('',None,'0','False','false') for k in ('tcp.analysis.retransmission','tcp.analysis.fast_retransmission','tcp.analysis.spurious_retransmission')))
        if d.get('eth.dst','').lower()=='ff:ff:ff:ff:ff:ff': self.broadcast[text(d.get('_ws.col.Protocol','unknown'),30)]+=1
        self.wireless.ingest(d,'saved capture',now=stamp if stamp is not None else time.monotonic())
    def snapshot(self):
        duration=max(0,(self.last or 0)-(self.first or 0)); pending=sum(t is not None and self.last is not None and self.last-t>=5 for t in self.pending_dns.values())
        incomplete=sum(bool(messages & {1,3}) and not messages & {5,6} for messages in self.dhcp.values())
        nak=sum(6 in messages for messages in self.dhcp.values())
        broadcast_rate=sum(self.broadcast.values())/duration if duration else None
        findings=[]
        if pending: findings.append(f'{pending} DNS request(s) had no captured reply within at least 5 seconds; check resolver reachability and capture completeness')
        if self.dns_errors: findings.append('DNS error replies observed; inspect response codes and the queried names')
        if nak: findings.append(f'{nak} DHCP transaction(s) received NAK; inspect address/subnet policy and DHCP server logs')
        if incomplete: findings.append(f'{incomplete} DHCP transaction(s) lack a captured ACK/NAK; check server response and capture start/end coverage')
        if self.retransmissions: findings.append(f'{self.retransmissions} TCP retransmission indication(s); compare with packet loss, RTT, congestion and capture duplication')
        if self.conflicts: findings.append('ARP sender address changed for '+', '.join(list(self.conflicts)[:10])+'; confirm conflict versus legitimate failover')
        if broadcast_rate is not None and broadcast_rate>=100: findings.append('Elevated captured broadcast rate (100/s heuristic); identify dominant senders/protocols and compare with a baseline')
        wireless=self.wireless.snapshot()
        if wireless['authentication_failures'] or wireless['association_failures']: findings.append('Wireless management rejection frames observed; inspect status codes and AP/client logs')
        return dict(frames=self.frames,duration_seconds=round(duration,2),dns_unanswered_after_5s=pending,dns_error_codes=dict(self.dns_errors),
                    dhcp_incomplete_transactions=incomplete,dhcp_nak_transactions=nak,tcp_frames=self.tcp_frames,tcp_retransmissions=self.retransmissions,
                    tcp_retransmission_percent=round(100*self.retransmissions/self.tcp_frames,1) if self.tcp_frames else None,
                    arp_address_changes=dict(self.conflicts),broadcast_frames=dict(self.broadcast),broadcast_frames_per_second=round(broadcast_rate,1) if broadcast_rate is not None else None,
                    findings=findings or ['No diagnostic finding in the decoded fields; this does not establish a healthy network'],
                    wireless=wireless,limitations=['Missing responses can reflect incomplete or asymmetric capture','ARP changes can be legitimate failover; conflicts need confirmation','Broadcast rate has no universal fault threshold','Encrypted Wi-Fi payloads cannot be interpreted without decrypted packets'])

BLE_COMPANIES={0x004c:'Apple',0x0075:'Samsung',0x0006:'Microsoft',0x0059:'Nordic Semiconductor',0x00c7:'Tile',0x000f:'Broadcom',0x000d:'Texas Instruments'}
BLE_SERVICES={'1800':'Generic Access','1801':'Generic Attribute','180a':'Device Information','180d':'Heart Rate','180f':'Battery','1812':'Human Interface Device','feaa':'Eddystone','fd6f':'Exposure Notification','fd5a':'Samsung SmartTag','00003081':'Flipper service'}

def ble_details(record):
    services=[]
    for uuid in sorted(record.get('uuids',[])):
        short=str(uuid).lower().split('-')[0]
        name=next((v for k,v in BLE_SERVICES.items() if short in (k,'0000'+k)),None)
        services.append(dict(uuid=uuid,name=name or 'Unmapped advertised service'))
    companies=[dict(id=int(k),name=BLE_COMPANIES.get(int(k),'Unknown company ID'),bytes=len(v),payload_hex=bytes(v).hex()) for k,v in record.get('manufacturer',{}).items()]
    rssis=[r for r in record.get('rssis',[]) if number(r) is not None and -130<=float(r)<0]
    return dict(address=record.get('address'),name=text(record.get('name')),services=services,manufacturers=companies,
                tx_power=record.get('tx_power'),signal_dbm=round(statistics.mean(rssis),1) if rssis else None,
                service_data={str(k):bytes(v).hex() for k,v in record.get('service_data',{}).items()},
                limitations='Advertisements indicate claimed services; address randomisation can change identity')

def history_update(previous, observations, complete_transports, now=None):
    now=time.time() if now is None else now; previous=previous or {}; devices=dict(previous.get('devices',{})); events=list(previous.get('events',[]))
    current={r['transport']+':'+r['address'].lower():r for r in observations}; complete=set(complete_transports)
    for key,row in current.items():
        old=devices.get(key); name=text(row.get('name')); ssid=text(row.get('ssid'))
        if old is None: events.append(dict(time=now,event='appeared',device=key,name=name))
        elif not old.get('present'): events.append(dict(time=now,event='reappeared',device=key,name=name))
        if old and ssid and old.get('ssid') and ssid!=old['ssid']:
            events.append(dict(time=now,event='SSID changed',device=key,old=old['ssid'],new=ssid,note='Configuration change or impersonation; investigate, not a rogue verdict'))
        devices[key]=dict(row,first_seen=old.get('first_seen',now) if old else now,last_seen=now,present=True)
    for key,old in list(devices.items()):
        if key not in current and old.get('transport') in complete and old.get('present'):
            old=dict(old); old['present']=False; devices[key]=old
            events.append(dict(time=now,event='not seen in this scan',device=key,note='Absence is not proof that the device left'))
    if len(devices)>5000: devices=dict(sorted(devices.items(),key=lambda item:item[1].get('last_seen',0),reverse=True)[:5000])
    wifi=[r for r in observations if r['transport']=='wifi']; ble=[r for r in observations if r['transport']=='ble']; correlations=[]
    for w in wifi:
        name=text(w.get('name') or w.get('ssid')).lower()
        if len(name)>=4:
            for b in ble:
                if name==text(b.get('name')).lower(): correlations.append(dict(wifi=w['address'],ble=b['address'],evidence='Matching advertised name; possible relationship only'))
                if len(correlations)>=100: break
        if len(correlations)>=100: break
    return dict(updated_at=now,devices=devices,events=events[-1000:],possible_correlations=correlations)

def topology(wifi=None, ethernet=None, neighbors=None):
    wifi=wifi or {}; ethernet=ethernet or {}; nodes={'cloverkit':dict(id='cloverkit',label='CloverKit',kind='observer')}; edges=[]
    def node(ident,label,kind,**attributes): nodes.setdefault(ident,dict(id=ident,label=text(label),kind=kind,**attributes))
    for ap in wifi.get('aps',[]):
        ident='ap:'+ap['bssid']; node(ident,ap.get('beacon_ap_name') or ap.get('ssid') or ap['bssid'],'AP',bssid=ap['bssid'])
        edges.append(dict(source='cloverkit',target=ident,relation='heard wirelessly',physical=False,evidence='passive capture',age_seconds=ap.get('last_seen_seconds')))
    seen=set()
    for client in wifi.get('clients',[]):
        link=(client['ap'],client['client'])
        if link in seen: continue
        seen.add(link); a='ap:'+client['ap']; c='client:'+client['client']; node(a,client['ap'],'AP'); node(c,client['client'],'client')
        edges.append(dict(source=a,target=c,relation='observed infrastructure traffic',physical=False,evidence='802.11 DS direction',age_seconds=client.get('last_seen_seconds')))
    neighbor=ethernet.get('switch')
    if neighbor not in (None,'','--'):
        ident='neighbor:'+text(neighbor); node(ident,neighbor,'advertised Ethernet neighbor',port=ethernet.get('port'),management_ip=ethernet.get('mgmt'))
        edges.append(dict(source='cloverkit',target=ident,relation='advertised direct neighbor',physical=True,evidence=ethernet.get('protocols','LLDP/CDP'),port=ethernet.get('port'),stale=bool(ethernet.get('stale'))))
    for row in neighbors or []:
        ident='ip:'+str(row.get('dst')); node(ident,row.get('dst'),'IP neighbor',mac=row.get('lladdr'),interface=row.get('dev'))
        edges.append(dict(source='cloverkit',target=ident,relation='neighbor-cache entry',physical=False,evidence='ARP/NDP cache; switch path unknown'))
    # Multiple observations of the same AP/channel share one graph link.
    unique={}
    for edge in edges:
        key=(edge['source'],edge['target'],edge['relation'],edge.get('port'))
        if key not in unique or (edge.get('age_seconds') is not None and edge['age_seconds']<(unique[key].get('age_seconds') or float('inf'))): unique[key]=edge
    return dict(nodes=list(nodes.values()),edges=list(unique.values()),limitations=['Wireless reception does not establish a wired connection','No switch-to-AP cable inferred from names, OUIs, or subnet membership','SNMP/controller data can be imported only when separately provided and authorised'])

def survey_point(snapshot, location, x, y, now=None):
    x=number(x); y=number(y)
    if x is None or y is None or not 0<=x<=1 or not 0<=y<=1: raise ValueError('Coordinates must be between 0 and 1')
    rows=[]; window=number(snapshot.get('measurement_window_seconds')) or 60
    for ap in snapshot.get('aps',[]):
        signal=number(ap.get('signal_dbm')); age=number(ap.get('signal_last_seen_seconds'))
        if signal is not None and -130<=signal<0 and age is not None and age<=window and ap.get('signal_samples',0)>=3:
            rows.append({k:ap.get(k) for k in ('bssid','ssid','frequency','signal_dbm','signal_samples','signal_last_seen_seconds','snr_db','beacon_ap_name')})
    if not rows: raise ValueError('No fresh qualified signal measurements; keep scanning before recording')
    rows=sorted(rows,key=lambda a:a['signal_dbm'],reverse=True)[:256]
    return dict(location=text(location,80),x=x,y=y,time=time.time() if now is None else now,aps=rows,
                measurement_window_seconds=window,notes='Measurements sampled during channel hopping; no coverage interpolated between points')
