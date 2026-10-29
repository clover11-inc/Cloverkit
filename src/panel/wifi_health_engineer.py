"""Receiver evidence and display context; no radio or scan policy changes."""
import collections
import math
import time

def number(value):
    try:
        value=float(str(value).split(',')[0])
        return value if math.isfinite(value) else None
    except (ValueError,TypeError):return None


def assumed_noise_estimate(ap,window,noise_floor=-95):
    signal=number(ap.get('signal_dbm'));age=number(ap.get('signal_last_seen_seconds'))
    if ap.get('snr_db') is not None or ap.get('estimated_snr_db') is not None:return {}
    if signal is None or not -130<=signal<0 or ap.get('signal_samples',0)<3 or age is None or not 0<=age<=window:return {}
    floor=number(noise_floor)
    if floor is None or not -130<=floor<=-20:floor=-95
    return dict(assumed_noise_snr_db=round(signal-floor,1),assumed_noise_floor_dbm=floor,
                assumed_noise_snr_source='measured signal minus assumed noise floor; actual noise/interference not measured')

def configured_noise_floor():
    import json
    from pathlib import Path
    try:
        value=number(json.loads(Path('/etc/cloverkit/wifi-snr-estimate.json').read_text()).get('noise_floor_dbm'))
        return value if value is not None and -130<=value<=-20 else -95
    except (OSError,ValueError,TypeError,AttributeError):return -95

def install_backend(cls):
    if getattr(cls,'_engineer_fix',False):return
    cls._engineer_fix=True
    original_ingest,original_snapshot=cls.ingest,cls.snapshot
    def ingest(self,line,radio):
        cells=line.rstrip('\n').split('\t')
        d=dict(zip(self.fields,cells))
        signal=number(d.get('radiotap.dbm_antsignal'))
        noise=number(d.get('radiotap.dbm_antnoise'))
        frequency=number(d.get('radiotap.channel.freq'))
        valid_signal=signal is not None and -130<=signal<0
        valid_noise=noise is not None and -130<=noise<0
        original_ingest(self,line,radio)
        if len(cells)<8 or len(cells)>len(self.fields):return
        with self.lock:
            counts=self.radios[radio].setdefault('metadata_samples',{'frames':0,'signal':0,'noise':0,'frequency':0})
            counts['frames']+=1;counts['signal']+=int(valid_signal);counts['noise']+=int(valid_noise)
            counts['frequency']+=int(frequency is not None)
            bssid=d.get('wlan.bssid','').lower()
            # Use the same live capture stream; names never gate initial results.
            # Accept only AP-origin beacons/probe responses on a decoded channel.
            if (frequency is not None and d.get('wlan.ta','').lower()==bssid
                    and number(d.get('wlan.fc.type'))==0
                    and number(d.get('wlan.fc.subtype')) in (5,8)):
                record=self.aps.get((bssid,int(frequency)))
                if record is not None:
                    for field in ('wlan.cisco.ccx1.name','wlan.vs.cisco.apname_v2'):
                        name=''.join(c for c in d.get(field,'') if c.isprintable()).strip()[:120]
                        if name:
                            record['beacon_ap_name']=name
                            record['beacon_ap_name_source']=field
                            record['beacon_ap_name_seen']=time.monotonic()
                            break
            if frequency is None or not valid_signal or d.get('wlan.ta','').lower()!=bssid:return
            key=(bssid,int(frequency))
            if key not in self.aps:return
            if not hasattr(self,'_engineer_samples'):self._engineer_samples={}
            # Bound auxiliary state to the scanner's retained AP records.
            for expired in set(self._engineer_samples)-set(self.aps):del self._engineer_samples[expired]
            samples=self._engineer_samples.setdefault(key,collections.deque(maxlen=120))
            samples.append((time.monotonic(),signal,noise if valid_noise else None,radio))
    def snapshot(self):
        with self.lock:
            result=original_snapshot(self)
            now=time.monotonic();window=result.get('measurement_window_seconds',60)
            surveys=list(self.samples)
            for ap in result.get('aps',[]):
                # Configuration identity may be shared across records of this
                # BSSID; reception measurements remain capture-specific.
                names=[a for a in self.aps.values()
                       if a.get('bssid')==ap['bssid'] and a.get('beacon_ap_name')]
                name=max(names,key=lambda a:a.get('beacon_ap_name_seen',0)) if names else None
                ap.pop('beacon_ap_name_seen',None)
                if name:
                    ap['beacon_ap_name']=name['beacon_ap_name']
                    ap['beacon_ap_name_source']=name['beacon_ap_name_source']
                    ap['beacon_ap_name_age_seconds']=round(now-name['beacon_ap_name_seen'],1)
                samples=getattr(self,'_engineer_samples',{}).get((ap['bssid'],ap['frequency']),[])
                current=[s for s in samples if 0<=now-s[0]<=window]
                ap['snr_source']='packet signal minus packet noise' if ap.get('snr_db') is not None else None
                if samples:
                    ap['last_signal_dbm']=samples[-1][1]
                    ap['last_signal_radio']=samples[-1][3]
                estimates=[]
                for stamp,signal,noise,radio in current:
                    matching=[r for r in surveys if r.get('radio')==radio and r.get('frequency')==ap['frequency']
                              and number(r.get('noise_dbm')) is not None and -130<=number(r['noise_dbm'])<0
                              and r['time']-r.get('observed_seconds',0)<=stamp<=r['time']
                              and 0<=now-r['time']<=window]
                    if noise is None and matching:
                        survey=max(matching,key=lambda r:r['time'])
                        estimates.append((signal-number(survey['noise_dbm']),number(survey['noise_dbm'])))
                ap['estimated_snr_db']=round(sum(e[0] for e in estimates)/len(estimates),1) if estimates else None
                ap['estimated_snr_samples']=len(estimates)
                ap['estimated_noise_dbm']=round(sum(e[1] for e in estimates)/len(estimates),1) if estimates else None
                ap['estimated_snr_source']='same adapter/channel visit survey noise' if estimates else None
                ap.update(assumed_noise_estimate(ap,window,configured_noise_floor()))
            result['limits']=[s for s in result.get('limits',[]) if s!='SNR uses same-frame radiotap signal/noise only']
            result['limits'].append('SNR = signal minus noise; survey-based estimates require the same adapter/channel visit and are separate from packet-paired SNR.')
            return result
    cls.ingest,cls.snapshot=ingest,snapshot

def display_context(data):
    data=dict(data);data['aps']=[dict(a) for a in data.get('aps',[])]
    for ap in data['aps']:
        if ap.get('beacon_ap_name'):
            ap['advertised_device']=dict(ap.get('advertised_device',{}))
            # Display fallback only: never replace confirmed inventory names or
            # use hostname equality as proof of shared physical hardware.
            ap['advertised_device'].setdefault('name',ap['beacon_ap_name'])
        same=[a for a in data['aps'] if a.get('bssid')==ap.get('bssid')]
        names=[a for a in same if a.get('ssid') and a['ssid']!='Unknown/hidden']
        if ap.get('ssid') in (None,'','Unknown/hidden') and names:
            source=min(names,key=lambda a:a.get('beacon_last_seen_seconds') if a.get('beacon_last_seen_seconds') is not None else 1e12)
            ap['ssid']=source['ssid'];ap['_name_context']=True
        # Advertised configuration can be retained as BSSID context; reception
        # and retry measurements must remain specific to each capture record.
        sources=[a for a in same if a.get('advertised_primary_channel') is not None or a.get('advertised_width')]
        if sources:
            source=min(sources,key=lambda a:a.get('beacon_last_seen_seconds') if a.get('beacon_last_seen_seconds') is not None else 1e12)
            for field in ('advertised_primary_channel','advertised_width'):
                if ap.get(field) in (None,'') and source.get(field) not in (None,''):
                    ap[field]=source[field];ap['_radio_context']=True
    return data


def visible_measurement_rows(lines):
    prefixes=('Capture noise:','Driver survey noise:','AP SNR:','AP SNR here:','Client SNR:',
              'AP signal here:','Client signal here:','AP → client:','Client → AP:',
              'Signal range:','Range:','Local noise / channel busy:')
    absent=('unavailable','not measured','no recent signal','no signal samples','not assessed','not supplied','no usable survey')
    result=[]
    for line in lines:
        if line.startswith(prefixes) and any(word in line.lower() for word in absent):continue
        if line.startswith('Missing capability fields mean unknown;'):continue
        result.append(line)
    return result

def install_browser(ns):
    if ns.get('_engineer_fix'):return
    ns['_engineer_fix']=True
    original=ns['page_data']
    def pages(task,nav):
        raw=ns['values'](task);data=display_context(raw)
        finder=dict(task.get('finder',{}));finder['values']=data
        task=dict(task,finder=finder)
        title,body,items=original(task,nav)
        body=list(body)
        frame=nav['stack'][-1];page,key=frame['page'],frame.get('key')
        address=key if page=='bssid' else key[0] if page in ('ap','bssid_evidence','link','link_evidence') and isinstance(key,(tuple,list)) else None
        frequency=key[1] if page in ('ap','bssid_evidence') and isinstance(key,(tuple,list)) and len(key)>1 else key[2] if page in ('link','link_evidence') and isinstance(key,(tuple,list)) and len(key)>2 else None
        aps=[a for a in data['aps'] if a.get('bssid')==address and (frequency is None or a.get('frequency')==frequency)]
        ap=min(aps,key=lambda a:a.get('signal_last_seen_seconds') if a.get('signal_last_seen_seconds') is not None else 1e12) if aps else None
        if ap:
            if ap.get('assumed_noise_snr_db') is not None:
                body.append(f"Est. SNR: {ap['assumed_noise_snr_db']:g} dB")
                body.append(f"Assumed noise: {ap['assumed_noise_floor_dbm']:g} dBm · not measured")
            if ap.get('beacon_ap_name'):
                body.append('Beacon AP name: '+ap['beacon_ap_name'])
                body.append('Name source: Cisco advertisement | age '+str(ap.get('beacon_ap_name_age_seconds','unknown'))+'s')
            if ap.get('_name_context') or ap.get('_radio_context'):
                body.append('Identity/config: retained observation of this BSSID; signal remains capture-specific.')
            for i,line in enumerate(body):
                if line.startswith('AP SNR:'):
                    if ap.get('snr_db') is not None:
                        body[i]=f"AP SNR: {ap['snr_db']:g} dB · calculated from packet signal − noise"
                    elif ap.get('estimated_snr_db') is not None:
                        body[i]=f"Estimated AP SNR: {ap['estimated_snr_db']:g} dB · same adapter/channel survey"
                    else:body[i]='AP SNR: unavailable · needs measured signal AND noise'
                if line.startswith('AP signal here:') and ap.get('signal_samples',0)==0 and ap.get('last_signal_dbm') is not None:
                    body[i]=line+f" · last value {ap['last_signal_dbm']:g} dBm (old)"
            if page in ('link','link_evidence'):
                if ap.get('snr_db') is not None:body.append(f"AP SNR here: {ap['snr_db']:g} dB · packet-paired calculation")
                elif ap.get('estimated_snr_db') is not None:body.append(f"Estimated AP SNR here: {ap['estimated_snr_db']:g} dB · survey-based")
        if page=='capture_status':
            for name,radio in data.get('radios',{}).items():
                counts=radio.get('metadata_samples',{})
                if counts:body.append(f"{name} metadata: signal {counts.get('signal',0)}/{counts.get('frames',0)}, noise {counts.get('noise',0)}/{counts.get('frames',0)} frames")
        return title,visible_measurement_rows(body),items
    ns['page_data']=pages
