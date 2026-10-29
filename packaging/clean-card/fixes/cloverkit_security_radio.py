"""Nearby-radio security evidence; no pairing, injection or automatic GATT connection."""
import asyncio,datetime,importlib.machinery,importlib.util,json,subprocess,time
from pathlib import Path
BLE_STATUS={'status':'not requested'}
BLE_RECORDS={}

def ble_output(seconds):
    global BLE_STATUS,BLE_RECORDS
    try:
        loader=importlib.machinery.SourceFileLoader('cloverkit_security_watch','/usr/local/bin/device-watch')
        spec=importlib.util.spec_from_loader(loader.name,loader);watch=importlib.util.module_from_spec(spec);loader.exec_module(watch)
        watch.live_event=lambda *args,**kwargs:None
        from cloverkit_ble_ready import scan_ready
        adapter,devices=asyncio.run(scan_ready(watch.select_bt_adapter(),seconds,watch.scan_ble))
        BLE_RECORDS=devices
        BLE_STATUS={'status':'checked','adapter':adapter,'devices':len(devices),'method':'advertisements; no connection'}
        lines=['Device '+str(record.get('address') or address)+' '+str(record.get('name') or '').replace('\n',' ') for address,record in devices.items()]
        return 0,'\n'.join(lines),''
    except Exception as error:
        BLE_STATUS={'status':'not checked','reason':str(error)}
        return 1,'',str(error)

def finding(code,severity,title,action,confidence='OBSERVED'):
    return dict(code=code,severity=severity,title=title,action=action,confidence=confidence,validation={'status':'OBSERVED','test':'Advertised configuration; no exploitation'})

def assess_wifi(row):
    findings=[]
    privacy=row.get('privacy');rsn=row.get('rsn',False);wpa=row.get('wpa',False)
    if privacy is False and not rsn and not wpa:
        findings.append(finding('WIFI_OPEN','LOW','Open Wi-Fi advertised without link encryption','Use a protected network for sensitive traffic; confirm any captive-portal policy.'))
    elif privacy is True and not rsn and not wpa:
        findings.append(finding('WIFI_LEGACY_PRIVACY','MEDIUM','Legacy privacy advertised without RSN/WPA','Confirm the actual protection; replace WEP or other obsolete protection.','POSSIBLE'))
    if wpa:findings.append(finding('WIFI_WPA1','MEDIUM','Legacy WPA1 compatibility advertised','Prefer WPA2-AES or WPA3; disable WPA1 when legacy clients are not required.'))
    if 'TKIP' in row.get('ciphers',[]):findings.append(finding('WIFI_TKIP','MEDIUM','TKIP cipher advertised','Prefer AES/CCMP or newer supported protection; remove TKIP where possible.'))
    if row.get('wps'):findings.append(finding('WIFI_WPS','LOW','WPS advertised; PIN vulnerability not tested','Disable WPS if it is not required.'))
    if not findings:
        protection='RSN' if rsn else 'WPA' if wpa else 'unknown'
        findings.append(finding('WIFI_PROTECTION','INFO','Advertised Wi-Fi protection: '+protection,'Review the advertised suites against your policy; this is not a negotiated-client or exploit test.'))
    return dict(bssid=row.get('bssid'),ssid=row.get('ssid'),frequency=row.get('freq'),signal_dbm=row.get('sig'),observed_by=row.get('observed_by',[]),advertised={k:row.get(k) for k in ('privacy','rsn','wpa','wps','ciphers','akms','pmf_capable','pmf_required') if row.get(k) is not None},findings=findings)

def collect_wifi():
    started=time.time()
    try:
        result=subprocess.run(['/usr/local/bin/cloverkit-device-watch-wifi'],capture_output=True,text=True,timeout=65)
        if result.returncode:return {'status':'not checked','reason':result.stderr.strip()[-350:]},[]
        manifest=Path('/run/cloverkit/wifi-groups.json')
        if manifest.stat().st_mtime<started-1:raise RuntimeError('No fresh Wi-Fi observation manifest')
        data=json.loads(manifest.read_text())
        return {'status':'checked','radios':data.get('coverage',[]),'notes':data.get('coverage_notes',[]),'method':'Wi-Fi discovery and advertised protection; native wlan0 excluded'},[assess_wifi(row) for row in data.get('rows',[])]
    except Exception as error:return {'status':'not checked','reason':str(error)},[]

def augment_report(path,wifi_status,wifi_devices,lan_status):
    path=Path(path);report=json.loads(path.read_text())
    report['wifi_devices']=wifi_devices
    report['coverage']={'wifi':wifi_status,'ble':report.get('ble_coverage',{'status':'not checked'}),'lan':lan_status}
    if lan_status.get('status')=='not connected':report['target']='Nearby radios'
    temporary=path.with_suffix('.new.json');temporary.write_text(json.dumps(report,indent=2)+'\n');temporary.replace(path)
    return report
