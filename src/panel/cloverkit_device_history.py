"""Device Watch history and advertisement enrichment using its existing scanners."""
from cloverkit_insights import atomic_json, ble_details, history_update, load_json, text
from pathlib import Path

STATE=Path('/var/lib/cloverkit/device-history/latest.json')

def record(ble_devices, wifi_result, ble_complete=True):
    observations=[dict(transport='ble',address=r['address'],name=text(r.get('name')),details=ble_details(r)) for r in ble_devices.values()]
    complete=['ble'] if ble_complete else []
    if wifi_result.get('status')=='ok' and wifi_result.get('sample_ok',True):
        complete.append('wifi')
        for row in wifi_result.get('rows',[]):
            address=row.get('bssid') or row.get('BSSID')
            if address: observations.append(dict(transport='wifi',address=address,ssid=text(row.get('ssid')),name=text(row.get('ap_name') or row.get('hostname')),details=row))
    data=history_update(load_json(STATE),observations,complete)
    atomic_json(STATE,data)
    print('DEVICE HISTORY: '+str(len(data['devices']))+' retained identities; '+str(len(data['events']))+' events',flush=True)
    for event in data['events'][-10:]: print('History: '+event['event']+' | '+event['device'],flush=True)
    for link in data['possible_correlations']: print('Possible Wi-Fi/BLE relation: '+link['wifi']+' / '+link['ble']+' | matching advertised name only',flush=True)
    for observation in observations:
        if observation['transport']=='ble':
            services=', '.join(r['name'] for r in observation['details']['services'])
            if services: print('BLE services: '+observation['address']+' | '+services,flush=True)
    print('Detailed history: '+str(STATE),flush=True)
    return data
