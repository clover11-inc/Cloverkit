#!/usr/bin/env python3
"""Report tools for existing CloverKit captures and measurements; no new capture engine."""
import argparse
import datetime
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import time
from cloverkit_insights import PacketEvidence, atomic_json, load_json, survey_point, topology

LATEST=Path('/var/lib/cloverkit/wifi-passive-health/latest.json')
SURVEY=Path('/var/lib/cloverkit/site-survey/points.json')
PACKET_FIELDS=['frame.time_epoch','frame.len','_ws.col.Protocol','eth.src','eth.dst','ip.src','ip.dst','udp.srcport','udp.dstport',
               'dns.id','dns.flags.response','dns.flags.rcode','dns.qry.name','dhcp.id','dhcp.hw.mac_addr','dhcp.option.dhcp',
               'tcp.stream','tcp.analysis.retransmission','tcp.analysis.fast_retransmission','tcp.analysis.spurious_retransmission',
               'arp.src.proto_ipv4','arp.src.hw_mac','wlan.bssid','wlan.ta','wlan.ra','wlan.fc.type','wlan.fc.subtype',
               'wlan.fc.tods','wlan.fc.fromds','wlan.fixed.current_ap','wlan.fixed.status_code','wlan.fixed.reason_code','wlan.seq','wlan.frag']
active=None

def stop(*_):
    if active is not None and active.poll() is None: active.terminate()
    raise KeyboardInterrupt

def supported(fields):
    # Offline validation against a tiny empty pcap; no interfaces opened.
    with tempfile.TemporaryDirectory() as folder:
        p=Path(folder)/'empty.pcap'; p.write_bytes(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
        remaining=list(fields)
        for _ in range(len(fields)+1):
            args=['tshark','-n','-r',str(p),'-T','fields']
            for f in remaining: args+=['-e',f]
            result=subprocess.run(args,capture_output=True,text=True,timeout=30)
            if not result.returncode: return remaining
            invalid={line.strip() for line in result.stderr.splitlines() if line.strip() in remaining}
            if not invalid: raise RuntimeError('TShark validation failed: '+result.stderr[-500:])
            remaining=[f for f in remaining if f not in invalid]
        raise RuntimeError('Unable to validate decoder fields')

def analyze(path,limit=200000):
    global active
    fields=supported(PACKET_FIELDS); missing=sorted(set(PACKET_FIELDS)-set(fields)); evidence=PacketEvidence()
    args=['tshark','-n','-r',str(path),'-c',str(limit),'-T','fields','-E','separator=/t','-E','occurrence=f']
    for f in fields: args+=['-e',f]
    with tempfile.TemporaryFile(mode='w+') as errors:
        active=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=errors,text=True)
        try:
            for line in active.stdout:
                cells=line.rstrip('\n').split('\t'); cells+=['']*max(0,len(fields)-len(cells)); evidence.ingest(dict(zip(fields,cells)))
            rc=active.wait()
            if rc:
                errors.seek(0); raise RuntimeError('Capture decoding failed: '+errors.read()[-800:])
        finally:
            if active.poll() is None:
                active.terminate()
                try: active.wait(3)
                except subprocess.TimeoutExpired: active.kill(); active.wait(3)
            active.stdout.close()
            active=None
    data=evidence.snapshot(); data.update(source=str(path),unsupported_fields=missing,frame_limit=limit,possibly_truncated=evidence.frames>=limit)
    return data

HTML='''<!doctype html><meta charset="utf-8"><title>CloverKit Site Survey</title>
<style>body{font:16px system-ui;margin:24px;background:#101a23;color:#eef3f6}button,input,select{font:inherit;margin:6px;padding:8px}canvas{background:#253441;max-width:100%;border:1px solid #718395}#detail{white-space:pre-wrap}label{display:inline-block}</style>
<h1>CloverKit Site Survey</h1><p>Measured locations only. Colour shows received signal at the survey device; no coverage is interpolated.</p>
<label>Floor plan <input type="file" id="plan" accept="image/*"></label>
<label>Band <select id="band"><option value="all">All bands</option><option value="2.4">2.4 GHz</option><option value="5">5 GHz</option><option value="6">6 GHz</option></select></label>
<label>AP <select id="ap"><option value="all">Strongest measured AP</option></select></label>
<p>Green ≥ −67 dBm · Amber ≥ −75 dBm · Red below −75 dBm · Grey no selected measurement.</p>
<canvas id="map" width="1000" height="700"></canvas><pre id="detail">Select a point for measurements.</pre>
<script>const points=__POINTS__;const canvas=document.getElementById('map'),ctx=canvas.getContext('2d'),detail=document.getElementById('detail');let image=null;
const b=f=>f<2500?'2.4':f<5925?'5':'6';const unique=new Map();points.forEach(p=>p.aps.forEach(a=>unique.set(a.bssid,a.beacon_ap_name||a.ssid||a.bssid)));
unique.forEach((name,id)=>{let o=document.createElement('option');o.value=id;o.textContent=name+' / '+id;document.getElementById('ap').appendChild(o)});
function rows(p){return p.aps.filter(a=>(band.value==='all'||b(a.frequency)===band.value)&&(ap.value==='all'||a.bssid===ap.value))}
function draw(){ctx.clearRect(0,0,canvas.width,canvas.height);if(image)ctx.drawImage(image,0,0,canvas.width,canvas.height);else{ctx.strokeStyle='#4e6475';for(let x=0;x<=4;x++){ctx.beginPath();ctx.moveTo(x*250,0);ctx.lineTo(x*250,700);ctx.stroke()}for(let y=0;y<=4;y++){ctx.beginPath();ctx.moveTo(0,y*175);ctx.lineTo(1000,y*175);ctx.stroke()}}
points.forEach(p=>{let r=rows(p),v=r.length?Math.max(...r.map(a=>a.signal_dbm)):null;ctx.fillStyle=v===null?'#8a9398':v>=-67?'#44d27c':v>=-75?'#ffcb54':'#fa665f';ctx.beginPath();ctx.arc(p.x*1000,p.y*700,12,0,Math.PI*2);ctx.fill();ctx.fillStyle='#fff';ctx.font='14px system-ui';ctx.fillText(p.location,p.x*1000+16,p.y*700+5)})}
canvas.onclick=e=>{let rect=canvas.getBoundingClientRect(),x=(e.clientX-rect.left)/rect.width,y=(e.clientY-rect.top)/rect.height;let p=points.reduce((best,p)=>!best||Math.hypot(p.x-x,p.y-y)<Math.hypot(best.x-x,best.y-y)?p:best,null);if(p){detail.textContent=p.location+' / '+new Date(p.time*1000).toLocaleString()+'\\n'+rows(p).map(a=>(a.beacon_ap_name||a.ssid||a.bssid)+' / '+a.bssid+' / '+a.frequency+' MHz / '+a.signal_dbm+' dBm / '+a.signal_samples+' samples').join('\\n')}};
document.getElementById('plan').onchange=e=>{const file=e.target.files[0];if(!file)return;let url=URL.createObjectURL(file);image=new Image();image.onload=()=>{draw();URL.revokeObjectURL(url)};image.src=url};document.getElementById('band').onchange=draw;document.getElementById('ap').onchange=draw;const band=document.getElementById('band'),ap=document.getElementById('ap');draw();</script>'''

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__); sub=p.add_subparsers(dest='mode',required=True)
    packet=sub.add_parser('packets'); packet.add_argument('capture',nargs='?'); packet.add_argument('--limit',type=int,default=200000)
    top=sub.add_parser('topology'); top.add_argument('--json',action='store_true')
    export=sub.add_parser('survey-export'); export.add_argument('--output',default=str(Path.home()/'cloverkit-site-survey.html'))
    record=sub.add_parser('survey-record'); record.add_argument('--location',required=True); record.add_argument('--x',type=float,required=True); record.add_argument('--y',type=float,required=True)
    history=sub.add_parser('history'); history.add_argument('--json',action='store_true')
    a=p.parse_args(argv)
    for sig in (signal.SIGINT,signal.SIGTERM): signal.signal(sig,stop)
    if a.mode=='packets':
        if not 1<=a.limit<=1000000: p.error('Frame limit must be 1–1000000')
        capture=Path(a.capture) if a.capture else max((f for f in Path('/mnt/captures').rglob('*') if f.is_file() and f.suffix.lower() in ('.pcap','.pcapng','.cap')),key=lambda f:f.stat().st_mtime,default=None)
        if capture is None: print('No saved capture found. Save a capture with the existing packet tool first.'); return 1
        data=analyze(capture,a.limit)
        for key in ('frames','duration_seconds','dns_unanswered_after_5s','dns_error_codes','dhcp_incomplete_transactions','dhcp_nak_transactions','tcp_retransmission_percent','arp_address_changes','broadcast_frames_per_second'):
            print(key.replace('_',' ').title()+': '+str(data[key]))
        for finding in data['findings']: print('Finding: '+finding)
        for note in data['limitations']: print('Note: '+note)
        folder=Path('/var/lib/cloverkit/packet-insights') if os.geteuid()==0 else Path.home()/'.local/share/cloverkit/packet-insights'; path=folder/('analysis-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'.json')
        atomic_json(path,data); print('Report: '+str(path)); return 0
    if a.mode=='topology':
        result=subprocess.run(['ip','-j','neigh','show'],capture_output=True,text=True,timeout=5)
        neighbors=json.loads(result.stdout) if result.returncode==0 else []
        ethernet=load_json('/var/lib/cloverkit/ethernet-evidence/latest.json')
        if time.time()-ethernet.get('updated_at',0)>10: ethernet=dict(ethernet,stale=True)
        graph=topology(load_json(LATEST),ethernet,[r for r in neighbors if r.get('dev') in ('eth0','wlan1','wlan2')])
        if a.json: print(json.dumps(graph,indent=2))
        else:
            print('OBSERVED NETWORK TOPOLOGY')
            for edge in graph['edges']: print(edge['source']+' -> '+edge['target']+' | '+edge['relation']+' | '+str(edge['evidence']))
            for note in graph['limitations']: print('Note: '+note)
        return 0
    if a.mode=='history':
        data=load_json('/var/lib/cloverkit/device-history/latest.json')
        if a.json: print(json.dumps(data,indent=2))
        else:
            print('DEVICE APPEARANCE HISTORY')
            events=data.get('events',[])
            if not events:
                print('No history recorded yet. Run Device Watch once, then reopen this page.')
                print('Later scans show appearances, reappearances, SSID changes and devices not seen again.')
            else:
                print(str(len(data.get('devices',{})))+' retained identities | '+str(len(events))+' saved events')
                print('Newest 40 events below. Not seen does not prove a device left.')
            for event in data.get('events',[])[-40:]: print(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(event['time']))+' | '+event['event']+' | '+event['device'])
            for link in data.get('possible_correlations',[]): print('Possible relation: '+json.dumps(link))
        return 0
    if a.mode=='survey-export':
        data=load_json(SURVEY,{'points':[]}); encoded=json.dumps(data.get('points',[])).replace('<','\\u003c')
        Path(a.output).write_text(HTML.replace('__POINTS__',encoded),encoding='utf-8')
        print('Interactive survey export: '+a.output); print('Open in a browser and add your floor-plan image.'); return 0
    if a.mode=='survey-record':
        if not 0<=a.x<=1 or not 0<=a.y<=1: p.error('Coordinates must be between 0 and 1')
        request=json.dumps(dict(location=a.location,x=a.x,y=a.y))
        result=subprocess.run(['sudo','-n','/usr/local/bin/cloverkit-survey-store'],input=request,capture_output=True,text=True,timeout=5)
        print(result.stdout.strip() or result.stderr.strip()); return result.returncode

def survey_store():
    """Root-owned no-argument writer, restricted to fresh current snapshot points."""
    if os.geteuid()!=0 or len(sys.argv)!=1: raise SystemExit('Use installed no-argument survey writer')
    try:
        request=json.loads(sys.stdin.read(4097))
        if not isinstance(request,dict): raise ValueError('Invalid survey request')
        if set(request)=={'row','column'}:
            row=request['row']; column=request['column']
            if type(row)!=int or type(column)!=int or not 0<=row<5 or not 0<=column<5: raise ValueError('Invalid grid coordinate')
            location=f'R{row+1} C{column+1}'; x=.05+column*.225; y=.05+row*.225
        elif set(request)=={'location','x','y'}:
            if not isinstance(request['location'],str) or not request['location'].strip() or len(request['location'])>80: raise ValueError('Invalid location name')
            location=request['location']; x=request['x']; y=request['y']
            if type(x) not in (int,float) or type(y) not in (int,float): raise ValueError('Invalid coordinates')
        else: raise ValueError('Invalid survey request')
        snapshot=load_json(LATEST)
        if not snapshot or time.time()-snapshot.get('updated_at',0)>10 or snapshot.get('state')!='RUNNING': raise ValueError('No current running scan snapshot')
        point=survey_point(snapshot,location,x,y)
        import fcntl
        SURVEY.parent.mkdir(parents=True,exist_ok=True)
        with (SURVEY.parent/'writer.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            saved=load_json(SURVEY,{'points':[]}); saved['points']=(saved.get('points',[])+[point])[-250:]
            atomic_json(SURVEY,saved)
        print(json.dumps(dict(status='saved',message='Saved '+point['location']+' with '+str(len(point['aps']))+' fresh AP readings')))
    except (OSError,ValueError,TypeError) as error:
        print(json.dumps(dict(status='failed',message=str(error)))); return 2
    return 0

if __name__=='__main__':
    try: raise SystemExit(main())
    except KeyboardInterrupt: print('Analysis stopped; child decoder terminated.'); raise SystemExit(130)
