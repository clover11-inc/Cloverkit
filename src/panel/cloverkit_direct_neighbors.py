"""Reuse Ethernet's existing passive L2 helper inside Direct Ethernet sessions."""
from pathlib import Path
import subprocess
import time
from cloverkit_insights import atomic_json, text

NEIGHBOR_FIELDS=['lldp.tlv.system.name','lldp.port.id','lldp.port.desc','lldp.mgn.addr.ip4','cdp.deviceid','cdp.portid','cdp.native_vlan','cdp.platform','vlan.id']

class NeighborEvidence:
    def __init__(self,folder,log):
        self.folder=Path(folder);self.log=log;self.process=None;self.output=None;self.buffer='';self.last={};self.previous=None
    def start(self):
        if self.process is not None:return
        args=['/usr/local/bin/ethernet-l2-capture']
        for field in NEIGHBOR_FIELDS:args+=['-e',field]
        # Separate reader/writer file descriptions: a shared file offset would
        # make the reader start after data written by the decoder.
        path=self.folder/'neighbors.tsv'
        with path.open('w') as writer:
            self.process=subprocess.Popen(args,stdout=writer,stderr=subprocess.DEVNULL)
        self.output=path.open('r')
        self.buffer='';self.last={};self.previous=None
    def consume(self,line):
        cells=line.rstrip('\n').split('\t');cells+=['']*max(0,len(NEIGHBOR_FIELDS)-len(cells));d=dict(zip(NEIGHBOR_FIELDS,cells))
        fields=dict(interface='eth0',link='UP',switch=text(d['cdp.deviceid'] or d['lldp.tlv.system.name']) or '--',
                    port=text(d['cdp.portid'] or d['lldp.port.id']) or '--',port_desc=text(d['lldp.port.desc']) or '--',
                    mgmt=text(d['lldp.mgn.addr.ip4']) or '--',native_vlan=text(d['cdp.native_vlan']) or '--',
                    platform=text(d['cdp.platform']) or '--',vlans=text(d['vlan.id']) or '--',
                    protocols='CDP' if d['cdp.deviceid'] else 'LLDP' if d['lldp.tlv.system.name'] else 'passive L2',stale=False,updated_at=time.time())
        # Keep advertisements from the same session; empty protocol fields do
        # not erase another protocol's observations.
        for key,value in fields.items():
            if value!='--' or key not in self.last:self.last[key]=value
        signature=tuple(self.last.get(k) for k in ('switch','port','native_vlan','vlans'))
        if signature!=self.previous:
            if self.last.get('switch')!='--':self.log('L2 NEIGHBOR: '+self.last['switch']+' | port '+self.last.get('port','--'))
            if self.last.get('native_vlan') not in (None,'--'):self.log('Advertised native VLAN: '+self.last['native_vlan'])
            if self.last.get('vlans') not in (None,'--'):self.log('Observed VLAN tags: '+self.last['vlans']+' (incomplete view)')
            self.previous=signature
        try:atomic_json('/var/lib/cloverkit/ethernet-evidence/latest.json',self.last)
        except OSError as error:self.log('L2 report unavailable: '+text(error))
    def poll(self):
        if self.output is None:return
        self.output.flush();self.buffer+=self.output.read()
        while '\n' in self.buffer:
            line,self.buffer=self.buffer.split('\n',1);self.consume(line)
        if self.process and self.process.poll() is not None:
            self.log('Passive L2 helper stopped: '+str(self.process.returncode));self.stop()
    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(3)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(3)
        self.process=None
        if self.output is not None:self.output.close();self.output=None
        if self.last:
            self.last.update(stale=True,updated_at=time.time())
            try:atomic_json('/var/lib/cloverkit/ethernet-evidence/latest.json',self.last)
            except OSError:pass
