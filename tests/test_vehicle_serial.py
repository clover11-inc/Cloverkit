"""Linux pseudo-terminal integration with the actual pinned python-OBD stack.

No real serial device is opened. USB inventory is injected with this test's PTY.
"""
import os,select,sys,threading,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src/vehicle'),str(ROOT/'src/vehicle/vendor')]
from cloverkit_vehicle.backend import Backend

def bitmap(pids,base):return sum(1<<(32-(p-base)) for p in pids if base<p<=base+32).to_bytes(4,'big')
def frames(payload,ecu='7E8'):
    payload=bytes(payload)
    if len(payload)<=7:return ecu+' '+bytes([len(payload)]).hex()+' '+payload.hex()
    lines=[ecu+' '+bytes([0x10|len(payload)>>8,len(payload)&255]).hex()+' '+payload[:6].hex()]
    for i,start in enumerate(range(6,len(payload),7),1):lines.append(ecu+' '+bytes([0x20|(i&15)]).hex()+' '+payload[start:start+7].hex())
    return '\r'.join(lines)

@unittest.skipUnless(sys.platform.startswith('linux'),'Linux pseudo-terminal test')
class SerialIntegration(unittest.TestCase):
    def setUp(self):
        import pty
        self.master,self.slave=pty.openpty();self.port=os.ttyname(self.slave);self.stop=threading.Event();self.seen=[];self.short=False
        self.thread=threading.Thread(target=self.emulate,daemon=True);self.thread.start();self.backend=Backend()
        self.inventory=patch('cloverkit_vehicle.adapters.usb_adapters',return_value=[{'device':self.port}]);self.inventory.start()
    def tearDown(self):
        self.backend.close();self.inventory.stop();self.stop.set();self.thread.join(timeout=2);os.close(self.master);os.close(self.slave)
    def respond(self,cmd):
        self.seen.append(cmd)
        if cmd=='ATZ':return 'ELM327 v2.1'
        if cmd=='ATI':return 'ELM327 v2.1'
        if cmd=='ATDPN':return 'A6'
        if cmd in ('ATRV','AT RV'):return '13.8V'
        if cmd.startswith('AT'):return 'OK'
        if cmd=='0100':return frames(b'\x41\x00'+bitmap([1,2,5,12,13,17,32],0))
        if cmd=='0120':return frames(b'\x41\x20'+bitmap([64],32))
        if cmd=='0140':return frames(b'\x41\x40'+bitmap([96],64))
        if cmd=='0160':return frames(b'\x41\x60'+bitmap([97],96))
        if cmd=='0161':return frames(b'\x41\x61\x7d')
        if cmd=='0101':return frames(bytes.fromhex('41018107A000'))
        if cmd=='0102':return frames(bytes.fromhex('41020301'))
        if cmd=='0105':return frames(bytes.fromhex('41057B'))
        if cmd=='010C':return frames(bytes.fromhex('410C1F' if self.short else '410C1F40'))+'\r'+frames(bytes.fromhex('410C0000'),'7E9')
        if cmd=='010D':return frames(bytes.fromhex('410D00'))
        if cmd=='0111':return frames(bytes.fromhex('411120'))
        if cmd=='020C00':return frames(bytes.fromhex('420C001F40'))
        if cmd=='0900':return frames(bytes.fromhex('490040000000'))
        if cmd=='0902':return frames(b'\x49\x02\x01' + b'1HGBH41JXMN109186')
        if cmd=='0600':return 'NO DATA'
        if cmd=='03':return frames(bytes.fromhex('43010301'))
        if cmd=='07':return frames(bytes.fromhex('47010171'))
        if cmd=='0A':return frames(bytes.fromhex('4A010420'))
        if cmd=='04':return frames(bytes.fromhex('44'))
        return 'NO DATA'
    def emulate(self):
        pending=b''
        while not self.stop.is_set():
            ready,_,_=select.select([self.master],[],[],.1)
            if not ready:continue
            try:data=os.read(self.master,4096)
            except OSError:break
            pending+=data
            while b'\r' in pending:
                request,pending=pending.split(b'\r',1);cmd=request.decode('ascii',errors='ignore').strip().upper()
                os.write(self.master,(self.respond(cmd)+'\r>').encode())
    def test_real_protocol_stack_scan_decoding_and_extended_parameter(self):
        result=self.backend.connect(self.port,38400)
        self.assertEqual(result['protocol_id'],'6')
        self.assertEqual(self.backend.query('GET_DTC')[0]['value'][0][0],'P0301')
        self.assertEqual(self.backend.query('GET_CURRENT_DTC')[0]['value'][0][0],'P0171')
        self.assertEqual(self.backend.query('PERMANENT_DTC')[0]['value'][0][0],'P0420')
        rpm=self.backend.query('RPM');self.assertEqual({r['value'] for r in rpm},{0,2000})
        self.assertEqual(self.backend.query('DTC_RPM')[0]['value'],2000)
        self.assertEqual(self.backend.query('VIN')[0]['value'],'1HGBH41JXMN109186')
        self.assertEqual(self.backend.query('PID01_61')[0]['value'],0)
        self.short=True;self.assertEqual(self.backend.query('RPM')[0]['state'],'invalid')
        self.assertNotIn('04',self.seen)  # no clearing during connection, discovery or reads

if __name__=='__main__':unittest.main()
