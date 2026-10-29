"""Offline tests: actual decode library, simulated sessions, exports and API isolation."""
import copy,json,os,queue,socket,sys,tempfile,threading,time,unittest,urllib.error,urllib.request
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src/vehicle'),str(ROOT/'src/vehicle/vendor')]
from cloverkit_vehicle.engine import Engine,Demo,Worker
from cloverkit_vehicle.backend import decode_messages,Backend,legacy_dtc_extension
from cloverkit_vehicle.profiles import formula,validate
from cloverkit_vehicle.reference import Reference
from cloverkit_vehicle.storage import Storage
from cloverkit_vehicle.adapters import usb_adapters,BluetoothSerial,bluetooth_status
from cloverkit_vehicle.service import API,Server,handler

def wait(test,condition,timeout=8):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        if condition():return
        time.sleep(.02)
    test.fail('Timed out waiting for '+str(condition))

class ReferenceTests(unittest.TestCase):
    def test_whole_offline_database_and_provenance(self):
        r=Reference();catalog=r.catalog();self.assertGreater(catalog['counts']['definitions'],28000)
        self.assertIn('FORD',catalog['counts']['makes']);self.assertEqual(len(catalog['sources']),3)
        self.assertIn('misfire',r.describe('P0301')['description'].lower())
    def test_unknown_and_manufacturer_isolation(self):
        r=Reference();self.assertEqual(r.describe('P1690')['definitions'],[])
        rows=r.query('P1690','FORD');self.assertTrue(rows);self.assertTrue(all(row['make'] in ('GENERIC','FORD') for row in rows))
        self.assertEqual(r.query("' OR 1=1 --"),[])
    def test_conflicting_sources_preserved(self):
        rows=Reference().query('P0420');self.assertGreaterEqual(len(rows),2)
        self.assertEqual({r['source'] for r in rows},{'obdex','dtc-database'})

class DecoderTests(unittest.TestCase):
    def message(self,data,ecu=0x7e8):return SimpleNamespace(data=bytearray(data),tx_id=ecu,ecu=2)
    def test_real_rpm_zero_short_frame_and_multi_ecu(self):
        import obd
        result=decode_messages(obd.commands.RPM,[self.message([0x41,0x0c,0,0]),self.message([0x41,0x0c,0x1f,0x40],0x7e9)])
        self.assertEqual(result[0]['value'],0);self.assertEqual(result[0]['state'],'measured');self.assertEqual(result[1]['value'],2000)
        self.assertEqual(result[1]['ecu'],'0x7e9')
        short=decode_messages(obd.commands.RPM,[self.message([0x41,0x0c,0x1f])])[0]
        self.assertEqual(short['state'],'invalid');self.assertIsNone(short['value'])
    def test_no_response_negative_and_wrong_pid(self):
        import obd
        self.assertEqual(decode_messages(obd.commands.SPEED,[])[0]['state'],'no_response')
        self.assertEqual(decode_messages(obd.commands.SPEED,[self.message([0x7f,1,0x12])])[0]['state'],'negative_response')
        self.assertEqual(decode_messages(obd.commands.SPEED,[self.message([0x41,5,0])])[0]['state'],'invalid')
    def test_dtc_status_payload_uses_upstream_decoder(self):
        import obd
        for request,service in [('GET_DTC',0x43),('GET_CURRENT_DTC',0x47)]:
            result=decode_messages(getattr(obd.commands,request),[self.message([service,1,3,1])])
            self.assertEqual(result[0]['value'][0][0],'P0301')
    def test_legacy_pending_and_permanent_normalization(self):
        import obd
        from obd.decoders import dtc
        protocol=SimpleNamespace(parse_message=lambda message:False)
        legacy_dtc_extension(protocol)
        for service in (0x47,0x4a):
            message=SimpleNamespace(frames=[SimpleNamespace(data=bytearray([service,3,1]))],tx_id=0x10)
            self.assertTrue(protocol.parse_message(message))
            command=obd.OBDCommand('TEST','Test',bytes([service-0x40]).hex().encode(),0,dtc)
            self.assertEqual(decode_messages(command,[message])[0]['value'][0][0],'P0301')
    def test_safe_formula_and_profile_writes_rejected(self):
        self.assertEqual(formula('(A*256+B)/4',bytes([0x1f,0x40])),2000)
        for bad in ("__import__('os').system('echo BAD')",'A**100000','A<<100','A/0','Z'):
            with self.subTest(bad=bad),self.assertRaises((ValueError,ZeroDivisionError)):formula(bad,bytes([1]))
        profile=dict(id='example',applicability={'make':'Example'},source='https://example.invalid',license='CC0',verification='unverified',commands=[dict(request='0400',header='7E0',bytes=2,formula='A',unit='x',name='bad')])
        with self.assertRaises(ValueError):validate(profile)

class AdapterTests(unittest.TestCase):
    def test_real_worker_rejects_native_uart_without_opening_it(self):
        worker=Worker()
        try:
            with self.assertRaisesRegex(ConnectionError,'Selected port'):
                worker.call('connect',port='/dev/ttyS0',baud=38400,timeout=20)
        finally:worker.close()
        self.assertIsNotNone(worker.process.poll())
    def test_discovery_excludes_flipper_and_native_uart_without_opening(self):
        def port(device,vid=0x403,pid=0x6001,description='USB serial'):
            return SimpleNamespace(device=device,vid=vid,pid=pid,description=description,manufacturer='',product='',serial_number='A',location='1-1')
        ports=[port('/dev/ttyS0'),port('/dev/ttyACM0',0x0483,0x5740,'Flipper Zero'),port('/dev/ttyUSB0')]
        with patch('serial.Serial') as serial:self.assertEqual([p['device'] for p in usb_adapters(ports)],['/dev/ttyUSB0']);serial.assert_not_called()
    def test_bluetooth_missing_controller_and_non_spp(self):
        with patch('cloverkit_vehicle.adapters.shutil.which',return_value='/bin/bluetoothctl'),patch('cloverkit_vehicle.adapters.command',return_value=''):
            self.assertEqual(bluetooth_status()['state'],'unavailable')
        with patch('cloverkit_vehicle.adapters.shutil.which',return_value='/bin/bluetoothctl'),patch('cloverkit_vehicle.adapters.command',side_effect=ValueError('controller timed out')):
            self.assertEqual(bluetooth_status()['state'],'unavailable')
        with patch('cloverkit_vehicle.adapters.command',side_effect=['Paired: yes','Service Name: BLE only']):
            with self.assertRaisesRegex(ValueError,'Serial Port Profile'):BluetoothSerial('AA:BB:CC:DD:EE:FF').open()

class SessionTests(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.e=Engine(self.tmp.name)
    def tearDown(self):self.e.close();self.tmp.cleanup()
    def demo(self):
        self.e.submit('demo');wait(self,lambda:self.e.snapshot()['state']=='connected')
    def scan(self):
        old=(self.e.snapshot().get('scan') or {}).get('id');self.e.submit('scan')
        wait(self,lambda:(self.e.snapshot().get('scan') or {}).get('complete') and self.e.snapshot()['scan']['id']!=old)
        return self.e.snapshot()['scan']
    def test_demo_full_scan_records_comparison_and_exports(self):
        self.demo();a=self.scan();b=self.scan()
        self.assertEqual({c['status'] for c in b['codes']},{'stored','pending'})
        self.assertEqual(b['coverage']['PERMANENT_DTC'][0]['state'],'measured')
        self.assertTrue(b['freeze_frames']);self.assertTrue(b['readiness']);self.assertTrue(b['demo'])
        self.assertEqual(self.e.storage.compare(a['id'],b['id'])['added'],[])
        self.assertEqual(json.loads(self.e.storage.export(b['id'],'json'))['codes'],b['codes'])
        self.assertIn('DEMO',self.e.storage.export(b['id'],'html'))
        self.e.submit('record',enabled=True);wait(self,lambda:bool(self.e.snapshot()['recording']));key=self.e.snapshot()['recording']
        wait(self,lambda:bool(self.e.snapshot()['live']));time.sleep(.5);self.e.submit('record',enabled=False);wait(self,lambda:not self.e.snapshot()['recording'])
        self.assertIn('RPM',self.e.storage.csv(key));self.assertIsNotNone(self.e.storage.recordings()[0]['ended'])
    def test_demo_never_clears_and_unknown_vehicle_comparison_refused(self):
        self.demo();self.e.submit('prepare_clear');wait(self,lambda:bool(self.e.snapshot()['error']))
        self.assertIn('disabled',self.e.snapshot()['error']);self.assertIsNone(self.e.clear_ticket)
        a=self.scan();b=copy.deepcopy(a);b['id']='other';b['vehicle']['id']='other';self.e.storage.save(b)
        with self.assertRaises(ValueError):self.e.storage.compare(a['id'],b['id'])
    def test_stale_and_disconnect_finalize_recording(self):
        self.demo()
        with self.e.lock:self.e.state['live']['test']=dict(time=time.time()-20,state='measured',value=0,unit='V')
        self.assertEqual(self.e.snapshot()['live']['test']['state'],'stale')
        self.e.submit('record',enabled=True);wait(self,lambda:bool(self.e.snapshot()['recording']))
        self.e.submit('disconnect');wait(self,lambda:self.e.snapshot()['state']=='disconnected')
        self.assertIsNotNone(self.e.storage.recordings()[0]['ended'])
    def test_clear_requires_fresh_single_use_ticket_and_preclear_save(self):
        self.demo();self.e.state['demo']=False
        class Clearable(Demo):
            def __init__(self):super().__init__();self.clears=0
            def call(self,op,**kwargs):
                if op=='clear':self.clears+=1;return {'state':'acknowledged'}
                return super().call(op,**kwargs)
        backend=Clearable();self.e.backend=backend;self.e.selected=[]
        self.e.submit('prepare_clear');wait(self,lambda:bool(self.e.snapshot().get('clear_confirmation')))
        ticket=self.e.snapshot()['clear_confirmation'];self.assertTrue(self.e.storage.get(ticket['preclear_scan']))
        self.e.submit('clear',token=ticket['token'],confirm='wrong');wait(self,lambda:bool(self.e.snapshot()['error']));self.assertEqual(backend.clears,0)
        self.e.submit('prepare_clear');wait(self,lambda:bool(self.e.snapshot().get('clear_confirmation')))
        token=self.e.snapshot()['clear_confirmation']['token'];self.e.submit('clear',token=token,confirm='CLEAR ENGINE CODES')
        wait(self,lambda:backend.clears==1 and self.e.snapshot()['state']=='connected')
        self.e.submit('clear',token=token,confirm='CLEAR ENGINE CODES');wait(self,lambda:bool(self.e.snapshot()['error']))
        self.assertEqual(backend.clears,1)
    def test_worker_cancellation_terminates_owner(self):
        class Slow:
            def __init__(self):self.closed=False
            def call(self,op,cancel=None,**kwargs):
                while not cancel.wait(.01):pass
                raise InterruptedError('Cancelled')
            def close(self):self.closed=True
        worker=Slow();self.e.backend=worker;self.e.state['state']='connected';self.e.state['supported']=[{'id':'STATUS'}]
        self.e.submit('scan');wait(self,lambda:self.e.snapshot()['state']=='scanning');self.e.submit('cancel')
        wait(self,lambda:self.e.snapshot()['state']=='cancelled');self.assertTrue(worker.closed)
        self.assertFalse(self.e.storage.get(self.e.storage.list()[0]['id'])['complete'])

class APITests(unittest.TestCase):
    def test_auth_csrf_and_shared_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine=Engine(tmp);server=Server(('127.0.0.1',0),handler(API(engine),'test-token'))
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();url='http://127.0.0.1:'+str(server.server_port)
            def req(path,token='',body=None,origin=None):
                headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'}
                if origin:headers['Origin']=origin
                request=urllib.request.Request(url+path,data=json.dumps(body).encode() if body else None,headers=headers)
                with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request) as r:return json.load(r)
            try:
                with self.assertRaises(urllib.error.HTTPError) as result:req('/api/state')
                self.assertEqual(result.exception.code,401)
                result.exception.close()
                with self.assertRaises(urllib.error.HTTPError) as result:req('/api/action','test-token',{'op':'demo'},'http://foreign.invalid')
                self.assertEqual(result.exception.code,403)
                result.exception.close()
                req('/api/action','test-token',{'op':'demo'});wait(self,lambda:engine.snapshot()['state']=='connected')
                self.assertTrue(req('/api/state','test-token')['demo'])
                self.assertIn('P0301',[r['code'] for r in req('/api/lookup?q=P0301','test-token')])
            finally:server.shutdown();server.server_close();engine.close();thread.join()

if __name__=='__main__':unittest.main()
