import sys,tempfile,unittest,time
from pathlib import Path
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/'src/vehicle'),str(Path(__file__).resolve().parents[1]/'src/vehicle/vendor')]
from cloverkit_vehicle.traffic import Journal,event,read_command,SerialTap
from cloverkit_vehicle.engine import Engine
class RemoteTests(unittest.TestCase):
 def test_read_policy(self):
  candidates={'RPM':'010C','CLEAR_DTC':'04','GET_DTC':'03'}
  for text in ('RPM','010C','01 0C'):self.assertEqual(read_command(text,candidates),'RPM')
  self.assertEqual(read_command('ATI',candidates),'ELM_VERSION')
  for text in ('04','CLEAR_DTC','ATZ','ATSP0','2E1234','010C\r04','010D'):
   with self.assertRaises(ValueError):read_command(text,candidates)
 def test_serial_proxy_captures_only_actual_bytes(self):
  class Port:
   timeout=1
   def write(self,data):return 2
   def read(self,size):return b'41\r>'
  rows=[];tap=SerialTap(Port(),lambda d,b:rows.append((d,b)),lambda:True)
  self.assertEqual(tap.write(b'010C\r'),2);self.assertEqual(tap.read(9),b'41\r>');tap.timeout=3
  self.assertEqual(tap._port.timeout,3);self.assertEqual(rows,[('TX',b'01'),('RX',b'41\r>')])
 def test_journal_bounds_and_disk_failure_does_not_break_transport(self):
  with tempfile.TemporaryDirectory() as tmp:
   j=Journal(Path(tmp),limit=3);j.enabled=True
   for n in range(6):j.capture(event('RX',b'hello'),demo=True)
   result=j.snapshot(after=1);self.assertTrue(result['gap']);self.assertEqual(len(result['events']),3);self.assertTrue(result['events'][0]['demo'])
   j.root=Path(tmp)/'absent';j.capture(event('RX',b'x'));self.assertFalse(j.enabled);self.assertIn('failed',j.error)
 def test_shared_engine_terminal(self):
  with tempfile.TemporaryDirectory() as tmp:
   e=Engine(tmp)
   try:
    e.submit('demo')
    end=time.monotonic()+10
    while not e.snapshot().get('demo') and time.monotonic()<end:time.sleep(.02)
    e.submit('terminal',command='010C',request_id='ok')
    while e.terminal_result('ok')['state']=='pending' and time.monotonic()<end:time.sleep(.02)
    self.assertEqual(e.terminal_result('ok')['state'],'complete');self.assertTrue(e.traffic.snapshot()['events'])
    e.submit('terminal',command='04',request_id='bad')
    while e.terminal_result('bad')['state']=='pending' and time.monotonic()<end:time.sleep(.02)
    self.assertEqual(e.terminal_result('bad')['state'],'error');self.assertTrue(e.snapshot()['demo'])
   finally:e.close()
if __name__=='__main__':unittest.main()
