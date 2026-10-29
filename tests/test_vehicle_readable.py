"""Presentation and navigation checks, without opening any adapter."""
import sys,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src/panel'),str(ROOT/'src/vehicle')]
from cloverkit_vehicle_readable import entries, page
from cloverkit_vehicle_menu import install

class Panel:
    HOME=['Game Boy']
    items=lambda *a:[]
    lines=lambda *a:[]
    handle=lambda *a:None
    mark=lambda self,i,item:('> ' if self.selected==i else '  ')+item

class ReadableTests(unittest.TestCase):
    def test_nested_readings_and_bounded_scroll(self):
        readings=entries({'readiness':[{'ecu':'0x7e8','value':{'MIL':True,'CATALYST_MONITORING':{'available':True,'complete':False}}}]},'readiness')
        self.assertEqual(readings[1][1],['Incomplete'])
        self.assertEqual(readings[0][1],['ON'])
        p=Panel();p._vehicle_scroll=999
        self.assertIn('last',page(p,['header'],['first','last'],8,53))
        self.assertEqual(p._vehicle_scroll,0)

    def test_summary_drilldown_and_clear_requires_confirmation(self):
        calls=[]
        with patch('cloverkit_vehicle.client.ensure'),patch('cloverkit_vehicle.client.request',return_value={}):
            class TestPanel(Panel):pass
            install(TestPanel,{})
            p=TestPanel();p.page='Vehicle codes';p.selected=0;p._vehicle_pending=False;p._vehicle_updated=time.monotonic()
            p._vehicle_state={'demo':True,'state':'connected','scan':{'complete':True,'codes':[{'code':'P0301','description':'Cylinder 1 misfire detected','status':'stored','definitions':[]}],'freeze_frames':{'DTC_COOLANT_TEMP':[{'state':'measured','value':91,'unit':'degree_Celsius','ecu':'0x7e8'}]}}}
            self.assertIn('Cylinder 1 misfire',p.items({})[0])
            p.handle('enter');self.assertEqual(p.page,'Vehicle code details')
            self.assertIn('What this code means',p.items({}))
            p.handle('enter');self.assertEqual(p.page,'Vehicle explanation')
            self.assertIn('Cylinder 1 misfire','\n'.join(p.lines({},18,53)))
            p.handle('back');p.selected=2;p.handle('enter');self.assertEqual(p.page,'Vehicle section')
            self.assertIn('91',p.items({})[0]);self.assertNotIn('DTC_',p.items({})[0])
            p.handle('enter');self.assertEqual(p.page,'Vehicle reading')
            p._vehicle_scroll=999;self.assertIn('91','\n'.join(p.lines({},18,53)))
            p.handle('back');p.handle('back');self.assertEqual(p.page,'Vehicle code details')
            p.handle('back');self.assertEqual(p.page,'Vehicle codes')
            p.page='Vehicle Diagnostics';self.assertIn('Read fault codes',p.items({}));self.assertIn('Clear fault codes',p.items({}))
            p.page='Vehicle clear';p.selected=1
            with patch('cloverkit_vehicle.client.request',side_effect=lambda *a,**k:calls.append((a,k)) or {}):p.handle('enter')
            self.assertFalse(calls,'No clear operation without a fresh confirmation ticket')

if __name__=='__main__':unittest.main()
