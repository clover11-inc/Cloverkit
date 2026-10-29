"""Panel/navigation regression and 480px LCD render using no display/serial device."""
import json,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src/panel'),str(ROOT/'src/vehicle'),str(ROOT/'src/vehicle/vendor')]
from cloverkit_vehicle.engine import Engine
from test_vehicle import wait

class PanelTests(unittest.TestCase):
    def test_menu_controls_and_small_display_render(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine=Engine(tmp);engine.submit('demo');wait(self,lambda:engine.snapshot()['state']=='connected')
            engine.submit('scan');wait(self,lambda:bool((engine.snapshot().get('scan') or {}).get('complete')))
            calls=[]
            def request(path='/api/state',data=None,**kwargs):
                if data:calls.append(data);return {'accepted':True}
                if path=='/api/adapters':return {'usb':[],'bluetooth':{'state':'unavailable','devices':[]}}
                if path=='/api/saved':return engine.storage.list()
                return engine.snapshot()
            try:
                with patch('cloverkit_vehicle.client.ensure',return_value=engine.snapshot()),patch('cloverkit_vehicle.client.request',side_effect=request):
                    import importlib,bh_panel
                    importlib.reload(bh_panel)  # Bind this test's mocked clients even after another test imported the panel.
                class Collector:
                    def snapshot(self):return {'system':{},'network':{'devices':[]},'services':[],'updated':time.time()}
                panel=bh_panel.Panel(Collector(),script_dir=ROOT/'src/launchers')
                self.assertIn('Vehicle Diagnostics',panel.items(Collector().snapshot()))
                panel.selected=panel.HOME.index('Vehicle Diagnostics');panel.handle('enter')
                wait(self,lambda:not getattr(panel,'_vehicle_pending',False))
                self.assertEqual(panel.page,'Vehicle Diagnostics')
                rows=panel.lines(Collector().snapshot(),18,53);self.assertIn('DEMO · Vehicle diagnostics',rows)
                self.assertTrue(any('Live readings' in row for row in rows))
                panel.selected=2;panel.handle('enter');self.assertEqual(panel.page,'Vehicle live')
                wait(self,lambda:not getattr(panel,'_vehicle_pending',False));wait(self,lambda:len(engine.snapshot()['live'])>=4)
                panel._vehicle_state=engine.snapshot()
                self.render(panel,'vehicle-live.png')
                panel.handle('back');self.assertEqual(panel.page,'Vehicle Diagnostics')
                panel.selected=1;panel.handle('enter');wait(self,lambda:not getattr(panel,'_vehicle_pending',False))
                self.assertTrue(any(call['op']=='scan' for call in calls));self.assertEqual(panel.page,'Vehicle codes')
                panel.selected=0;panel.handle('enter');self.assertEqual(panel.page,'Vehicle code details')
                self.assertIn('P0301','\n'.join(panel.lines(Collector().snapshot(),18,53)))
                self.render(panel,'vehicle-code.png');panel.handle('back');self.assertEqual(panel.page,'Vehicle codes')
                panel.handle('back');self.render(panel,'vehicle-menu.png')
                panel.handle('back');self.assertEqual(panel.page,'Home')
                panel.page='Network';self.assertTrue(panel.items(Collector().snapshot()))
            finally:engine.close()
    def render(self,panel,name):
        from PIL import Image,ImageFont
        import bh_panel
        from clover_lcd_panel import LCDPanel
        out=ROOT/'build/vehicle-previews';out.mkdir(parents=True,exist_ok=True)
        lcd=LCDPanel.__new__(LCDPanel);lcd.last=None;lcd.cols=53;lcd.rows=26;lcd.cellw=9;lcd.cellh=18
        lcd.font=ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf',14);lcd.ascent=lcd.font.getmetrics()[0]
        dark=Image.new('RGB',(480,480),(8,17,13));art=Image.open(ROOT/'src/panel/clover-boot.png').convert('RGB').resize((480,480))
        lcd.background=Image.blend(dark,art,.28);lcd.write=lambda image:image.transpose(Image.Transpose.ROTATE_90).save(out/name)
        lcd.frame(bh_panel.render(panel,26,53))

if __name__=='__main__':unittest.main()
