"""Public source packaging, privacy and isolated install regression tests."""
import hashlib,io,json,subprocess,sys,tempfile,unittest,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from release_inputs import selected
from privacy_audit import audit
class ReleaseTests(unittest.TestCase):
 def test_runtime_and_debug_files_excluded(self):
  for name in ('src/panel/.env','src/vehicle/cloverkit_vehicle/data/access.token','src/panel/__pycache__/a.pyc','flipper/dist/debug/a.elf','build/vehicle-demo/sessions.sqlite3','config/email.json','src/panel/example.pcap','flipper/dist/cloverkit.fap'):
   self.assertFalse(selected(Path(name)),name)
  for name in ('README.md','config/cloverkit.example.json','src/vehicle/cloverkit_vehicle/data/codes.sqlite3','hardware/README.md'):
   self.assertTrue(selected(Path(name)),name)
 def test_known_private_value_in_binary_and_wheel_blocked(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);(root/'src').mkdir();(root/'src/blob.bin').write_bytes(b'123EXAMPLE-PRIVATE-VALUE456')
   vendor=root/'vendor';vendor.mkdir()
   with zipfile.ZipFile(vendor/'example.whl','w') as z:z.writestr('nested.txt','EXAMPLE-PRIVATE-VALUE')
   report=audit(root,[b'example-private-value']);self.assertFalse(report['passed']);self.assertGreaterEqual(len(report['findings']),2);self.assertTrue(any('::nested.txt' in row['file'] for row in report['findings']))
 def test_isolated_install_verifies_and_uninstalls(self):
  with tempfile.TemporaryDirectory() as tmp:
   prefix=Path(tmp)/'toolkit';args=[sys.executable,str(ROOT/'packaging/installer.py')]
   result=subprocess.run(args+['install','--prefix',str(prefix)],capture_output=True,text=True);self.assertEqual(result.returncode,0,result.stderr)
   installed=prefix/('cloverkit-'+(ROOT/'VERSION').read_text().strip())
   verified=subprocess.run([sys.executable,str(installed/'tools/verify_package.py')],capture_output=True,text=True);self.assertEqual(verified.returncode,0,verified.stderr+verified.stdout)
   again=subprocess.run(args+['install','--prefix',str(prefix)],capture_output=True,text=True);self.assertNotEqual(again.returncode,0)
   outside=prefix/'private-user-data';outside.write_text('preserve')
   removed=subprocess.run(args+['uninstall','--prefix',str(prefix)],capture_output=True,text=True);self.assertEqual(removed.returncode,0,removed.stderr);self.assertEqual(outside.read_text(),'preserve')
 def test_changed_installed_file_blocks_uninstall(self):
  with tempfile.TemporaryDirectory() as tmp:
   args=[sys.executable,str(ROOT/'packaging/installer.py')];prefix=Path(tmp)/'toolkit'
   installed=subprocess.run(args+['install','--prefix',str(prefix)],capture_output=True,text=True);self.assertEqual(installed.returncode,0,installed.stderr)
   folder=prefix/('cloverkit-'+(ROOT/'VERSION').read_text().strip());readme=folder/'README.md';readme.write_text('user edit')
   removed=subprocess.run(args+['uninstall','--prefix',str(prefix)],capture_output=True,text=True);self.assertNotEqual(removed.returncode,0);self.assertEqual(readme.read_text(),'user edit')
 def test_vendor_archives_have_pinned_hashes(self):
  for row in json.loads((ROOT/'THIRD-PARTY.json').read_text())['components']:
   self.assertEqual(hashlib.sha256((ROOT/row['source_file']).read_bytes()).hexdigest(),row['source_sha256'])
 @unittest.skipUnless(sys.platform.startswith('linux'),'Linux backend test')
 def test_direct_ethernet_has_no_private_static_fallback(self):
  import importlib.machinery,importlib.util
  from unittest.mock import patch
  sys.path.insert(0,str(ROOT/'src/panel'))
  loader=importlib.machinery.SourceFileLoader('test_direct_backend',str(ROOT/'src/commands/clover-direct-ethernet'));spec=importlib.util.spec_from_loader(loader.name,loader);module=importlib.util.module_from_spec(spec);loader.exec_module(module)
  with tempfile.TemporaryDirectory() as tmp,patch.object(module,'CONFIG',Path(tmp)/'missing.json'),patch.object(module.os,'geteuid',return_value=0),patch.object(module,'run') as run:
   with self.assertRaisesRegex(ValueError,'Configure your direct Ethernet'):module.main(['static'])
   run.assert_not_called()
 def test_companion_excluded(self):
  self.assertFalse((ROOT/'flipper').exists())
  self.assertFalse(selected(Path('flipper/blackhat_app.c')))
  self.assertFalse(selected(Path('flipper/dist/blackhat.fap')))
if __name__=='__main__':unittest.main()
