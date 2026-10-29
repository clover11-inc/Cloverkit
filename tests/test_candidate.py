"""Offline candidate behaviour tests; all SMTP/network/account effects are mocked."""
import importlib.util,json,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch,MagicMock
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src/panel'))
import cloverkit_optional_setup as setup
import cloverkit_recovery_hotspot as recovery

class CandidateTests(unittest.TestCase):
    def test_missing_email_never_connects(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(setup.smtplib,'SMTP') as smtp:
            self.assertEqual(setup.send_access('Report','conwifi','EXAMPLE-ONLY','device.local',Path(folder)),'NOT CONFIGURED')
            smtp.assert_not_called()
    def test_email_failure_returns_fallback_state(self):
        config=dict(host='smtp.example.invalid',port=587,tls='starttls',username='example',password='EXAMPLE-ONLY',sender='a@example.invalid',recipient='b@example.invalid')
        with patch.object(setup,'email_settings',return_value=config),patch.object(setup.smtplib,'SMTP',side_effect=OSError('not connected')):
            self.assertEqual(setup.send_access('Report','conwifi','EXAMPLE-ONLY','device.local'),'FAILED')
    def test_email_tls_and_shared_template(self):
        config=dict(host='smtp.example.invalid',port=587,tls='starttls',username='example',password='EXAMPLE-ONLY',sender='a@example.invalid',recipient='b@example.invalid')
        client=MagicMock();smtp=MagicMock();smtp.return_value.__enter__.return_value=client
        with patch.object(setup,'email_settings',return_value=config),patch.object(setup.smtplib,'SMTP',smtp):
            self.assertEqual(setup.send_access('Serial console','console','EXAMPLE-ONLY','device.local'),'SENT')
            client.starttls.assert_called_once()
            message=client.send_message.call_args.args[0]
            self.assertIn('console@device.local',message.get_content())
    def test_profile_rejects_hooks_and_external_files(self):
        for line in ('up /tmp/run','plugin /tmp/plugin.so','config /tmp/other','ca /etc/private','tls-export-cert /tmp'):
            with self.subTest(line=line),self.assertRaises(ValueError):
                setup.validate_profile('client\nremote example.invalid 1194\n'+line+'\n')
    def test_self_contained_profile_requires_server_certificate(self):
        output=setup.validate_profile('client\nremote example.invalid 1194\n<ca>\nEXAMPLE ONLY\n</ca>\nauth-user-pass old-path\n')
        self.assertIn('remote-cert-tls server',output);self.assertNotIn('old-path',output)
    def test_hotspot_profile_identity_and_password(self):
        text=recovery.profile_text('Recovery hotspot','EXAMPLE-ONLY','02:00:00:00:00:01','00000000-0000-4000-8000-000000000001')
        self.assertIn('interface-name=wlan0',text);self.assertIn('autoconnect=false',text)
        self.assertIn('psk=EXAMPLE-ONLY',text);import configparser
        parsed=configparser.ConfigParser(interpolation=None);parsed.read_string(text)
        self.assertEqual(bytes(int(v) for v in parsed['wifi']['ssid'].split(';') if v).decode('utf-8'),'Recovery hotspot')
    def test_hotspot_rejects_short_password(self):
        with self.assertRaises(ValueError):recovery.profile_text('Test','short','02:00:00:00:00:01','example')
    def test_setup_never_sends_or_connects(self):
        with patch.object(setup.os,'geteuid',return_value=0,create=True),patch.object(setup.os,'isatty',return_value=True),patch('builtins.input',return_value='n'),patch.object(setup,'atomic_private') as write,patch.object(setup,'send_access') as send,patch.object(setup.smtplib,'SMTP') as smtp:
            setup.wizard('email');write.assert_called_once();send.assert_not_called();smtp.assert_not_called()
    def test_docs_reject_path_traversal(self):
        r=subprocess.run([sys.executable,str(ROOT/'tools/cloverkit.py'),'docs','../../etc/passwd'],capture_output=True,text=True)
        self.assertEqual(r.returncode,2);self.assertNotIn('root:',r.stdout)
    def test_installer_refuses_live_activation(self):
        r=subprocess.run([sys.executable,str(ROOT/'packaging/installer.py'),'install'],capture_output=True,text=True)
        self.assertEqual(r.returncode,2);self.assertIn('disabled',r.stderr)
    def test_installer_stages_once_and_preserves_existing_target(self):
        with tempfile.TemporaryDirectory() as folder:
            destination=Path(folder)/'candidate'
            args=[sys.executable,str(ROOT/'packaging/installer.py'),'stage','--root',str(destination)]
            r=subprocess.run(args,capture_output=True,text=True);self.assertEqual(r.returncode,0,r.stderr)
            self.assertTrue((destination/'CLOVERKIT-STAGING.json').exists())
            marker=destination/'keep.txt';marker.write_text('preserve')
            second=subprocess.run(args,capture_output=True,text=True)
            self.assertNotEqual(second.returncode,0);self.assertEqual(marker.read_text(),'preserve')
    def test_generated_docs_include_three_perspectives(self):
        features=json.loads((ROOT/'catalog/features.json').read_text())['features']
        for feature in features:
            text=(ROOT/'docs/generated'/(feature['id']+'.md')).read_text()
            for section in ('What it does','When to use it','Why it is useful'):
                self.assertIn(section,text)
    @unittest.skipUnless(sys.platform.startswith('linux'),'Linux framebuffer panel imports fcntl')
    def test_system_setup_menu_and_advanced_scan_choices(self):
        import bh_panel
        class Collector:
            def snapshot(self):return {'system':{},'network':{'devices':[]},'services':[]}
        panel=bh_panel.Panel(Collector(),script_dir=ROOT/'src/launchers')
        panel.page='System';items=panel.items(Collector().snapshot())
        for name in ('Email setup','VPN setup','Recovery hotspot'):self.assertIn(name,items)
        panel.selected=items.index('Recovery hotspot');panel.handle('enter')
        self.assertEqual(panel.page,'Recovery hotspot')
        self.assertTrue(any('cloverkit-setup recovery-hotspot' in line for line in panel.lines(Collector().snapshot())))
        panel.page='Network';panel.details=ROOT/'src/launchers/wifi-health.sh';panel.selected=1
        calls=[];panel.start_task=lambda *args:calls.append(args)
        panel.handle('enter')
        self.assertIn('/usr/local/bin/conwifi-run',calls[0][1])
    def test_credentials_are_at_top_and_removed_when_session_ends(self):
        import wifi_health_browser as browser
        snapshot=dict(schema=1,state='RUNNING',aps=[],clients=[],frames_observed=0,radios={},local_access=dict(username='conwifi',host='device.local',password='EXAMPLE-ONLY',email='NOT CONFIGURED',show_password=True))
        task=dict(state='RUNNING',finder=dict(values=snapshot),lines=[])
        lines=browser.report(task,browser.new_navigation())
        self.assertTrue(lines[0].startswith('REPORT ACCESS:'))
        self.assertIn('Password: EXAMPLE-ONLY','\n'.join(lines[:4]))
        task['state']='COMPLETE'
        self.assertNotIn('EXAMPLE-ONLY','\n'.join(browser.report(task,browser.new_navigation())))
if __name__=='__main__':unittest.main()
