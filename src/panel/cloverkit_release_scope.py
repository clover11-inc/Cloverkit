"""Keep deferred integrations out of the candidate panel; retain independent serial CLI."""
from pathlib import Path
def install(Panel,namespace):
    # No status probes for omitted VPN or guest-account control helpers.
    namespace['CONTROLS']['VPN']={'status':['sudo','-n','/usr/local/bin/cloverkit-vpn','status'],'On':['sudo','-n','/usr/local/bin/cloverkit-vpn','on'],'Off':['sudo','-n','/usr/local/bin/cloverkit-vpn','off']}
    # Shared USB serial account provisioned on clean cards.
    Panel.HOME=[label for label in Panel.HOME if label!='PC Recovery']
    old_items=Panel.items
    def items(panel,data):
        rows=old_items(panel,data)
        if panel.details is None:
            rows=[r for r in rows if not (isinstance(r,str) and r in ('PC Recovery',))]
            rows=[r for r in rows if not (isinstance(r,Path) and r.stem in ('packet-scan','packet-beacon','packet-ndp'))]
        if panel.page=='System' and panel.details is None:
            rows += ['Owner setup','Email setup','VPN setup','Recovery hotspot']
        if panel.page in ('Email setup','VPN setup','Recovery hotspot'):return ['Return']
        return rows
    Panel.items=items
    old_handle=Panel.handle;old_lines=Panel.lines
    setup_pages={'Owner setup':'owner','Email setup':'email','VPN setup':'vpn','Recovery hotspot':'recovery-hotspot'}
    def handle(panel,key):
        if panel.page=='System' and panel.details is None and key in ('enter','right'):
            rows=panel.items(panel.collector.snapshot())
            choice=rows[min(panel.selected,len(rows)-1)] if rows else None
            if choice in setup_pages:panel.page=choice;panel.selected=0;return
        if panel.page in setup_pages:
            if key in ('enter','right','left','back'):panel.page='System';panel.details=None;panel.selected=0
            return
        return old_handle(panel,key)
    def lines(panel,data,capacity=30,cols=80):
        if panel.page in setup_pages:
            feature=setup_pages[panel.page]
            rows=[panel.page,'Optional setup','1. Open an SSH or serial terminal.','2. Run: sudo '+('cloverkit-owner-setup' if feature=='owner' else 'cloverkit-setup '+feature),'3. Follow the guided prompts.','Passwords are entered privately.','']
            if feature=='email':rows+=['Used by all access notifications.','Not configured / failed: details stay local.']
            elif feature=='vpn':rows+=['Import your OpenVPN profile.','No profile: VPN is not used.','Setup does not connect the VPN.']
            else:rows+=['Set hotspot name and Wi-Fi password.','CloverKit joins your phone/router hotspot.','Optional override can replace the uplink.']
            return (rows+['',panel.mark(0,'Return')])[:capacity]
        return old_lines(panel,data,capacity,cols)
    Panel.handle=handle;Panel.lines=lines
