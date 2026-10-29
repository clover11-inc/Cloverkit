"""Local Advanced capture entry; account/email integration is deferred."""
from pathlib import Path
def install(Panel):
    old_items,old_handle,old_start=Panel.items,Panel.handle,Panel.start_script
    def selected(panel):return isinstance(panel.details,Path) and panel.details.name=='wifi-health.sh'
    def launch(panel,remote=False):
        backend='/usr/local/bin/conwifi-run' if remote else '/usr/local/bin/wifi-passive-health-panel'
        panel.start_task('Wi-Fi Health',['sudo','-n',backend],{'kind':'wifi-health'})
    def items(panel,data):
        return ['Run','Run with console','Return'] if selected(panel) else old_items(panel,data)
    def handle(panel,key):
        if selected(panel) and key in ('enter','right'):
            if panel.selected<2:launch(panel,remote=panel.selected==1)
            else:panel.details=None;panel.selected=0
            return
        return old_handle(panel,key)
    def start_script(panel,script,args=()):
        if script.name=='wifi-health.sh':launch(panel);return
        return old_start(panel,script,args)
    Panel.items,Panel.handle,Panel.start_script=items,handle,start_script
