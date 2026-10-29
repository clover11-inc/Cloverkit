"""Small integrations for the established CloverKit panel."""
from pathlib import Path

def install(Panel, ns):
    if getattr(Panel,'_roadmap_features',False): return
    Panel._roadmap_features=True
    ns['FUNCTION_NAMES'].update({'wifi-client-health':'Connected client health','packet-insights':'Analyze saved capture',
                                 'net-topology':'Observed topology','device-history':'Device history'})
    category=ns['script_category']
    def classify(path):
        if path.stem=='device-history': return 'Security'
        return category(path)
    ns['script_category']=classify
    ethernet_lines=ns['ethernet_lines']
    def ethernet(task):
        rows=ethernet_lines(task); data=task.get('finder',{}).get('values',{})
        return rows+['','DIAGNOSIS']+data.get('diagnosis',[])
    ns['ethernet_lines']=ethernet
    handle=Panel.handle; original_items=Panel.items
    def items(panel,data):
        if isinstance(panel.details,Path) and panel.details.name=='wifi-client-health.sh': return ['Test wlan1','Test wlan2','Return']
        return original_items(panel,data)
    Panel.items=items
    def keys(panel,key):
        if isinstance(panel.details,Path) and panel.details.name=='wifi-client-health.sh' and key in ('right','enter'):
            choice=min(panel.selected,2)
            if choice==2: panel.details=None;panel.selected=0
            else: panel.start_task('Connected client health',['/usr/local/bin/wifi-health-connected','--once','--interface','wlan'+str(choice+1)])
            return
        if panel.page=='Tasks' and key in ('back','left') and panel.task.snapshot().get('state')=='RUNNING':
            task=panel.task.snapshot(); deep=(task.get('metadata') or {}).get('kind')=='wifi-health' and len(getattr(panel,'wifi_navigation',{}).get('stack',[]))>1
            if not deep: panel.task.stop()
        return handle(panel,key)
    Panel.handle=keys
