"""Display-only Network sections; tools keep their existing launch handlers."""
from pathlib import Path
GROUPS=(
    ('WI-FI',('wifi','wifi-health','wifi-waterfall','wifi-client-health')),
    ('ETHERNET',('ethernet','net-direct-passive','net-direct-static','net-direct-test')),
    ('DISCOVERY & MONITORING',('hosts','monitor','net-topology')),
    ('DIAGNOSTICS & CAPTURE',('Packet Captures','iperf','path-test')),
)
def key(item):return item.stem.lower() if isinstance(item,Path) else str(item)
def groups(items):
    remaining=list(items);result=[]
    for label,order in GROUPS:
        selected=[]
        for name in order:
            matches=[item for item in remaining if key(item)==name]
            selected.extend(matches)
            remaining=[item for item in remaining if key(item)!=name]
        if selected:result.append((label,selected))
    if remaining:result.append(('OTHER NETWORK TOOLS',remaining))
    return result
def install(Panel,namespace):
    old_items=Panel.items;old_lines=Panel.lines
    def items(self,data):
        original=old_items(self,data)
        if self.page!='Network' or self.details is not None:return original
        return [item for label,entries in groups(original) for item in entries]
    def lines(self,data,capacity=30,cols=80):
        if self.page!='Network' or self.details is not None:return old_lines(self,data,capacity,cols)
        result=[];index=0
        for label,entries in groups(self.items(data)):
            result.append(label)
            for item in entries:
                name=namespace['function_name'](item) if isinstance(item,Path) else str(item)
                result.append(self.mark(index,name));index+=1
        # The shared renderer handles wrapping and scrolling to the selected action.
        return result or ['No network tools available']
    old_handle=Panel.handle
    def handle(self,key):
        if self.page=='Network' and self.details is None and key in ('enter','right'):
            actions=self.items(self.collector.snapshot())
            if actions:
                selected=actions[min(self.selected,len(actions)-1)]
                if isinstance(selected,Path) and selected.stem.lower()=='wifi-waterfall':
                    # Existing waterfall start hook opens modes without starting capture.
                    self.start_task('Wi-Fi waterfall',[],{'kind':'wifi-health'})
                    return
        return old_handle(self,key)
    Panel.items=items;Panel.lines=lines;Panel.handle=handle
    previous=namespace['colour_details']
    headings={label for label,order in GROUPS}|{'OTHER NETWORK TOOLS'}
    def colour(text,*args,**kwargs):
        if text in headings:return '\x1b[36m'+text+'\x1b[0m'
        return previous(text,*args,**kwargs)
    namespace['colour_details']=colour
