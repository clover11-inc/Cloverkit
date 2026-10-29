"""Optional restricted Vehicle SSH controls layered over the readable OBD menus."""
import threading,time
from pathlib import Path

def install(Panel):
 old_items,old_lines,old_handle=Panel.items,Panel.lines,Panel.handle
 def items(panel,data):
  rows=old_items(panel,data)
  return ['Enable / renew SSH console','Disable SSH console',*rows] if panel.page=='Vehicle remote access' else rows
 def control(panel,operation):
  if getattr(panel,'_ssh_pending',False):return
  panel._ssh_pending=True
  def work():
   try:
    from cloverkit_vehicle.ssh_access import HELPER,control as request
    if not HELPER.is_file():panel._ssh_access={'enabled':False,'notice':'Optional SSH account not provisioned'}
    else:panel._ssh_access=request(operation)
   except Exception:panel._ssh_access={'enabled':False,'notice':'SSH control unavailable; see optional setup guide'}
   finally:panel._ssh_pending=False;panel._ssh_updated=time.monotonic()
  threading.Thread(target=work,daemon=True).start()
 def handle(panel,key):
  if panel.page!='Vehicle remote access':return old_handle(panel,key)
  if key in ('up','down'):
   panel.selected=(panel.selected+(1 if key=='down' else -1))%len(items(panel,{}));return
  if key in ('enter','right'):
   if panel.selected<2:control(panel,'enable' if panel.selected==0 else 'disable');return
   panel.selected-=2;old_handle(panel,key)
   if panel.page=='Vehicle remote access':panel.selected+=2
   return
  return old_handle(panel,key)
 def lines(panel,data,capacity=30,cols=80):
  if panel.page!='Vehicle remote access':return old_lines(panel,data,capacity,cols)
  if not getattr(panel,'_ssh_pending',False) and time.monotonic()-getattr(panel,'_ssh_updated',0)>3:control(panel,'status')
  access=getattr(panel,'_ssh_access',{});rows=['Vehicle SSH access','Username: conveh','SSH: '+('ENABLED' if access.get('enabled') else 'disabled')]
  if access.get('enabled'):rows+=['Passphrase: '+access.get('password',''),'Email: '+access.get('email','NOT CONFIGURED'),'Ends: disable / disconnect / reboot','Maximum: 8 hours']
  if access.get('notice'):rows+=[access['notice']]
  rows+=['ssh -t conveh@CLOVERKIT_IP','Vehicle menus + T: read terminal','No system shell / file forwarding','']
  return rows+[panel.mark(i,row) for i,row in enumerate(items(panel,data))]
 Panel.items,Panel.lines,Panel.handle=items,lines,handle
