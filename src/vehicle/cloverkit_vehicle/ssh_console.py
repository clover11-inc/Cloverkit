"""Forced SSH view: Vehicle Diagnostics only, independent navigation, shared adapter."""
import json,os,select,shutil,sys,termios,threading,time,tty
from types import SimpleNamespace
from .client import ensure,request

def printable(value):return ''.join(c if c.isprintable() else ' ' for c in str(value))
class VehiclePanel:
 HOME=['Vehicle Diagnostics','Game Boy']
 def __init__(self):
  self.page='Vehicle Diagnostics';self.selected=0;self.details=None;self.message='';self.running=True
  self.collector=SimpleNamespace(snapshot=lambda:{})
 def items(self,data):return []
 def lines(self,data,capacity=30,cols=80):return []
 def mark(self,index,label):return ('> ' if self.selected==index else '  ')+label
 def handle(self,key):
  if key=='quit' or self.page=='Home':self.running=False

def session(access):
 if not sys.stdin.isatty() or not sys.stdout.isatty():print('Use ssh -t conveh@CLOVERKIT_IP');return 1
 first=access()
 if not first.get('enabled'):print('Vehicle SSH disabled. Enable SSH console from the local Vehicle menu.');return 1
 from cloverkit_vehicle_menu import install
 class SessionPanel(VehiclePanel):HOME=list(VehiclePanel.HOME)
 install(SessionPanel,{})
 panel=SessionPanel();token=first['token'];old=termios.tcgetattr(0);pending=b'';command=None;terminal_result=[];busy=False
 def send(text):
  nonlocal busy,terminal_result
  busy=True
  try:
   reply=request('/api/action',dict(op='terminal',command=text));end=time.monotonic()+90
   while time.monotonic()<end:
    value=request('/api/terminal?id='+reply['id'])
    if value['state']!='pending':terminal_result=['> '+text]+json.dumps(value,indent=1).splitlines();break
    time.sleep(.2)
   else:terminal_result=['Request still pending; return to the menu to inspect progress.']
  except Exception as exc:terminal_result=[str(exc)]
  finally:busy=False
 try:
  ensure();tty.setraw(0)
  while panel.running:
   current=access()
   if not current.get('enabled') or current.get('token')!=token:break
   if panel.page=='Home':break
   # Do not expose local account management or token instructions to a guest session.
   if panel.page=='Vehicle remote access':panel.page='Vehicle traffic';panel.selected=0
   size=shutil.get_terminal_size((80,30));cols=max(20,min(size.columns-1,160));capacity=max(6,min(size.lines-5,80))
   if command is None:
    rows=panel.lines({},capacity,cols)
    if len(rows)>capacity:
     first_action=next((i for i,line in enumerate(rows) if line.startswith('> ')),0)
     start=max(0,first_action-capacity+1);rows=rows[start:start+capacity]
    footer='Arrows/WASD browse | Enter open | Backspace back | T terminal | Q exit'
   else:
    rows=['OBD read terminal | Escape: menu',*terminal_result[-max(1,capacity-4):],('Working...' if busy else 'Command: '+command)]
    footer='Read commands only: RPM / 010C / 03 / ATI / ATRV | Enter send'
   output=['CloverKit Vehicle Diagnostics · conveh',*rows,panel.message,footer]
   sys.stdout.write('\x1b[?25l\x1b[H\x1b[2J'+'\r\n'.join(printable(line)[:cols] for line in output));sys.stdout.flush()
   if not select.select([0],[],[],.3)[0]:continue
   raw=os.read(0,128)
   if not raw:break
   pending+=raw
   while pending:
    arrows={b'\x1b[A':'up',b'\x1b[B':'down',b'\x1b[C':'right',b'\x1b[D':'left'}
    match=next((code for code in arrows if pending.startswith(code)),None)
    if match:key=arrows[match];pending=pending[len(match):];c=None
    elif pending.startswith(b'\x1b[') and len(pending)<3:break
    else:c=pending[0];pending=pending[1:];key=None
    if c in (3,4):panel.running=False;break
    if command is not None:
     if c==27:command=None
     elif c in (8,127):command=command[:-1]
     elif c in (10,13) and command and not busy:threading.Thread(target=send,args=(command,),daemon=True).start();command=''
     elif c is not None and 32<=c<=126 and len(command)<64:command+=chr(c)
     continue
    if c in (ord('q'),ord('Q')):panel.running=False;break
    if c in (ord('t'),ord('T')):command='';continue
    if key is None:key={ord('w'):'up',ord('s'):'down',ord('a'):'left',ord('d'):'right',13:'enter',10:'enter',8:'back',127:'back',27:'back'}.get(c)
    if key:panel.handle(key)
 finally:
  termios.tcsetattr(0,termios.TCSANOW,old);sys.stdout.write('\x1b[0m\x1b[?25h\x1b[2J\x1b[HVehicle SSH closed.\r\n');sys.stdout.flush()
 return 0
