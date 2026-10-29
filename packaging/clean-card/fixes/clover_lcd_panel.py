"""Render existing ANSI panel frames over a faint clover on the local LCD only."""
import fcntl, math, mmap, os, re, struct, subprocess
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
from clover_boot_splash import Fix

PALETTE=[(8,17,13),(240,91,91),(94,233,140),(255,215,105),(120,160,255),(230,150,245),(105,230,240),(235,244,239)]
ANSI=re.compile(r'\x1b\[([0-9;?]*)([A-Za-z])')

class LCDPanel:
    def __init__(self):
        self.fd=self.tty=self.memory=None
        try:
            self.fd=os.open('/dev/fb0',os.O_RDWR)
            v=struct.unpack('40I',fcntl.ioctl(self.fd,0x4600,b'\0'*160))
            self.fix=Fix(); fcntl.ioctl(self.fd,0x4602,self.fix)
            self.v=v; self.w,self.h,self.xoff,self.yoff,self.bpp=v[0],v[1],v[4],v[5],v[6]
            if self.fix.visual!=2 or self.bpp not in (16,24,32): raise RuntimeError('Unsupported LCD format')
            if (self.yoff+self.h)*self.fix.line_length>self.fix.smem_len: raise RuntimeError('LCD bounds invalid')
            self.memory=mmap.mmap(self.fd,self.fix.smem_len)
            self.font=ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf',14)
            self.cellw=math.ceil(self.font.getlength('M')); self.cellh=18; self.ascent=self.font.getmetrics()[0]
            self.logical_w,self.logical_h=self.h,self.w
            self.cols=self.logical_w//self.cellw; self.rows=self.logical_h//self.cellh
            if self.cols<40 or self.rows<12: raise RuntimeError('LCD too small for panel layout')
            dark=Image.new('RGB',(self.logical_w,self.logical_h),(8,17,13))
            with Image.open('/usr/local/lib/bh-interactive/clover-boot.png') as art:
                art=art.convert('RGB').resize(dark.size,Image.Resampling.LANCZOS)
                # CLOVER_BACKGROUND_CENTRE_V2
                shifted=Image.new('RGB',dark.size,(8,17,13))
                shifted.paste(art,(0,round(self.logical_h*0.10)))
                self.background=Image.blend(dark,shifted,.28)
            self.tty=os.open('/dev/tty1',os.O_RDWR|os.O_NOCTTY)
            self.old=struct.unpack('i',fcntl.ioctl(self.tty,0x4B3B,struct.pack('i',0)))[0]
            fcntl.ioctl(self.tty,0x4B3A,1)
            self.last=None
        except Exception:
            self.close(); raise

    # CLOVER_CACHED_RENDER_V1
    def frame(self,ansi):
        if ansi==self.last: return
        if not hasattr(self,'canvas') or self.last is None:
            self.canvas=self.background.copy()
            self.previous={}
            self.glyphs={}
        cells={}
        x=y=0; foreground=PALETTE[7]; background=None
        position=0
        def text(segment):
            nonlocal x,y
            for char in segment:
                if char=='\n': y+=1; x=0; continue
                if char=='\r': x=0; continue
                if not char.isprintable(): continue
                if 0<=x<self.cols and 0<=y<self.rows:
                    cells[(x,y)]=(char,foreground,background)
                x+=1
        for match in ANSI.finditer(ansi):
            text(ansi[position:match.start()]); position=match.end()
            raw,operation=match.groups()
            if raw.startswith('?'): continue
            args=[int(a) if a else 0 for a in raw.split(';')]
            if operation in ('H','f'):
                y=(args[0] or 1)-1; x=((args[1] if len(args)>1 else 1) or 1)-1
            elif operation=='m':
                for value in args:
                    if value==0: foreground=PALETTE[7]; background=None
                    elif 30<=value<=37: foreground=PALETTE[value-30]
                    elif 40<=value<=47: background=PALETTE[value-40]
                    elif 90<=value<=97: foreground=PALETTE[value-90]
                    elif 100<=value<=107: background=PALETTE[value-100]
                    elif value==39: foreground=PALETTE[7]
                    elif value==49: background=None
        text(ansi[position:])
        changed=False
        for pos in self.previous.keys() | cells.keys():
            value=cells.get(pos)
            if value==self.previous.get(pos): continue
            changed=True
            px,py=pos[0]*self.cellw,pos[1]*self.cellh
            box=(px,py,px+self.cellw,py+self.cellh)
            self.canvas.paste(self.background.crop(box),(px,py))
            if value is None: continue
            if value not in self.glyphs:
                char,fg,bg=value
                tile=Image.new('RGBA',(self.cellw,self.cellh),bg+(255,) if bg is not None else (0,0,0,0))
                draw=ImageDraw.Draw(tile)
                if bg is None:
                    draw.text((1,self.ascent+1),char,font=self.font,fill=(0,0,0,255),anchor='ls')
                draw.text((0,self.ascent),char,font=self.font,fill=fg+(255,),anchor='ls')
                if len(self.glyphs)>=1024: self.glyphs.clear()
                self.glyphs[value]=tile
            tile=self.glyphs[value]
            self.canvas.paste(tile,(px,py),tile)
        self.previous=cells
        if changed:
            self.write(self.canvas.transpose(Image.Transpose.ROTATE_270))
        self.last=ansi

    def write(self,image):
        v=self.v; count=self.bpp//8
        if self.bpp==32 and (v[8],v[9],v[11],v[12],v[14],v[15])==(16,8,8,8,0,8):
            output=image.convert('RGBA').tobytes('raw','BGRA') if v[18] else image.tobytes('raw','BGRX')
        else:
            raw=image.tobytes(); output=bytearray(self.w*self.h*count)
            for i in range(self.w*self.h):
                pixel=0
                for channel,index in enumerate((8,11,14)):
                    offset,length=v[index],v[index+1]
                    pixel|=((raw[i*3+channel]*((1<<length)-1)+127)//255)<<offset
                if v[18]: pixel|=((1<<v[18])-1)<<v[17]
                output[i*count:(i+1)*count]=pixel.to_bytes(count,'little')
        # The first complete menu frame is ready. Stop the splash without
        # clearing its last image or restoring the text console underneath us.
        if not getattr(self,'display_handoff_complete',False):
            service='cloverkit-boot-splash.service'
            active=subprocess.run(['/usr/bin/systemctl','is-active','--quiet',service],timeout=5).returncode==0
            if active:
                subprocess.run(['/usr/bin/systemctl','kill','--kill-whom=main','--signal=SIGUSR1',service],check=True,timeout=5)
                subprocess.run(['/usr/bin/systemctl','stop',service],check=True,timeout=10)
            fcntl.ioctl(self.tty,0x4B3A,1)
            self.display_handoff_complete=True
        for row in range(self.h):
            offset=(row+self.yoff)*self.fix.line_length+self.xoff*count
            self.memory[offset:offset+self.w*count]=output[row*self.w*count:(row+1)*self.w*count]

    def close(self):
        if self.memory is not None: self.memory.close(); self.memory=None
        if self.fd is not None: os.close(self.fd); self.fd=None
        if self.tty is not None:
            try: fcntl.ioctl(self.tty,0x4B3A,getattr(self,'old',0))
            except OSError: pass
            os.close(self.tty); self.tty=None

def open_local():
    if Path('/etc/cloverkit/lcd-text-only').exists(): return None
    try:
        if os.ttyname(1)!='/dev/tty1': return None
        return LCDPanel()
    except Exception as error:
        print('LCD background unavailable; using text panel: '+str(error),flush=True)
        return None
