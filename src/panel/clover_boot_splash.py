#!/usr/bin/env python3
import ctypes, fcntl, mmap, os, signal, struct, time
from functools import lru_cache
from PIL import Image, ImageDraw, ImageFont

class Fix(ctypes.Structure):
    _fields_=[('id',ctypes.c_char*16),('smem_start',ctypes.c_ulong),('smem_len',ctypes.c_uint32),
              ('type',ctypes.c_uint32),('type_aux',ctypes.c_uint32),('visual',ctypes.c_uint32),
              ('xpanstep',ctypes.c_uint16),('ypanstep',ctypes.c_uint16),('ywrapstep',ctypes.c_uint16),
              ('line_length',ctypes.c_uint32),('mmio_start',ctypes.c_ulong),('mmio_len',ctypes.c_uint32),
              ('accel',ctypes.c_uint32),('capabilities',ctypes.c_uint16),('reserved',ctypes.c_uint16*2)]
running=True
handoff=False

def transfer(*_):
    global running,handoff
    handoff=True; running=False

def stop(*_):
    global running
    running=False

@lru_cache(maxsize=2)
def background(w,h):
    with Image.open('/usr/local/lib/bh-interactive/clover-boot.png') as source:
        return source.convert('RGB').resize((w,h),Image.Resampling.LANCZOS)

def artwork(w,h,phase):
    image=background(w,h).copy(); d=ImageDraw.Draw(image)
    scale=min(w,h)/480
    try: font=ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',max(12,int(27*scale)))
    except OSError: font=ImageFont.load_default()
    title='Cloverkit'; box=d.textbbox((0,0),title,font=font)
    d.text(((w-(box[2]-box[0]))/2,h*.73),title,font=font,fill=(225,245,233))
    left,right=int(w*.12),int(w*.88); top,bottom=int(h*.88),int(h*.905)
    d.rounded_rectangle((left,top,right,bottom),radius=max(1,int(4*scale)),fill=(29,60,43))
    span=right-left; length=max(8,int(span*.22)); start=left+int((span-length)*(1-abs((phase%2)-1)))
    d.rounded_rectangle((start,top,start+length,bottom),radius=max(1,int(4*scale)),fill=(45,205,110))
    return image

def main():
    for s in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP): signal.signal(s,stop)
    signal.signal(signal.SIGUSR1,transfer)
    deadline=time.monotonic()+15
    while running and not os.path.exists('/dev/fb0') and time.monotonic()<deadline: time.sleep(.1)
    if not running or not os.path.exists('/dev/fb0'): return
    tty=os.open('/dev/tty1',os.O_RDWR|os.O_NOCTTY); fd=None; memory=None; old=None
    try:
        old=struct.unpack('i',fcntl.ioctl(tty,0x4B3B,struct.pack('i',0)))[0]
        fd=os.open('/dev/fb0',os.O_RDWR)
        v=struct.unpack('40I',fcntl.ioctl(fd,0x4600,b'\0'*160))
        fix=Fix(); fcntl.ioctl(fd,0x4602,fix)
        w,h,xoff,yoff,bpp=v[0],v[1],v[4],v[5],v[6]
        if bpp not in (16,24,32) or fix.visual!=2: raise RuntimeError('Unsupported framebuffer pixel format')
        count=bpp//8; stride=fix.line_length
        if (yoff+h)*stride>fix.smem_len: raise RuntimeError('Framebuffer bounds invalid')
        memory=mmap.mmap(fd,fix.smem_len)
        fcntl.ioctl(tty,0x4B3A,1)
        start=time.monotonic()
        # CLOVER_FADE_OUT_V1
        fade_started = None
        while time.monotonic()-start<300:
            if handoff: break
            if not running:
                if fade_started is None: fade_started = time.monotonic()
                if time.monotonic()-fade_started >= .4: break
            if struct.unpack('i',fcntl.ioctl(tty,0x4B3B,struct.pack('i',0)))[0] != 1:
                fcntl.ioctl(tty,0x4B3A,1)
            image=artwork(h,w,(time.monotonic()-start)*.6).transpose(Image.Transpose.ROTATE_270)
            if fade_started is not None:
                amount = .28 + .72 * max(0, 1-(time.monotonic()-fade_started)/.4)
                image = Image.blend(Image.new('RGB', image.size, (8,17,13)), image, amount)
            if bpp==32 and (v[8],v[9],v[11],v[12],v[14],v[15])==(16,8,8,8,0,8):
                output=image.convert('RGBA').tobytes('raw','BGRA') if v[18] else image.tobytes('raw','BGRX')
            else:
                raw=image.tobytes(); output=bytearray(w*h*count)
                for i in range(w*h):
                    pixel=0
                    for channel,index in enumerate((8,11,14)):
                        offset,length=v[index],v[index+1]
                        pixel|=((raw[i*3+channel]*((1<<length)-1)+127)//255)<<offset
                    if v[18]: pixel|=((1<<v[18])-1)<<v[17]
                    output[i*count:(i+1)*count]=pixel.to_bytes(count,'little')
            for y in range(h):
                target=(y+yoff)*stride+xoff*count
                memory[target:target+w*count]=output[y*w*count:(y+1)*w*count]
            time.sleep(.15)
    finally:
        # Clear splash pixels before releasing the framebuffer.
        if memory is not None:
            try:
                for row in range(0 if handoff else h):
                    offset = (row + yoff) * stride + xoff * count
                    memory[offset:offset + w * count] = bytes(w * count)
                memory.flush()
            except Exception as error:
                print('Splash framebuffer cleanup failed: ' + str(error), flush=True)
            finally:
                memory.close()
        if fd is not None: os.close(fd)
        try:
            if old is not None and not handoff: fcntl.ioctl(tty,0x4B3A,old)
        except OSError as error:
            print('Console restore unavailable; handing over to BH display: '+str(error), flush=True)
        finally:
            os.close(tty)

if __name__=='__main__': main()
