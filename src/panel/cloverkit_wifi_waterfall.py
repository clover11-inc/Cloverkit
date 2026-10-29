"""AP packet RSSI waterfall. This is not an RF spectrum measurement."""
import collections
import math
import time

BANDS=('2.4 GHz','5 GHz','6 GHz')
BACKGROUND=(8,17,13)
GREEN=(94,233,140)
WHITE=(235,244,239)
MUTED=(150,166,159)

def band_for(frequency):
    return 0 if 2400<=frequency<2500 else 1 if 4900<=frequency<5925 else 2 if 5925<=frequency<7125 else None

def channel(frequency):
    if frequency==2484:return 14
    return round((frequency-2407)/5) if frequency<2500 else round((frequency-5000)/5) if frequency<5925 else round((frequency-5950)/5)

def finite(value,minimum,maximum):
    return isinstance(value,(int,float)) and not isinstance(value,bool) and math.isfinite(value) and minimum<=value<=maximum

def signal_colour(value):
    anchors=[(-100,(30,65,150)),(-85,(32,154,215)),(-70,(30,215,157)),(-55,(210,224,57)),(-40,(255,145,32)),(-30,(244,70,58))]
    if value<=anchors[0][0]:return anchors[0][1]
    for (low,a),(high,b) in zip(anchors,anchors[1:]):
        if value<=high:
            fraction=(value-low)/(high-low)
            return tuple(round(x+(y-x)*fraction) for x,y in zip(a,b))
    return anchors[-1][1]

def install_backend(Monitor):
    """Reuse existing observations; never add a capture or radio operation."""
    previous=Monitor.snapshot
    def snapshot(self):
        result=previous(self)
        with self.lock:
            points=[]
            for (bssid,frequency),ap in self.aps.items():
                readings=ap.get('ap_signal')
                if not readings:continue
                stamp,dbm=readings[-1]
                if finite(dbm,-130,0):
                    points.append(dict(bssid=bssid,frequency=frequency,dbm=dbm,observed_monotonic=stamp))
            result['waterfall_samples']=points
            result['waterfall_source']='Decoded AP packet RSSI; no RF energy or noise inferred'
        return result
    Monitor.snapshot=snapshot

class Waterfall:
    def __init__(self):
        self.session=None
        self.history=collections.deque(maxlen=120)
        self.last_slot=None
        self.last_update=None
        self.last_frame_signature=None
        self.band=0
        self.allowed_bands=(0,1,2)
        self.selected=0
        self.paused=False
        self.seen={}
        self.latest={}
        self.frequencies=set()
        self.values={}

    def consume(self,values,now=None):
        now=time.monotonic() if now is None else now
        if not isinstance(values,dict):return
        session=values.get('session')
        if session!=self.session:
            self.session=session;self.history.clear();self.seen.clear();self.latest.clear();self.frequencies.clear();self.last_slot=None;self.last_update=None
        if self.paused:return
        self.values=values
        update=values.get('updated_at')
        if update==self.last_update:return
        self.last_update=update
        slot=int(now)
        if self.last_slot is not None:
            for missing in range(max(self.last_slot+1,slot-119),slot):self.history.append((missing,{},set()))
        listened=set()
        for radio in values.get('radios',{}).values():
            for frequency in radio.get('channels',[]):
                if finite(frequency,2400,7125) and band_for(frequency) is not None:self.frequencies.add(int(frequency))
            frequency=radio.get('frequency')
            if finite(frequency,2400,7125) and not radio.get('error') and not radio.get('tune_error') and values.get('state')=='RUNNING':
                listened.add(int(frequency));self.frequencies.add(int(frequency))
        row={}
        for point in values.get('waterfall_samples',[]):
            frequency=point.get('frequency');dbm=point.get('dbm');stamp=point.get('observed_monotonic');bssid=point.get('bssid')
            if not finite(frequency,2400,7125) or band_for(frequency) is None or not finite(dbm,-130,0) or not finite(stamp,0,now+1):continue
            key=(str(bssid),int(frequency))
            if stamp<=self.seen.get(key,-1):continue
            self.seen[key]=stamp
            if now-stamp>2.5:continue
            frequency=int(frequency);self.frequencies.add(frequency)
            row[frequency]=max(row.get(frequency,-130),float(dbm))
            old=self.latest.get(frequency)
            if old is None or stamp>old[1] or stamp==old[1] and dbm>old[0]:self.latest[frequency]=(float(dbm),stamp,str(bssid))
        if self.last_slot==slot and self.history:
            stamp,old,old_listened=self.history.pop()
            for frequency,value in row.items():old[frequency]=max(old.get(frequency,-130),value)
            self.history.append((slot,old,old_listened|listened))
        else:self.history.append((slot,row,listened))
        self.last_slot=slot
        # Bound identities as well as time history for busy sites.
        if len(self.seen)>2048:self.seen={key:stamp for key,stamp in self.seen.items() if now-stamp<120}

    def channels(self):
        result=sorted(f for f in self.frequencies if band_for(f)==self.band)
        return result or ([2412+5*i for i in range(13)] if self.band==0 else [5180,5200,5220,5240,5260,5280,5300,5320,5500,5520,5540,5560,5580,5600,5620,5640,5660,5680,5700,5720,5745,5765,5785,5805,5825] if self.band==1 else [5955+20*i for i in range(59)])

    def key(self,key):
        if key in ('up','down'):
            if len(self.allowed_bands)==1:return
            position=self.allowed_bands.index(self.band) if self.band in self.allowed_bands else 0
            self.band=self.allowed_bands[(position+(-1 if key=='up' else 1))%len(self.allowed_bands)];self.selected=0
        elif key in ('left','right'):self.selected=(self.selected+(-1 if key=='left' else 1))%len(self.channels())
        elif key=='enter':
            self.paused=not self.paused
            if not self.paused:self.last_update=None
        self.last_frame_signature=None

    def controls(self):
        return ('U/D band | ' if len(self.allowed_bands)>1 else '')+'L/R channel | Centre pause'

    def status(self,task):
        if self.paused:return 'PAUSED VIEW · capture continues'
        age=time.monotonic()-task.get('finder',{}).get('received',time.monotonic())
        if task.get('state')!='RUNNING':return task.get('state','STOPPED')+' · final observations'
        if age>5:return f'STALE STREAM · update {int(age)}s ago'
        if self.values.get('state')=='RUNNING' and self.values.get('radios') and not any(band_for(f)==self.band for f in self.frequencies):return 'Band not in adapter capture plan'
        return str(self.values.get('state') or 'Starting')

    def _graph_image(self,size,task,now=None):
        from PIL import Image,ImageDraw,ImageFont
        now=time.monotonic() if now is None else now
        width,height=size
        if width<400 or height<440:
            return self._graph_image((480,480),task,now).resize(size,Image.Resampling.LANCZOS)
        image=Image.new('RGB',size,BACKGROUND);draw=ImageDraw.Draw(image)
        font_path='/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf'
        normal=ImageFont.truetype(font_path,12 if width<500 else 15)
        small=ImageFont.truetype(font_path,10 if width<500 else 12)
        title=ImageFont.truetype(font_path,17 if width<500 else 22)
        def text(x,y,value,colour=WHITE,font=normal):
            value=''.join(char if char.isprintable() else ' ' for char in str(value))
            while value and draw.textlength(value,font=font)>width-x-8:value=value[:-1]
            draw.text((x,y),value,font=font,fill=colour)
        text(12,8,'CloverKit · Wi-Fi Waterfall',GREEN,title)
        text(12,32,f'{BANDS[self.band]} | {self.status(task)}',GREEN)
        text(12,49,'AP packet RSSI · not RF spectrum',MUTED,small)
        if self.values.get('state')=='FAILED' and self.values.get('notes'):
            draw.rectangle((0,48,width,64),fill=BACKGROUND)
            text(12,49,self.values['notes'][-1],(255,215,105),small)
        # Signal scale explicitly denotes received Wi-Fi strength, not severity.
        ramp_y=68
        for x in range(90,width-55):
            dbm=-100+70*(x-90)/max(1,width-146);draw.line((x,ramp_y,x,ramp_y+7),fill=signal_colour(dbm))
        text(12,ramp_y-2,'-100 dBm',MUTED,small);text(width-51,ramp_y-2,'-30',MUTED,small)
        left,right=43,width-12;top=103;bottom=max(top+65,int(height*.39))
        text(12,85,'Latest per channel · grey = older than 10s',MUTED,small)
        frequencies=self.channels();self.selected%=len(frequencies)
        cell=(right-left)/len(frequencies)
        for level in (-100,-70,-40):
            y=bottom-(level+100)/70*(bottom-top);draw.line((left,y,right,y),fill=(34,50,43));text(4,y-5,str(level),MUTED,small)
        for i,frequency in enumerate(frequencies):
            x0=round(left+i*cell);x1=max(x0,round(left+(i+1)*cell)-1)
            reading=self.latest.get(frequency)
            if reading:
                dbm,stamp,_=reading;y=round(bottom-max(0,min(70,dbm+100))/70*(bottom-top))
                colour=signal_colour(dbm) if now-stamp<=10 else (83,105,94)
                draw.rectangle((x0+1,y,x1,bottom),fill=colour)
            if i==self.selected:draw.rectangle((x0,top,x1,bottom),outline=GREEN)
        for i,frequency in enumerate(frequencies):
            if i%max(1,math.ceil(len(frequencies)/8))==0:text(round(left+i*cell),bottom+3,channel(frequency),MUTED,small)
        waterfall_top=bottom+35;waterfall_bottom=height-134
        text(12,waterfall_top-16,'WATERFALL · newest at bottom · 120s retained',GREEN,small)
        draw.rectangle((left,waterfall_top,right,waterfall_bottom),fill=(16,25,22),outline=(54,75,64))
        history=list(self.history);visible=min(120,waterfall_bottom-waterfall_top)
        for age,(_,samples,listened) in enumerate(reversed(history[-visible:])):
            y=waterfall_bottom-1-age
            for i,frequency in enumerate(frequencies):
                colour=signal_colour(samples[frequency]) if frequency in samples else (54,67,60) if frequency in listened else (16,25,22)
                draw.line((round(left+i*cell),y,round(left+(i+1)*cell)-1,y),fill=colour)
        cursor=round(left+(self.selected+.5)*cell);draw.line((cursor,waterfall_top,cursor,waterfall_bottom),fill=(130,220,160))
        text(3,waterfall_bottom-11,'NOW',MUTED,small)
        y=height-124;frequency=frequencies[self.selected]
        text(12,y,f'CH {channel(frequency)} · {frequency} MHz',GREEN)
        reading=self.latest.get(frequency)
        if reading:
            dbm,stamp,bssid=reading;age=max(0,int(now-stamp))
            ap=next((ap for ap in self.values.get('aps',[]) if ap.get('bssid')==bssid),{})
            text(12,y+18,f'{ap.get("ssid") or "Hidden"} · {dbm:.1f} dBm · {age}s ago',WHITE)
            text(12,y+35,bssid,MUTED,small)
        else:text(12,y+19,'No AP signal sampled on this channel',MUTED)
        text(12,height-72,'Dark: unobserved | grey: listened, no AP sample',MUTED,small)
        text(12,height-56,'Hopping misses traffic; missing is not quiet RF.',MUTED,small)
        text(12,height-38,self.controls(),GREEN,small)
        text(12,height-22,'Back stop/return | Hold Back exit',GREEN,small)
        return image

    def panel_background(self,size,source=None):
        from PIL import Image
        if source is not None:return source.copy() if source.size==size else source.resize(size,Image.Resampling.LANCZOS)
        if getattr(self,'_background_size',None)!=size:
            dark=Image.new('RGB',size,BACKGROUND)
            try:
                with Image.open('/usr/local/lib/bh-interactive/clover-boot.png') as art:
                    art=art.convert('RGB').resize(size,Image.Resampling.LANCZOS)
                    shifted=dark.copy();shifted.paste(art,(0,round(size[1]*.10)))
                    self._background=Image.blend(dark,shifted,.28)
            except OSError:self._background=dark
            self._background_size=size
        return self._background.copy()

    def image(self,size,task,now=None,header=None,background=None):
        from PIL import Image,ImageDraw,ImageFont
        width,height=size
        if width<400 or height<440:
            return self.image((480,480),task,now,header,background).resize(size,Image.Resampling.LANCZOS)
        graph=self._graph_image(size,task,now)
        canvas=self.panel_background(size,background);draw=ImageDraw.Draw(canvas)
        font=ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf',10 if width<500 else 13)
        title=ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf',13 if width<500 else 17)
        def text(y,value,colour=WHITE,use_font=font):
            value=''.join(c for c in str(value) if c.isprintable())
            while value and draw.textlength(value,font=use_font)>width-20:value=value[:-1]
            draw.text((10,y),value,font=use_font,fill=colour)
        text(6,'CloverKit Wi-Fi Waterfall',GREEN,title)
        summary=header or ('Network: checking','Connection: checking')
        text(25,summary[0],(80,220,235));text(40,summary[1])
        if 'VPN OFF' in summary[0] or 'VPN ON' in summary[0]:
            token='VPN OFF' if 'VPN OFF' in summary[0] else 'VPN ON'
            prefix=summary[0].split(token)[0]
            x=10+draw.textlength(prefix,font=font)
            if x+draw.textlength(token,font=font)<=width-10:
                draw.text((x,25),token,font=font,fill=(255,215,105) if token.endswith('OFF') else GREEN)
        draw.line((10,59,width-10,59),fill=(70,100,84))
        # Keep existing signal, history, cursor and selected AP; reserve shared chrome.
        body=graph.crop((0,32,width,height-78))
        body=body.resize((width,height-112),Image.Resampling.LANCZOS)
        from PIL import ImageChops
        def exact_mask(colour):
            difference=ImageChops.difference(body,Image.new('RGB',body.size,colour))
            r,g,b=difference.split()
            return ImageChops.lighter(ImageChops.lighter(r,g),b).point(lambda v:0 if v else 255)
        # Text, signal colours and grid stay opaque; unobserved areas reveal the clover.
        mask=ImageChops.invert(exact_mask(BACKGROUND))
        mask=Image.composite(Image.new('L',body.size,210),mask,exact_mask((16,25,22)))
        canvas.paste(body,(0,66),mask)
        draw.line((10,height-43,width-10,height-43),fill=(70,100,84))
        text(height-37,self.controls()+' | Back stop',GREEN)
        text(height-21,'Hold Back: exit | SSH: WASD Enter Q',(80,220,235))
        return canvas

def model_for(panel):
    task=panel.task.snapshot()
    if getattr(panel,'_waterfall_started',None)!=panel.task.started:
        panel._waterfall_started=panel.task.started;panel._waterfall=Waterfall();panel._waterfall.band={'5':1,'6':2}.get(getattr(panel,'_waterfall_mode','general'),0)
    model=panel._waterfall
    focused={'2.4':0,'5':1,'6':2}.get(getattr(panel,'_waterfall_mode','general'))
    model.allowed_bands=(focused,) if focused is not None else (0,1)
    if model.band not in model.allowed_bands:model.band=model.allowed_bands[0];model.selected=0
    model.consume(task.get('finder',{}).get('values') or {})
    return model,task

def draw_local(panel,lcd):
    if panel.page!='Tasks' or panel.task.snapshot().get('title')!='Wi-Fi waterfall':return False
    model,task=model_for(panel)
    summary=panel._waterfall_network_header(panel.collector.snapshot())
    signature=(task.get('state'),model.last_update,model.band,model.selected,model.paused,int(time.monotonic()),str(summary))
    if signature!=model.last_frame_signature:
        summary=panel._waterfall_network_header(panel.collector.snapshot())
        if isinstance(summary,str):summary=(summary,'')
        image=model.image((lcd.logical_w,lcd.logical_h),task,header=summary,background=getattr(lcd,'background',None))
        from PIL import Image
        lcd.write(image.transpose(Image.Transpose.ROTATE_270))
        lcd.last=None;model.last_frame_signature=signature
    return True

def install_panel(Panel,namespace):
    Panel._waterfall_network_header=staticmethod(namespace['network_header'])
    old_handle=Panel.handle;old_lines=Panel.lines
    old_start=Panel.start_task;old_items=Panel.items
    modes=[('General','general'),('2.4 GHz','2.4'),('5 GHz','5'),('6 GHz','6')]
    def start(panel,title,argv,metadata=None):
        panel._waterfall_network_header=namespace['network_header']
        if title=='Wi-Fi waterfall' and not (metadata or {}).get('waterfall_mode'):
            panel.page='Waterfall modes';panel.details=None;panel.selected=0;return
        return old_start(panel,title,argv,metadata)
    def items(panel,data):
        if panel.page=='Waterfall modes':return [label for label,mode in modes]
        return old_items(panel,data)
    def handle(panel,key):
        if panel.page=='Waterfall modes':
            if key in ('up','down'):panel.selected=(panel.selected+(-1 if key=='up' else 1))%4
            elif key in ('enter','right'):
                mode=modes[panel.selected][1];panel._waterfall_mode=mode
                panel._waterfall=Waterfall();panel._waterfall_started=None
                old_start(panel,'Wi-Fi waterfall',['sudo','-n','/usr/local/bin/wifi-waterfall-capture',mode],{'kind':'wifi-health','waterfall_mode':mode})
            elif key in ('back','left'):panel.page='Network';panel.details=None;panel.selected=0
            return
        if panel.page=='Tasks' and panel.task.snapshot().get('title')=='Wi-Fi waterfall':
            if key in ('up','down','left','right','enter'):
                model,task=model_for(panel);model.key(key);return
            if key=='back':panel.task.stop();panel.page='Waterfall modes';panel.details=None;panel.selected=0;return
        return old_handle(panel,key)
    def lines(panel,data,capacity=30,cols=80):
        if panel.page=='Waterfall modes':
            return ['Wi-Fi waterfall','Choose capture mode','',*[panel.mark(i,label) for i,(label,mode) in enumerate(modes)],'','General: one radio per band (2.4 / 5 GHz)','Focused: split channels across compatible radios','6 GHz needs compatible hardware','wlan0 protected'][:capacity]
        # Preserve pending-task transitions handled by the existing UI.
        original=old_lines(panel,data,capacity,cols)
        if panel.page!='Tasks' or panel.task.snapshot().get('title')!='Wi-Fi waterfall':return original
        model,task=model_for(panel)
        result=['Wi-Fi waterfall',model.status(task),BANDS[model.band],'AP packet RSSI; not RF spectrum','Local LCD shows the full graphical waterfall.']
        frequencies=model.channels()
        for frequency in frequencies[:max(1,capacity-9)]:
            reading=model.latest.get(frequency)
            text=f'{reading[0]:g} dBm · {int(max(0,time.monotonic()-reading[1]))}s ago' if reading else 'not sampled'
            result.append(f'CH {channel(frequency):3} | {text}')
        result+=[model.controls(),'Back stop/return; wlan0 protected']
        return result[:capacity]
    Panel.handle=handle;Panel.lines=lines;Panel.start_task=start;Panel.items=items
