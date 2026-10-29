"""One Wi-Fi adapters status and recovery page under Device Network Controls."""
def install(Panel):
    items=Panel.items;handle=Panel.handle;lines=Panel.lines
    def menu_items(self,data):
        if self.page=='Wi-Fi adapters':return ['Reset','Return']
        result=items(self,data)
        if self.page=='System' and self.details is None:
            return ['Wi-Fi adapters' if item=='Wi-Fi hardware status' else item for item in result if item!='Wi-Fi adapters']
        return result
    def menu_handle(self,key):
        if self.page=='System' and self.details is None and key in ('enter','right'):
            selected=self.items(self.collector.snapshot())
            if selected and selected[min(self.selected,len(selected)-1)]=='Wi-Fi adapters':
                self.page='Wi-Fi adapters';self.details=None;self.selected=0;return
        if self.page=='Wi-Fi adapters':
            if key in ('up','down'):self.selected=1-self.selected
            elif key in ('back','left') or key in ('enter','right') and self.selected==1:
                self.page='System';self.details=None;self.selected=0
            elif key in ('enter','right'):
                self.start_task('Reset Wi-Fi adapters',['sudo','-n','/usr/local/bin/cloverkit-radio-reset'])
            return
        return handle(self,key)
    def menu_lines(self,data,capacity=30,cols=80):
        if self.page=='Wi-Fi adapters':
            rows=['Wi-Fi adapters','']
            devices=[d for d in data.get('network',{}).get('devices',[]) if d.get('type')=='wifi' or d.get('device') in ('wlan0','wlan1','wlan2')]
            for device in devices:
                name=device.get('device','?')
                rows.append(name+'  '+device.get('state','checking')+(' | protected' if name=='wlan0' else ''))
                connection=device.get('connection');address=device.get('ip')
                if connection and connection!='--':rows.append('  Connection: '+connection)
                if address and address!='--':rows.append('  IPv4: '+address)
                rows.append('')
            if not devices:rows.append('Checking Wi-Fi adapters...')
            rows.append('Reset recovers wlan1 / wlan2; wlan0 protected.')
            return rows[:max(0,capacity-3)]+['',self.mark(0,'Reset'),self.mark(1,'Return')]
        if self.page=='System' and self.details is None:
            current=self.items(data);rows=lines(self,data,capacity,cols)
            if 'Device Network Controls' not in rows and 'Wi-Fi adapters' in current:
                label=self.mark(current.index('Wi-Fi adapters'),'Wi-Fi adapters')
                if label in rows:rows.insert(rows.index(label),'Device Network Controls')
            return rows[:capacity]
        return lines(self,data,capacity,cols)
    Panel.items=menu_items;Panel.handle=menu_handle;Panel.lines=menu_lines
