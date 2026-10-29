"""Fixed evidence summary above a scrollable, timestamped task history."""
import re,textwrap

def view(task,task_end,capacity,cols):
    link='CHECKING';speed='--';duplex='--';last=None;peer='--';mac='--';proof='No address observed';ports={};ping='--';arp=set();leases=set();cleanup='Pending';current='--'
    for raw in task['lines']:
        line=re.sub(r'^\[\d+:\d+\] ', '',raw)
        if line.startswith('LINK: '): link='UP' if line=='LINK: UP' else 'DOWN'
        if line.startswith('Speed:'): speed=line.split(':',1)[1].strip()
        if line.startswith('Duplex:'): duplex=line.split(':',1)[1].strip()
        found=re.match(r'OBSERVED: MAC (\S+) \| IP (\S+)',line)
        if found:
            mac,peer=found.groups();arp.add((mac,peer));proof='Observed ARP sender'
        found=re.match(r'LEASE: (\S+) \| (\S+) \|',line)
        if found:
            peer,mac=found.groups();leases.add((mac,peer));proof='Confirmed DHCP lease'
        if line.startswith('TESTING: '):
            current=line.split(': ',1)[1];ports={};ping='--'
        if line.startswith('PING: '): ping=line.split(': ',1)[1]
        found=re.match(r'TCP (\d+): (.*)',line)
        if found: ports[found[1]]=found[2]
        if line.startswith('RESTORED:'): cleanup='Complete'
        if line.startswith('RESTORE ERROR:'): cleanup='FAILED - see log'
    first=task['count']-len(task['lines']);end=task['count'] if task_end is None else max(first+1,min(task['count'],task_end))
    summary=[f"{task['title']} | {task['state']} {task['elapsed']:.0f}s",
        f'LINK {link} | {speed} | {duplex}',
        f'ARP peers seen {len(arp)} | DHCP leases {len(leases)}',
        f'Last peer IP: {peer}',f'MAC: {mac}',proof,
        f'Test target: {current} | Ping: {ping}',
        'TCP '+ ' '.join(f'{p}:{ports.get(p,"--")}' for p in ('9100','80','443')),
        f'Cleanup: {cleanup}',
        ('EVENTS - FOLLOW LIVE' if task_end is None else 'EVENTS - REVIEW; Right: latest')]
    width=max(1,cols-1)
    summary=[part for row in summary for part in textwrap.wrap(row,width=width) or ['']]
    # Keep at least three event rows, even on a small console.
    summary=summary[:max(1,capacity-3)]
    history=task['lines'][:max(0,end-first)]
    wrapped=[part for row in history for part in textwrap.wrap(row,width=width) or ['']]
    remaining=max(1,capacity-len(summary))
    return summary+wrapped[-remaining:]
