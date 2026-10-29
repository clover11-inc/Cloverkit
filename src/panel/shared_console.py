#!/usr/bin/env python3
"""One serial reader per adapter, shared terminal clients and an LCD snapshot.

Unix socket only; no shell or commands received from clients are executed.
Serial output history lives in bounded RAM, never a persistent log.
"""
import base64
import errno
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import socket
import stat
import struct
import subprocess
import sys
import termios
import time
import tty

SOCKET = '/run/cloverkit-serial/broker.sock'
LIMIT = 131072
MARKER = 'CLOVERKIT_SHARED_SERIAL_V1'


def encode(message):
    return (json.dumps(message, separators=(',', ':'))+'\n').encode()


def preview(raw):
    text = raw.decode('utf-8', errors='replace')
    text = re.sub(r'\x1b\][^\x07]*(?:\x07|\x1b\\)', '', text)
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
    text = re.sub(r'\x1b.', '', text)
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    return '\n'.join(''.join(c for c in line if c.isprintable() or c=='\t')
                     for line in text.splitlines()[-30:])


class Broker:
    def __init__(self, path=SOCKET, allowed=None, opener=None, listener=None):
        self.path = path
        self.allowed = allowed if allowed is not None else {0, pwd.getpwnam('console').pw_uid,
                                                          pwd.getpwnam(os.environ.get('CLOVERKIT_USER', 'clover')).pw_uid}
        self.opener = opener or self.open_serial
        self.selector = selectors.DefaultSelector()
        self.clients = {}
        self.ports = {}
        self.running = True
        self.listener = listener or socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if listener is None:
            self.listener.bind(path)
            os.chmod(path, 0o666)  # SO_PEERCRED below authenticates every connection.
        self.listener.listen(16)
        self.listener.setblocking(False)
        self.selector.register(self.listener, selectors.EVENT_READ, ('listen', None))

    @staticmethod
    def open_serial(port, baud):
        if not re.fullmatch(r'/dev/tty(?:USB|ACM)[0-9]+', port):
            raise ValueError('Only USB serial adapters are allowed')
        if Path(port).is_symlink() or not stat.S_ISCHR(os.stat(port).st_mode):
            raise ValueError('Not a serial device node')
        check = subprocess.run(['/usr/bin/fuser', port], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=2)
        if check.returncode == 0:
            raise ValueError('Port is held by another program; close that program first')
        if check.returncode != 1:
            raise ValueError('Unable to check serial ownership')
        fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK | os.O_NOFOLLOW)
        try:
            fcntl.ioctl(fd, termios.TIOCEXCL)
            tty.setraw(fd)
            settings = termios.tcgetattr(fd)
            settings[4] = settings[5] = {9600: termios.B9600, 115200: termios.B115200}[baud]
            settings[2] |= termios.CLOCAL | termios.CREAD
            settings[2] &= ~getattr(termios, 'CRTSCTS', 0)
            termios.tcsetattr(fd, termios.TCSANOW, settings)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def queue(self, connection, message):
        client = self.clients.get(connection)
        if not client:
            return
        client['out'] += encode(message)
        if len(client['out']) > LIMIT:
            self.detach(connection)
        else:
            self.selector.modify(connection, selectors.EVENT_READ | selectors.EVENT_WRITE, ('client', connection))

    def detach(self, connection):
        client = self.clients.pop(connection, None)
        if not client:
            return
        self.selector.unregister(connection)
        connection.close()
        port = client['port']
        if port and port in self.ports and not any(c['port']==port for c in self.clients.values()):
            state = self.ports[port]
            if state['fd'] is not None:
                self.selector.unregister(state['fd'])
                try:
                    fcntl.ioctl(state['fd'], termios.TIOCNXCL)
                except OSError:
                    pass
                os.close(state['fd'])
                state['fd'] = None
                state['pending'] = b''

    def snapshot(self):
        return [{'port': port, 'baud': state['baud'], 'sessions': sum(c['port']==port for c in self.clients.values()),
                 'rx': state['rx'], 'tx': state['tx'], 'last_rx': round(time.monotonic()-state['last_rx'], 1) if state['last_rx'] else None,
                 'active': state['fd'] is not None, 'output': preview(state['history'])}
                for port, state in sorted(self.ports.items())]

    def request(self, connection, message):
        client = self.clients[connection]
        operation = message.get('op')
        if operation == 'snapshot' and not client['port']:
            self.queue(connection, {'ports': self.snapshot()})
            client['closing'] = True
        elif operation == 'attach' and not client['port']:
            port = message.get('port', '')
            if not isinstance(port, str) or not re.fullmatch(r'/dev/tty(?:USB|ACM)[0-9]+', port):
                raise ValueError('Invalid USB serial port')
            baud = message.get('baud')
            if baud not in (None, 9600, 115200) or isinstance(baud, bool):
                raise ValueError('Baud must be 9600 or 115200')
            state = self.ports.get(port)
            if state and state['fd'] is not None and baud and state['baud'] != baud:
                raise ValueError('Port is already shared at '+str(state['baud'])+' baud; join at that baud')
            if not state or state['fd'] is None:
                actual_baud = baud or (state['baud'] if state else 9600)
                fd = self.opener(port, actual_baud)
                state = dict(fd=fd, baud=actual_baud, history=b'', rx=0, tx=0, last_rx=None, pending=b'')
                self.ports[port] = state
                self.selector.register(fd, selectors.EVENT_READ, ('serial', port))
            client['port'] = port
            self.queue(connection, {'attached': port, 'baud': state['baud']})
            if state['history']:
                self.queue(connection, {'data': base64.b64encode(state['history']).decode()})
        elif operation == 'data' and client['port']:
            raw = base64.b64decode(message.get('data', ''), validate=True)
            if len(raw)>4096:
                raise ValueError('Input too large')
            state = self.ports[client['port']]
            if len(state['pending']) + len(raw)>LIMIT:
                raise ValueError('Serial input queue is full')
            state['pending'] += raw
            self.selector.modify(state['fd'], selectors.EVENT_READ | selectors.EVENT_WRITE, ('serial', client['port']))
        else:
            raise ValueError('Invalid request')

    def step(self, timeout=0.1):
        for key, events in self.selector.select(timeout):
            kind, item = key.data
            if kind == 'listen':
                connection, _ = self.listener.accept()
                uid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
                if uid not in self.allowed or len(self.clients)>=32:
                    connection.close()
                    continue
                connection.setblocking(False)
                self.clients[connection] = dict(port=None, incoming=b'', out=b'', closing=False, since=time.monotonic())
                self.selector.register(connection, selectors.EVENT_READ, ('client', connection))
            elif kind == 'client' and item in self.clients:
                client = self.clients[item]
                try:
                    if events & selectors.EVENT_READ:
                        raw = item.recv(8192)
                        if not raw:
                            self.detach(item)
                            continue
                        client['incoming'] += raw
                        if len(client['incoming'])>32768:
                            raise ValueError('Request too large')
                        while b'\n' in client['incoming']:
                            line, client['incoming'] = client['incoming'].split(b'\n', 1)
                            self.request(item, json.loads(line))
                    if events & selectors.EVENT_WRITE and item in self.clients:
                        count = item.send(client['out'])
                        client['out'] = client['out'][count:]
                        if not client['out']:
                            if client['closing']:
                                self.detach(item)
                            else:
                                self.selector.modify(item, selectors.EVENT_READ, ('client', item))
                except BlockingIOError:
                    pass
                except (ValueError, TypeError, AttributeError, OSError) as error:
                    explanation = str(error) if isinstance(error, ValueError) and not isinstance(error, json.JSONDecodeError) else 'Serial request failed; check adapter availability'
                    self.queue(item, {'error': explanation})
                    if item in self.clients:
                        self.clients[item]['closing'] = True
            elif kind == 'serial' and self.ports[item]['fd'] is not None:
                state = self.ports[item]
                try:
                    if events & selectors.EVENT_READ:
                        raw = os.read(state['fd'], 4096)
                        if not raw:
                            raise OSError('Adapter disconnected')
                        state['history'] = (state['history']+raw)[-8192:]
                        state['rx'] += len(raw)
                        state['last_rx'] = time.monotonic()
                        for connection, client in list(self.clients.items()):
                            if client['port']==item:
                                self.queue(connection, {'data': base64.b64encode(raw).decode()})
                    if events & selectors.EVENT_WRITE and state['fd'] is not None:
                        count = os.write(state['fd'], state['pending'])
                        state['pending'] = state['pending'][count:]
                        state['tx'] += count
                        if not state['pending']:
                            self.selector.modify(state['fd'], selectors.EVENT_READ, ('serial', item))
                except BlockingIOError:
                    pass
                except OSError:
                    for connection, client in list(self.clients.items()):
                        if client['port']==item:
                            self.detach(connection)
        for connection, client in list(self.clients.items()):
            if client['port'] is None and not client['closing'] and time.monotonic()-client['since']>5:
                self.detach(connection)

    def close(self):
        for connection in list(self.clients):
            self.detach(connection)
        self.selector.close()
        self.listener.close()
        Path(self.path).unlink(missing_ok=True)


def get_snapshot(path=SOCKET):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(0.4)
        connection.connect(path)
        connection.sendall(encode({'op': 'snapshot'}))
        data = b''
        while b'\n' not in data:
            chunk = connection.recv(8192)
            if not chunk or len(data)>1048576:
                raise OSError('Snapshot unavailable')
            data += chunk
        return json.loads(data.split(b'\n', 1)[0])['ports']


def terminal(port, baud=None):
    if not sys.stdin.isatty():
        raise ValueError('An interactive SSH terminal is required')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.connect(SOCKET)
        connection.sendall(encode({'op': 'attach', 'port': port, 'baud': baud}))
        # Handshake before raw mode, so errors remain readable.
        data = b''
        while b'\n' not in data:
            chunk = connection.recv(8192)
            if not chunk:
                raise OSError('Serial service disconnected')
            data += chunk
        line, data = data.split(b'\n', 1)
        response = json.loads(line)
        if 'error' in response:
            raise ValueError(response['error'])
        print('Shared serial: '+port+' | '+str(response['baud'])+' baud')
        print('Everyone attached can view and type. Ctrl+A then Ctrl+X detaches.', flush=True)
        original = termios.tcgetattr(sys.stdin.fileno())
        selector = selectors.DefaultSelector()
        selector.register(connection, selectors.EVENT_READ)
        selector.register(sys.stdin, selectors.EVENT_READ)
        escape = False
        try:
            tty.setraw(sys.stdin.fileno())
            while True:
                while b'\n' in data:
                    line, data = data.split(b'\n', 1)
                    response = json.loads(line)
                    if 'data' in response:
                        sys.stdout.buffer.write(base64.b64decode(response['data']))
                        sys.stdout.buffer.flush()
                    if 'error' in response:
                        return
                for key, _ in selector.select():
                    if key.fileobj is connection:
                        raw = connection.recv(8192)
                        if not raw:
                            return
                        data += raw
                    else:
                        raw = os.read(sys.stdin.fileno(), 4096)
                        if not raw:
                            return
                        output = bytearray()
                        for value in raw:
                            if escape:
                                escape = False
                                if value==24:
                                    return
                                output.extend((1, value))
                            elif value==1:
                                escape = True
                            else:
                                output.append(value)
                        if output:
                            connection.sendall(encode({'op': 'data', 'data': base64.b64encode(output).decode()}))
        finally:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, original)
            selector.close()
            print('\r\nDetached.', flush=True)


def choose(ports):
    if not ports:
        raise ValueError('No USB serial adapters detected')
    if len(ports)==1:
        return ports[0]
    print('Serial adapters (active ports can be joined):')
    for index, port in enumerate(ports, 1):
        print(f'  {index}) {port}')
    choice = input('Select device: ').strip()
    if not choice.isdigit() or not 1<=int(choice)<=len(ports):
        raise ValueError('Invalid selection')
    return ports[int(choice)-1]


def main():
    if sys.argv[1:] == ['broker']:
        if os.geteuid()!=0:
            raise ValueError('Serial broker requires its root service')
        lock = open('/run/cloverkit-serial/broker.lock', 'w')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        Path(SOCKET).unlink(missing_ok=True)
        broker = Broker()
        try:
            while True:
                broker.step()
        finally:
            broker.close()
    elif len(sys.argv)<=2 and (len(sys.argv)==1 or sys.argv[1] in ('9600', '115200')):
        ports = sorted(str(p) for pattern in ('ttyUSB[0-9]*', 'ttyACM[0-9]*') for p in Path('/dev').glob(pattern)
                       if re.fullmatch(r'tty(?:USB|ACM)[0-9]+', p.name))
        port = choose(ports)
        baud = int(sys.argv[1]) if len(sys.argv)==2 else None
        remote = os.environ.get('SSH_ORIGINAL_COMMAND', '').strip()
        if remote:
            if remote not in ('9600', '115200'):
                raise ValueError('Use ssh -t console@HOST [9600|115200]')
            baud = int(remote)
        # Auto uses the existing session's baud, or 9600 for a new session.
        terminal(port, baud)
    else:
        raise ValueError('Usage: console [9600|115200]')


if __name__=='__main__':
    try:
        main()
    except (OSError, ValueError, EOFError, KeyboardInterrupt) as error:
        print('\nConsole: '+str(error), file=sys.stderr)
        raise SystemExit(1)
