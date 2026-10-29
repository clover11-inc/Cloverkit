"""Cloverkit game lifecycle: input proxy, VT handoff, scoped cleanup."""
# CLOVER_GAME_SESSION_V2
import fcntl
import os
from pathlib import Path
import select
import signal
import subprocess
import time

LOG = Path('/run/cloverkit/game-launch.log')


def activate_vt(number):
    fd = os.open('/dev/tty0', os.O_RDWR | os.O_NOCTTY)
    try:
        # VT_ACTIVATE only; do not block on VT_WAITACTIVE during a failed launch.
        fcntl.ioctl(fd, 0x5606, number)
    finally:
        os.close(fd)


def reset_controls():
    fd = os.open('/dev/ttyS0', os.O_WRONLY | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        if os.write(fd, b'\x92') != 1:
            raise OSError('Flipper reset was not sent')
    finally:
        os.close(fd)


def processes():
    result = {}
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
            result[int(entry.name)] = (int(fields[1]), int(fields[3]), fields[19])
        except (OSError, ValueError, IndexError):
            continue
    return result


def remember_children(root, owned):
    table = processes()
    parents = {pid for pid, started in owned.items()
               if pid in table and table[pid][2] == started}
    parents.add(root)
    changed = True
    while changed:
        changed = False
        for pid, (parent, session, started) in table.items():
            if pid not in parents and (parent in parents or session == root):
                parents.add(pid)
                changed = True
    for pid in parents:
        if pid in table:
            owned[pid] = table[pid][2]


def stop_children(proc, owned):
    remember_children(proc.pid, owned)
    # PID + start time protects unrelated processes if a PID was reused.
    for sig in (signal.SIGTERM, signal.SIGKILL):
        if proc.poll() is None:
            try:
                proc.send_signal(sig)
            except ProcessLookupError:
                pass
        table = processes()
        for pid, started in tuple(owned.items()):
            if pid in table and table[pid][2] == started:
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    pass
        if sig == signal.SIGTERM:
            # Exit-only grace: no startup delay or timer that kills a running game.
            try:
                proc.wait(timeout=0.8)
            except subprocess.TimeoutExpired:
                pass
    proc.wait(timeout=2)


# CLOVER_GAME_CENTRE_V1
def centre_game_window():
    import ctypes as C
    import ctypes.util
    try:
        x = C.CDLL(ctypes.util.find_library('X11'))
        W, D = C.c_ulong, C.c_void_p
        x.XOpenDisplay.argtypes=[C.c_char_p];x.XOpenDisplay.restype=D
        x.XDefaultRootWindow.argtypes=[D];x.XDefaultRootWindow.restype=W
        x.XQueryTree.argtypes=[D,W,C.POINTER(W),C.POINTER(W),C.POINTER(C.POINTER(W)),C.POINTER(C.c_uint)]
        x.XFetchName.argtypes=[D,W,C.POINTER(C.c_void_p)]
        x.XMoveWindow.argtypes=[D,W,C.c_int,C.c_int]
        x.XFree.argtypes=[C.c_void_p];x.XFlush.argtypes=[D];x.XCloseDisplay.argtypes=[D]
        for socket in sorted(Path('/tmp/.X11-unix').glob('X*')):
            d=x.XOpenDisplay((':'+socket.name[1:]).encode())
            if not d: continue
            try:
                queue=[x.XDefaultRootWindow(d)]
                while queue:
                    w=queue.pop();name=C.c_void_p()
                    if x.XFetchName(d,w,C.byref(name)) and name.value:
                        title=C.string_at(name).decode(errors='replace').lower();x.XFree(name)
                        if 'mgba' in title or 'pokémon' in title or 'pokemon' in title:
                            x.XMoveWindow(d,w,0,24);x.XFlush(d);return True
                    root,parent=W(),W();children=C.POINTER(W)();count=C.c_uint()
                    if x.XQueryTree(d,w,C.byref(root),C.byref(parent),C.byref(children),C.byref(count)):
                        queue.extend(children[i] for i in range(count.value))
                        if children:x.XFree(children)
            finally:x.XCloseDisplay(d)
    except (OSError,TypeError):pass
    return False


def run_game(rom, keep_running, input_fd=0):
    proc = None
    owned = {}
    message = 'Game closed'
    errors = []
    try:
        LOG.parent.mkdir(parents=True, exist_ok=True)
        with LOG.open('wb', buffering=0) as log:
            activate_vt(2)
            # bhtui's verified play_rom loop reads raw button bytes from stdin.
            # The panel owns the real input; only the game launcher reads this pipe.
            proc = subprocess.Popen(['/usr/local/bin/bhtui', '--play-rom', str(rom)],
                                    stdin=subprocess.PIPE, stdout=log, stderr=log,
                                    bufsize=0, start_new_session=True)
            os.set_blocking(proc.stdin.fileno(), False)
            pending = b''
            centre_until = time.monotonic() + 30
            centre_next = 0
            centred = False
            while proc.poll() is None:
                remember_children(proc.pid, owned)
                now = time.monotonic()
                if not centred and now < centre_until and now >= centre_next:
                    centred = centre_game_window()
                    centre_next = now + 0.5
                if not keep_running():
                    message = 'Game cancelled'
                    break
                readers, writers, _ = select.select(
                    [input_fd], [proc.stdin.fileno()] if pending else [], [], 0.05)
                if readers:
                    data = os.read(input_fd, 128)
                    # Firmware hold-to-exit = 0x90; Ctrl-C also cancels via SSH.
                    if not data or b'\x90' in data or b'\x03' in data:
                        message = 'Game cancelled'
                        break
                    pending += data
                if writers:
                    try:
                        count = os.write(proc.stdin.fileno(), pending)
                        pending = pending[count:]
                    except BlockingIOError:
                        pass
                    except BrokenPipeError:
                        break
            if proc.poll() is not None and proc.returncode != 0:
                message = f'Game failed ({proc.returncode}); see game-launch.log'
    except (OSError, ValueError) as error:
        message = f'Game unavailable: {error}'
    finally:
        if proc is not None:
            try:
                stop_children(proc, owned)
            except (OSError, subprocess.TimeoutExpired) as error:
                errors.append(f'game cleanup: {error}')
            if proc.stdin is not None:
                proc.stdin.close()
        try:
            reset_controls()
        except OSError as error:
            errors.append(f'control reset: {error}')
        try:
            activate_vt(1)
        except OSError as error:
            errors.append(f'screen return: {error}')
    return message + (' | ' + '; '.join(errors) if errors else '')
