#!/usr/bin/env python3
"""stdin/stdout <-> 127.0.0.1:<port> relay. qemu starts it per guest connection (`guestfwd=tcp:10.0.2.100:PORT-cmd:...`), so the restricted user-mode network
lets the guest reach exactly one host listener (the throw-away ICS simulator) and nothing else."""
import os
import socket
import sys
import threading

port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=10)
s.settimeout(None)


def up():
    try:
        while True:
            d = os.read(0, 65536)
            if not d:
                break
            s.sendall(d)
    except OSError:
        pass
    try:
        s.shutdown(socket.SHUT_WR)
    except OSError:
        pass


threading.Thread(target=up, daemon=True).start()
try:
    while True:
        d = s.recv(65536)
        if not d:
            break
        os.write(1, d)
except OSError:
    pass
