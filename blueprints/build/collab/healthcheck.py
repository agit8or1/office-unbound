#!/usr/bin/env python3
"""container healthcheck: `healthcheck.py http://127.0.0.1:PORT/path` (expects 200) or `healthcheck.py unix:/path/to.sock` (a connect must succeed)."""
import socket
import sys
import urllib.request

t = sys.argv[1]
try:
    if t.startswith("unix:"):
        s = socket.socket(socket.AF_UNIX)
        s.settimeout(4)
        s.connect(t[5:])
        s.close()
    else:
        sys.exit(0 if urllib.request.urlopen(t, timeout=4).status == 200 else 1)
except Exception:
    sys.exit(1)
