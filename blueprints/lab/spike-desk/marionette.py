#!/usr/bin/env python3
"""Minimal Marionette client (stdlib only): drives Thunderbird/Firefox internals over the remote protocol.
Used by the client-compat tests to run chrome-privileged JavaScript inside a real Thunderbird process
(the same internal modules the account-setup UI and the mail/calendar code use). Not a GUI driver."""
import json, socket, itertools


class Marionette:
    def __init__(self, host="127.0.0.1", port=2828, timeout=300):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.buf = b""
        self.ids = itertools.count(1)
        self.hello = self._recv()
        self.cmd("WebDriver:NewSession", {"capabilities": {}})
        self.cmd("Marionette:SetContext", {"value": "chrome"})

    def _read(self):
        d = self.s.recv(65536)
        if not d:
            raise EOFError("marionette closed")
        return d

    def _recv(self):
        while b":" not in self.buf:
            self.buf += self._read()
        n, rest = self.buf.split(b":", 1)
        n = int(n)
        while len(rest) < n:
            rest += self._read()
        self.buf = rest[n:]
        return json.loads(rest[:n].decode())

    def cmd(self, name, params=None):
        i = next(self.ids)
        msg = json.dumps([0, i, name, params or {}]).encode()
        self.s.sendall(b"%d:" % len(msg) + msg)
        while True:
            r = self._recv()
            if r[0] == 1 and r[1] == i:
                if r[2]:
                    raise RuntimeError("%s: %s" % (name, r[2]))
                return r[3]

    def run(self, script, args=None, timeout=240000):
        """Async chrome script; call `resolve(value)` to finish."""
        self.cmd("WebDriver:SetTimeouts", {"script": timeout})
        r = self.cmd("WebDriver:ExecuteAsyncScript",
                     {"script": "const resolve = arguments[arguments.length-1];\n" + script, "args": args or []})
        return r.get("value") if isinstance(r, dict) else r

    def sync(self, script, args=None):
        r = self.cmd("WebDriver:ExecuteScript", {"script": script, "args": args or []})
        return r.get("value") if isinstance(r, dict) else r

    def run_robust(self, script, args=None, timeout=240):
        """Like run(), but the result is also written to a pref so that it survives the Marionette sandbox being torn
        down (a calendar error dialog does that): if the call returns nothing, poll the pref."""
        import time, uuid
        key = "cc.res." + uuid.uuid4().hex[:8]
        pre = ("const __orig = arguments[arguments.length-1];"
               "const resolve = v => { try { Services.prefs.setStringPref(%s, v); } catch(e) {} __orig(v); };\n" % json.dumps(key))
        self.cmd("WebDriver:SetTimeouts", {"script": timeout * 1000})
        try:
            r = self.cmd("WebDriver:ExecuteAsyncScript", {"script": pre + script, "args": args or []})
            v = r.get("value") if isinstance(r, dict) else r
        except RuntimeError as e:
            if "unexpected alert" not in str(e):
                raise
            v = None
        end = time.time() + timeout
        while v is None and time.time() < end:
            time.sleep(1)
            try:
                v = self.sync("return Services.prefs.getStringPref(arguments[0], '');", [key]) or None
            except RuntimeError:
                v = None
        return v
