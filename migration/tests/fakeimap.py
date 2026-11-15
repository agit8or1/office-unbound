"""Minimal in-process IMAP4rev1 server (plaintext, loopback only) for engine tests.

Records every command verb so tests can prove the source is only ever read (EXAMINE, BODY.PEEK) and never written.
Fault injection: ``drop_before_append`` / ``drop_after_append`` = close the socket on the Nth APPEND (before / after the
message is stored, i.e. "lost acknowledgement")."""
from __future__ import annotations

import re
import socketserver
import threading
import time

SPECIAL = {"Sent": "\\Sent", "Drafts": "\\Drafts", "Trash": "\\Trash", "Junk": "\\Junk", "Archive": "\\Archive"}


class Msg:
    def __init__(self, uid, data, flags=(), date="03-Mar-2025 10:00:00 +0000"):
        self.uid, self.data, self.flags, self.date = uid, data, set(flags), date


class Folder:
    def __init__(self, name, uidvalidity=1000, attrs=()):
        self.name, self.uidvalidity, self.attrs = name, uidvalidity, list(attrs)
        self.msgs: list[Msg] = []
        self.uidnext = 1

    def add(self, data, flags=(), date="03-Mar-2025 10:00:00 +0000"):
        m = Msg(self.uidnext, data, flags, date)
        self.uidnext += 1
        self.msgs.append(m)
        return m


class FakeImap:
    def __init__(self, delim="/", user="u", password="pw", token=None, caps="IMAP4rev1 UIDPLUS"):
        self.delim, self.user, self.password, self.token = delim, user, password, token
        self.folders: dict[str, Folder] = {}
        self.log: list[str] = []          # command verbs (UID FETCH => "UID FETCH")
        self.fetch_args: list[str] = []
        self.caps = caps
        self.appends = 0
        self.drop_before_append: set[int] = set()
        self.drop_after_append: set[int] = set()
        self.fail_login_once = False
        self.list_literal = False        # send LIST names as {N} literals (lets a hostile name contain CR/LF)
        self.advertised_size = None      # lie about RFC822.SIZE
        self.reject_token_once = False
        self.logins = 0
        self.lock = threading.Lock()
        outer = self

        class H(socketserver.StreamRequestHandler):
            def handle(self):
                _Conn(outer, self.rfile, self.wfile, self.request).serve()

        class S(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self._srv = S(("127.0.0.1", 0), H)
        self.port = self._srv.server_address[1]
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()

    def stop(self):
        self._srv.shutdown()
        self._srv.server_close()

    def folder(self, name, attrs=(), uidvalidity=1000) -> Folder:
        f = self.folders.get(name)
        if f is None:
            f = self.folders[name] = Folder(name, uidvalidity, attrs)
        return f


def mk(i, size=0, mid=True, subject="s"):
    h = f"From: a{i}@x.org\r\nTo: b@y.org\r\nSubject: {subject} {i}\r\n"
    if mid:
        h += f"Message-ID: <m{i}@x.org>\r\n"
    h += "Date: Mon, 3 Mar 2025 10:00:00 +0000\r\n\r\n"
    return (h + f"body {i}\r\n" + "x" * size).encode()


class _Conn:
    def __init__(self, srv, rf, wf, sock):
        self.s, self.rf, self.wf, self.sock = srv, rf, wf, sock
        self.auth = False
        self.sel: Folder | None = None

    def w(self, b):
        self.wf.write(b if isinstance(b, bytes) else b.encode())
        self.wf.flush()

    def serve(self):
        self.w("* OK fake ready\r\n")
        while True:
            line = self.rf.readline()
            if not line:
                return
            line = line.rstrip(b"\r\n").decode("utf-8", "replace")
            tag, _, rest = line.partition(" ")
            verb, _, args = rest.partition(" ")
            verb = verb.upper()
            try:
                if not self.dispatch(tag, verb, args):
                    return
            except (BrokenPipeError, ConnectionError):
                return

    # -------------------------------------------------------------
    def dispatch(self, tag, verb, args):
        s = self.s
        with s.lock:
            s.log.append(verb if verb != "UID" else "UID " + args.split(" ", 1)[0].upper())
        if verb == "CAPABILITY":
            self.w(f"* CAPABILITY {s.caps}\r\n{tag} OK done\r\n")
        elif verb == "NOOP":
            self.w(f"{tag} OK\r\n")
        elif verb == "LOGOUT":
            self.w(f"* BYE\r\n{tag} OK bye\r\n")
            return False
        elif verb == "LOGIN":
            m = re.match(r'"?([^" ]+)"? "?(.*?)"?$', args)
            if s.fail_login_once:
                s.fail_login_once = False
                self.w(f"{tag} NO [UNAVAILABLE] try again later\r\n")
            elif m and m.group(1) == s.user and m.group(2) == s.password:
                self.auth = True
                s.logins += 1
                self.w(f"{tag} OK logged in\r\n")
            else:
                self.w(f"{tag} NO [AUTHENTICATIONFAILED] bad credentials\r\n")
        elif verb == "AUTHENTICATE":
            self.w("+ \r\n")
            resp = self.rf.readline().strip()
            import base64
            raw = base64.b64decode(resp).decode()
            ok = s.token is not None and f"user={s.user}\x01auth=Bearer {s.token}\x01\x01" == raw
            if s.reject_token_once:
                s.reject_token_once, ok = False, False
            if ok:
                self.auth = True
                s.logins += 1
                self.w(f"{tag} OK authenticated\r\n")
            else:
                self.w("+ eyJzdGF0dXMiOiI0MDEifQ==\r\n")
                self.rf.readline()
                self.w(f"{tag} NO [AUTHENTICATIONFAILED] invalid token\r\n")
        elif not self.auth:
            self.w(f"{tag} NO not authenticated\r\n")
        elif verb == "LIST":
            for n, f in sorted(s.folders.items()):
                at = " ".join(f.attrs)
                nm = n.replace("\\", "\\\\").replace('"', '\\"')
                if s.list_literal:
                    self.w(f'* LIST ({at}) "{s.delim}" {{{len(n.encode())}}}\r\n'.encode() + n.encode() + b"\r\n")
                else:
                    self.w(f'* LIST ({at}) "{s.delim}" "{nm}"\r\n')
            self.w(f"{tag} OK list done\r\n")
        elif verb in ("EXAMINE", "SELECT"):
            n = _unq(args)
            f = s.folders.get(n)
            if not f:
                self.w(f"{tag} NO no such mailbox\r\n")
            else:
                self.sel = f
                self.w(f"* {len(f.msgs)} EXISTS\r\n* OK [UIDVALIDITY {f.uidvalidity}] ok\r\n* OK [UIDNEXT {f.uidnext}] ok\r\n"
                       f"{tag} OK [READ-ONLY] examined\r\n")
        elif verb == "STATUS":
            n = _unq(args.split(" (")[0])
            f = s.folders.get(n)
            if not f:
                self.w(f"{tag} NO no such mailbox\r\n")
            else:
                self.w(f'* STATUS "{n}" (MESSAGES {len(f.msgs)} UIDVALIDITY {f.uidvalidity} UIDNEXT {f.uidnext})\r\n{tag} OK\r\n')
        elif verb == "CREATE":
            n = _unq(args)
            if n in s.folders:
                self.w(f"{tag} NO [ALREADYEXISTS] exists\r\n")
            else:
                s.folder(n)
                self.w(f"{tag} OK created\r\n")
        elif verb == "APPEND":
            return self.append(tag, args)
        elif verb == "UID":
            sub, _, rest = args.partition(" ")
            if sub.upper() == "SEARCH":
                self.uid_search(tag, rest)
            elif sub.upper() == "FETCH":
                self.uid_fetch(tag, rest)
            else:
                self.w(f"{tag} NO unsupported\r\n")
        else:  # STORE/EXPUNGE/DELETE/... only logged
            self.w(f"{tag} OK {verb} (fake)\r\n")
        return True

    def append(self, tag, args):
        s = self.s
        m = re.match(r'"((?:[^"\\]|\\.)*)"(?: \(([^)]*)\))?(?: "([^"]+)")? \{(\d+)(\+?)\}$', args)
        if not m:
            self.w(f"{tag} BAD append syntax\r\n")
            return True
        name, flags, date, n, plus = m.group(1).replace('\\"', '"'), m.group(2) or "", m.group(3), int(m.group(4)), m.group(5)
        if not plus:
            self.w("+ go ahead\r\n")
        data = self.rf.read(n)
        self.rf.readline()
        with s.lock:
            s.appends += 1
            k = s.appends
        f = s.folders.get(name)
        if f is None:
            self.w(f"{tag} NO [TRYCREATE] no such folder\r\n")
            return True
        if k in s.drop_before_append:
            self.sock.close()
            return False
        f.add(data, flags.split(), date or "01-Jan-2026 00:00:00 +0000")
        if k in s.drop_after_append:
            self.sock.close()
            return False
        self.w(f"{tag} OK [APPENDUID {f.uidvalidity} {f.uidnext - 1}] done\r\n")
        return True

    def _sel_uids(self, spec):
        f = self.sel
        out = []
        top = f.uidnext - 1
        for part in spec.split(","):
            if ":" in part:
                a, b = part.split(":")
                a = top if a == "*" else int(a)
                b = top if b == "*" else int(b)
                lo, hi = min(a, b), max(a, b)
                out += [m.uid for m in f.msgs if lo <= m.uid <= hi]
                if b == top and not any(m.uid >= lo for m in f.msgs) and f.msgs and spec.endswith(":*"):
                    out.append(f.msgs[-1].uid)  # RFC 3501: n:* always includes the last message
            else:
                out += [m.uid for m in f.msgs if m.uid == int(part)]
        return sorted(set(out))

    def uid_search(self, tag, rest):
        if self.sel is None:
            self.w(f"{tag} NO no mailbox selected\r\n")
            return
        r = rest.strip().upper()
        if r == "ALL":
            u = [m.uid for m in self.sel.msgs]
        else:
            u = self._sel_uids(rest.split(" ", 1)[1])
        self.w(f"* SEARCH {' '.join(map(str, u))}\r\n{tag} OK search done\r\n")

    def uid_fetch(self, tag, rest):
        s = self.s
        if self.sel is None:
            self.w(f"{tag} NO no mailbox selected\r\n")
            return
        spec, _, items = rest.partition(" ")
        s.fetch_args.append(items)
        peek = "BODY.PEEK" in items
        by = {m.uid: m for m in self.sel.msgs}
        for uid in self._sel_uids(spec):
            m = by[uid]
            parts = [f"UID {uid}"]
            if "FLAGS" in items:
                parts.append("FLAGS (" + " ".join(sorted(m.flags)) + ")")
            if "INTERNALDATE" in items:
                parts.append(f'INTERNALDATE "{m.date}"')
            if "RFC822.SIZE" in items:
                parts.append(f"RFC822.SIZE {s.advertised_size if s.advertised_size is not None else len(m.data)}")
            lits = []
            hm = re.search(r"BODY\.PEEK\[HEADER\.FIELDS \(([^)]*)\)\]", items)
            if hm:
                want = {x.lower() for x in hm.group(1).split()}
                head = m.data.split(b"\r\n\r\n", 1)[0].decode()
                keep = [ln for ln in head.split("\r\n") if ln.split(":")[0].lower() in want]
                blob = ("\r\n".join(keep) + "\r\n\r\n").encode()
                lits.append((f"BODY[HEADER.FIELDS ({hm.group(1)})]", blob))
            elif "BODY.PEEK[]" in items or "BODY[]" in items or "RFC822" in items.replace("RFC822.SIZE", ""):
                lits.append(("BODY[]", m.data))
                if not peek:
                    m.flags.add("\\Seen")  # a non-PEEK fetch would mark the message read
            head = f"* {self.sel.msgs.index(m) + 1} FETCH (" + " ".join(parts)
            if lits:
                for k, (lab, blob) in enumerate(lits):
                    self.w(f"{head} {lab} {{{len(blob)}}}\r\n".encode() + blob + b")\r\n")
            else:
                self.w(head + ")\r\n")
        self.w(f"{tag} OK fetch done\r\n")


def _unq(a):
    a = a.strip()
    if a.startswith('"') and a.endswith('"'):
        return a[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return a
