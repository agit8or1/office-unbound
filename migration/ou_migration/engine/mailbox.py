"""Mailbox-level IMAP operations (listing, metadata, bodies, append) and message fingerprints."""
from __future__ import annotations

import datetime as dt
import email.parser
import hashlib
import re
from dataclasses import dataclass

from .imapx import ImapError, Session, quote

PRESERVED_FLAGS = {"\\seen": "\\Seen", "\\flagged": "\\Flagged", "\\answered": "\\Answered", "\\draft": "\\Draft"}
HDR_FIELDS = "MESSAGE-ID DATE FROM TO SUBJECT"
META_ITEMS = f"(UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[HEADER.FIELDS ({HDR_FIELDS})])"
_MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}


@dataclass
class MsgMeta:
    uid: int
    flags: tuple
    internaldate: str | None
    size: int
    msgid: str
    hdrhash: str

    @property
    def epoch(self) -> int:
        return internaldate_epoch(self.internaldate) if self.internaldate else 0

    def keep_flags(self) -> list:
        return [PRESERVED_FLAGS[f.lower()] for f in self.flags if f.lower() in PRESERVED_FLAGS]


def internaldate_epoch(s: str) -> int:
    m = re.match(r'\s*(\d{1,2})-(\w{3})-(\d{4}) (\d\d):(\d\d):(\d\d) ([+-])(\d\d)(\d\d)', s)
    if not m:
        return 0
    d, mon, y, H, M, S, sg, oh, om = m.groups()
    off = dt.timedelta(hours=int(oh), minutes=int(om)) * (1 if sg == "+" else -1)
    t = dt.datetime(int(y), _MONTHS[mon.title()], int(d), int(H), int(M), int(S), tzinfo=dt.timezone(off))
    return int(t.timestamp())


def fingerprint(m: MsgMeta, mode: str = "strict") -> str:
    """Message-ID + INTERNALDATE (+ size in strict mode). Messages without a Message-ID fall back to a hash of
    Date/From/To/Subject. Only the digest is persisted, never the identifiers."""
    mid = m.msgid.strip().strip("<>").lower() if m.msgid else "nomid:" + m.hdrhash
    base = f"{mid}|{m.epoch}" + (f"|{m.size}" if mode == "strict" else "")
    return hashlib.sha256(base.encode("utf-8", "replace")).hexdigest()[:32]


# ---------------------------------------------------------------- response parsing
_UID = re.compile(rb"\bUID (\d+)")
_FLAGS = re.compile(rb"\bFLAGS \(([^)]*)\)")
_DATE = re.compile(rb'\bINTERNALDATE "([^"]+)"')
_SIZE = re.compile(rb"\bRFC822\.SIZE (\d+)")


def parse_fetch(data) -> list[tuple[bytes, bytes | None]]:
    """imaplib FETCH data -> [(metadata line, literal or None)] one per message."""
    out, i = [], 0
    while i < len(data):
        it = data[i]
        if isinstance(it, tuple):
            line, lit = it[0], it[1]
            if i + 1 < len(data) and isinstance(data[i + 1], bytes):
                line += data[i + 1]
                i += 1
            out.append((line, lit))
        elif isinstance(it, bytes) and it.strip() not in (b"", b")"):
            out.append((it, None))
        i += 1
    return out


def _hdr(block: bytes | None):
    if not block:
        return "", hashlib.sha256(b"").hexdigest()[:16]
    msg = email.parser.BytesParser().parsebytes(block, headersonly=True)
    mid = (msg.get("Message-ID") or "").strip()
    mid = re.sub(r"\s+", "", str(mid))
    norm = b"\n".join(sorted(re.sub(rb"\s+", b" ", x).strip().lower() for x in re.split(rb"\r?\n(?![ \t])", block) if x.strip()))
    return mid, hashlib.sha256(norm).hexdigest()[:16]


def parse_meta(data) -> list[MsgMeta]:
    res = []
    for line, lit in parse_fetch(data):
        u, s = _UID.search(line), _SIZE.search(line)
        if not (u and s):
            continue
        f, d = _FLAGS.search(line), _DATE.search(line)
        mid, hh = _hdr(lit)
        res.append(MsgMeta(int(u.group(1)), tuple(f.group(1).decode().split()) if f else (),
                           d.group(1).decode() if d else None, int(s.group(1)), mid, hh))
    return res


_LIST = re.compile(rb'\(([^)]*)\) (NIL|"(?:[^"\\]|\\.)*") (.*)$', re.S)


def parse_list(data):
    res, i = [], 0
    while i < len(data):
        it = data[i]
        if it is None:
            i += 1
            continue
        if isinstance(it, tuple):  # name sent as literal
            line = it[0]
            name = it[1].decode("ascii", "replace")
            m = _LIST.match(line[: line.rfind(b"{")].rstrip() + b" X")
        else:
            m = _LIST.match(it)
            name = None
        if m:
            flags = m.group(1).decode().split()
            dl = m.group(2)
            delim = None if dl == b"NIL" else dl.strip(b'"').decode().replace("\\\\", "\\")
            if name is None:
                raw = m.group(3).strip()
                name = (raw[1:-1].replace(b'\\"', b'"').replace(b"\\\\", b"\\") if raw.startswith(b'"') else raw).decode("ascii", "replace")
            res.append((name, delim, flags))
        i += 1
    return res


def uid_ranges(uids) -> str:
    uids = sorted(uids)
    out, i = [], 0
    while i < len(uids):
        j = i
        while j + 1 < len(uids) and uids[j + 1] == uids[j] + 1:
            j += 1
        out.append(str(uids[i]) if i == j else f"{uids[i]}:{uids[j]}")
        i = j + 1
    return ",".join(out)


# ---------------------------------------------------------------- operations
class Mailbox:
    def __init__(self, session: Session):
        self.s = session

    def list_folders(self):
        def f(imap):
            typ, data = imap.list()
            if typ != "OK":
                raise ImapError("LIST failed")
            return parse_list(data)

        return self.s.run(f)

    def examine(self, wire_name):
        return self.s.examine(wire_name)

    def search_uids(self, lo=1) -> list[int]:
        def f(imap):
            typ, data = imap.uid("SEARCH", *(("UID", f"{lo}:*") if lo > 1 else ("ALL",)))
            if typ != "OK":
                raise ImapError("UID SEARCH failed")
            return sorted(u for u in (int(x) for x in (data[0] or b"").split()) if u >= lo)

        return self.s.run(f)

    def fetch_meta(self, uids, batch=100) -> list[MsgMeta]:
        out = []
        uids = sorted(uids)
        for i in range(0, len(uids), batch):
            rng = uid_ranges(uids[i:i + batch])

            def f(imap, rng=rng):
                typ, data = imap.uid("FETCH", rng, META_ITEMS)
                if typ != "OK":
                    raise ImapError("UID FETCH meta failed")
                return parse_meta(data)

            out.extend(self.s.run(f))
        return sorted(out, key=lambda m: m.uid)

    def fetch_body(self, uid) -> bytes:
        def f(imap):
            typ, data = imap.uid("FETCH", str(uid), "(BODY.PEEK[])")
            if typ != "OK":
                raise ImapError("UID FETCH body failed")
            for line, lit in parse_fetch(data):
                if lit is not None:
                    return bytes(lit)
            raise ImapError("message body missing in FETCH response")

        return self.s.run(f)

    def ensure_folder(self, path: str, wire_path: str, known: set):
        """CREATE every missing level of ``wire_path`` ("/"-separated, mUTF-7)."""
        parts = wire_path.split("/")
        for i in range(1, len(parts) + 1):
            p = "/".join(parts[:i])
            if p in known:
                continue

            def f(imap, p=p):
                typ, data = imap.create(quote(p))
                if typ != "OK":
                    raise ImapError("CREATE failed")

            try:
                self.s.run(f)
            except ImapError:
                # may already exist (case differences, races): re-list before giving up
                if p not in {n for n, _d, _f in self.list_folders()}:
                    raise
            known.add(p)

    def append(self, wire_name, flags, internaldate, data: bytes):
        fl = "(" + " ".join(flags) + ")"
        date = f'"{internaldate}"' if internaldate else None

        def f(imap):
            typ, resp = imap.append(quote(wire_name), fl, date, data)
            if typ != "OK":
                raise ImapError("APPEND failed")
            return resp

        return self.s.run(f, retry=False)

    def scan(self, wire_name, min_uid=1):
        """Metadata of every message in a (target) folder with uid >= min_uid. Returns (uidnext, [MsgMeta])."""
        uv, exists, nxt = self.examine(wire_name)
        if exists == 0:
            return uv, nxt, []
        uids = self.search_uids(min_uid)
        return uv, nxt, self.fetch_meta(uids)
