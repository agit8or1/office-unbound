"""Folder mapping: source IMAP folder (name, delimiter, flags) -> Gromox folder path.

* special-use attributes (RFC 6154) win; name heuristics are the fallback for servers without them
* custom hierarchy is preserved; the delimiter becomes "/" (Gromox's), segment names are sanitised
* the source namespace prefix "INBOX<delim>" is dropped (Courier/Cyrus style), INBOX itself stays INBOX
* two source folders that map to the same target are merged on purpose (fingerprint dedupe makes that safe)
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

from . import mutf7

# Gromox 3.x as observed on ou-gw1 (LIST: Deleted Items, Drafts, INBOX, Junk Email, Sent Items; no special-use attrs advertised)
GROMOX_SPECIAL = {"\\sent": "Sent Items", "\\drafts": "Drafts", "\\trash": "Deleted Items", "\\junk": "Junk Email",
                  "\\archive": "Archive", "\\all": "Archive"}
# Virtual duplicates (Gmail "Starred"/"Important" views) are skipped by default: they would double-import mail
VIRTUAL_ATTRS = {"\\flagged", "\\important"}
NAME_HINTS = {
    "sent": "\\sent", "sent items": "\\sent", "sent mail": "\\sent", "sent messages": "\\sent", "gesendet": "\\sent",
    "gesendete elemente": "\\sent", "gesendete objekte": "\\sent", "envoyés": "\\sent", "elementos enviados": "\\sent",
    "drafts": "\\drafts", "draft": "\\drafts", "entwürfe": "\\drafts", "brouillons": "\\drafts",
    "trash": "\\trash", "deleted items": "\\trash", "deleted messages": "\\trash", "bin": "\\trash", "papierkorb": "\\trash",
    "gelöschte elemente": "\\trash", "corbeille": "\\trash",
    "junk": "\\junk", "junk email": "\\junk", "junk e-mail": "\\junk", "spam": "\\junk", "bulk mail": "\\junk",
    "archive": "\\archive", "archives": "\\archive", "archiv": "\\archive",
}
MAX_SEGMENT = 120
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def sanitize_segment(seg: str) -> str:
    seg = unicodedata.normalize("NFC", seg)
    seg = _CTRL.sub("", seg)
    seg = seg.replace("/", "_").replace("\\", "_").replace("*", "_").replace("%", "_").replace('"', "'")
    seg = seg.strip().strip(".").strip()
    if len(seg) > MAX_SEGMENT:
        seg = seg[:MAX_SEGMENT].rstrip()
    return seg or "_"


@dataclass
class FolderPlan:
    src_name: str            # as the source returned it (mUTF-7)
    src_display: str         # decoded
    delim: str | None
    target: str | None       # decoded Unicode path with "/", None = skipped
    target_wire: str | None  # mUTF-7 for the wire
    reason: str              # special-use:<x> | name-hint:<x> | custom | inbox | rename | skipped:<why>


@dataclass
class Mapper:
    special: dict = field(default_factory=lambda: dict(GROMOX_SPECIAL))
    include_virtual: bool = False
    exclude: tuple = ()                       # regexes on the decoded source name
    rename: dict = field(default_factory=dict)  # decoded source name -> target path (explicit override)

    def map_all(self, folders):
        """folders: iterable of (name, delim, flags)."""
        return [self._map_one(n, d, {f.lower() for f in fl}) for n, d, fl in folders]

    def _map_one(self, name, delim, flags) -> FolderPlan:
        disp = mutf7.decode(name)

        def skip(why):
            return FolderPlan(name, disp, delim, None, None, "skipped:" + why)

        if _CTRL.search(name) or _CTRL.search(disp) or not name.isascii():
            return skip("unsafe-name")   # CR/LF/NUL/control chars are never put on a source connection (IMAP command injection)
        if flags & {"\\noselect", "\\nonexistent"}:
            return skip("not-selectable")
        if not self.include_virtual and flags & VIRTUAL_ATTRS:
            return skip("virtual-view")
        if any(re.fullmatch(p, disp) for p in self.exclude):
            return skip("excluded")
        if name.upper() == "INBOX":
            return FolderPlan(name, disp, delim, "INBOX", "INBOX", "inbox")
        if disp in self.rename:
            t = self.rename[disp]
            return FolderPlan(name, disp, delim, t, mutf7.encode(t), "rename")
        for f in sorted(flags):
            if f in self.special:
                t = self.special[f]
                return FolderPlan(name, disp, delim, t, mutf7.encode(t), "special-use:" + f)
        segs = disp.split(delim) if delim else [disp]
        if len(segs) > 1 and segs[0].upper() == "INBOX":
            segs = segs[1:]
        if len(segs) == 1:  # name hint only for top-level names ("Archive/2025" stays custom)
            h = NAME_HINTS.get(segs[0].strip().lower())
            if h and h in self.special:
                t = self.special[h]
                return FolderPlan(name, disp, delim, t, mutf7.encode(t), "name-hint:" + h)
        t = "/".join(sanitize_segment(s) for s in segs)
        return FolderPlan(name, disp, delim, t, mutf7.encode(t), "custom")
