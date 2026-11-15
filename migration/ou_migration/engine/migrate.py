"""Per-mailbox IMAP -> IMAP (Gromox) migration job: incremental, idempotent, resumable, never writes to the source."""
from __future__ import annotations

import collections
import logging
import time
from dataclasses import dataclass

from . import mutf7
from .imapx import Fatal, GuardViolation, ImapError, Throttle, Transient
from .mailbox import Mailbox, MsgMeta, fingerprint
from .mapping import Mapper
from .state import State

log = logging.getLogger("ou_migration.engine")


@dataclass
class Options:
    dedupe_mode: str = "strict"            # strict: Message-ID+INTERNALDATE+size; loose: without size
    max_message_bytes: int = 64 * 1024 * 1024
    append_attempts: int = 4
    meta_batch: int = 100
    retry_sleep: float = 1.0


class TargetIndex:
    """Fingerprints present in one target folder. ``owed`` = how many of them earlier runs (or this run) already
    account for; ``present - owed`` are messages that exist on the target without a state record: a crash between
    APPEND and the state commit, mail the user already had there, or mail delivered directly in the meantime."""

    def __init__(self, wire, present=None, owed=None, next_uid=1):
        self.wire = wire
        self.present = collections.Counter(present or {})
        self.owed = collections.Counter(owed or {})
        self.next_uid = next_uid

    def adoptable(self, fp):
        return self.present[fp] - self.owed[fp] > 0

    def take(self, fp):
        self.owed[fp] += 1

    def appended(self, fp):
        self.present[fp] += 1
        self.owed[fp] += 1


class Migrator:
    def __init__(self, src: Mailbox, dst: Mailbox | None, state: State | None, mapper: Mapper, *, options=None,
                 throttle=None, hook=None, sleep=time.sleep):
        self.src, self.dst, self.state = src, dst, state
        self.mapper = mapper
        self.opt = options or Options()
        self.throttle = throttle or Throttle()
        self.hook = hook or (lambda event, **kw: None)
        self.sleep = sleep
        self._known_wire: set | None = None
        self._index: dict[str, TargetIndex | None] = {}

    # ------------------------------------------------------------------ planning
    def plan(self):
        folders = self.src.list_folders()
        if self.dst is not None:
            for name, _d, flags in self._target_folders():
                for f in flags:
                    if f.lower() in self.mapper.special and f.lower() in ("\\sent", "\\drafts", "\\trash", "\\junk"):
                        self.mapper.special[f.lower()] = mutf7.decode(name)
        plans = self.mapper.map_all(folders)
        # INBOX first, then stable source order
        plans.sort(key=lambda p: (0 if p.reason == "inbox" else 1))
        return plans

    def _target_folders(self):
        if not hasattr(self, "_tf"):
            self._tf = self.dst.list_folders()
            self._known_wire = {n for n, _d, _f in self._tf}
        return self._tf

    # ------------------------------------------------------------------ run
    def run(self, dry_run=False) -> dict:
        if not dry_run and (self.dst is None or self.state is None):
            raise ValueError("a real run needs a target and a state file")
        t0 = time.time()
        plans = self.plan()
        if self.dst is not None:
            self._target_folders()
        rep = {"mode": "dry-run" if dry_run else "migrate", "started": t0, "folders": [], "skipped_folders": []}
        failed_fatal = None
        for p in plans:
            if p.target is None:
                rep["skipped_folders"].append({"source": p.src_display, "reason": p.reason})
                continue
            fr = {"source": p.src_display, "target": p.target, "reason": p.reason, "source_messages": 0, "candidates": 0,
                  "bytes_candidates": 0, "copied": 0, "adopted": 0, "bytes_copied": 0, "skipped_too_large": 0,
                  "failed": 0, "errors": [], "uidvalidity_reset": False}
            rep["folders"].append(fr)
            try:
                self._folder(p, fr, dry_run)
            except Fatal as e:
                fr["errors"].append(str(e))
                failed_fatal = e
                break
            except GuardViolation:
                raise
        rep["finished"] = time.time()
        tot = collections.Counter()
        for fr in rep["folders"]:
            for k in ("source_messages", "candidates", "bytes_candidates", "copied", "adopted", "bytes_copied",
                      "skipped_too_large", "failed"):
                tot[k] += fr[k]
        rep["totals"] = dict(tot)
        rep["stats"] = {"throttle_sleep_s": round(self.throttle.slept, 3)}
        for nm, m in (("source", self.src), ("target", self.dst)):
            if m is not None:
                rep["stats"][nm] = {"reconnects": m.s.reconnects, "retries": m.s.retries, "throttle_events": m.s.throttle_events}
        rep["complete"] = failed_fatal is None and tot["failed"] == 0 and tot["skipped_too_large"] == 0
        if failed_fatal:
            rep["fatal"] = str(failed_fatal)
        return rep

    # ------------------------------------------------------------------ one folder
    def _target_index(self, plan, create: bool):
        if plan.target in self._index:
            return self._index[plan.target]
        wire = plan.target_wire
        idx = None
        if self.dst is not None:
            owed = self.state.owed(plan.target) if self.state else collections.Counter()
            if wire in self._known_wire:
                _uv, nxt, metas = self.dst.scan(wire)
                present = collections.Counter(fingerprint(m, self.opt.dedupe_mode) for m in metas)
                idx = TargetIndex(wire, present, owed, nxt or 1)
            else:
                idx = TargetIndex(wire, None, owed)
        self._index[plan.target] = idx
        return idx

    def _folder(self, p, fr, dry_run):
        uv, exists, _nxt = self.src.examine(p.src_name)
        fr["source_messages"] = exists
        fr["uidvalidity"] = uv
        st = self.state.folder(p.src_name) if self.state else None
        hwm = 0
        released = None
        if st:
            if st["uidvalidity"] != uv:
                fr["uidvalidity_reset"] = True
                log.warning("folder UIDVALIDITY changed (%s -> %s); falling back to fingerprint dedupe", st["uidvalidity"], uv)
                released = self.state.folder_fps(p.src_name, st["uidvalidity"])
            else:
                hwm = st["hwm"]
        if self.state and not dry_run:
            self.state.set_folder(p.src_name, uv, hwm, p.target, "running")
        uids = self.src.search_uids(hwm + 1) if exists else []
        known = self.state.known_uids(p.src_name, uv) if self.state else set()
        cand = [u for u in uids if u not in known]
        metas = self.src.fetch_meta(cand, self.opt.meta_batch) if cand else []
        fr["candidates"] = len(metas)
        fr["bytes_candidates"] = sum(m.size for m in metas)
        idx = self._target_index(p, create=not dry_run)
        if released:
            if idx is not None:
                idx.owed.subtract(released)
            if not dry_run:
                self.state.supersede(p.src_name, st["uidvalidity"])
        if not dry_run:
            self.dst.ensure_folder(p.target, p.target_wire, self._known_wire)
            if idx is None:  # cannot happen (dst required), kept for clarity
                idx = TargetIndex(p.target_wire)
        blocked = False
        for m in metas:
            fp = fingerprint(m, self.opt.dedupe_mode)
            if idx is not None and idx.adoptable(fp):
                idx.take(fp)
                fr["adopted"] += 1
                if not dry_run:
                    self.state.record(p.src_name, uv, m.uid, fp, m.size, p.target, "adopted", None if blocked else m.uid)
                continue
            if m.size > self.opt.max_message_bytes:
                fr["skipped_too_large"] += 1
                blocked = True
                fr["errors"].append(f"uid {m.uid}: {m.size} bytes exceeds max-message-bytes")
                continue
            if dry_run:
                if idx is not None:
                    idx.take(fp)
                fr["copied"] += 1
                fr["bytes_copied"] += m.size
                continue
            try:
                outcome = self._copy_one(p, idx, m, fp)
            except Fatal:
                raise
            except ImapError as e:
                fr["failed"] += 1
                blocked = True
                fr["errors"].append(f"uid {m.uid}: {e}")
                continue
            fr[outcome] += 1
            if outcome == "copied":
                fr["bytes_copied"] += m.size
            self.state.record(p.src_name, uv, m.uid, fp, m.size, p.target, outcome, None if blocked else m.uid)
            self.hook("after_record", folder=p.src_display, uid=m.uid)
        if not dry_run:
            cur = self.state.folder(p.src_name)["hwm"]
            final = max(uids) if (uids and not blocked) else cur
            self.state.set_folder(p.src_name, uv, max(final, cur), p.target, "complete" if not blocked else "incomplete")

    def _copy_one(self, p, idx, m: MsgMeta, fp) -> str:
        self.throttle.acquire(m.size)
        body = self.src.fetch_body(m.uid)
        if len(body) != m.size:
            log.warning("uid %s: fetched %d bytes, RFC822.SIZE said %d", m.uid, len(body), m.size)
        last = None
        for attempt in range(self.opt.append_attempts):
            try:
                self.hook("before_append", folder=p.src_display, uid=m.uid)
                self.dst.append(p.target_wire, m.keep_flags(), m.internaldate, body)
                self.hook("after_append", folder=p.src_display, uid=m.uid)
                idx.appended(fp)
                return "copied"
            except Transient as e:
                last = e
                # the APPEND may have been executed although the answer was lost: look before retrying
                self._rescan(idx)
                if idx.adoptable(fp):
                    idx.take(fp)
                    return "adopted"
                self.sleep(self.opt.retry_sleep * (2 ** attempt))
        raise ImapError(f"append failed after {self.opt.append_attempts} attempts: {last}")

    def _rescan(self, idx):
        """Full re-scan of the target folder (only after an ambiguous APPEND failure)."""
        _uv, nxt, metas = self.dst.scan(idx.wire)
        idx.present = collections.Counter(fingerprint(m, self.opt.dedupe_mode) for m in metas)
        idx.next_uid = nxt or idx.next_uid
