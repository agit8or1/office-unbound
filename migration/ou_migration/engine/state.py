"""Durable job state (SQLite, mode 0600, one commit per message => crash/kill safe).

Holds only identifiers needed to resume: per-folder UIDVALIDITY + UID high-water mark, and one row per processed source
message (uid, sha-256-derived fingerprint, size, outcome). No message content, subjects, addresses, Message-IDs or
credentials are stored. A state file is bound to its (source, target) identity; a mismatch is refused."""
from __future__ import annotations

import collections
import os
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS folders(src TEXT PRIMARY KEY, uidvalidity INTEGER, hwm INTEGER NOT NULL DEFAULT 0,
  target TEXT, status TEXT, updated REAL);
CREATE TABLE IF NOT EXISTS msgs(src TEXT NOT NULL, uidvalidity INTEGER NOT NULL, uid INTEGER NOT NULL,
  fp TEXT NOT NULL, size INTEGER, target TEXT, outcome TEXT NOT NULL, ts REAL,
  PRIMARY KEY(src, uidvalidity, uid));
CREATE INDEX IF NOT EXISTS msgs_target_fp ON msgs(target, fp);
"""
# outcomes that mean "a copy of this message exists on the target"
PRESENT = ("copied", "adopted")


class StateError(Exception):
    pass


class State:
    def __init__(self, path: str, job_key: str):
        self.path = path
        # O_NOFOLLOW: a symlink planted at the state path must not redirect writes or chmod to another file (review 4, L6)
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript(SCHEMA)
        row = self.db.execute("SELECT v FROM meta WHERE k='job'").fetchone()
        if row is None:
            self.db.execute("INSERT INTO meta VALUES('job', ?)", (job_key,))
        elif row[0] != job_key:
            raise StateError("state file belongs to a different source/target pair; refusing to resume")

    def close(self):
        self.db.close()

    # -- folders
    def folder(self, src):
        r = self.db.execute("SELECT uidvalidity, hwm, target, status FROM folders WHERE src=?", (src,)).fetchone()
        return {"uidvalidity": r[0], "hwm": r[1], "target": r[2], "status": r[3]} if r else None

    def set_folder(self, src, uidvalidity, hwm, target, status):
        self.db.execute("INSERT INTO folders(src,uidvalidity,hwm,target,status,updated) VALUES(?,?,?,?,?,?) "
                        "ON CONFLICT(src) DO UPDATE SET uidvalidity=excluded.uidvalidity, hwm=excluded.hwm, "
                        "target=excluded.target, status=excluded.status, updated=excluded.updated",
                        (src, uidvalidity, hwm, target, status, time.time()))

    # -- messages
    def known_uids(self, src, uidvalidity) -> set:
        return {r[0] for r in self.db.execute("SELECT uid FROM msgs WHERE src=? AND uidvalidity=?", (src, uidvalidity))}

    def record(self, src, uidvalidity, uid, fp, size, target, outcome, hwm=None):
        """Record one message (and advance the folder high-water mark) in ONE transaction."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.db.execute("INSERT OR REPLACE INTO msgs VALUES(?,?,?,?,?,?,?,?)",
                            (src, uidvalidity, uid, fp, size, target, outcome, time.time()))
            if hwm is not None:
                self.db.execute("UPDATE folders SET hwm=?, updated=? WHERE src=?", (hwm, time.time(), src))
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def owed(self, target) -> collections.Counter:
        """fingerprints already accounted for on ``target`` by earlier runs (copied or adopted)."""
        q = "SELECT fp, COUNT(*) FROM msgs WHERE target=? AND outcome IN (%s) GROUP BY fp" % ",".join("?" * len(PRESENT))
        return collections.Counter(dict(self.db.execute(q, (target, *PRESENT)).fetchall()))

    def counts(self):
        return {r[0]: r[1] for r in self.db.execute("SELECT outcome, COUNT(*) FROM msgs GROUP BY outcome")}

    def folder_fps(self, src, uidvalidity) -> collections.Counter:
        q = "SELECT fp, COUNT(*) FROM msgs WHERE src=? AND uidvalidity=? AND outcome IN (%s) GROUP BY fp" % ",".join("?" * len(PRESENT))
        return collections.Counter(dict(self.db.execute(q, (src, uidvalidity, *PRESENT)).fetchall()))

    def supersede(self, src, uidvalidity):
        """UIDVALIDITY changed: the old UIDs are meaningless; the messages are re-evaluated by fingerprint."""
        self.db.execute("UPDATE msgs SET outcome='superseded' WHERE src=? AND uidvalidity=? AND outcome IN (%s)"
                        % ",".join("?" * len(PRESENT)), (src, uidvalidity, *PRESENT))
