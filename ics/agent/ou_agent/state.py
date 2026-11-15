"""Replay journal: every accepted nonce and job id is recorded with O_EXCL + fsync BEFORE anything runs.
A job id is single use for ever (never re-run, even after a crash); a nonce is remembered for a day (> window + skew)."""
import hashlib
import os
import time

from .proto import Reject


class Journal:
    def __init__(self, directory: str):
        self.dir = directory
        os.makedirs(directory, mode=0o700, exist_ok=True)

    def _mark(self, name: str, code: str) -> None:
        path = os.path.join(self.dir, name)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise Reject(code, "replayed request") from None
        try:
            os.write(fd, str(int(time.time())).encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        dfd = os.open(self.dir, os.O_RDONLY)   # review L6: the directory entry must survive a power loss too
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)

    def accept(self, nonce: str, job_id: str) -> None:
        """Record nonce and job id, or raise Reject(replay_nonce|replay_job). Nonce first: a replay of a whole request is a nonce replay."""
        self._mark("n-" + hashlib.sha256(nonce.encode()).hexdigest(), "replay_nonce")
        self._mark("j-" + job_id, "replay_job")

    def gc(self, nonce_ttl: int = 86400) -> int:
        n, cutoff = 0, time.time() - nonce_ttl
        for f in os.listdir(self.dir):
            if f.startswith("n-"):
                p = os.path.join(self.dir, f)
                try:
                    if os.stat(p).st_mtime < cutoff:
                        os.unlink(p)
                        n += 1
                except OSError:
                    pass
        return n
