"""Checkpoint/resume. State file is JSON, 0600, written atomically. Holds ONLY: per-stage completion,
paging cursors and the metadata already collected (counts, ids, sizes) - never content or tokens.
A checkpoint is bound to (provider, tenant key); a mismatch is refused so results never mix tenants."""
from __future__ import annotations

import json
import os
import tempfile


class CheckpointError(Exception):
    pass


class Checkpoint:
    VERSION = 1

    def __init__(self, path: str | None, provider: str, tenant_key: str):
        self.path, self.provider, self.tenant_key = path, provider, tenant_key
        self.data = {"version": self.VERSION, "provider": provider, "tenant": tenant_key, "stages": {}}
        if path and os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                d = json.load(f)
            if d.get("version") != self.VERSION or d.get("provider") != provider or d.get("tenant") != tenant_key:
                raise CheckpointError("checkpoint belongs to a different provider/tenant/version; refusing to resume")
            self.data = d

    def stage(self, name: str) -> dict:
        return self.data["stages"].setdefault(name, {"done": False})

    def is_done(self, name: str) -> bool:
        return bool(self.data["stages"].get(name, {}).get("done"))

    def save(self):
        if not self.path:
            return
        d = os.path.dirname(os.path.abspath(self.path))
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".ckpt-")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.data, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
