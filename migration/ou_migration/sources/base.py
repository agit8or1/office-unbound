"""Shared collector plumbing: staged execution with checkpointing and partial-failure capture."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from ..auth import AuthError
from ..checkpoint import Checkpoint
from ..http import HttpError, TransportError
from ..model import Inventory

log = logging.getLogger("ou_migration.collect")


class Stage:
    """Run ``fn(state)`` once; ``state`` is the checkpointed dict (cursor + partial items). A failure is
    recorded in ``inv.coverage`` / ``inv.warnings`` and the run continues with the other stages
    (a missing permission must not abort the whole assessment)."""

    def __init__(self, inv: Inventory, ckpt: Checkpoint):
        self.inv, self.ckpt = inv, ckpt

    def run(self, name: str, fn, *, required_permission: str = ""):
        st = self.ckpt.stage(name)
        if st.get("done"):
            self.inv.coverage[name] = st.get("coverage", "ok")
            return st.get("result")
        try:
            result = fn(st)
        except HttpError as e:
            hint = f" (missing permission/scope: {required_permission}?)" if e.status in (401, 403) and required_permission else ""
            self._fail(name, f"HTTP {e.status}{hint}")
            return None
        except AuthError as e:
            self._fail(name, f"authentication/authorization: {e}")
            return None
        except TransportError as e:
            self._fail(name, f"transport error: {e}")
            return None
        st.update(done=True, result=result, coverage=self.inv.coverage.get(name, "ok"))
        st.pop("next", None)
        st.pop("items", None)
        self.inv.coverage.setdefault(name, "ok")
        self.ckpt.save()
        return result

    def _fail(self, name, why):
        self.inv.coverage[name] = f"failed: {why}"
        self.inv.warnings.append(f"{name}: {why}")
        log.warning("stage %s failed: %s", name, why)
        self.ckpt.save()  # keeps cursor so --resume continues from the last good page


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
