"""Controller epoch and role (ADR-0012): the single-writer guarantee for a warm-standby controller pair.

`controller_state` (one row, replicated with the rest of the database) holds a monotonic epoch and a role. Every signed
ICS->agent request carries the epoch; agents refuse a lower one than they have seen (ou_agent.proto.EpochGate). Promotion of a
standby bumps the epoch, so a resurrected old primary - which still holds the signing key - cannot drive any agent that has
heard from the new primary. A refused controller fences itself (role='fenced'), which also makes /readyz red.
"""
from sqlalchemy import text

from .agentclient import AgentError


class NotActive(AgentError):
    """This controller must not drive agents (standby, or fenced)."""


def get_state(db) -> dict:
    r = db.execute(text("SELECT epoch, role, node_name, changed_at, note FROM controller_state WHERE id = 1")).first()
    if r is None:
        raise RuntimeError("controller_state row missing (run migrations)")
    return {"epoch": int(r.epoch), "role": r.role, "node_name": r.node_name, "changed_at": r.changed_at.isoformat(), "note": r.note}


def check_active(*, configured_role: str, state: dict) -> int:
    """Pure decision used before every signed request: returns the epoch to stamp or raises NotActive."""
    if configured_role != "primary":
        raise NotActive("this controller is a STANDBY: it must not send signed requests to agents")
    if state["role"] != "primary":
        raise NotActive(f"this controller was fenced (epoch {state['epoch']}): it must not send signed requests to agents")
    return state["epoch"]


def assert_active(rt, db=None, *, lock: bool = False) -> int:
    """Review 7 H-5: ONE check for every side effect (job claim, provider/agent/backup/notification calls, enrollment, API mutations).
    Raises NotActive unless (a) this controller is configured primary, (b) controller_state says role=primary and (c) the epoch in the database is still
    the epoch this process started with (a promotion elsewhere, `ics-promote --fence-old-dsn-file`, an agent-learned self-fence or a DB that was
    replaced under us all make it differ). The first call fixes the process epoch. A fenced controller stays fenced until it is restarted.
    `lock=True` reads the row FOR SHARE inside the caller's transaction, so a concurrent fence waits for (or precedes) a job claim."""
    if getattr(rt, "fenced_reason", None):
        raise NotActive(rt.fenced_reason)
    if rt.settings.role != "primary":
        raise NotActive("this controller is a STANDBY: it must not cause side effects")
    lease = getattr(rt, "lease", None)
    if lease is not None:
        lease.require()       # a partitioned primary still believes its own database: only a live grant from the WITNESS makes it active (ics/lease.py)

    def _read(d):
        r = d.execute(text("SELECT epoch, role, node_name, changed_at, note FROM controller_state WHERE id = 1" + (" FOR SHARE" if lock else ""))).first()
        if r is None:
            raise NotActive("controller_state row missing")
        return {"epoch": int(r.epoch), "role": r.role}
    if db is not None:
        st = _read(db)
    else:
        with rt.session() as d:
            st = _read(d)
    try:
        ep = check_active(configured_role=rt.settings.role, state=st)
        if getattr(rt, "own_epoch", None) is None:
            rt.own_epoch = ep
        elif ep != rt.own_epoch:
            raise NotActive(f"this controller was started at epoch {rt.own_epoch} but the database says epoch {ep}: it was superseded")
    except NotActive as e:
        rt.fenced_reason = str(e)         # sticky: only a restart (which re-reads the state) can make this controller active again
        raise
    return ep


def current_db_epoch(rt) -> int:
    with rt.session() as db:
        return get_state(db)["epoch"]


def current_epoch(rt) -> int:
    return assert_active(rt)


def self_fence(rt, seen_epoch, *, mine: int | None = None) -> bool:
    """An agent refused us as stale: record that we are fenced (once an agent has seen a higher epoch we are not the primary)."""
    if not isinstance(seen_epoch, int):
        return False
    if getattr(rt, "fenced_reason", None) is None and isinstance(getattr(rt, "own_epoch", None), int) and seen_epoch > rt.own_epoch:
        rt.fenced_reason = f"self-fenced: an agent has seen epoch {seen_epoch} > ours {rt.own_epoch}"    # immediate, even if the DB write below fails
    with rt.session() as db:
        st = get_state(db)
        if seen_epoch <= st["epoch"] or st["role"] == "fenced":
            return False
        db.execute(text("UPDATE controller_state SET role = 'fenced', note = :n WHERE id = 1"),
                   {"n": f"self-fenced: an agent has seen epoch {seen_epoch} > ours {st['epoch']}"})
        from . import audit
        audit.append(db, "controller.self_fenced", actor_name="controller", resource="controller",
                     details={"own_epoch": st["epoch"], "agent_epoch": seen_epoch})
        db.commit()
        return True


def bump_for_promotion(db, node_name: str, note: str) -> tuple[int, int]:
    """Inside the promoting transaction: epoch+1, role primary. Returns (old, new)."""
    old = get_state(db)["epoch"]
    new = old + 1
    db.execute(text("UPDATE controller_state SET epoch = :e, role = 'primary', node_name = :n, note = :t WHERE id = 1"),
               {"e": new, "n": node_name, "t": note})
    return old, new
