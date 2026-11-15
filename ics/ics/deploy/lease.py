"""Per-deployment execution lock with a lease and a fencing token (security review 3, H1).

A deployment executor must hold the `deployment_locks` row of its deployment (unique per deployment => a second executor can never
run concurrently). The lease is renewed by a heartbeat thread for as long as the current step is within its own deadline; there is no
fixed wall clock for the whole job. `check()` is called before EVERY provider / agent / check call (through the `_Guard` proxies) and
inside long steps: it raises `Fenced` when the lock or the job was lost (lease expiry, reaper, a newer executor, the caller abandoned
the thread), `Cancelled` on a cancel request and `StepFailed` when the step deadline passed - so an orphaned thread stops issuing
calls instead of mutating infrastructure behind a 'failed' job."""
import dataclasses
import logging
import threading
import time

from sqlalchemy import text

from .ports import Cancelled, DeployError, Fenced, StepFailed

log = logging.getLogger("ics.deploy.lease")
GRACE = 5.0   # seconds after a step deadline during which the lease is still renewed (the step may be inside one blocking call)


class Lease:
    def __init__(self, rt, deployment_id: str, job_id: str, stop: threading.Event | None = None):
        self.rt, self.dep, self.job = rt, deployment_id, job_id
        self.stop = stop or threading.Event()
        self.seconds = max(3, int(rt.settings.deployment_lease_seconds))
        self.token = 0
        self.deadline = float("inf")
        self._dead = False
        self._thread: threading.Thread | None = None

    # -- acquisition ---------------------------------------------------------------------------------------------
    def acquire(self) -> None:
        with self.rt.session() as db:
            row = db.execute(text(
                "INSERT INTO deployment_locks (deployment_id, job_id, token, lease_expires_at) "
                "VALUES (:d, :j, 1, now() + make_interval(secs => :l)) "
                "ON CONFLICT (deployment_id) DO UPDATE SET job_id = :j, token = deployment_locks.token + 1, acquired_at = now(), "
                "lease_expires_at = now() + make_interval(secs => :l) "
                "WHERE deployment_locks.lease_expires_at < now() OR deployment_locks.job_id = :j RETURNING token"),
                {"d": self.dep, "j": self.job, "l": self.seconds}).first()
            db.commit()
        if row is None:
            raise DeployError("another executor currently holds this deployment's execution lock; try again when it has finished")
        self.token = int(row.token)
        self._thread = threading.Thread(target=self._beat, daemon=True, name=f"ics-lease-{self.job}")
        self._thread.start()

    def release(self) -> None:
        self._dead = True
        try:
            with self.rt.session() as db:
                db.execute(text("DELETE FROM deployment_locks WHERE deployment_id = :d AND job_id = :j AND token = :t"),
                           {"d": self.dep, "j": self.job, "t": self.token})
                db.commit()
        except Exception:  # noqa: BLE001
            log.exception("could not release deployment lock (it expires by itself)")

    # -- heartbeat -----------------------------------------------------------------------------------------------
    def _beat(self) -> None:
        while not self._dead:
            time.sleep(self.seconds / 3.0)
            if self._dead:
                return
            if time.monotonic() > self.deadline + GRACE:   # the current step is stuck beyond its deadline: stop renewing, the lease runs out
                log.error("deployment %s: step deadline exceeded; lease no longer renewed", self.dep)
                self._dead = True
                return
            try:
                with self.rt.session() as db:
                    a = db.execute(text("UPDATE deployment_locks SET lease_expires_at = now() + make_interval(secs => :l) "
                                        "WHERE deployment_id = :d AND job_id = :j AND token = :t"),
                                   {"l": self.seconds, "d": self.dep, "j": self.job, "t": self.token}).rowcount
                    b = db.execute(text("UPDATE jobs SET lease_expires_at = now() + make_interval(secs => :l) WHERE id = :j AND status = 'running'"),
                                   {"l": self.seconds, "j": self.job}).rowcount
                    db.commit()
                if a != 1 or b != 1:
                    self._dead = True
                    return
                hook = getattr(self.rt, "progress_hook", None)
                if hook:
                    hook()
            except Exception:  # noqa: BLE001  (transient DB error: the lease simply is not extended)
                log.exception("lease renewal failed")

    # -- per-step deadline and checkpoint -----------------------------------------------------------------------------
    def begin_step(self, seconds: float) -> None:
        self.deadline = time.monotonic() + seconds

    def end_step(self) -> None:
        self.deadline = float("inf")

    def check(self) -> None:
        """Call before every provider/agent/check call and inside long loops."""
        if self.stop.is_set() or self._dead:
            raise Fenced("this executor lost its lease on the deployment; stopping without further changes")
        with self.rt.session() as db:
            r = db.execute(text(
                "SELECT l.token, l.lease_expires_at > now() AS live, j.status, j.cancel_requested FROM deployment_locks l "
                "JOIN jobs j ON j.id = l.job_id WHERE l.deployment_id = :d AND l.job_id = :j"), {"d": self.dep, "j": self.job}).first()
        if r is None or int(r.token) != self.token or not r.live or r.status != "running":
            self._dead = True
            raise Fenced("this executor lost its lease on the deployment; stopping without further changes")
        if r.cancel_requested:
            raise Cancelled("cancelled by operator; completed steps are kept and the deployment can be resumed")
        if time.monotonic() > self.deadline:
            raise StepFailed("the step exceeded its deadline", "The step took longer than allowed; check the infrastructure and re-run "
                             "the deployment (completed steps are kept).", retryable=False)


class _Guard:
    """Proxy: every public method call first passes lease.check()."""

    def __init__(self, inner, lease: Lease):
        self._inner, self._lease = inner, lease

    def __getattr__(self, name):
        attr = getattr(self._inner, name)
        if name.startswith("_") or not callable(attr):
            return attr

        def call(*a, **k):
            self._lease.check()
            return attr(*a, **k)
        return call


def guard_env(env, lease: Lease):
    return dataclasses.replace(env, provider=_Guard(env.provider, lease), agent=_Guard(env.agent, lease), checks=_Guard(env.checks, lease))
