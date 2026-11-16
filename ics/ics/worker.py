import logging
import threading
import time

from sqlalchemy import text

from . import identity, monitor
from .credentials import expiry as cred_expiry
from .tenancy import approvals as tapprovals
from .backups import ops as backups_ops
from .inventory import collector
from .provisioning import service as prov_service
from .actions import claim_job, reap_expired, run_job
from .epoch import NotActive
from .runtime import Runtime

log = logging.getLogger("ics.worker")


def heartbeat(rt: Runtime, name: str = "inproc") -> None:
    with rt.session() as db:
        db.execute(text(
            "INSERT INTO worker_heartbeat (name, at) VALUES (:n, now()) ON CONFLICT (name) DO UPDATE SET at = now()"), {"n": name})
        db.commit()


def run_once(rt: Runtime, beat: bool = True, backup_lane: bool = False) -> bool:
    """Heartbeat (unless the Worker's own watchdog owns it), then claim and run at most one job. Returns True if a job ran."""
    try:
        rt.assert_active()      # review 7 H-5: fenced/standby/superseded -> nothing is claimed, run or reaped and no heartbeat is written
    except NotActive:
        return False
    if beat:
        heartbeat(rt)
    reap_expired(rt)
    job = claim_job(rt, backup_lane)
    if job is None:
        return False
    run_job(rt, job)
    return True


class Worker(threading.Thread):
    """Three independent threads (review M2): the job loop, the monitor loop (checks, remediation sync, notifications, identity
    reconcile) and a heartbeat timer. A check that stalls can no longer block jobs or approvals, and the heartbeat is only written
    while BOTH loops are making progress, so a stalled component turns /readyz red instead of staying falsely green."""
    MONITOR_MAX_CONSECUTIVE_FAILURES = 3

    def __init__(self, rt: Runtime, interval: float = 1.0):
        super().__init__(daemon=True, name="ics-worker")
        self.rt, self.interval, self._stop_evt = rt, interval, threading.Event()
        now = time.monotonic()
        self.progress = {"jobs": now, "monitor": now, "inventory": now}
        self.threads: dict[str, threading.Thread] = {}
        self.job_stall_seconds = rt.settings.job_timeout_seconds + 30.0
        rt.progress_hook = self._job_progress  # long deployment jobs renew their lease and report progress here
        self.monitor_stall_seconds = float(rt.settings.monitor_stall_seconds)
        # Production bug 2026-11-15: this was assigned after the `return` in healthy() (dead code) -> every monitor pass raised
        # AttributeError while /readyz stayed green. A loop that fails on every pass must also make the worker unhealthy.
        self._next_vault = 0.0
        self.monitor_failures = 0

    def _job_progress(self) -> None:
        self.progress["jobs"] = time.monotonic()

    def active(self) -> bool:
        """Review 7 H-5: False once this controller is fenced, superseded or a standby. Every loop checks it before each pass and does NOTHING
        otherwise (no jobs, backups, checks, notifications, inventory, provider calls); the heartbeat is withheld so /readyz turns red."""
        try:
            self.rt.assert_active()
            return True
        except NotActive as e:
            if not getattr(self, "_fence_logged", False):
                self._fence_logged = True
                log.error("controller is not active (%s): all worker loops are stopped", e)
            return False
        except Exception:  # noqa: BLE001  (database unreachable: nothing to do either)
            return False

    def healthy(self) -> bool:
        now = time.monotonic()
        return self.active() and (now - self.progress["jobs"] <= self.job_stall_seconds
                and (not self.rt.settings.monitor_enabled or (now - self.progress["monitor"] <= self.monitor_stall_seconds
                                                               and self.monitor_failures < self.MONITOR_MAX_CONSECUTIVE_FAILURES)))

    def _beat(self) -> None:
        """Own timer thread, so the heartbeat keeps ticking while a long job runs (old M8) but stops when a loop is stalled."""
        while not self._stop_evt.is_set():
            try:
                if self.healthy():
                    heartbeat(self.rt)
                else:
                    log.error("worker stalled (jobs %.0fs, monitor %.0fs without progress): heartbeat withheld",
                              time.monotonic() - self.progress["jobs"], time.monotonic() - self.progress["monitor"])
            except Exception:  # noqa: BLE001
                log.exception("heartbeat error")
            self._stop_evt.wait(self.beat_interval)

    beat_interval = 5.0

    def _job_loop(self) -> None:
        while not self._stop_evt.is_set():
            try:
                if not self.active():
                    self._stop_evt.wait(self.interval)
                    continue
                self.progress["jobs"] = time.monotonic()
                while run_once(self.rt, beat=False):
                    self.progress["jobs"] = time.monotonic()
            except Exception:  # noqa: BLE001
                log.exception("job loop error")
            self._stop_evt.wait(self.interval)

    def _backup_loop(self) -> None:
        """backup.* jobs on their own lane + the backup scheduler (due backups / repository checks / restore verifications / prune)."""
        while not self._stop_evt.is_set():
            try:
                if not self.active():
                    self._stop_evt.wait(self.interval)
                    continue
                if self.rt.settings.backup_scheduler_enabled:
                    backups_ops.tick(self.rt)
                while run_once(self.rt, beat=False, backup_lane=True):
                    pass
            except Exception:  # noqa: BLE001
                log.exception("backup loop error")
            self._stop_evt.wait(self.interval)

    def _monitor_loop(self) -> None:
        while not self._stop_evt.is_set():
            try:
                if not self.active():
                    self._stop_evt.wait(self.interval)
                    continue
                self.progress["monitor"] = time.monotonic()
                monitor.tick(self.rt)
                self.progress["monitor"] = time.monotonic()
                identity.reconcile_due(self.rt)
                self.progress["monitor"] = time.monotonic()
                if time.monotonic() >= self._next_vault:
                    self._next_vault = time.monotonic() + 60
                    cred_expiry.tick(self.rt)
                    tapprovals.expire_due(self.rt)
                    self.progress["monitor"] = time.monotonic()
                self.monitor_failures = 0
            except Exception:  # noqa: BLE001
                self.monitor_failures += 1
                log.exception("monitor loop error (%d consecutive)", self.monitor_failures)
            self._stop_evt.wait(self.interval)

    def _inventory_loop(self) -> None:
        """Inventory/metrics collection on its own thread: a slow provider can never stall checks, jobs or the heartbeat."""
        while not self._stop_evt.is_set():
            try:
                if not self.active():
                    self._stop_evt.wait(self.interval)
                    continue
                self.progress["inventory"] = time.monotonic()
                collector.tick(self.rt)
                prov_service.tick(self.rt)
                self.progress["inventory"] = time.monotonic()
            except Exception:  # noqa: BLE001
                log.exception("inventory loop error")
            self._stop_evt.wait(self.interval)

    def run(self) -> None:
        self.threads["jobs"] = threading.current_thread()
        self.threads["heartbeat"] = threading.Thread(target=self._beat, daemon=True, name="ics-heartbeat")
        if self.rt.settings.monitor_enabled:
            self.threads["monitor"] = threading.Thread(target=self._monitor_loop, daemon=True, name="ics-monitor")
            self.threads["inventory"] = threading.Thread(target=self._inventory_loop, daemon=True, name="ics-inventory")
        self.threads["backup"] = threading.Thread(target=self._backup_loop, daemon=True, name="ics-backup")
        self._children = [t for k, t in self.threads.items() if k != "jobs"]   # joined by stop()
        for t in self._children:
            t.start()
        self._job_loop()

    def stop(self, timeout: float = 15.0) -> None:
        """Signal every loop and wait for them, so no loop is still inside a DB transaction when stop() returns
        (found 2026-11-15: stop() only set the event; test teardown deadlocked against a still-running loop)."""
        self._stop_evt.set()
        deadline = time.monotonic() + timeout
        for t in list(getattr(self, "_children", [])) + ([self] if self.is_alive() and threading.current_thread() is not self else []):
            t.join(max(0.0, deadline - time.monotonic()))
