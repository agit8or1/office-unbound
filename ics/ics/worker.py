import logging
import threading
import time

from sqlalchemy import text

from . import identity, monitor
from .actions import claim_job, reap_expired, run_job
from .runtime import Runtime

log = logging.getLogger("ics.worker")


def heartbeat(rt: Runtime, name: str = "inproc") -> None:
    with rt.session() as db:
        db.execute(text(
            "INSERT INTO worker_heartbeat (name, at) VALUES (:n, now()) ON CONFLICT (name) DO UPDATE SET at = now()"), {"n": name})
        db.commit()


def run_once(rt: Runtime, beat: bool = True) -> bool:
    """Heartbeat (unless the Worker's own watchdog owns it), then claim and run at most one job. Returns True if a job ran."""
    if beat:
        heartbeat(rt)
    reap_expired(rt)
    job = claim_job(rt)
    if job is None:
        return False
    run_job(rt, job)
    return True


class Worker(threading.Thread):
    """Three independent threads (review M2): the job loop, the monitor loop (checks, remediation sync, notifications, identity
    reconcile) and a heartbeat timer. A check that stalls can no longer block jobs or approvals, and the heartbeat is only written
    while BOTH loops are making progress, so a stalled component turns /readyz red instead of staying falsely green."""

    def __init__(self, rt: Runtime, interval: float = 1.0):
        super().__init__(daemon=True, name="ics-worker")
        self.rt, self.interval, self._stop_evt = rt, interval, threading.Event()
        now = time.monotonic()
        self.progress = {"jobs": now, "monitor": now}
        self.job_stall_seconds = rt.settings.job_timeout_seconds + 30.0
        self.monitor_stall_seconds = float(rt.settings.monitor_stall_seconds)

    def healthy(self) -> bool:
        now = time.monotonic()
        return (now - self.progress["jobs"] <= self.job_stall_seconds
                and (not self.rt.settings.monitor_enabled or now - self.progress["monitor"] <= self.monitor_stall_seconds))

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
                self.progress["jobs"] = time.monotonic()
                while run_once(self.rt, beat=False):
                    self.progress["jobs"] = time.monotonic()
            except Exception:  # noqa: BLE001
                log.exception("job loop error")
            self._stop_evt.wait(self.interval)

    def _monitor_loop(self) -> None:
        while not self._stop_evt.is_set():
            try:
                self.progress["monitor"] = time.monotonic()
                monitor.tick(self.rt)
                self.progress["monitor"] = time.monotonic()
                identity.reconcile_due(self.rt)
                self.progress["monitor"] = time.monotonic()
            except Exception:  # noqa: BLE001
                log.exception("monitor loop error")
            self._stop_evt.wait(self.interval)

    def run(self) -> None:
        threading.Thread(target=self._beat, daemon=True, name="ics-heartbeat").start()
        if self.rt.settings.monitor_enabled:
            threading.Thread(target=self._monitor_loop, daemon=True, name="ics-monitor").start()
        self._job_loop()

    def stop(self) -> None:
        self._stop_evt.set()
