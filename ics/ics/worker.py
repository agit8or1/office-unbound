import logging
import threading

from sqlalchemy import text

from .actions import claim_job, reap_expired, run_job
from .runtime import Runtime

log = logging.getLogger("ics.worker")


def heartbeat(rt: Runtime, name: str = "inproc") -> None:
    with rt.session() as db:
        db.execute(text(
            "INSERT INTO worker_heartbeat (name, at) VALUES (:n, now()) ON CONFLICT (name) DO UPDATE SET at = now()"), {"n": name})
        db.commit()


def run_once(rt: Runtime) -> bool:
    """Heartbeat, then claim and run at most one job. Returns True if a job ran."""
    heartbeat(rt)
    reap_expired(rt)
    job = claim_job(rt)
    if job is None:
        return False
    run_job(rt, job)
    return True


class Worker(threading.Thread):
    def __init__(self, rt: Runtime, interval: float = 1.0):
        super().__init__(daemon=True, name="ics-worker")
        self.rt, self.interval, self._stop_evt = rt, interval, threading.Event()

    def _beat(self) -> None:
        """Own timer thread: the heartbeat keeps ticking while a long job runs (M8)."""
        while not self._stop_evt.is_set():
            try:
                heartbeat(self.rt)
            except Exception:  # noqa: BLE001
                log.exception("heartbeat error")
            self._stop_evt.wait(5.0)

    def run(self) -> None:
        threading.Thread(target=self._beat, daemon=True, name="ics-heartbeat").start()
        while not self._stop_evt.is_set():
            try:
                while run_once(self.rt):
                    pass
            except Exception:  # noqa: BLE001
                log.exception("worker loop error")
            self._stop_evt.wait(self.interval)

    def stop(self) -> None:
        self._stop_evt.set()
