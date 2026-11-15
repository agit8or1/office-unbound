"""Production wiring of the executor's ExecEnv: the real Proxmox provider (provision credential, scope re-checked on every call).

Called by `ops._run` inside job execution, so `open_mutations` (which requires `providers.base.job_execution`) is reachable only
from a job. The agent port stays unconfigured until the guest enrollment flow exists (ADR-0009 section 5): steps that need an
agent fail with a clear message instead of pretending."""
from sqlalchemy import text

from ..providers.proxmox import open_mutations
from .ports import ExecEnv, StepFailed


def real_env_factory(rt, dep: dict) -> ExecEnv:
    with rt.session() as db:
        ep = db.execute(text("SELECT e.* FROM endpoints e JOIN deployments d ON d.endpoint_id = e.id WHERE d.id = :i"), {"i": dep["id"]}).first()
    if ep is None:
        raise StepFailed("the deployment's endpoint no longer exists", "Register the endpoint again before running this deployment.")
    return ExecEnv(provider=open_mutations(rt, ep), poll_interval=3.0, task_timeout=900.0)
