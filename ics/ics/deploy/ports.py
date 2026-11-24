"""Ports the executor talks to (dependency injection). The deployment engine never imports a concrete provider or agent client:
the process wires an `ExecEnv` via `ops.set_env_factory`. Tests inject fakes. Real implementations:

- provider: `ics.providers.*` (provider branch) restricted to the mutation verbs below.
- agent: a thin adapter over `agentclient` (needs the `podman.*`/`pkg.install_pinned` runbooks and a guest enrollment flow: ADR-0009 sec. 5).
- checks: `DbChecks` below (real, writes the `checks` table and runs the real check runners).
"""
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Literal, Protocol

from sqlalchemy import text

from ..providers.base import Discovery, TaskRef, TaskStatus, VmCloneSpec, VmConfigSpec, VmRef


class DeployError(Exception):
    """Base for errors whose text is safe to show to operators (listed in actions._SAFE_ERRORS)."""


class StepFailed(DeployError):
    def __init__(self, message: str, explanation: str = "", retryable: bool = False):
        super().__init__(message)
        self.message, self.explanation, self.retryable = message, explanation, retryable


class Cancelled(DeployError):
    pass


class Fenced(DeployError):
    """This executor no longer owns the deployment (lease expired / job reaped / newer executor). It must not touch anything."""


class ProviderMutations(Protocol):
    """The subset of providers.base.Provider the executor may call (mutations + the read-only discover used for idempotency)."""

    def discover(self) -> Discovery: ...
    def clone_vm(self, spec: VmCloneSpec) -> TaskRef: ...
    def finalize_clone(self, task: TaskRef) -> TaskRef: ...   # applies the ownership tags once the clone task succeeded
    def configure_vm(self, ref: VmRef, spec: VmConfigSpec) -> TaskRef: ...
    def resize_disk(self, ref: VmRef, disk: str, new_size_gb: int) -> TaskRef: ...
    def power(self, ref: VmRef, op: Literal["start", "shutdown", "stop", "reboot"]) -> TaskRef: ...
    def snapshot(self, ref: VmRef, name: str) -> TaskRef: ...
    def destroy_vm(self, ref: VmRef) -> TaskRef: ...
    def task_status(self, task: TaskRef) -> TaskStatus: ...


class AgentPort(Protocol):
    def wait_enrollment(self, vm_name: str, timeout_s: int) -> str:
        """Block until the VM's node agent has enrolled; return the ICS node id."""

    def run_runbook(self, node_id: str, runbook: str, params: dict) -> dict:
        """Run an allowlisted runbook (idempotent). Raise StepFailed on refusal/failure."""

    def address(self, vm_name: str) -> str:
        """Address of the VM (for checks)."""

    def tls_trust(self, node_id: str, port: int) -> dict:
        """{'fingerprint_sha256': ...} of the certificate the service on `port` presents (read through the agent)."""


class ChecksPort(Protocol):
    def register(self, rt, check: dict, host: str, trust: dict | None, created_by: str, deployment_id: str | None = None) -> str: ...
    def verify(self, rt, names: list[str]) -> list[tuple[str, bool, str]]: ...


class _Unconfigured:
    def __init__(self, what: str):
        self._what = what

    def __getattr__(self, name):
        def call(*a, **k):
            raise StepFailed(f"no {self._what} is configured on this ICS",
                             f"The deployment engine needs a {self._what} integration that is not wired in this installation yet.")
        return call


class DbChecks:
    """Registers checks in the monitoring tables (same shape as the check.create executor) and runs the real runners."""

    def register(self, rt, check: dict, host: str, trust: dict | None, created_by: str, deployment_id: str | None = None) -> str:
        from .. import checks as checkmod  # local import: keeps this module light for the pure planner tests
        kind = check["kind"]
        if kind == "agent_probe":
            cfg = check["config"]
        elif kind == "http":
            cfg = {"url": f"https://{host}:{check['port']}{check.get('path') or '/'}", "expect_status": check["expect_status"], **(trust or {})}
            if check.get("body_contains"):
                cfg["body_contains"] = check["body_contains"]
        elif kind == "tcp_tls" or kind in ("sip_options_tls", "jitsi_jwt"):
            cfg = {"host": host, "port": check["port"], **(trust or {})}
        else:
            cfg = {"host": host, "port": check["port"]}
        cfg = checkmod.validate_config(kind, cfg)
        with rt.session() as db:
            row = db.execute(text("SELECT id, deployment_id FROM checks WHERE name = :n"), {"n": check["name"]}).first()
            if row:  # review 3 L4: never adopt a check this deployment did not create
                if deployment_id is None or str(row.deployment_id) != deployment_id:
                    raise StepFailed(f"a check named {check['name']!r} already exists and does not belong to this deployment",
                                     "Rename or remove the conflicting check, then re-run the deployment.", retryable=False)
                # this deployment's own check: a re-run registers what the plan says now (a check registered wrongly by an earlier
                # release is corrected, officeunbound8 job 8b19638e); state and history stay with the row
                db.execute(text("UPDATE checks SET kind = :k, config = CAST(:c AS jsonb), interval_seconds = :iv WHERE id = :i "
                                "AND (kind <> :k OR config <> CAST(:c AS jsonb) OR interval_seconds <> :iv)"),
                           {"i": row.id, "k": kind, "c": json.dumps(cfg, sort_keys=True), "iv": check["interval_seconds"]})
                db.commit()
                return str(row.id)
            cid = str(uuid.uuid4())
            db.execute(text("INSERT INTO checks (id, name, kind, config, interval_seconds, created_by, deployment_id, customer_id) "
                            "VALUES (:i, :n, :k, CAST(:c AS jsonb), :iv, :cb, :dp, COALESCE((SELECT e.customer_id FROM deployments d JOIN endpoints e ON e.id = d.endpoint_id "
                            "WHERE d.id = CAST(:dp AS uuid)), '00000000-0000-0000-0000-00000000a001'))"),
                       {"i": cid, "n": check["name"], "k": kind, "c": json.dumps(cfg, sort_keys=True), "iv": check["interval_seconds"], "cb": created_by,
                        "dp": deployment_id})
            db.commit()
            return cid

    def verify(self, rt, names: list[str]) -> list[tuple[str, bool, str]]:
        from .. import monitor
        out = []
        for n in names:
            with rt.session() as db:
                row = db.execute(text("SELECT id FROM checks WHERE name = :n"), {"n": n}).first()
            if row is None:
                out.append((n, False, "check is not registered"))
                continue
            state, o = monitor.run_and_record(rt, row.id, remediate=False)
            out.append((n, state == "ok", o.message[:200]))
        return out


@dataclass
class ExecEnv:
    provider: ProviderMutations = field(default_factory=lambda: _Unconfigured("infrastructure provider"))
    agent: AgentPort = field(default_factory=lambda: _Unconfigured("node agent integration"))
    checks: ChecksPort = field(default_factory=DbChecks)
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic
    poll_interval: float = 2.0
    task_timeout: float = 900.0
    max_attempts: int = 3
    retry_delay: float = 5.0


# job id -> threading.Event set by actions.run_job when it gives up on a deployment executor thread (see lease.Lease)
STOP_EVENTS: dict = {}
