"""release.promote: ICS-mediated package promotion (security review 5 H2).

The plan carries the EXACT package set (file names, names, versions, sha256) and the test evidence references (sha256 of the runner's attestation
per .deb). Approvers are real ICS approvers (requester excluded by the global rules; staging>stable is `high` = required_approvals_high, i.e. two).
The executor builds a promotion manifest from the approved plan, signs it with the ICS signing key and hands it to the release pipeline
(`ICS_RELEASE_PROMOTE_CMD <manifest-file>`, normally `repo.sh promote-manifest`). The signer (ou-release-sign) verifies the signature, the approver
count, the exact package set and the evidence before it signs anything. Nothing here can promote without that program; nothing there can promote
without this manifest."""
import json
import os
import re
import secrets
import shlex
import subprocess
import tempfile
import time
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import text

from . import agentclient

PROMO_PREFIX = b"ou-release-promotion-v1\n"
MANIFEST_TTL = 900
SHA = r"^[0-9a-f]{64}$"
FILE = r"^[A-Za-z0-9][A-Za-z0-9._+~:-]{0,200}$"


class Pkg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    file: str = Field(pattern=FILE)
    sha256: str = Field(pattern=SHA)
    name: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9.+-]{0,100}$")
    version: str | None = Field(default=None, pattern=r"^[A-Za-z0-9.+~:-]{1,100}$")


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sha256: str = Field(pattern=SHA, description="sha256 of the .deb the test ran on")
    attestation_sha256: str = Field(pattern=SHA, description="hash of the test runner's signed attestation (pipeline record)")


class ReleasePromote(BaseModel):
    model_config = ConfigDict(extra="forbid")
    component: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,60}$")
    from_channel: Literal["dev", "staging"]
    to_channel: Literal["staging", "stable"]
    packages: list[Pkg] = Field(min_length=1, max_length=200)
    evidence: list[Evidence] = Field(default_factory=list, max_length=200)
    reason: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _chk(self) -> Self:
        if (self.from_channel, self.to_channel) not in (("dev", "staging"), ("staging", "stable")):
            raise ValueError("only dev>staging or staging>stable")
        if len({p.file for p in self.packages}) != len(self.packages):
            raise ValueError("duplicate file in the package set")
        have = {e.sha256 for e in self.evidence}
        for p in self.packages:
            if p.file.endswith(".deb"):
                if not p.name or not p.version:
                    raise ValueError(f"{p.file}: a .deb needs name and version")
                if p.sha256 not in have:
                    raise ValueError(f"{p.file}: no test evidence (attestation hash) for this sha256")
            if p.file.startswith("oci:"):      # container image: file = oci:<repo with / as ~>:<tag>, sha256 = the manifest digest (hex), evidence = the scan attestation
                if not self.component.startswith("oci-") or len(self.packages) != 1 or len(self.evidence) != 1 or self.evidence[0].sha256 != p.sha256:
                    raise ValueError("an OCI promotion is one image (component oci-*) with exactly one evidence entry for its digest")
        return self


def risk(p: ReleasePromote) -> str:
    return "high" if p.to_channel == "stable" else "normal"


def precheck(db, rt, p: ReleasePromote) -> dict:
    return {"channel": f"{p.from_channel}>{p.to_channel}", "packages": len(p.packages)}


def build_manifest(plan, p: ReleasePromote, approvers: list[dict], now: int | None = None) -> dict:
    now = int(time.time()) if now is None else now
    return {"v": 1, "plan_id": str(plan.id), "from": p.from_channel, "to": p.to_channel, "component": p.component,
            "requested_by_id": str(plan.requested_by), "approvers": approvers, "approvals_required": 2 if p.to_channel == "stable" else 1,
            "packages": [{"file": x.file, "sha256": x.sha256, "name": x.name, "version": x.version} for x in p.packages],
            "evidence": [e.model_dump() for e in p.evidence], "nonce": secrets.token_urlsafe(24), "issued_at": now, "expires_at": now + MANIFEST_TTL}


def exec_promote(rt, db, m: ReleasePromote, plan, known) -> dict:
    from .actions import PlanIntegrityError
    rt.assert_active()      # review 7 H-5: a fenced/standby controller must not promote packages
    is_oci = m.component.startswith("oci-")
    cmd = rt.settings.release_promote_oci_cmd if is_oci else rt.settings.release_promote_cmd
    if not cmd:
        raise PlanIntegrityError("ICS_RELEASE_PROMOTE_OCI_CMD is not configured on this ICS" if is_oci else "ICS_RELEASE_PROMOTE_CMD is not configured on this ICS")
    rows = db.execute(text("SELECT u.id, u.username FROM plan_approvals a JOIN users u ON u.id = a.approver_id WHERE a.plan_id = :p ORDER BY a.approver_id"),
                      {"p": str(plan.id)}).all()
    approvers = [{"id": str(r.id), "username": r.username} for r in rows]
    need = 2 if m.to_channel == "stable" else 1
    if len({a["id"] for a in approvers}) < need or str(plan.requested_by) in {a["id"] for a in approvers}:
        raise PlanIntegrityError("not enough independent approvers for this channel; refusing to build a manifest")
    man = build_manifest(plan, m, approvers)
    # review 7 L-4: a dedicated promotion key (not part of the standby key bundle, never used for agent requests) when configured
    doc = {"manifest": man, "sig": agentclient.sign(agentclient.load_signing_key(rt.settings.release_promotion_key_file or rt.settings.signing_key_file), PROMO_PREFIX, man)}
    with tempfile.TemporaryDirectory(prefix="ou-promo-") as d:
        fn = os.path.join(d, "manifest.json")
        fd = os.open(fn, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(doc, f)
        r = subprocess.run([*shlex.split(cmd), fn], capture_output=True, text=True, timeout=1800, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": d})
    if r.returncode != 0:
        raise agentclient.AgentError(("release pipeline refused the promotion: " + re.sub(r"\s+", " ", (r.stdout + r.stderr))[-300:]).strip())
    return {"promoted": len(m.packages), "channel": f"{m.from_channel}>{m.to_channel}", "approvers": [a["username"] for a in approvers]}
