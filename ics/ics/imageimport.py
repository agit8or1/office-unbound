"""image.import: turn a signed golden-image release into a Proxmox template, as an approved typed action (Stage 2; ADR-0008 output).

Trust model (review 5 M7, review 7 M-4):
  * the release is chosen by NAME from the operator-configured releases directory (ICS_GUEST_GOLDEN_RELEASES_DIR); no path is ever taken from a plan
  * trust (release key, pin, attestor key) comes from Settings only (golden.trust_from_settings); the rollback floor from the ICS database
  * the requester states the image sha256 they previewed; the plan is refused when the verified release differs, and the job re-verifies at execution
    (a release swapped between approval and execution is refused before anything is uploaded)
  * always high risk; a downgrade below the DB floor needs `allow_downgrade` (also high risk, shown to the approvers) and never lowers the floor
The provider verb (ProxmoxMutations.import_image) verifies the release a third time, re-hashes the file, uploads with a Proxmox-side checksum and
records the floor after the template exists."""
from __future__ import annotations

import os
import re
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from .runtime import Runtime

RELEASE = r"^[a-z0-9][a-z0-9_-]{0,40}(?:\.[a-z0-9][a-z0-9_-]{0,40}){0,3}$"   # one directory name; no '/', no '.' or '..' segments
NAME = r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$"
STORAGE = r"^[A-Za-z][A-Za-z0-9._-]{0,63}$"
SHA = r"^[0-9a-f]{64}$"
TPL = r"^ou-tpl-[a-z0-9][a-z0-9-]{0,50}$"


class ImageImport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: UUID
    pve_node: str = Field(pattern=NAME, description="Proxmox node name (not an ICS node)")
    release: str = Field(pattern=RELEASE, description="release directory name under ICS_GUEST_GOLDEN_RELEASES_DIR")
    expected_sha256: str = Field(pattern=SHA, description="image sha256 the requester previewed; must equal the verified release")
    import_storage: str = Field(pattern=STORAGE)
    target_storage: str = Field(pattern=STORAGE)
    pool: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    bridge: str | None = Field(default=None, pattern=r"^[A-Za-z][A-Za-z0-9._-]{0,31}$")
    template_name: str | None = Field(default=None, pattern=TPL)
    cores: int = Field(default=2, ge=1, le=64)
    memory_mb: int = Field(default=2048, ge=256, le=262144)
    allow_downgrade: bool = False


def releases_root(rt: Runtime) -> str:
    root = getattr(rt.settings, "guest_golden_releases_dir", None)
    if not root:
        raise ValueError("golden image releases are not configured (ICS_GUEST_GOLDEN_RELEASES_DIR)")
    return os.path.realpath(root)


def release_dir(rt: Runtime, name: str) -> str:
    """The release directory for a NAME, confined to the configured root (symlinks resolved; anything outside is refused)."""
    if not re.fullmatch(RELEASE, name or ""):
        raise ValueError("invalid release name")
    root = releases_root(rt)
    d = os.path.realpath(os.path.join(root, name))
    if os.path.dirname(d) != root or not os.path.isdir(d):
        raise KeyError("release not found")
    return d


def default_template(os_id: str) -> str:
    t = "ou-tpl-" + re.sub(r"[^a-z0-9-]+", "-", os_id.lower().replace(".", "")).strip("-")   # ubuntu-24.04 -> ou-tpl-ubuntu-2404 (catalog name)
    return t[:57]


def versioned_template(os_id: str, version) -> str:
    """The template's Proxmox name: the catalog name plus the signed version (ou-tpl-ubuntu-2404-v10), so the list in Proxmox shows which
    golden image each template is (owner 2026-11-20). Deployments match the catalog name with or without the suffix (executor.template_base)."""
    return f"{default_template(os_id)}-v{int(version)}" if version is not None else default_template(os_id)


def _verify(rt: Runtime, m: ImageImport):
    from .guest import golden
    rel = golden.verify_for_import(rt, release_dir(rt, m.release), allow_downgrade=m.allow_downgrade)
    if rel.sha256 != m.expected_sha256:
        raise LookupError("the release image differs from the previewed sha256 (re-preview and submit a new plan)")
    return rel


def list_releases(rt: Runtime) -> list[dict]:
    """Every release under the root, each verified with Settings trust and the DB floor. Unverifiable releases are listed with the reason, never hidden."""
    from .guest import golden
    root = releases_root(rt)
    out = []
    for n in sorted(os.listdir(root)):
        if not re.fullmatch(RELEASE, n) or not os.path.isdir(os.path.join(root, n)):
            continue
        try:
            rel = golden.verify_for_import(rt, release_dir(rt, n))
            fl = golden.get_floor(rt, rel.os)
            out.append({"release": n, "verified": True, "os": rel.os, "version": rel.version, "image": os.path.basename(rel.path), "sha256": rel.sha256,
                        "date": rel.date, "attestation_run_id": rel.attestation_run_id, "floor_version": fl.version if fl else None,
                        "default_template": default_template(rel.os)})
        except (golden.ReleaseError, KeyError, ValueError) as e:
            out.append({"release": n, "verified": False, "reason": str(e)[:300]})
    return out


def precheck(db: Session, rt: Runtime, p: ImageImport) -> dict:
    from .actions import PlanError
    from .guest import golden
    ep = db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": str(p.endpoint_id)}).first()
    if ep is None:
        raise PlanError(404, "endpoint not found")
    if ep.detached_at is not None or ep.enabled is False:
        raise PlanError(409, "endpoint is disabled or removed")
    if not ep.provision_token_id:
        raise PlanError(409, "endpoint has no provision credential")
    if p.pve_node not in (ep.allowed_nodes or ()):
        raise PlanError(422, f"node {p.pve_node!r} is not an authorized node of this endpoint")
    if p.pool not in (ep.allowed_pools or ()):
        raise PlanError(422, f"pool {p.pool!r} is not an allowed pool of this endpoint")
    for st in (p.import_storage, p.target_storage):
        if ep.allowed_storage and st not in ep.allowed_storage:
            raise PlanError(422, f"storage {st!r} is not an allowed storage of this endpoint")
    if p.bridge and ep.allowed_networks and p.bridge not in ep.allowed_networks:
        raise PlanError(422, f"bridge {p.bridge!r} is not an allowed network of this endpoint")
    try:
        rel = _verify(rt, p)
    except KeyError:
        raise PlanError(404, "release not found") from None
    except LookupError as e:
        raise PlanError(409, str(e)) from None
    except (golden.ReleaseError, ValueError) as e:
        raise PlanError(422, f"release verification failed: {e}") from None
    tpl = p.template_name or versioned_template(rel.os, rel.version)
    fl = golden.get_floor(rt, rel.os)
    extra = {"endpoint_name": ep.name, "image": {"os": rel.os, "version": rel.version, "file": os.path.basename(rel.path), "sha256": rel.sha256,
                                                  "attestation_run_id": rel.attestation_run_id},
             "template_name": tpl, "floor_version": fl.version if fl else None, "downgrade": bool(fl and rel.version < fl.version)}
    tmpl = tuple(getattr(ep, "allowed_templates", None) or ())
    if tmpl and tpl not in tmpl:
        extra["warning"] = f"template {tpl!r} is not in the endpoint's allowed templates; deployments cannot clone it until it is added"
    return extra


def exec_import(rt: Runtime, db: Session, m: ImageImport, plan, known: list[str]) -> dict:
    from .guest import golden
    from .providers.base import ImageImportSpec
    from .providers.proxmox import open_mutations
    ep = db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": str(m.endpoint_id)}).first()
    if ep is None:
        raise LookupError("endpoint not found")
    rel = _verify(rt, m)                                     # re-verified at execution: Settings trust + current DB floor + the approved sha256
    rdir = release_dir(rt, m.release)
    prov = open_mutations(rt, ep, known)
    tpl = m.template_name or versioned_template(rel.os, rel.version)
    res = prov.import_image(ImageImportSpec(node=m.pve_node, import_storage=m.import_storage, target_storage=m.target_storage, file_path=rel.path,
                                            sha256=rel.sha256, name=tpl, pool=m.pool, cores=m.cores, memory_mb=m.memory_mb, bridge=m.bridge,
                                            release_dir=rdir, allow_downgrade=m.allow_downgrade))
    return {"node": res.node, "vmid": res.vmid, "template": res.name, "volid": res.volid, "os": rel.os, "version": rel.version, "sha256": rel.sha256}
