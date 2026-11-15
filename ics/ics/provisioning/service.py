"""Permission drift runner (periodic, read-only) and the read API for provisioned integrations.

The drift check uses the integration's OWN token(s): GET /access/permissions compared with the stored policy. It never restores or widens
anything: a finding is recorded (audit + endpoint_policy.last_drift) and the correction is a plan (provider.permissions.reconcile) that needs
approval. A 401 from Proxmox is a *token failure* (revoked/expired/disabled) and is reported as such, distinct from the cluster being unreachable.
"""
from __future__ import annotations

import io
import json
import logging
import time
import zipfile
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Response
from sqlalchemy import text
from sqlalchemy.orm import Session

from .. import audit
from ..auth import User, get_db, require
from ..providers.proxmox import provisioning as pp
from ..proxmox import ProxmoxError, ProxmoxHTTPError
from ..runtime import Runtime
from ..tenancy import scope as tscope
from .model import Policy

log = logging.getLogger("ics.provisioning")
API = "/api/v1"
DRIFT_INTERVAL = 6 * 3600
_next: dict[str, float] = {}


def check_endpoint(rt: Runtime, db: Session, ep, st) -> dict:
    """Run one drift check; persist and audit the outcome. Returns the stored report."""
    from ..actions import _new_client
    policy = Policy.model_validate(st.policy)
    d = pp.design_from_stored(policy, st.design)
    report: dict = {"ok": True, "kinds": {}}
    status = "ok"
    try:
        for kind, t in st.tokens.items():
            sec = _secret(rt, ep, kind)
            c = _new_client(rt, ep.base_url, t["id"], sec, ep.ca_pem, ep.fingerprint_sha256)
            try:
                r = pp.drift_check(_R(c), policy, {}, d, kind)
            finally:
                c.close()
            report["kinds"][kind] = r
            if not r["ok"]:
                report["ok"] = False
                status = "drift"
    except ProxmoxHTTPError as e:
        report = {"ok": False, "error": "token failure" if e.status == 401 else f"Proxmox answered HTTP {e.status}",
                  "error_code": "token_failed" if e.status == 401 else "pve_error", "kinds": report["kinds"]}
        status = "token_failed" if e.status == 401 else "error"
    except ProxmoxError as e:
        report = {"ok": False, "error": str(e)[:200], "error_code": "unreachable", "kinds": report["kinds"]}
        status = "unreachable"
    report["checked_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    prev = st.status
    db.execute(text("UPDATE endpoint_policy SET last_drift = CAST(:d AS jsonb), last_drift_at = now(), status = :s WHERE endpoint_id = :e"),
               {"d": json.dumps(audit.sanitize(report), default=str), "s": status if st.status != "revoked" else "revoked", "e": str(ep.id)})
    if status != prev and status in ("drift", "token_failed"):
        _notify(db, ep, status, report)
    if status != prev:
        ev = {"drift": "provider.permissions.drift", "token_failed": "provider.token.failed"}.get(status, "provider.permissions.check")
        audit.append(db, ev, actor_name="worker", resource="endpoint", resource_id=str(ep.id),
                     details={"status": status, "previous": prev, "error": report.get("error"),
                              "missing": {k: v.get("missing") for k, v in report["kinds"].items()},
                              "unexpected": {k: v.get("unexpected") for k, v in report["kinds"].items()}})
    return report


def _notify(db: Session, ep, status: str, report: dict) -> int:
    """Route drift / token failure to the alert outbox (alert_channels -> notifications -> monitor.dispatch_notifications). No secrets."""
    kind = {"drift": "provider.permissions.drift", "token_failed": "provider.token.failed"}[status]
    detail = (f"Integration '{ep.name}': " + ("the token(s) were rejected by Proxmox (revoked, expired or disabled)." if status == "token_failed"
              else "permissions drifted from the approved policy (missing/unexpected privileges). Review and reconcile with an approved plan."))
    chans = db.execute(text("SELECT id FROM alert_channels WHERE enabled")).all()
    for ch in chans:
        db.execute(text("INSERT INTO notifications (incident_id, channel_id, event, status, detail) VALUES (NULL, :ch, :e, 'pending', :d)"),
                   {"ch": str(ch.id), "e": kind, "d": detail})
    return len(chans)


class _R:
    def __init__(self, c):
        self.get = c._get


def _secret(rt, ep, kind):
    from .actions import _vault_token
    return _vault_token(rt, ep, kind)


def tick(rt: Runtime) -> None:
    now = time.monotonic()
    with rt.session() as db:
        rows = db.execute(text("SELECT e.id FROM endpoints e JOIN endpoint_policy p ON p.endpoint_id = e.id "
                               "WHERE e.enabled AND e.detached_at IS NULL AND p.status <> 'revoked'")).all()
    for r in rows:
        if _next.get(str(r.id), 0) > now:
            continue
        _next[str(r.id)] = now + DRIFT_INTERVAL
        try:
            with rt.session() as db:
                ep = db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": str(r.id)}).first()
                st = db.execute(text("SELECT * FROM endpoint_policy WHERE endpoint_id = :i"), {"i": str(r.id)}).first()
                check_endpoint(rt, db, ep, st)
                db.commit()
        except Exception:  # noqa: BLE001
            log.exception("permission drift check failed")


def permissions_view(db: Session, eid) -> dict:
    ep = db.execute(text("SELECT id, name, token_id, provision_token_id, enabled FROM endpoints WHERE id = :i AND detached_at IS NULL"), {"i": str(eid)}).first()
    if ep is None:
        raise HTTPException(404, "endpoint not found")
    st = db.execute(text("SELECT * FROM endpoint_policy WHERE endpoint_id = :i"), {"i": str(eid)}).first()
    if st is None:
        return {"endpoint_id": str(eid), "managed_by_provisioning": False,
                "note": "this endpoint was registered with manually supplied tokens; no provisioning policy is stored"}
    policy = Policy.model_validate(st.policy)
    d = pp.design_from_stored(policy, st.design)
    expected = {k: {p: sorted(v) for p, v in pp.expected_permissions(d, k).items()} for k in d.tokens}
    return {
        "endpoint_id": str(eid), "managed_by_provisioning": True, "mode": st.mode, "status": st.status, "preset": policy.preset,
        "service_user": d.userid, "tokens": st.tokens, "plan_hash": st.plan_hash,
        "roles": {cap: {"name": n, "privileges": sorted(p)} for cap, (n, p) in d.roles.items()},
        "expected": expected,
        "actual": {k: {"expected_paths": sorted(v)} for k, v in expected.items()},
        "last_verification": st.last_verification, "last_verified_at": st.last_verified_at, "last_drift": st.last_drift, "last_drift_at": st.last_drift_at,
        "enforcement": [e.__dict__ for e in pp.enforcement_matrix(policy)],
        "scope": policy.scope.model_dump(mode="json"),
        "never_granted": sorted(pp.FORBIDDEN), "managed_objects": st.managed,
    }


def mount(app: FastAPI, rt: Runtime) -> None:
    @app.get(f"{API}/providers/{{provider_id}}/permissions")
    def permissions(provider_id: UUID, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        tscope.assert_endpoint(db, user, provider_id)
        return permissions_view(db, provider_id)

    @app.post(f"{API}/providers/{{provider_id}}/permissions/check")
    def check_now(provider_id: UUID, user: User = Depends(require("operator")), db: Session = Depends(get_db)):
        """Read-only live check with the integration's own token (no plan needed: it changes nothing in Proxmox)."""
        tscope.assert_endpoint(db, user, provider_id)
        ep = db.execute(text("SELECT * FROM endpoints WHERE id = :i AND detached_at IS NULL AND enabled"), {"i": str(provider_id)}).first()
        st = db.execute(text("SELECT * FROM endpoint_policy WHERE endpoint_id = :i"), {"i": str(provider_id)}).first()
        if ep is None or st is None or st.status == "revoked":
            raise HTTPException(404, "no active provisioned integration")
        rep = check_endpoint(rt, db, ep, st)
        db.commit()
        return rep

    @app.get(f"{API}/providers/{{provider_id}}/provisioning/packages/{{package_id}}")
    def package(provider_id: str, package_id: UUID, format: str = "json", user: User = Depends(require("admin")), db: Session = Depends(get_db)):
        row = db.execute(text("SELECT * FROM provision_artifacts WHERE id = :i AND kind = 'package'"), {"i": str(package_id)}).first()
        if row is None:
            raise HTTPException(404, "package not found")
        if not tscope.allowed(user, row.customer_id) if row.customer_id else getattr(user, "customer_ids", None) is not None:
            raise HTTPException(404, "package not found")
        bound = str(row.endpoint_id) if row.endpoint_id else "unbound"
        if provider_id != bound:
            raise HTTPException(404, "package not found")
        files = row.data["files"]
        audit.append(db, "provider.provision.package_downloaded", actor_id=user.id, actor_name=user.username, resource="package",
                     resource_id=str(package_id), details={"format": format})
        db.commit()
        if format == "json":
            return {"package_id": str(package_id), "plan_hash": row.plan_hash, "files": files}
        if format == "zip":
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                for n, c in files.items():
                    z.writestr(n, c)
            return Response(buf.getvalue(), media_type="application/zip",
                            headers={"Content-Disposition": f'attachment; filename="ou-proxmox-package-{str(package_id)[:8]}.zip"'})
        if format not in files:
            raise HTTPException(404, f"no such file; choose one of json, zip, {', '.join(sorted(files))}")
        ctype = "text/html" if format.endswith(".html") else "text/plain"
        return Response(files[format], media_type=ctype + "; charset=utf-8", headers={"X-Content-Type-Options": "nosniff",
                                                                                      "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
