"""Read-only API behind the console pages Operations > Releases and the guest bootstrap panel (no mutations: promotion itself is the
`release.promote` plan, scope changes are plans too).

GET /releases                         package channels (dev/staging/stable) read from the signed repo tree, test evidence from the signer's records,
                                      and the promotions that are possible now, each with the exact `release.promote` params and the approver count.
GET /deployments/{slug}/bootstrap     per-VM guest bootstrap state (pending callback, enrolled, replay alarm, rate-limited).
Both only read local files / the database; the signing key and the records' content beyond result + attestation hash are never returned."""
import json
import os
import re
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from .auth import User, get_db, require
from .guest import callback as guest_callback
from .tenancy import scope as tscope

CHANNELS = ("dev", "staging", "stable")
PROMOTIONS = (("dev", "staging"), ("staging", "stable"))
SHA = re.compile(r"^[0-9a-f]{64}$")
EVIDENCE_TEST = "install-smoke"        # the record the signer requires for every .deb (ou-release-sign verify_manifest)
MAX_PACKAGES = 2000


def parse_packages(raw: str) -> list[dict]:
    """Debian `Packages` stanzas -> [{name, version, file, sha256, component}] (only pool/<suite>/<component>/<file> entries)."""
    out = []
    for stanza in re.split(r"\n\s*\n", raw):
        f: dict[str, str] = {}
        for line in stanza.splitlines():
            if line[:1] in (" ", "\t") or ":" not in line:
                continue
            k, _, v = line.partition(":")
            f[k.strip()] = v.strip()
        parts = f.get("Filename", "").split("/")
        if not f.get("Package") or len(parts) != 4 or parts[0] != "pool" or not SHA.match(f.get("SHA256", "")):
            continue
        out.append({"name": f["Package"], "version": f.get("Version", ""), "file": parts[3], "component": parts[2], "sha256": f["SHA256"],
                    "arch": f.get("Architecture")})
        if len(out) >= MAX_PACKAGES:
            break
    return out


def _evidence(records_dir: str | None, sha: str) -> dict | None:
    if not records_dir or not SHA.match(sha):
        return None
    try:
        with open(os.path.join(records_dir, sha + ".json")) as fh:
            res = json.load(fh).get("results", {})
    except (OSError, ValueError):
        return None
    r = res.get(EVIDENCE_TEST)
    if not isinstance(r, dict):
        return {"test": EVIDENCE_TEST, "result": None, "attestation_sha256": None, "at": None, "other": sorted(res)[:10]}
    return {"test": EVIDENCE_TEST, "result": r.get("result"), "attestation_sha256": r.get("attestation_sha256"), "at": r.get("at") or None,
            "other": sorted(k for k in res if k != EVIDENCE_TEST)[:10]}


def read_channels(repo_dir: str, records_dir: str | None) -> dict:
    chans: dict[str, dict] = {}
    for ch in CHANNELS:
        p = os.path.join(repo_dir, "dists", ch, "main", "binary-amd64", "Packages")
        try:
            with open(p) as fh:
                pk = parse_packages(fh.read())
            at = datetime.fromtimestamp(os.stat(p).st_mtime, timezone.utc).isoformat()
        except OSError:
            chans[ch] = {"name": ch, "available": False, "indexed_at": None, "components": []}
            continue
        comps: dict[str, list] = {}
        for x in pk:
            x["evidence"] = _evidence(records_dir, x["sha256"])
            comps.setdefault(x["component"], []).append(x)
        chans[ch] = {"name": ch, "available": True, "indexed_at": at,
                     "components": [{"component": c, "packages": sorted(v, key=lambda y: y["file"])} for c, v in sorted(comps.items())]}
    return chans


def candidates(chans: dict, need: dict[str, int]) -> list[dict]:
    """Promotions that would change something: the component's package set in `from` differs from `to`. Params are exactly what the plan takes."""
    out = []
    for frm, to in PROMOTIONS:
        if not chans[frm]["available"]:
            continue
        have_to = {c["component"]: {p["sha256"] for p in c["packages"]} for c in chans[to]["components"]}
        for c in chans[frm]["components"]:
            pk = c["packages"]
            if {p["sha256"] for p in pk} == have_to.get(c["component"]):
                continue
            blocked = []
            for p in pk:
                if not p["file"].endswith(".deb"):
                    continue
                ev = p["evidence"]
                if not ev or ev["result"] is None:
                    blocked.append(f"{p['file']}: no {EVIDENCE_TEST} test record yet")
                elif ev["result"] != "pass":
                    blocked.append(f"{p['file']}: the {EVIDENCE_TEST} test did not pass")
            params = {"component": c["component"], "from_channel": frm, "to_channel": to,
                      "packages": [{"file": p["file"], "sha256": p["sha256"], **({"name": p["name"], "version": p["version"]} if p["file"].endswith(".deb") else {})} for p in pk],
                      "evidence": [{"sha256": p["sha256"], "attestation_sha256": p["evidence"]["attestation_sha256"]} for p in pk
                                   if p["file"].endswith(".deb") and p["evidence"] and p["evidence"]["result"] == "pass" and p["evidence"]["attestation_sha256"]]}
            out.append({"component": c["component"], "from_channel": frm, "to_channel": to, "ready": not blocked, "blocked": blocked,
                        "approvals_required": need[to], "risk": "high" if to == "stable" else "normal",
                        "current_in_target": len(have_to.get(c["component"], ())), "params": params})
    return out


def bootstrap_view(row, alarms: dict, now: datetime, limited: bool | None) -> dict:
    """One VM. `state` is the stored one except that a pending record past its expiry reads 'expired'."""
    state = row["state"]
    if state == "pending" and row["expires_at"] <= now:
        state = "expired"
    a = alarms.get(row["bid"])
    return {"vm": row["vm"], "vmid": row["vmid"], "mode": row["mode"], "state": state, "attempts": row["attempts"],
            "created_at": row["created_at"].isoformat(), "expires_at": row["expires_at"].isoformat(),
            "reported_at": row["reported_at"].isoformat() if row["reported_at"] else None,
            "sealed_at": row["sealed_at"].isoformat() if row["sealed_at"] else None,
            "replay_alarm": {"count": a[0], "last_at": a[1].isoformat(), "stopped_deployment": a[2]} if a else None, "rate_limited": limited}


def register(app: FastAPI, rt, API: str) -> None:
    @app.get(f"{API}/releases")
    def releases(user: User = Depends(require("viewer"))):
        s = rt.settings
        need = {"staging": 1, "stable": s.required_approvals_high}
        base = {"promote_enabled": bool(s.release_promote_cmd), "approvals_required": need, "evidence_test": EVIDENCE_TEST}
        if not s.release_repo_dir:
            return {**base, "configured": False, "channels": [], "candidates": []}
        chans = read_channels(s.release_repo_dir, s.release_records_dir)
        return {**base, "configured": True, "records_readable": bool(s.release_records_dir and os.path.isdir(s.release_records_dir)),
                "channels": [chans[c] for c in CHANNELS], "candidates": candidates(chans, need)}

    @app.get(f"{API}/images/releases")
    def image_releases(user: User = Depends(require("admin"))):
        """Signed golden-image releases available to image.import, each verified with Settings trust and the DB floor (global ICS data, no customer data)."""
        from . import imageimport
        try:
            return {"configured": True, "releases": imageimport.list_releases(rt)}
        except (ValueError, OSError):
            return {"configured": False, "releases": []}

    @app.get(f"{API}/approvals/policy")
    def approval_policy(user: User = Depends(require("viewer"))):
        """How many distinct approvers a plan needs per risk level (the console shows this; it never computes it)."""
        from .actions import may_self_approve, single_admin
        return {"normal": 1, "high": rt.settings.required_approvals_high, "mode": rt.settings.approval_mode,
                "self_approval": may_self_approve(rt, user.role), **({"note": "single-admin mode: an admin approves their own plans"} if single_admin(rt) else {})}

    @app.get(f"{API}/deployments/{{slug}}/bootstrap")
    def bootstrap(slug: str, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        d = db.execute(text(f"SELECT id FROM deployments WHERE slug = :s AND {tscope.endpoint_clause(db)}"), {"s": slug}).first()
        if d is None:
            raise HTTPException(404, "deployment not found")
        rows = db.execute(text("SELECT bid, vm, vmid, mode, state, attempts, created_at, expires_at, reported_at, sealed_at FROM guest_bootstrap "
                               "WHERE deployment_id = :d ORDER BY vm, vmid, created_at DESC"), {"d": str(d.id)}).mappings().all()
        bids = [r["bid"] for r in rows]
        alarms: dict[str, tuple] = {}
        if bids:
            for a in db.execute(text("SELECT resource_id, count(*) AS n, max(at) AS last, bool_or(action = 'guest.bootstrap_failed_by_replay') AS failed FROM audit_events "
                                     "WHERE action IN ('guest.bootstrap_replay_alarm','guest.bootstrap_failed_by_replay') AND resource_id = ANY(:b) GROUP BY resource_id"),
                                {"b": bids}):
                alarms[a.resource_id] = (a.n, a.last, bool(a.failed))
        now = datetime.now(timezone.utc)
        dedicated = bool(rt.settings.guest_callback_dedicated)
        out, seen = [], set()
        for r in rows:   # newest record per VM first; older records of the same VM are history
            key = (r["vm"], r["vmid"])
            if key in seen:
                continue
            seen.add(key)
            limited = None if dedicated else guest_callback.LIMITER.is_limited(rt, "bid:" + r["bid"], guest_callback.PER_BID_LIMIT, guest_callback.PER_BID_WINDOW)
            out.append(bootstrap_view(r, alarms, now, limited))
        return {"deployment": slug, "vms": out}
