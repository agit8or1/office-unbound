"""Read-only HTTP API for the infrastructure model + setup probe. Every mutation of endpoints is a typed plan (POST /plans)."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from uuid import UUID

from fastapi import Body, Depends, FastAPI, HTTPException, Request
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, field_validator, model_validator
from sqlalchemy import text
from sqlalchemy.orm import Session

from .. import audit, endpoint_actions as ea
from ..auth import User, client_ip, get_db, require
from ..proxmox import ProxmoxError, fetch_peer_certificate, normalize_fingerprint
from ..providers.proxmox import EndpointScope, probe_connection
from ..tenancy import scope as tscope
from . import health, ledger
from .collector import RANGES, query_metrics

API = "/api/v1"
class AdminDiscover(BaseModel):
    """Temporary admin credentials for ONE read-only discovery. Held in memory only; wiped in `finally`; never stored, audited or returned."""
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    stage: Literal["discover"]
    base_url: str
    ca_pem: str | None = Field(default=None, max_length=100_000)
    fingerprint_sha256: str | None = None
    username: str | None = Field(default=None, max_length=70)
    password: SecretStr | None = None
    token_id: str | None = Field(default=None, pattern=ea.TOKEN_ID_RE)
    token_secret: SecretStr | None = None

    @field_validator("base_url")
    @classmethod
    def _u(cls, v):
        return ea._check_url(v)

    @field_validator("ca_pem")
    @classmethod
    def _c(cls, v):
        return ea._check_ca(v)

    @model_validator(mode="after")
    def _one(self):
        pw, tok = bool(self.username and self.password), bool(self.token_id and self.token_secret)
        if pw == tok:
            raise ValueError("supply either username+password or token_id+token_secret")
        return self


def _discover(rt, db, user, request, body: dict):
    from ..providers.base import ProviderError
    from ..providers.proxmox import provisioning as pp
    from ..providers.proxmox.admin import ProxmoxAdminClient
    try:
        a = AdminDiscover.model_validate(body)
    except ValidationError as e:
        raise HTTPException(422, [{"loc": list(x["loc"]), "msg": x["msg"]} for x in e.errors()]) from None
    client = None
    try:
        client = ProxmoxAdminClient(a.base_url, username=a.username, password=a.password.get_secret_value() if a.password else None,
                                    token_id=a.token_id, token_secret=a.token_secret.get_secret_value() if a.token_secret else None,
                                    ca_pem=a.ca_pem, fingerprint_sha256=a.fingerprint_sha256, allow_loopback=rt.settings.allow_loopback_endpoints)
        f = pp.collect_facts(client)   # GET-only
    except (ProxmoxError, ProviderError, ValueError) as e:
        audit.append(db, "setup.discover", actor_id=user.id, actor_name=user.username, ip=client_ip(request), resource="setup",
                     details={"base_url": a.base_url, "ok": False})
        db.commit()
        raise HTTPException(422, str(e)[:200]) from None
    finally:
        if client is not None:
            client.discard()
    audit.append(db, "setup.discover", actor_id=user.id, actor_name=user.username, ip=client_ip(request), resource="setup",
                 details={"base_url": a.base_url, "ok": True, "nodes": len(f.nodes)})  # no credential in the audit record
    db.commit()
    return {"ok": True, "version": f.version, "readonly": True,
            "nodes": [{"name": n, "status": st} for n, st in sorted(f.nodes.items())],
            "storages": [{"name": n, **v} for n, v in sorted(f.storages.items())],
            "pools": sorted(f.pools),
            "bridges": [{"name": n, "zone": z} for n, z in sorted(f.networks.items())],
            "templates": [{"vmid": v, "name": g["name"], "node": g["node"], "pool": g["pool"]} for v, g in sorted(f.guests.items()) if g["template"]],
            "guests": len(f.guests), "notes": f.notes}


def _active(db) -> str:
    return f"{_ACTIVE} AND {tscope.endpoint_clause(db)}"


_ACTIVE = "endpoint_id IN (SELECT id FROM endpoints WHERE detached_at IS NULL)"


class TlsStage(BaseModel):
    """Stage 'tls': certificate check only. No credential is accepted (extra=forbid) and none is sent."""
    model_config = ConfigDict(extra="forbid")
    stage: Literal["tls"]
    base_url: str
    ca_pem: str | None = Field(default=None, max_length=100_000)
    fingerprint_sha256: str | None = None

    @field_validator("base_url")
    @classmethod
    def _u(cls, v):
        return ea._check_url(v)

    @field_validator("ca_pem")
    @classmethod
    def _c(cls, v):
        return ea._check_ca(v)

    @field_validator("fingerprint_sha256")
    @classmethod
    def _f(cls, v):
        return normalize_fingerprint(v) if v is not None else v


class SetupProbe(ea.ScopeLists):
    """Connection details to test. Nothing is stored. Secrets are accepted but never returned or logged."""
    model_config = ConfigDict(extra="forbid")
    base_url: str
    token_id: str = Field(pattern=ea.TOKEN_ID_RE)
    token_secret: SecretStr
    ca_pem: str | None = Field(default=None, max_length=100_000)
    fingerprint_sha256: str | None = None
    provision_token_id: str | None = Field(default=None, pattern=ea.TOKEN_ID_RE)
    provision_token_secret: SecretStr | None = None

    @field_validator("token_secret", "provision_token_secret", mode="before")
    @classmethod
    def _s(cls, v):
        return ea.norm_secret(v)

    @field_validator("base_url")
    @classmethod
    def _u(cls, v):
        return ea._check_url(v)

    @field_validator("ca_pem")
    @classmethod
    def _c(cls, v):
        return ea._check_ca(v)

    @field_validator("fingerprint_sha256")
    @classmethod
    def _f(cls, v):
        return normalize_fingerprint(v) if v is not None else v

    @model_validator(mode="after")
    def _t(self):
        if bool(self.ca_pem) == bool(self.fingerprint_sha256):
            raise ValueError("TLS trust is required: provide exactly one of ca_pem or fingerprint_sha256")
        if (self.provision_token_id is None) != (self.provision_token_secret is None):
            raise ValueError("provision_token_id and provision_token_secret go together")
        return self


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


def _ser(r, kind: str | None, now: datetime, stale: int) -> dict:
    d = {k: (str(v) if k == "id" or k.endswith("_id") and v is not None else _iso(v)) for k, v in r._mapping.items()}
    if kind:
        d["health"] = health.with_health(r, kind, now, stale)
    return d


def endpoint_health(r, now: datetime, stale: int) -> dict:
    if r.detached_at is not None:
        return {"status": "detached", "reason": "endpoint was removed; history kept"}
    if not r.enabled:
        return {"status": "disabled", "reason": "endpoint is disabled"}
    if r.last_discovery_at is None:
        return {"status": "unknown", "reason": "not discovered yet"}
    if r.last_discovery_ok is False:
        return {"status": "critical", "reason": f"discovery failing: {r.last_error}"}
    if (now - r.last_discovery_at).total_seconds() > stale:
        return {"status": "unknown", "reason": "discovery is stale"}
    if r.last_discovery_ok and (r.warnings or r.last_metrics_error):
        return {"status": "warning", "reason": "partial data (see warnings)"}
    return {"status": "ok", "reason": None}


_EP_SQL = ("SELECT e.id, e.name, e.display_name, e.type, e.base_url, e.token_id, e.provision_token_id, e.fingerprint_sha256, "
           "(e.ca_pem IS NOT NULL) AS has_ca_bundle, e.allowed_pools, e.allowed_nodes, e.allowed_storage, e.allowed_networks, e.allowed_templates, "
           "e.allow_cicustom, e.protected_vmids, e.managed_vmids, e.defaults, e.enabled, e.detached_at, e.created_at, e.last_probe, e.last_probe_at, "
           "s.last_discovery_at, s.last_discovery_ok, s.last_error, s.warnings, s.counts, s.last_metrics_at, s.last_metrics_error "
           "FROM endpoints e LEFT JOIN infra_collect_state s ON s.endpoint_id = e.id")


def _ep_out(r, now, stale) -> dict:
    p = r.last_probe or {}
    return {
        "id": str(r.id), "name": r.name, "display_name": r.display_name, "type": r.type, "base_url": r.base_url,
        "trust": "fingerprint" if r.fingerprint_sha256 else "ca_bundle", "fingerprint_sha256": r.fingerprint_sha256,
        "credentials": {"inventory": {"present": r.detached_at is None, "token_id": r.token_id},
                        "provision": {"present": r.provision_token_id is not None, "token_id": r.provision_token_id}},
        "scope": {"allowed_pools": r.allowed_pools, "allowed_nodes": r.allowed_nodes, "allowed_storage": r.allowed_storage, "allowed_networks": r.allowed_networks, "managed_vmids": list(r.managed_vmids or []),
                  "allowed_templates": r.allowed_templates, "allow_cicustom": r.allow_cicustom, "protected_vmids": r.protected_vmids},
        "defaults": r.defaults or {},
        "enabled": r.enabled, "detached_at": _iso(r.detached_at), "created_at": _iso(r.created_at),
        "health": endpoint_health(r, now, stale),
        "last_probe": {"at": _iso(r.last_probe_at), "ok": p.get("ok"), "version": p.get("version"), "cluster_name": p.get("cluster_name"),
                       "verbs": {v["verb"]: v["ok"] for v in p.get("verbs", [])}} if p else None,
        "last_discovery": {"at": _iso(r.last_discovery_at), "ok": r.last_discovery_ok, "error": r.last_error,
                           "warnings": r.warnings or [], "counts": r.counts or {}},
        "last_metrics": {"at": _iso(r.last_metrics_at), "error": r.last_metrics_error},
    }


def _wizard_permissions(res) -> dict:
    """Frontend shape: {inventory, provision}: {ok, missing:[{path, privilege}], unnecessary:[...], fix_commands:[...]}."""
    def cap(verbs):
        miss = [{"path": m["path"], "privilege": pv} for v in verbs for m in v.missing for pv in m["privileges"]]
        miss = list({(m["path"], m["privilege"]): m for m in miss}.values())
        fixes = list(dict.fromkeys(m["fix"] for v in verbs for m in v.missing))
        unn = []
        for w in res.warnings:
            mt = re.match(r"warning: the provision token has privileges ICS does not use on (\S+): (.*?) \(", w)
            if mt and verbs and verbs[0].verb not in ("discover", "metrics"):
                unn += [{"path": mt.group(1), "privilege": x.strip()} for x in mt.group(2).split(",")]
        return {"ok": all(v.ok for v in verbs) if verbs else False, "missing": miss, "unnecessary": unn, "fix_commands": fixes}
    inv = [v for v in res.verbs if v.verb in ("discover", "metrics")]
    prov = [v for v in res.verbs if v.verb not in ("discover", "metrics")]
    return {"inventory": cap(inv), "provision": cap(prov)}


def guest_visibility(db) -> dict:
    """Which guests the read tokens can see, from the approved access policy (endpoint_policy.policy->>'monitor_cluster').
    cluster = every connected integration monitors the whole cluster read-only; own_only = at least one only sees Office Unbound's own
    pool(s) (listed in guest_visibility_limited); unknown = an integration was registered with a hand-made token (no policy to read);
    none = no integration. Never guessed from guest counts."""
    rows = db.execute(text("SELECT e.id, e.name, e.display_name, p.endpoint_id IS NOT NULL AS has_policy, "
                           "COALESCE((p.policy->>'monitor_cluster')::boolean, false) AS whole FROM endpoints e "
                           "LEFT JOIN endpoint_policy p ON p.endpoint_id = e.id "
                           f"WHERE e.detached_at IS NULL AND {tscope.clause(db, 'e.customer_id')} ORDER BY e.name")).all()
    limited = [{"endpoint_id": str(r.id), "name": r.display_name or r.name} for r in rows if r.has_policy and not r.whole]
    vis = "none" if not rows else "own_only" if limited else "cluster" if all(r.has_policy for r in rows) else "unknown"
    return {"guest_visibility": vis, "guest_visibility_limited": limited}


def mount(app: FastAPI) -> None:
    def stale(request: Request) -> int:
        return request.app.state.rt.settings.inventory_stale_seconds

    @app.get(f"{API}/endpoints")
    def list_endpoints(request: Request, include_detached: bool = False, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        rows = db.execute(text(_EP_SQL + f" WHERE {tscope.clause(db, 'e.customer_id')}" + ("" if include_detached else " AND e.detached_at IS NULL") + " ORDER BY e.name")).all()
        now = datetime.now(timezone.utc)
        return [_ep_out(r, now, stale(request)) for r in rows]

    @app.get(f"{API}/endpoints/{{endpoint_id}}")
    def get_endpoint(endpoint_id: UUID, request: Request, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        r = db.execute(text(_EP_SQL + f" WHERE e.id = :i AND {tscope.clause(db, 'e.customer_id')}"), {"i": str(endpoint_id)}).first()
        if r is None:
            raise HTTPException(404, "endpoint not found")
        return _ep_out(r, datetime.now(timezone.utc), stale(request))

    @app.get(f"{API}/infra/summary")
    def summary(request: Request, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        st = stale(request)
        h = health.summary(db, st)
        q = lambda sql: db.execute(text(sql)).first()  # noqa: E731
        g = q(f"SELECT count(*) FILTER (WHERE kind='vm') AS vms, count(*) FILTER (WHERE kind='lxc') AS lxc, "
              f"count(*) FILTER (WHERE status='running') AS running FROM infra_guests WHERE {_active(db)}")
        n = q(f"SELECT count(*) AS total, count(*) FILTER (WHERE status='online') AS online, count(*) FILTER (WHERE managed) AS managed, "
              f"COALESCE(sum(cpu_total) FILTER (WHERE managed), 0)::bigint AS cpu, COALESCE(sum(mem_total) FILTER (WHERE managed), 0)::bigint AS mem "
              f"FROM infra_nodes WHERE {_active(db)}")
        s = q(f"SELECT count(DISTINCT name) AS total, COALESCE(sum(total),0)::bigint AS bytes_total, COALESCE(sum(used),0)::bigint AS bytes_used "
              f"FROM infra_storage WHERE {_active(db)}")
        return {"health": {"status": h["status"], "reasons": h["reasons"]},
                "endpoints": {"active": h["endpoints_active"], "total": h["endpoints_total"]},
                "clusters": h["resources"]["cluster"],
                "nodes": {"total": n.total, "online": n.online, "managed": n.managed},
                "capacity": {"scope": "managed nodes only (token has Sys.Audit)", "cpu_total": n.cpu, "mem_total": n.mem},
                "guests": {"vms": g.vms, "containers": g.lxc, "running": g.running},
                "templates": q(f"SELECT count(*) AS c FROM infra_templates WHERE {_active(db)}").c,
                "storage": {"pools": s.total, "bytes_total": s.bytes_total, "bytes_used": s.bytes_used},
                "networks": q(f"SELECT count(*) AS c FROM infra_networks WHERE {_active(db)}").c,
                "new_resources": ledger.new_count(db, f"e.detached_at IS NULL AND {tscope.clause(db, 'e.customer_id')}"),
                **guest_visibility(db)}

    @app.get(f"{API}/infra/overview")
    def infra_overview(request: Request, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        from .overview import overview
        return {"clusters": overview(db, f"e.detached_at IS NULL AND {tscope.clause(db, 'e.customer_id')}", stale(request)),
                "stale_after_seconds": stale(request)}

    @app.get(f"{API}/endpoints/{{endpoint_id}}/access")
    def endpoint_access(endpoint_id: UUID, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        """Authorized vs discovered resources for one integration (inventory ledger + approved scope). Read-only."""
        ep = db.execute(text(f"SELECT * FROM endpoints e WHERE e.id = :i AND e.detached_at IS NULL AND {tscope.clause(db, 'e.customer_id')}"),
                        {"i": str(endpoint_id)}).first()
        if ep is None:
            raise HTTPException(404, "endpoint not found")
        return ledger.view(db, ep)

    @app.post(f"{API}/endpoints/{{endpoint_id}}/access/acknowledge")
    def endpoint_access_ack(endpoint_id: UUID, request: Request, body: dict = Body(default={}), user: User = Depends(require("operator")),
                            db: Session = Depends(get_db)):
        """Mark new / changed resources as reviewed. This NEVER grants access (authorization only changes through approved plans)."""
        ep = db.execute(text(f"SELECT * FROM endpoints e WHERE e.id = :i AND e.detached_at IS NULL AND {tscope.clause(db, 'e.customer_id')}"),
                        {"i": str(endpoint_id)}).first()
        if ep is None:
            raise HTTPException(404, "endpoint not found")
        keys = body.get("keys") if isinstance(body, dict) else None
        if keys is not None:
            if not isinstance(keys, list) or len(keys) > 2000 or not all(isinstance(k, list) and len(k) == 2 and k[0] in ("node", "guest", "storage", "network", "pool")
                                                                       and isinstance(k[1], str) and len(k[1]) <= 200 for k in keys):
                raise HTTPException(422, "keys must be a list of [kind, key] pairs")
            keys = [(k[0], k[1]) for k in keys]
        n = ledger.acknowledge(db, str(ep.id), keys)
        audit.append(db, "inventory.acknowledged", actor_id=user.id, actor_name=user.username, ip=client_ip(request), resource="endpoint",
                     resource_id=str(ep.id), details={"count": n, "all": keys is None})
        db.commit()
        return {"acknowledged": n}

    def _list(request: Request, db: Session, table: str, kind: str | None, where: list[str], params: dict, order: str, limit: int):
        sql = f"SELECT * FROM {table} WHERE {_active(db)}" + "".join(f" AND {w}" for w in where) + f" ORDER BY {order} LIMIT :lim"
        rows = db.execute(text(sql), {**params, "lim": max(1, min(limit, 2000))}).all()
        now, st = datetime.now(timezone.utc), stale(request)
        return [_ser(r, kind, now, st) for r in rows]

    @app.get(f"{API}/infra/clusters")
    def clusters(request: Request, endpoint: UUID | None = None, limit: int = 500, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        w, p = ([ "endpoint_id = :e"], {"e": str(endpoint)}) if endpoint else ([], {})
        return _list(request, db, "infra_clusters", "infra_clusters", w, p, "name", limit)

    @app.get(f"{API}/infra/nodes")
    def nodes(request: Request, endpoint: UUID | None = None, limit: int = 500, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        w, p = (["endpoint_id = :e"], {"e": str(endpoint)}) if endpoint else ([], {})
        return _list(request, db, "infra_nodes", "infra_nodes", w, p, "name", limit)

    @app.get(f"{API}/infra/storage")
    def storage(request: Request, endpoint: UUID | None = None, node: str | None = None, limit: int = 1000,
                user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        w, p = [], {}
        if endpoint:
            w.append("endpoint_id = :e"); p["e"] = str(endpoint)  # noqa: E702
        if node:
            w.append("node = :n"); p["n"] = node  # noqa: E702
        return _list(request, db, "infra_storage", "infra_storage", w, p, "name, node", limit)

    @app.get(f"{API}/infra/networks")
    def networks(request: Request, endpoint: UUID | None = None, node: str | None = None, limit: int = 1000,
                 user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        w, p = [], {}
        if endpoint:
            w.append("endpoint_id = :e"); p["e"] = str(endpoint)  # noqa: E702
        if node:
            w.append("(node = :n OR node = '')"); p["n"] = node  # noqa: E702
        return _list(request, db, "infra_networks", None, w, p, "kind, name, node", limit)

    @app.get(f"{API}/infra/guests")
    def guests(request: Request, endpoint: UUID | None = None, node: str | None = None, deployment: str | None = None,
               kind: str | None = None, status: str | None = None, limit: int = 1000,
               user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        w, p = [], {}
        for col, val, key in (("endpoint_id", str(endpoint) if endpoint else None, "e"), ("node", node, "n"),
                              ("ou_deployment_id", deployment, "d"), ("kind", kind, "k"), ("status", status, "s")):
            if val:
                w.append(f"{col} = :{key}"); p[key] = val  # noqa: E702
        return _list(request, db, "infra_guests", "infra_guests", w, p, "vmid", limit)

    @app.get(f"{API}/infra/templates")
    def templates(request: Request, endpoint: UUID | None = None, limit: int = 500, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        w, p = (["endpoint_id = :e"], {"e": str(endpoint)}) if endpoint else ([], {})
        return _list(request, db, "infra_templates", None, w, p, "vmid", limit)

    @app.get(f"{API}/infra/metrics")
    def metrics(scope: str, id: UUID, metric: str, range: str = "1h", user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        if scope not in ("node", "guest", "storage"):
            raise HTTPException(422, "scope must be node, guest or storage")
        if range not in RANGES:
            raise HTTPException(422, "range must be one of " + ", ".join(RANGES))
        if not re.fullmatch(r"[a-z0-9_]{1,40}", metric):
            raise HTTPException(422, "invalid metric name")
        table = {"node": "infra_nodes", "guest": "infra_guests", "storage": "infra_storage"}[scope]
        if user.customer_ids is not None and not db.execute(text(f"SELECT 1 FROM {table} WHERE id = :i AND {tscope.endpoint_clause(db)}"), {"i": str(id)}).first():
            raise HTTPException(404, "resource not found")
        return query_metrics(db, scope, str(id), metric, range)

    # ---- setup wizard ----
    @app.post(f"{API}/setup/probe")
    def setup_probe(body: dict, request: Request, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
        """Dry probe: validates TLS trust + credentials and reports effective permissions per verb. Persists nothing, never echoes secrets."""
        rt = request.app.state.rt
        if body.get("stage") == "tls":
            try:
                t = TlsStage.model_validate(body)
            except ValidationError as e:
                raise HTTPException(422, [{"loc": list(x["loc"]), "msg": x["msg"]} for x in e.errors()]) from None
            out = fetch_peer_certificate(t.base_url, ca_pem=t.ca_pem, fingerprint_sha256=t.fingerprint_sha256,
                                         allow_loopback=rt.settings.allow_loopback_endpoints)
            audit.append(db, "setup.probe", actor_id=user.id, actor_name=user.username, ip=client_ip(request), resource="setup",
                         details={"stage": "tls", "base_url": t.base_url, "ok": out["ok"]})
            db.commit()
            return {"tls": out}
        if body.get("stage") == "discover":
            return _discover(rt, db, user, request, body)
        try:
            p = SetupProbe.model_validate(body)
        except ValidationError as e:
            raise HTTPException(422, [{"loc": list(x["loc"]), "msg": x["msg"]} for x in e.errors()]) from None
        scope = EndpointScope(tuple(p.allowed_pools or ()), tuple(p.allowed_storage or ()), tuple(p.allowed_networks or ()),
                              tuple(p.allowed_templates or ()), bool(p.allow_cicustom), (), tuple(p.allowed_nodes or ()))
        try:
            res = probe_connection(rt, base_url=p.base_url, token_id=p.token_id, token_secret=p.token_secret.get_secret_value(),
                                   ca_pem=p.ca_pem, fingerprint_sha256=p.fingerprint_sha256, provision_token_id=p.provision_token_id,
                                   provision_token_secret=p.provision_token_secret.get_secret_value() if p.provision_token_secret else None,
                                   scope=scope, discovery=True)
        except (ProxmoxError, ValueError) as e:
            raise HTTPException(422, str(e)[:200]) from None
        out = ea.probe_dict(res)
        out["permissions"] = _wizard_permissions(res)
        out["tls"] = {**res.tls, "verified_by": "fingerprint" if res.tls.get("trust") == "fingerprint" else "ca"}
        if res.errors:
            out["error"] = res.errors[0]
        out["fixes"] = [m["fix"] for v in res.verbs for m in v.missing]
        out["fixes"] = list(dict.fromkeys(out["fixes"]))
        audit.append(db, "setup.probe", actor_id=user.id, actor_name=user.username, ip=client_ip(request), resource="setup",
                     details={"base_url": p.base_url, "token_id": p.token_id, "ok": res.ok, "tls_ok": res.tls.get("ok"),
                              "trust": res.tls.get("trust")})
        db.commit()
        return out

    @app.get(f"{API}/setup/state")
    def setup_state(user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        r = db.execute(text(
            "SELECT count(*) AS n, count(*) FILTER (WHERE s.last_discovery_ok) AS discovered, "
            "count(*) FILTER (WHERE cardinality(e.allowed_pools) > 0) AS defaults, "
            "count(*) FILTER (WHERE e.provision_token_id IS NOT NULL) AS prov, "
            "count(*) FILTER (WHERE e.defaults <> '{}'::jsonb) AS saved_defaults "
            f"FROM endpoints e LEFT JOIN infra_collect_state s ON s.endpoint_id = e.id WHERE e.detached_at IS NULL AND {tscope.clause(db, 'e.customer_id')}")).first()
        step = "register_endpoint" if r.n == 0 else "discover" if r.discovered == 0 else "save_defaults" if r.defaults == 0 else "done"
        return {"has_endpoint": r.n > 0, "has_endpoints": r.n > 0, "endpoints": r.n, "discovery_done": r.discovered > 0, "defaults_saved": r.defaults > 0 or r.saved_defaults > 0,
                "provision_configured": r.prov > 0, "next_step": step}
