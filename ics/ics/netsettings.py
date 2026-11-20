"""Settings -> Network & domains (owner 2026-11-20: "these should all be listed in settings ... and run the checks from the ui").

* settings: the installation's public address (typed action settings.network.update; stored in system_settings).
* requirements: for every deployment that is not destroyed, from its APPLIED plan: the public DNS records it needs and the port forwards the
  owner's router must make (80/443 to the gateway = the edge VM; mail ports to the mail VM until the gateway forwards them, ADR-0018 G5).
* checks (read-only): DNS answers compared with what is required, and each forwarded port tested on the public address with a check that proves
  WHICH machine answered (TLS certificate of this deployment for the name, SMTP banner with the mail host, HTTP redirect to the name). Results
  say honestly what they prove: a test from inside the network needs the router to reach its own public address (hairpin NAT)."""
from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import time

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import text
from sqlalchemy.orm import Session

from .deploy import appaccess

KEY = "network"
TIMEOUT = 4.0
MAIL_PORTS = {25: "incoming mail (SMTP)", 465: "sending from mail apps (SMTPS)", 587: "sending from mail apps (submission)", 993: "mail apps (IMAPS)"}
WEB_PORTS = {80: "web (redirects to HTTPS; certificate validation)", 443: "web: portal, sign-in, files, documents, webmail, mail apps over HTTPS"}


class NetworkSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    public_ipv4: str | None = Field(default=None, description="the installation's public IPv4 address (the router forwards to the gateway)")

    @field_validator("public_ipv4")
    @classmethod
    def _ip(cls, v):
        if v in (None, ""):
            return None
        a = ipaddress.ip_address(v)
        if a.version != 4 or a.is_private or a.is_loopback or a.is_multicast or a.is_unspecified or a.is_reserved or a.is_link_local:
            raise ValueError("a public IPv4 address (not a private, loopback or reserved one)")
        return str(a)


def get(db) -> NetworkSettings:
    row = db.execute(text("SELECT value FROM system_settings WHERE key = :k"), {"k": KEY}).first()
    return NetworkSettings.model_validate(row.value) if row else NetworkSettings()


def put(db, s: NetworkSettings, by: str) -> None:
    db.execute(text("INSERT INTO system_settings (key, value, updated_at, updated_by) VALUES (:k, CAST(:v AS jsonb), now(), :b) "
                    "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now(), updated_by = EXCLUDED.updated_by"),
               {"k": KEY, "v": json.dumps(s.model_dump(mode="json")), "b": by[:120]})


def _deployments(db) -> list:
    return db.execute(text("SELECT * FROM deployments WHERE status NOT IN ('destroyed', 'destroying') ORDER BY slug")).all()


def requirements_for(plan: dict, addresses: dict[str, str], public_ipv4: str | None) -> dict:
    """Pure: the DNS records and port forwards one deployment needs."""
    vms = {v["name"]: v for v in plan.get("vms", [])}
    edge = next((v["name"] for v in plan.get("vms", []) if "edge" in (v.get("components") or []) and not v.get("tenant")), None) \
        or next((v["name"] for v in plan.get("vms", []) if "edge" in (v.get("components") or [])), None)
    want = public_ipv4 or "<public IPv4>"
    records = []
    for r in sorted(plan.get("dns", []), key=lambda r: (r["name"], r["type"])):
        if r["type"] == "A" and str(r["value"]).startswith("vm:"):
            records.append({"name": r["name"], "type": "A", "value": want, "component": r.get("component"), "required": True,
                            "purpose": "points at the public address; the gateway routes it"})
        elif r["type"] == "CNAME":
            records.append({"name": r["name"], "type": "CNAME", "value": r["value"], "component": r.get("component"), "required": True,
                            "purpose": "alias"})
        else:   # MX / TXT: only once external mail is enabled (Stage 3: public IP, SPF/DKIM/DMARC)
            records.append({"name": r["name"], "type": r["type"], "value": r["value"], "component": r.get("component"), "required": False,
                            "purpose": "for external mail (later): leave the current record until external mail is enabled"})
    ports: dict[tuple, dict] = {}
    for f in plan.get("firewall", []):
        if f.get("from") != "any":
            continue
        port, proto = int(f["port"]), f["proto"]
        target = edge if (port in WEB_PORTS and edge) else f["vm"]
        comp = str(f.get("purpose", "")).split(":")[0]
        k = (port, proto)
        if k in ports:
            continue
        ports[k] = {"port": port, "port_end": f.get("port_end"), "proto": proto, "vm": target, "address": addresses.get(target),
                    "component": comp, "purpose": WEB_PORTS.get(port) or MAIL_PORTS.get(port) or f.get("purpose"),
                    "when": "now" if port in WEB_PORTS else ("when external mail is enabled" if port in MAIL_PORTS else "when this service is used")}
    names = {"web": next((r["name"] for r in plan.get("dns", []) if r["type"] == "A" and r.get("component") == "portal"),
                         next((r["name"] for r in plan.get("dns", []) if r["type"] == "A"), None)),
             "mail": next((r["name"] for r in plan.get("dns", []) if r["type"] == "A" and r.get("component") == "groupware"), None)}
    return {"domain": plan["input"]["domain"], "records": records, "ports": [ports[k] for k in sorted(ports)], "probe_names": names,
            "edge_vm": edge, "edge_address": addresses.get(edge) if edge else None, "known_vms": sorted(vms)}


def overview(db) -> dict:
    s = get(db)
    out = []
    for d in _deployments(db):
        plan = appaccess._applied_plan(db, d)
        if plan is None:
            out.append({"deployment": d.slug, "status": d.status, "ready": False})
            continue
        out.append({"deployment": d.slug, "status": d.status, "ready": True, **requirements_for(plan, appaccess._addresses(db, d), s.public_ipv4)})
    return {"settings": s.model_dump(), "deployments": out,
            "notes": ["Checks run from this server. A port test reaches your public address from inside your network: it needs the router to "
                      "support that (hairpin NAT). 'No answer' can mean the forward is missing OR the router does not hairpin; test from outside "
                      "to be sure. Port 80 is proven from the internet when a public certificate is issued."]}


# ---------------------------------------------------------------- checks (read-only)
def _resolver():
    import dns.resolver
    r = dns.resolver.Resolver()
    r.lifetime = TIMEOUT
    return r


def check_record(rec: dict, public_ipv4: str | None, resolver=None) -> dict:
    import dns.exception
    import dns.resolver
    r = resolver or _resolver()
    try:
        ans = r.resolve(rec["name"], rec["type"])
        seen = sorted(x.to_text().rstrip(".").strip('"') for x in ans)
    except dns.resolver.NXDOMAIN:
        return {**rec, "status": "missing", "seen": [], "detail": "the name does not exist in public DNS"}
    except dns.resolver.NoAnswer:
        return {**rec, "status": "missing", "seen": [], "detail": f"no {rec['type']} record"}
    except dns.exception.DNSException as e:
        return {**rec, "status": "error", "seen": [], "detail": f"lookup failed: {type(e).__name__}"}
    want = (public_ipv4 if rec["type"] == "A" else rec["value"].rstrip(".")) or ""
    if rec["type"] == "A" and not public_ipv4:
        return {**rec, "status": "unknown", "seen": seen, "detail": "set the public IPv4 address first"}
    ok = want in seen if rec["type"] in ("A", "CNAME") else want in seen
    if ok:
        return {**rec, "status": "ok", "seen": seen, "detail": "matches"}
    return {**rec, "status": "wrong" if rec["required"] else "differs", "seen": seen,
            "detail": f"expected {want}" + ("" if rec["required"] else " (only needed for external mail)")}


def _tls_names(ip: str, port: int, name: str, ca_pem: str | None) -> tuple[str, str]:
    """Connect, verify the certificate for `name` against the system store + this deployment's CA. Never skips verification."""
    ctx = ssl.create_default_context()
    if ca_pem:
        ctx.load_verify_locations(cadata=ca_pem)
    with socket.create_connection((ip, port), timeout=TIMEOUT) as raw:
        try:
            with ctx.wrap_socket(raw, server_hostname=name) as t:
                issuer = dict(x[0] for x in t.getpeercert().get("issuer", ()))
                return "ok", f"this deployment's gateway answered for {name} (certificate issued by {issuer.get('organizationName') or issuer.get('commonName', '?')})"
        except ssl.SSLCertVerificationError as e:
            return "wrong", f"something answered, but not with a certificate for {name} that this deployment trusts ({e.verify_message}): is the forward pointing at the right machine?"


def _smtp_banner(ip: str, port: int, host: str) -> tuple[str, str]:
    with socket.create_connection((ip, port), timeout=TIMEOUT) as s:
        s.settimeout(TIMEOUT)
        line = s.recv(512).decode("ascii", "replace").strip()
        s.sendall(b"QUIT\r\n")
    if line.startswith("220") and host in line:
        return "ok", f"the mail server of this deployment answered ({line[:60]})"
    return "wrong", f"something answered, but not this deployment's mail server: {line[:80]!r}"


def _http_redirect(ip: str, name: str, port: int = 80) -> tuple[str, str]:
    with socket.create_connection((ip, port), timeout=TIMEOUT) as s:
        s.settimeout(TIMEOUT)
        s.sendall(f"GET / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\nUser-Agent: office-unbound-check\r\n\r\n".encode())
        head = s.recv(2048).decode("latin-1", "replace")
    status = head.split("\r\n", 1)[0]
    loc = next((x.split(":", 1)[1].strip() for x in head.split("\r\n") if x.lower().startswith("location:")), "")
    if status.split(" ")[1:2] and status.split(" ")[1].startswith("30") and loc.startswith(f"https://{name}"):
        return "ok", f"the gateway answered and redirects to https://{name}"
    return "wrong", f"something answered ({status[:40]}), but not this deployment's gateway"


def check_port(p: dict, public_ipv4: str | None, names: dict, ca_pem: str | None) -> dict:
    if not public_ipv4:
        return {**p, "status": "unknown", "detail": "set the public IPv4 address first"}
    if p["proto"] != "tcp":
        return {**p, "status": "not_testable", "detail": "UDP cannot be tested by connecting; it is verified when the service is used"}
    port, web, mail = p["port"], names.get("web"), names.get("mail")
    t0 = time.monotonic()
    try:
        if port == 443 and web:
            st, msg = _tls_names(public_ipv4, 443, web, ca_pem)
        elif port == 80 and web:
            st, msg = _http_redirect(public_ipv4, web)
        elif port in (25, 587) and mail:
            st, msg = _smtp_banner(public_ipv4, port, mail)
        elif port in (465, 993) and mail:
            st, msg = _tls_names(public_ipv4, port, mail, ca_pem)
        else:
            with socket.create_connection((public_ipv4, port), timeout=TIMEOUT):
                st, msg = "open", "something accepts connections (which machine is not proven for this port)"
    except (TimeoutError, socket.timeout):
        st, msg = "no_answer", "no answer: the forward is missing, or your router cannot reach its own public address from inside (hairpin)"
    except ConnectionRefusedError:
        st, msg = "refused", "refused: the public address answers but nothing accepts this port (forward missing or service down)"
    except OSError as e:
        st, msg = "error", f"could not test: {e.strerror or type(e).__name__}"
    return {**p, "status": st, "detail": msg, "ms": int((time.monotonic() - t0) * 1000), "tested_from": "inside (this server)"}


def run_checks(rt, db, slug: str | None = None) -> dict:
    """DNS + port checks for one or all deployments. Read-only; contacts only the public DNS and the configured public address."""
    ov = overview(db)
    pub = ov["settings"]["public_ipv4"]
    res = []
    for d in ov["deployments"]:
        if not d.get("ready") or (slug and d["deployment"] != slug):
            continue
        dep = db.execute(text("SELECT id FROM deployments WHERE slug = :s"), {"s": d["deployment"]}).first()
        ca = appaccess._secret_if_present(rt, db, str(dep.id), "deployment-ca")   # read only: never creates a CA
        ca_pem = json.loads(ca)["cert"] if ca else None
        r = _resolver()
        res.append({"deployment": d["deployment"], "records": [check_record(x, pub, r) for x in d["records"]],
                    "ports": [check_port(x, pub, d["probe_names"], ca_pem) for x in d["ports"]]})
    return {"public_ipv4": pub, "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "results": res, "notes": ov["notes"]}


# ---------------------------------------------------------------- typed action + API
def exec_update(rt, db, m: NetworkSettings, plan, known) -> dict:
    """settings.network.update (plan -> approval -> job): replaces the network settings; the old value goes into the audit record."""
    from . import audit
    old = get(db)
    put(db, m, f"plan:{plan.id}")
    audit.append(db, "settings.network_updated", actor_name="worker", resource="settings", resource_id=KEY,
                 details={"old": old.model_dump(), "new": m.model_dump(), "requested_by": str(plan.requested_by), "plan_id": str(plan.id)})
    return {"settings": m.model_dump()}


_RUNNING = {"busy": False}


class CheckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    deployment: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9-]{1,30}$")


def register_routes(app, rt) -> None:
    from . import audit
    from .auth import User, client_ip, get_db, require

    @app.get("/api/v1/settings/network")
    def network_overview(user: User = Depends(require("admin")), db: Session = Depends(get_db)):
        """Required DNS records and port forwards per deployment, and the network settings. Read-only, no secret."""
        return overview(db)

    @app.post("/api/v1/settings/network/check")
    def network_check(body: CheckIn, request: Request, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
        """Run the DNS and port checks now (read-only; contacts public DNS and the configured public address only). One run at a time."""
        if _RUNNING["busy"]:
            raise HTTPException(409, "a check is already running")
        _RUNNING["busy"] = True
        try:
            out = run_checks(rt, db, body.deployment)
        finally:
            _RUNNING["busy"] = False
        summary = {d["deployment"]: {"records_ok": sum(r["status"] == "ok" for r in d["records"]), "records": len(d["records"]),
                                     "ports_ok": sum(p["status"] == "ok" for p in d["ports"]), "ports": len(d["ports"])} for d in out["results"]}
        audit.append(db, "settings.network_checked", actor_id=user.id, actor_name=user.username, ip=client_ip(request), details={"summary": summary})
        db.commit()
        return out
