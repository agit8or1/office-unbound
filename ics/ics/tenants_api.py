"""ADR-0021 step 1: tenants in the console (read side) and the tenant DNS checker.

A tenant is a customer row; its deployments are those whose `customer_id` names the customer's slug (migration 0012b; a legacy value
that is the customer's id still matches). Every route checks the operator's customer scope: an out-of-scope tenant answers 404.

The DNS checker is read-only and checks ONLY names derived from the deployment's applied plan and the installation's public address
(never a caller-supplied name). It reuses Network & domains' expected records (netsettings.requirements_for) and lookups
(netsettings.check_record), and adds what a domain owner also needs: DMARC, the client-setup SRV records, CAA and reverse DNS. Results
are kept for 24 hours per deployment, so the page opens without new queries; `refresh=true` checks again.

Public view (authorized-endpoints.md, 2026-11-25): the zone's records are asked of the domain's own authoritative servers, found from
its NS records through this server's resolver (walking up from the domain). Only A/AAAA/CNAME/MX/TXT/SRV/CAA for names inside that
zone go to them; discovery uses NS/A/AAAA on the local resolver; PTR always stays local. No zone transfers, no ANY. When no
authoritative server answers, the row is checked with the local resolver and says so."""
from __future__ import annotations

import time
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from .auth import User, get_db, require
from .tenancy import scope as tscope

API = "/api/v1"
CACHE_SECONDS = 24 * 3600
_cache: dict[str, tuple[float, dict]] = {}
HOOKS = {"resolver": None, "authoritative": None}   # tests replace the local resolver and the authoritative-resolver factory
AUTH_TYPES = frozenset({"A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA"})   # the only types sent to a domain's own servers
MAX_NS = 4
FALLBACK_NOTE = "The domain's own name servers did not answer, so this was checked with this server's resolver (it may show older, cached data)."


def _iso(v):
    return v.isoformat() if hasattr(v, "isoformat") else (str(v) if isinstance(v, UUID) else v)


def _deployments(db, c) -> list:
    return db.execute(text("SELECT * FROM deployments WHERE (customer_id = :s OR customer_id = :i) AND status <> 'destroyed' ORDER BY slug"),
                      {"s": c.slug, "i": str(c.id)}).all()


def _tenant(db, c, detail: bool = False) -> dict:
    from .deploy import appaccess
    deps = []
    for d in _deployments(db, c):
        plan = appaccess._applied_plan(db, d)
        comps = sorted({x for v in (plan or {}).get("vms", []) for x in (v.get("components") or [])})
        deps.append({"slug": d.slug, "status": d.status, "domain": (plan or {}).get("input", {}).get("domain"), "components": comps})
    out = {"id": str(c.id), "slug": c.slug, "name": c.name, "provisioning_mode": c.provisioning_mode, "msp_owned": c.msp_owned,
           "disabled": c.disabled_at is not None, "deployments": deps,
           "domains": sorted({x["domain"] for x in deps if x["domain"]})}
    if detail:
        out.update({"contact_name": c.contact_name, "contact_email": c.contact_email, "extra_approvals": c.extra_approvals,
                    "created_at": _iso(c.created_at)})
    return out


def _customer(db, user, tenant_id: UUID):
    tscope.assert_customer(user, tenant_id, "tenant")
    c = db.execute(text("SELECT * FROM customers WHERE id = :i"), {"i": str(tenant_id)}).first()
    if c is None:
        raise HTTPException(404, "tenant not found")
    return c


# ---------------------------------------------------------------- DNS checker
SRV = (("_autodiscover._tcp", 443, "Outlook finds the mail server by itself"),
       ("_imaps._tcp", 993, "mail apps find incoming mail (IMAP)"),
       ("_submission._tcp", 587, "mail apps find outgoing mail (SMTP)"),
       ("_caldavs._tcp", 443, "calendar apps find the calendar server"),
       ("_carddavs._tcp", 443, "contacts apps find the address book server"))


def _lookup(r, name: str, rtype: str) -> tuple[str, list[str]]:
    """('ok', values) | ('missing', []) | ('error', [reason])."""
    import dns.exception
    import dns.resolver
    try:
        vals = [x.to_text().rstrip(".") for x in r.resolve(name, rtype)]
        return "ok", sorted(v[1:-1] if len(v) > 1 and v[0] == v[-1] == '"' else v for v in vals)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return "missing", []
    except dns.exception.DNSException as e:
        return "error", [type(e).__name__]


def _auth_resolver(addresses: list[str]):
    """A dnspython resolver that asks only the given (authoritative) addresses, with the standard timeout."""
    import dns.resolver
    from . import netsettings
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = list(addresses)
    r.lifetime = netsettings.TIMEOUT
    r.timeout = netsettings.TIMEOUT
    return r


def find_authoritative(dom: str, local) -> tuple[str | None, list[str], list[str]]:
    """(zone, NS names, their addresses), walking up from the plan's domain with NS queries on the local resolver.
    Stops before the top-level label: a TLD's servers are not the domain's. Addresses come from A/AAAA on the local resolver."""
    labels = dom.rstrip(".").split(".")
    for i in range(len(labels) - 1):
        name = ".".join(labels[i:])
        st, ns = _lookup(local, name, "NS")
        if st == "ok" and ns:
            names = sorted({n.rstrip(".").lower() for n in ns})[:MAX_NS]
            v4, v6 = [], []
            for n in names:
                for rtype, acc in (("A", v4), ("AAAA", v6)):
                    s2, ips = _lookup(local, n, rtype)
                    if s2 == "ok":
                        acc.extend(ip for ip in ips if ip not in acc)
            return name, names, v4 + v6      # IPv4 first: the ICS host may have no IPv6 route
        if st == "error":
            return None, [], []
    return None, [], []


class _ZoneResolver:
    """Sends in-zone A/AAAA/CNAME/MX/TXT/SRV/CAA queries to the zone's own servers, everything else to the local resolver.
    If the authoritative servers fail (timeout, refused, no server), it stops asking them and records the names checked locally."""

    def __init__(self, zone: str | None, auth, local):
        self.zone, self.auth, self.local = zone, auth, local
        self.dead = auth is None
        self.fell_back: set[str] = set()

    def in_zone(self, name: str) -> bool:
        n = name.rstrip(".").lower()
        return bool(self.zone) and (n == self.zone or n.endswith("." + self.zone))

    def resolve(self, name, rtype):
        import dns.exception
        import dns.resolver
        if rtype not in AUTH_TYPES or not self.zone or not self.in_zone(name):
            return self.local.resolve(name, rtype)
        if not self.dead:
            try:
                return self.auth.resolve(name, rtype)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                raise
            except dns.exception.DNSException:
                self.dead = True
        self.fell_back.add(name.rstrip(".").lower())
        return self.local.resolve(name, rtype)


def _row(group, name, rtype, expected, status, found, why, how="", required=True):
    return {"group": group, "name": name, "type": rtype, "expected": expected, "status": status, "found": found, "why": why,
            "how": how, "required": required}


def dns_rows(plan: dict, public_ipv4: str | None, local, make_auth=None, info: dict | None = None) -> list[dict]:
    """Pure apart from the resolvers: every record a deployment's domain needs, checked. The zone's records go to the domain's
    authoritative servers (`make_auth(addresses)` builds that resolver); PTR and discovery use `local`. `info` receives the zone and
    the authoritative server names used."""
    from . import netsettings
    dom = plan["input"]["domain"]
    zone, servers, addrs = find_authoritative(dom, local)
    auth = (make_auth or _auth_resolver)(addrs) if addrs else None
    resolver = _ZoneResolver(zone or dom.lower(), auth, local)
    if info is not None:
        info.update({"zone": zone, "servers": servers if auth is not None else []})
    req = netsettings.requirements_for(plan, {}, public_ipv4)
    rows: list[dict] = []
    mail_host = next((r["name"] for r in req["records"] if r["type"] == "A" and r.get("component") == "groupware"), None)
    for rec in req["records"]:
        if rec["name"].startswith("autodiscover."):
            group = "Client setup"
        elif rec["type"] in ("MX", "TXT") or rec.get("component") == "groupware":
            group = "Mail"
        else:
            group = "Web names"
        c = netsettings.check_record(rec, public_ipv4, resolver=resolver)
        if rec["type"] == "CNAME" and c["status"] != "ok" and public_ipv4:
            # an A record straight to the public address reaches the same gateway: as good as the alias
            ast, afound = _lookup(resolver, rec["name"], "A")
            if ast == "ok" and public_ipv4 in afound:
                c = {**c, "status": "ok", "seen": afound, "detail": f"an A record to your public address {public_ipv4} instead of the alias: works the same"}
        st = {"ok": "ok", "missing": "missing", "wrong": "differs", "differs": "differs", "error": "unknown", "unknown": "unknown"}.get(c["status"], c["status"])
        why = rec.get("purpose") or ""
        if rec["type"] == "MX":
            why = "delivers mail for the domain to this deployment"
        elif rec["type"] == "TXT" and str(rec["value"]).lower().startswith("v=spf1"):
            why = "SPF: says which servers may send mail for the domain"
        rows.append(_row(group, rec["name"], rec["type"], rec["value"], st, c.get("seen", []), why,
                         c.get("detail", ""), required=rec["required"]))
    if mail_host:
        st, found = _lookup(resolver, f"_dmarc.{dom}", "TXT")
        dm = [x for x in found if x.lower().startswith("v=dmarc1")] if st == "ok" else []
        rows.append(_row("Mail", f"_dmarc.{dom}", "TXT", f"v=DMARC1; p=quarantine; rua=mailto:postmaster@{dom}",
                         "ok" if dm else ("unknown" if st == "error" else "missing"), dm or found,
                         "DMARC: tells receivers what to do with mail that fails SPF (start with p=none to observe)", required=False))
        rows.append(_row("Mail", f"<selector>._domainkey.{dom}", "TXT", "-", "not_available", [],
                         "DKIM: this deployment does not sign outgoing mail yet, so there is no key to publish (planned with internet mail)",
                         required=False))
        for svc, port, why in SRV:
            want = f"0 1 {port} {mail_host}"
            st, found = _lookup(resolver, f"{svc}.{dom}", "SRV")
            ok = any(x.split()[-2:] == [str(port), mail_host] for x in found)
            rows.append(_row("Client setup", f"{svc}.{dom}", "SRV", want, "ok" if ok else ("unknown" if st == "error" else ("differs" if found else "missing")),
                             found, why + " (optional)", required=False))
    # CAA: the closest name up the tree that has CAA records decides; none at all lets any authority issue
    labels, caa, at = dom.split("."), [], None
    for i in range(len(labels) - 1):
        n = ".".join(labels[i:])
        st, found = _lookup(resolver, n, "CAA")
        if st == "ok" and found:
            caa, at = found, n
            break
    caa_ok = not caa or any(" issue " in f" {x} " and "letsencrypt.org" in x for x in caa)
    rows.append(_row("Certificates", at or dom, "CAA", "none, or one that allows letsencrypt.org", "ok" if caa_ok else "differs", caa,
                     "Let's Encrypt may issue the public certificate only if CAA allows it", required=True))
    if public_ipv4 and mail_host:
        import dns.reversename
        st, found = _lookup(local, dns.reversename.from_address(public_ipv4).to_text().rstrip("."), "PTR")   # PTR stays local
        rows.append(_row("Mail", public_ipv4, "PTR", mail_host, "ok" if mail_host in found else ("unknown" if st == "error" else ("differs" if found else "missing")),
                         found, "reverse DNS of the public address: receivers trust mail more when it names the mail server. Set by whoever "
                         "provides the address (your internet provider), not in your DNS zone", required=False))
    for r in rows:
        if r["type"] != "PTR" and r["name"].lower() in resolver.fell_back:
            r["how"] = (r["how"] + " " if r["how"] else "") + FALLBACK_NOTE
    if info is not None:
        info["servers_answered"] = auth is not None and not resolver.dead
    return rows


def check_deployment(db, d, refresh: bool = False) -> dict:
    from . import netsettings
    from .deploy import appaccess
    hit = _cache.get(d.slug)
    if hit and not refresh and time.time() - hit[0] < CACHE_SECONDS:
        return {**hit[1], "cached": True}
    plan = appaccess._applied_plan(db, d)
    if plan is None:
        return {"deployment": d.slug, "domain": None, "rows": [], "checked_at": None, "available": False,
                "reason": "the deployment has not been created yet"}
    dom = plan["input"]["domain"]
    if not netsettings.publishable(dom):
        return {"deployment": d.slug, "domain": dom, "rows": [], "checked_at": None, "available": False,
                "reason": f"{dom} is a reserved test name: it never has public DNS records"}
    s = netsettings.get(db)
    info: dict = {}
    rows = dns_rows(plan, s.public_ipv4, HOOKS["resolver"] or netsettings._resolver(), HOOKS["authoritative"], info)
    if info.get("servers") and info.get("servers_answered"):
        note = (f"Checked with the domain's own name servers ({', '.join(info['servers'])}), so changes show at once. Reverse DNS "
                "is checked with this server's resolver.")
    elif info.get("servers"):
        note = ("The domain's own name servers did not answer every question; those rows were checked with this server's resolver, "
                "where a record you just changed can take up to its TTL to show.")
    else:
        note = ("The domain's name servers could not be found, so this was checked with this server's resolver: a record you just "
                "changed can take up to its TTL to show.")
    out = {"deployment": d.slug, "domain": dom, "public_ipv4": s.public_ipv4, "available": True, "rows": rows,
           "zone": info.get("zone"), "servers": info.get("servers", []),
           "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "summary": {k: sum(1 for r in rows if r["status"] == k) for k in ("ok", "missing", "differs", "unknown", "not_available")},
           "note": note}
    _cache[d.slug] = (time.time(), out)
    return {**out, "cached": False}


def mount(app: FastAPI) -> None:
    @app.get(f"{API}/tenants")
    def list_tenants(user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        from . import tenancy_mode
        rows = db.execute(text(f"SELECT * FROM customers WHERE {tscope.clause(db, 'id')} ORDER BY name")).all()
        return {"mode": tenancy_mode.get(db), "tenants": [_tenant(db, c) for c in rows]}

    @app.get(f"{API}/tenants/{{tenant_id}}")
    def get_tenant(tenant_id: UUID, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        return _tenant(db, _customer(db, user, tenant_id), detail=True)

    @app.get(f"{API}/tenants/{{tenant_id}}/dns")
    def tenant_dns(tenant_id: UUID, deployment: str, refresh: bool = False, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        c = _customer(db, user, tenant_id)
        d = next((x for x in _deployments(db, c) if x.slug == deployment), None)
        if d is None:
            raise HTTPException(404, "deployment not found for this tenant")
        return check_deployment(db, d, refresh)
