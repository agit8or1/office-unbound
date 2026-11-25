"""ADR-0021 step 1: tenants in the console (scope-checked) and the tenant DNS checker (read-only, plan-derived names only)."""
import dns.resolver
import pytest
from sqlalchemy import text

from ics import tenants_api
from ics.deploy import appaccess

from .test_review5 import world  # noqa: F401

H = "/api/v1"
IP = "203.0.113.7"
DOM = "acme.example.com"


def _plan(dom=DOM):
    return {"input": {"domain": dom, "deployment_id": "acme1"},
            "vms": [{"name": "gw", "components": ["edge", "identity", "portal"]}, {"name": "mail", "components": ["groupware"]},
                    {"name": "files", "components": ["files", "office"]}],
            "dns": [{"name": f"app.{dom}", "type": "A", "value": "vm:gw", "component": "portal"},
                    {"name": f"cloud.{dom}", "type": "A", "value": "vm:gw", "component": "files"},
                    {"name": f"mail.{dom}", "type": "A", "value": "vm:mail", "component": "groupware"},
                    {"name": dom, "type": "MX", "value": f"10 mail.{dom}", "component": "groupware"},
                    {"name": f"autodiscover.{dom}", "type": "CNAME", "value": f"mail.{dom}", "component": "groupware"},
                    {"name": dom, "type": "TXT", "value": "v=spf1 mx -all", "component": "groupware"}],
            "firewall": []}


class _Rec:
    def __init__(self, t):
        self.t = t

    def to_text(self):
        return self.t


class FakeResolver:
    def __init__(self, zone):
        self.zone, self.asked = zone, []

    def resolve(self, name, rtype):
        self.asked.append((name, rtype))
        v = self.zone.get((name, rtype))
        if v is None:
            raise dns.resolver.NXDOMAIN()
        return [_Rec(x) for x in v]


GOOD = {(f"app.{DOM}", "A"): [IP], (f"cloud.{DOM}", "A"): [IP], (f"mail.{DOM}", "A"): [IP], (DOM, "MX"): [f"10 mail.{DOM}."],
        (f"autodiscover.{DOM}", "CNAME"): [f"mail.{DOM}."], (DOM, "TXT"): ['"v=spf1 mx -all"'],
        (f"_dmarc.{DOM}", "TXT"): ['"v=DMARC1; p=none"'], (f"_imaps._tcp.{DOM}", "SRV"): [f"0 1 993 mail.{DOM}."],
        ("example.com", "CAA"): ['0 issue "letsencrypt.org"'], ("7.113.0.203.in-addr.arpa", "PTR"): [f"mail.{DOM}."]}


def _by(rows):
    return {(r["type"], r["name"]): r for r in rows}


def test_a_correct_zone_checks_ok_and_every_name_comes_from_the_plan():
    r = FakeResolver(GOOD)
    rows = tenants_api.dns_rows(_plan(), IP, r)
    b = _by(rows)
    for k in (("A", f"app.{DOM}"), ("A", f"mail.{DOM}"), ("MX", DOM), ("CNAME", f"autodiscover.{DOM}"), ("TXT", DOM), ("TXT", f"_dmarc.{DOM}"),
              ("SRV", f"_imaps._tcp.{DOM}"), ("CAA", "example.com"), ("PTR", IP)):
        assert b[k]["status"] == "ok", (k, b[k])
    assert b[("SRV", f"_caldavs._tcp.{DOM}")]["status"] == "missing" and not b[("SRV", f"_caldavs._tcp.{DOM}")]["required"]
    dk = next(x for x in rows if "_domainkey" in x["name"])
    assert dk["status"] == "not_available" and "does not sign" in dk["why"]     # honest: no DKIM key exists to publish
    assert all(n == DOM or n.endswith("." + DOM) or n in ("example.com", "com", "7.113.0.203.in-addr.arpa") for n, _ in r.asked), r.asked


def test_a_wrong_or_missing_record_is_reported_and_an_a_record_may_replace_the_alias():
    z = {**GOOD, (f"cloud.{DOM}", "A"): ["198.51.100.1"], ("example.com", "CAA"): ['0 issue "digicert.com"']}
    z.pop((f"app.{DOM}", "A"))
    z.pop((f"autodiscover.{DOM}", "CNAME"))
    z[(f"autodiscover.{DOM}", "A")] = [IP]
    b = _by(tenants_api.dns_rows(_plan(), IP, FakeResolver(z)))
    assert b[("A", f"cloud.{DOM}")]["status"] == "differs" and b[("A", f"cloud.{DOM}")]["found"] == ["198.51.100.1"]
    assert b[("A", f"app.{DOM}")]["status"] == "missing"
    assert b[("CNAME", f"autodiscover.{DOM}")]["status"] == "ok" and "A record" in b[("CNAME", f"autodiscover.{DOM}")]["how"]
    assert b[("CAA", "example.com")]["status"] == "differs"      # Let's Encrypt could not issue


def test_no_caa_anywhere_allows_issuance_and_without_a_public_address_web_names_are_unknown():
    z = {k: v for k, v in GOOD.items() if k[1] != "CAA"}
    b = _by(tenants_api.dns_rows(_plan(), None, FakeResolver(z)))
    assert b[("CAA", DOM)]["status"] == "ok"
    assert b[("A", f"app.{DOM}")]["status"] == "unknown"
    assert ("PTR", IP) not in b


def _no_network_factory(addresses):
    raise AssertionError(f"unexpected authoritative resolver for {addresses}")


# ---------------------------------------------------------------- authoritative servers (public view), fakes only
NS = {(DOM, "NS"): ["ns2.dnshost.test.", "ns1.dnshost.test."], ("ns1.dnshost.test", "A"): ["192.0.2.53"],
      ("ns2.dnshost.test", "A"): ["192.0.2.54"], ("ns2.dnshost.test", "AAAA"): ["2001:db8::53"]}


class TimeoutResolver(FakeResolver):
    def resolve(self, name, rtype):
        import dns.exception
        self.asked.append((name, rtype))
        raise dns.exception.Timeout()


class Factory:
    def __init__(self, auth):
        self.auth, self.calls = auth, []

    def __call__(self, addresses):
        self.calls.append(list(addresses))
        return self.auth


def test_the_zone_is_asked_of_its_own_servers_and_ptr_stays_local():
    stale = {**GOOD, **NS, (f"app.{DOM}", "A"): ["198.51.100.9"]}          # the local resolver still caches an old address
    local, auth = FakeResolver(stale), FakeResolver(GOOD)
    f, info = Factory(auth), {}
    b = _by(tenants_api.dns_rows(_plan(), IP, local, f, info))
    assert info["zone"] == DOM and info["servers"] == ["ns1.dnshost.test", "ns2.dnshost.test"] and info["servers_answered"]
    assert f.calls == [["192.0.2.53", "192.0.2.54", "2001:db8::53"]]          # IPv4 first
    assert b[("A", f"app.{DOM}")]["status"] == "ok"                           # the authoritative answer wins
    assert all(tenants_api.FALLBACK_NOTE not in r["how"] for r in b.values())
    # the domain's servers get only allowed types for names inside the zone; never PTR, NS, ANY or transfers
    assert auth.asked and all(t in tenants_api.AUTH_TYPES and (n == DOM or n.endswith("." + DOM)) for n, t in auth.asked), auth.asked
    assert ("7.113.0.203.in-addr.arpa", "PTR") in local.asked and b[("PTR", IP)]["status"] == "ok"
    # the local resolver only found the servers (NS/A/AAAA), answered PTR, and the CAA names above the zone
    assert all(t in ("NS", "A", "AAAA", "PTR") or (t == "CAA" and n == "example.com") for n, t in local.asked), local.asked
    assert not any(t in ("ANY", "AXFR", "IXFR") for _, t in local.asked + auth.asked)


def test_the_zone_is_found_by_walking_up_from_the_domain():
    z = {**GOOD, ("example.com", "NS"): ["ns1.dnshost.test."], ("ns1.dnshost.test", "A"): ["192.0.2.53"]}
    local, f, info = FakeResolver(z), Factory(FakeResolver(GOOD)), {}
    tenants_api.dns_rows(_plan(), IP, local, f, info)
    assert info["zone"] == "example.com" and info["servers"] == ["ns1.dnshost.test"]
    assert [n for n, t in local.asked if t == "NS"] == [DOM, "example.com"]     # never the TLD
    assert tenants_api.find_authoritative("acme.example", FakeResolver({})) == (None, [], [])


def test_silent_authoritative_servers_fall_back_to_the_local_resolver_with_a_note():
    local, auth = FakeResolver({**GOOD, **NS}), TimeoutResolver({})
    info = {}
    rows = tenants_api.dns_rows(_plan(), IP, local, Factory(auth), info)
    b = _by(rows)
    assert len(auth.asked) == 1                                               # gives up after the first failure, no retry storm
    assert b[("A", f"app.{DOM}")]["status"] == "ok" and tenants_api.FALLBACK_NOTE in b[("A", f"app.{DOM}")]["how"]
    assert tenants_api.FALLBACK_NOTE not in b[("PTR", IP)]["how"]
    assert info["servers"] and info["servers_answered"] is False


def test_no_nameservers_found_checks_locally_and_notes_it():
    info = {}
    b = _by(tenants_api.dns_rows(_plan(), IP, FakeResolver(GOOD), _no_network_factory, info))
    assert info["servers"] == [] and b[("MX", DOM)]["status"] == "ok" and tenants_api.FALLBACK_NOTE in b[("MX", DOM)]["how"]


def test_the_authoritative_resolver_asks_only_the_given_addresses_with_the_standard_timeout():
    from ics import netsettings
    r = tenants_api._auth_resolver(["192.0.2.53"])                            # built, not used: no query is sent
    assert r.nameservers == ["192.0.2.53"] and r.lifetime == netsettings.TIMEOUT


@pytest.fixture()
def tenants(rt, world, monkeypatch):  # noqa: F811
    with rt.session() as db:
        sa = db.execute(text("SELECT slug FROM customers WHERE id = :i"), {"i": world["ca"]}).scalar()
        sb = db.execute(text("SELECT slug FROM customers WHERE id = :i"), {"i": world["cb"]}).scalar()
        for slug, cs in (("dep-a", sa), ("dep-b", sb)):
            db.execute(text("INSERT INTO deployments (slug, customer_id, profile, profile_version, status, desired_spec) "
                            "VALUES (:s, :c, 'small', '1', 'active', '{}'::jsonb)"), {"s": slug, "c": cs})
        db.commit()
    monkeypatch.setattr(appaccess, "_applied_plan", lambda db, d: _plan())
    from ics import netsettings
    real = netsettings.get
    monkeypatch.setattr(netsettings, "get", lambda db: real(db).model_copy(update={"public_ipv4": IP}))
    fake = FakeResolver(GOOD)
    monkeypatch.setitem(tenants_api.HOOKS, "resolver", fake)
    monkeypatch.setitem(tenants_api.HOOKS, "authoritative", _no_network_factory)
    tenants_api._cache.clear()
    return fake


def test_a_scoped_operator_sees_only_their_tenant(world, tenants):  # noqa: F811
    c, _ = world["sessions"]["sa"]
    r = c.get(f"{H}/tenants")
    assert r.status_code == 200
    ids = [t["id"] for t in r.json()["tenants"]]
    assert ids == [world["ca"]]
    t = c.get(f"{H}/tenants/{world['ca']}").json()
    assert [d["slug"] for d in t["deployments"]] == ["dep-a"] and t["domains"] == [DOM]
    assert c.get(f"{H}/tenants/{world['cb']}").status_code == 404
    assert c.get(f"{H}/tenants/{world['cb']}/dns", params={"deployment": "dep-b"}).status_code == 404


def test_the_dns_check_answers_only_for_the_tenants_own_deployment_and_is_kept_a_day(world, tenants):  # noqa: F811
    c, _ = world["sessions"]["all"]
    assert c.get(f"{H}/tenants/{world['ca']}/dns", params={"deployment": "dep-b"}).status_code == 404   # dep-b is tenant B's
    r1 = c.get(f"{H}/tenants/{world['ca']}/dns", params={"deployment": "dep-a"}).json()
    assert r1["available"] and r1["cached"] is False and r1["domain"] == DOM and r1["summary"]["ok"] >= 8
    n = len(tenants.asked)
    r2 = c.get(f"{H}/tenants/{world['ca']}/dns", params={"deployment": "dep-a"}).json()
    assert r2["cached"] is True and len(tenants.asked) == n          # no new lookups
    r3 = c.get(f"{H}/tenants/{world['ca']}/dns", params={"deployment": "dep-a", "refresh": "true"}).json()
    assert r3["cached"] is False and len(tenants.asked) > n


def test_a_viewer_without_customers_sees_no_tenant(world, tenants):  # noqa: F811
    c, _ = world["sessions"]["none"]
    assert c.get(f"{H}/tenants").json()["tenants"] == []
    assert c.get(f"{H}/tenants/{world['ca']}").status_code == 404


def test_the_result_names_the_authoritative_servers_used(world, tenants, monkeypatch):  # noqa: F811
    tenants.zone.update(NS)
    auth = FakeResolver(GOOD)
    monkeypatch.setitem(tenants_api.HOOKS, "authoritative", Factory(auth))
    c, _ = world["sessions"]["all"]
    r = c.get(f"{H}/tenants/{world['ca']}/dns", params={"deployment": "dep-a", "refresh": "true"}).json()
    assert r["servers"] == ["ns1.dnshost.test", "ns2.dnshost.test"] and r["zone"] == DOM
    assert "own name servers" in r["note"] and auth.asked
    n = len(auth.asked)
    assert c.get(f"{H}/tenants/{world['ca']}/dns", params={"deployment": "dep-a"}).json()["cached"] is True and len(auth.asked) == n
