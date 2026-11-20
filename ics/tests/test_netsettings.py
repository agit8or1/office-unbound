"""Settings -> Network & domains (ics/netsettings.py): required DNS records and port forwards from the applied plan, the public address setting
(typed action), and the read-only checks that prove WHICH machine answered."""
import socket
import ssl
import threading

import pytest

from ics import netsettings as ns
from ics import worker
from ics.deploy import configure

H = "/api/v1"
PLAN = {"input": {"domain": "officeunbound.com", "deployment_id": "ou-test1"},
        "vms": [{"name": "id", "components": ["identity", "edge", "portal"]}, {"name": "mail", "components": ["groupware"]}],
        "dns": [{"name": "app.officeunbound.com", "type": "A", "value": "vm:id", "component": "portal"},
                {"name": "auth.officeunbound.com", "type": "A", "value": "vm:id", "component": "edge"},
                {"name": "mail.officeunbound.com", "type": "A", "value": "vm:mail", "component": "groupware"},
                {"name": "autodiscover.officeunbound.com", "type": "CNAME", "value": "mail.officeunbound.com", "component": "groupware"},
                {"name": "officeunbound.com", "type": "MX", "value": "10 mail.officeunbound.com", "component": "groupware"}],
        "firewall": [{"vm": "id", "port": 443, "proto": "tcp", "from": "any", "purpose": "edge:https"},
                     {"vm": "id", "port": 80, "proto": "tcp", "from": "any", "purpose": "edge:http"},
                     {"vm": "mail", "port": 443, "proto": "tcp", "from": "any", "purpose": "groupware:client-https"},
                     {"vm": "mail", "port": 25, "proto": "tcp", "from": "any", "purpose": "groupware:smtp"},
                     {"vm": "mail", "port": 993, "proto": "tcp", "from": "any", "purpose": "groupware:imaps"},
                     {"vm": "mail", "port": 636, "proto": "tcp", "from": "id", "purpose": "identity:ldaps"}]}
ADDR = {"id": "192.168.22.214", "mail": "192.168.22.215"}


def test_requirements_list_records_and_forwards_to_the_right_vm():
    r = ns.requirements_for(PLAN, ADDR, "184.175.230.187")
    rec = {(x["name"], x["type"]): x for x in r["records"]}
    assert rec[("app.officeunbound.com", "A")]["value"] == "184.175.230.187" and rec[("app.officeunbound.com", "A")]["required"]
    assert rec[("autodiscover.officeunbound.com", "CNAME")]["value"] == "mail.officeunbound.com"
    assert rec[("officeunbound.com", "MX")]["required"] is False                         # only once external mail is enabled
    ports = {(p["port"], p["proto"]): p for p in r["ports"]}
    assert ports[(443, "tcp")]["vm"] == "gateway VM of ou-test1" and ports[(443, "tcp")]["address"] == "192.168.22.214"   # web always to the gateway
    assert ports[(25, "tcp")]["address"] == "192.168.22.215" and ports[(25, "tcp")]["when"] == "when external mail is enabled"
    assert (636, "tcp") not in ports                                                      # internal ports are never forwarded
    assert r["probe_names"] == {"web": "app.officeunbound.com", "mail": "mail.officeunbound.com"}


@pytest.mark.parametrize("ip", ["192.168.1.1", "10.0.0.1", "127.0.0.1", "::1", "not-an-ip", "224.0.0.1"])
def test_only_a_public_ipv4_is_accepted(ip):
    with pytest.raises(ValueError):
        ns.NetworkSettings(public_ipv4=ip)


class _Ans(list):
    pass


class _Rdata:
    def __init__(self, t):
        self.t = t

    def to_text(self):
        return self.t


class _Resolver:
    def __init__(self, table):
        self.table = table

    def resolve(self, name, typ):
        import dns.resolver
        if (name, typ) not in self.table:
            raise dns.resolver.NXDOMAIN()
        return _Ans(_Rdata(x) for x in self.table[(name, typ)])


def test_dns_check_reports_ok_missing_and_wrong():
    r = _Resolver({("app.officeunbound.com", "A"): ["184.175.230.187"], ("auth.officeunbound.com", "A"): ["184.175.230.184"],
                   ("officeunbound.com", "MX"): ["0 ."]})
    reqs = {(x["name"], x["type"]): x for x in ns.requirements_for(PLAN, ADDR, "184.175.230.187")["records"]}
    assert ns.check_record(reqs[("app.officeunbound.com", "A")], "184.175.230.187", r)["status"] == "ok"
    bad = ns.check_record(reqs[("auth.officeunbound.com", "A")], "184.175.230.187", r)
    assert bad["status"] == "wrong" and bad["seen"] == ["184.175.230.184"]
    assert ns.check_record(reqs[("mail.officeunbound.com", "A")], "184.175.230.187", r)["status"] == "missing"
    mx = ns.check_record(reqs[("officeunbound.com", "MX")], "184.175.230.187", r)
    assert mx["status"] == "differs" and "external mail" in mx["detail"]                 # optional record: never "wrong"


def _serve(handler):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)

    def run():
        for _ in range(4):
            try:
                c, _a = srv.accept()
            except OSError:
                return
            with c:
                handler(c)
    threading.Thread(target=run, daemon=True).start()
    return srv, srv.getsockname()[1]


def test_tls_check_proves_the_deployment_answered_and_detects_a_foreign_certificate(tmp_path):
    ca = configure.json.loads(configure._new_ca("officeunbound.com", "t"))
    cert, key = configure.leaf(ca, ["app.officeunbound.com"])
    (tmp_path / "c.pem").write_text(cert + ca["cert"])
    (tmp_path / "k.pem").write_text(key)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")

    def tls(c):
        try:
            with sctx.wrap_socket(c, server_side=True) as t:
                t.recv(1)
        except (ssl.SSLError, OSError):
            pass
    srv, port = _serve(tls)
    st, msg = ns._tls_names("127.0.0.1", port, "app.officeunbound.com", ca["cert"])
    assert st == "ok" and "app.officeunbound.com" in msg
    other = configure.json.loads(configure._new_ca("officeunbound.com", "other"))["cert"]
    st, msg = ns._tls_names("127.0.0.1", port, "app.officeunbound.com", other)      # someone else's machine
    assert st == "wrong" and "right machine" in msg
    srv.close()


def test_smtp_and_http_checks_need_this_deployments_answer():
    srv, port = _serve(lambda c: (c.sendall(b"220 mail.officeunbound.com ESMTP\r\n"), c.recv(64)))
    assert ns._smtp_banner("127.0.0.1", port, "mail.officeunbound.com")[0] == "ok"
    assert ns._smtp_banner("127.0.0.1", port, "mail.officeunbound.com")[0] == "ok"
    srv.close()
    srv, port = _serve(lambda c: (c.sendall(b"220 smtp.isp.example ESMTP\r\n"), c.recv(64)))
    assert ns._smtp_banner("127.0.0.1", port, "mail.officeunbound.com")[0] == "wrong"
    srv.close()
    srv, port = _serve(lambda c: (c.recv(2048), c.sendall(b"HTTP/1.1 301 Moved\r\nLocation: https://app.officeunbound.com/\r\n\r\n")))
    assert ns._http_redirect("127.0.0.1", "app.officeunbound.com", port)[0] == "ok"
    srv.close()


def test_closed_and_udp_ports_are_reported_honestly():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    r = ns.check_port({"port": port, "proto": "tcp", "purpose": "x"}, "127.0.0.1", {"web": None, "mail": None}, None)
    assert r["status"] == "refused" and r["tested_from"] == "inside (this server)"
    assert ns.check_port({"port": 10000, "proto": "udp"}, "127.0.0.1", {}, None)["status"] == "not_testable"
    assert ns.check_port({"port": 443, "proto": "tcp"}, None, {}, None)["status"] == "unknown"


def test_public_address_is_set_through_an_audited_action_and_only_admins_see_the_page(rt, client, mk_user, login):
    adm, ah = login(mk_user("boss", "admin"))
    op, oh = login(mk_user("op", "operator"))
    assert op.get(f"{H}/settings/network").status_code == 403
    assert op.post(f"{H}/plans", json={"action": "settings.network.update", "params": {"public_ipv4": "184.175.230.187"}}, headers=oh).status_code == 403
    assert adm.post(f"{H}/plans", json={"action": "settings.network.update", "params": {"public_ipv4": "10.0.0.5"}}, headers=ah).status_code == 422
    r = adm.post(f"{H}/plans", json={"action": "settings.network.update", "params": {"public_ipv4": "184.175.230.187"}}, headers=ah)
    assert r.status_code in (200, 201) and r.json()["status"] == "approved", r.text          # low risk: approved and audited
    assert worker.run_once(rt)
    assert adm.get(f"{H}/jobs/{r.json()['job_id']}").json()["status"] == "succeeded"
    ov = adm.get(f"{H}/settings/network").json()
    assert ov["settings"] == {"public_ipv4": "184.175.230.187", "entry_address": None} and ov["deployments"] == [] and ov["forwards"] == []
    c = adm.post(f"{H}/settings/network/check", json={}, headers=ah)
    assert c.status_code == 200, c.text
    assert c.json()["public_ipv4"] == "184.175.230.187" and c.json()["records"] == [] and c.json()["forwards"] == []
    assert adm.get(f"{H}/audit/verify").json()["ok"] is True


def test_web_forwards_go_to_the_entry_host_when_the_router_forwards_there():
    r = ns.requirements_for(PLAN, ADDR, "184.175.230.187", "192.168.22.167")
    ports = {(p["port"], p["proto"]): p for p in r["ports"]}
    assert ports[(443, "tcp")]["address"] == "192.168.22.167" and ports[(80, "tcp")]["address"] == "192.168.22.167"
    assert ports[(25, "tcp")]["address"] == "192.168.22.215"                              # mail ports still straight to the mail VM
    with pytest.raises(ValueError):
        ns.NetworkSettings(entry_address="184.175.230.187")                              # must be inside the network


def _dep(slug, plan, entry=None):
    return {"deployment": slug, **ns.requirements_for(plan, ADDR, "184.175.230.187", entry)}


def test_one_public_ip_means_one_forward_per_port_for_the_whole_installation():
    other = {**PLAN, "input": {"domain": "customer-b.com", "deployment_id": "b"},
             "dns": [{**r, "name": r["name"].replace("officeunbound.com", "customer-b.com"), "value": str(r["value"]).replace("officeunbound.com", "customer-b.com")} for r in PLAN["dns"]]}
    a, b = _dep("a", {**PLAN, "input": {**PLAN["input"], "deployment_id": "a"}}), _dep("b", other)
    f = {(x["port"], x["proto"]): x for x in ns.merge_forwards([a, b], None)}
    assert f[(443, "tcp")]["conflict"] and "this server" in f[(443, "tcp")]["conflict"]          # without an entry: impossible, explained
    assert f[(25, "tcp")]["conflict"] and f[(25, "tcp")]["deployments"] == ["a", "b"]
    a, b = _dep("a", {**PLAN, "input": {**PLAN["input"], "deployment_id": "a"}}, "192.168.22.167"), _dep("b", other, "192.168.22.167")
    f = {(x["port"], x["proto"]): x for x in ns.merge_forwards([a, b], "192.168.22.167")}
    assert f[(443, "tcp")]["conflict"] is None and f[(443, "tcp")]["address"] == "192.168.22.167"
    assert f[(443, "tcp")]["names"] == ["app.officeunbound.com", "app.customer-b.com"]        # the check tests every deployment's name
    assert len([x for x in ns.merge_forwards([a, b], "192.168.22.167") if x["port"] == 443]) == 1


@pytest.mark.parametrize("dom, ok", [("officeunbound.com", True), ("e2e-gw2.example", False), ("corp.internal", False), ("x.test", False), ("lan", False), ("a.home.arpa", False)])
def test_reserved_test_domains_are_never_published(dom, ok):
    assert ns.publishable(dom) is ok
