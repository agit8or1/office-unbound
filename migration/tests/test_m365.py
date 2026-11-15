import json

from conftest import make_ckpt
from fakeserver import GRAPH_SECRET, GRAPH_TOKEN, TENANT, fixture
from ou_migration.auth import AuthError, GraphAuth
from ou_migration.sources.m365 import M365Collector
import pytest


def collect(http, auth, graph, path, **kw):
    return M365Collector(http, auth, make_ckpt(path), graph_base=graph.base + "/graph/v1.0", page_size=2, **kw).collect()


def test_full_collect_against_fixtures(http, graph_auth, graph, ckpt_path):
    inv = collect(http, graph_auth, graph, ckpt_path)
    assert inv.tenant_name == "Contoso Example" and inv.tenant_id == TENANT
    assert [d.name for d in inv.domains] == ["contoso.example", "contosoexample.onmicrosoft.com", "pending.example"]
    assert [d.verified for d in inv.domains] == [True, True, False]
    # paging: 2 pages of users were followed
    assert len(inv.users) == 5
    assert len(graph.seen("/graph/v1.0/users")) == 2
    alice = next(u for u in inv.users if u.login == "alice@contoso.example")
    assert alice.aliases == ["a.adams@contoso.example", "alice@contosoexample.onmicrosoft.com"]
    assert alice.mailbox_bytes == 21474836480 and alice.mailbox_items == 52000 and alice.file_bytes == 107374182400
    assert next(u for u in inv.users if u.source_id == "u-0004").user_type == "guest"
    sup = next(u for u in inv.users if u.login == "support@contoso.example")
    assert sup.shared_mailbox_guess and not sup.enabled   # estimate heuristic
    assert {g.kind for g in inv.groups} == {"distribution", "team", "security"}
    assert next(g for g in inv.groups if g.source_id == "g-3").dynamic
    assert all(g.members == 3 for g in inv.groups)
    assert len(inv.sites) == 2                         # deleted site excluded
    assert inv.signals["teams_plan"] and inv.signals["power_automate_plan"] and inv.signals["on_prem_sync_enabled"]
    assert inv.signals["teams_count"] == 1
    assert set(inv.coverage.values()) == {"ok"}


def test_only_documented_least_privilege_endpoints_are_called(http, graph_auth, graph, ckpt_path):
    collect(http, graph_auth, graph, ckpt_path)
    paths = {r.path for r in graph.requests if r.path.startswith("/graph/")}
    banned = ("/messages", "/mailFolders", "/events", "/contacts", "/drive", "/sites", "/content")
    assert not [p for p in paths if any(b in p for b in banned)]


def test_report_download_gets_no_authorization_header(http, graph_auth, graph, ckpt_path):
    collect(http, graph_auth, graph, ckpt_path)
    dl = graph.seen("/download/")
    assert len(dl) == 3 and all(r.auth is None for r in dl)


def test_throttling_mid_run_is_absorbed(http, graph_auth, graph, ckpt_path, sleeper):
    graph.script("GET", "/graph/v1.0/users", [(429, {"Retry-After": "2"}, b'{"error":{"code":"TooManyRequests"}}')])
    graph.script("GET", "/graph/v1.0/groups", [(503, {"Retry-After": "1"}, b"{}")])
    inv = collect(http, graph_auth, graph, ckpt_path)
    assert len(inv.users) == 5 and http.throttle_events == 1 and 2.0 in sleeper.calls


def test_partial_failure_missing_permission_is_recorded_not_fatal(http, graph_auth, graph, ckpt_path):
    graph.routes[("GET", "/graph/v1.0/reports/getMailboxUsageDetail(period='D30')")] = (
        403, {}, {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}})
    inv = collect(http, graph_auth, graph, ckpt_path)
    assert inv.coverage["report_mailbox"].startswith("failed: HTTP 403") and "Reports.Read.All" in inv.coverage["report_mailbox"]
    assert inv.coverage["users"] == "ok" and len(inv.users) == 5
    assert all(u.mailbox_bytes is None for u in inv.users)
    assert inv.users[0].file_bytes is not None            # other stages continued


def test_concealed_names_detected(http, graph_auth, graph, ckpt_path):
    csv = ("Report Refresh Date,User Principal Name,Display Name,Is Deleted,Item Count,Storage Used (Byte)\n"
           "2026-11-13,0A1B2C3D4E5F,0A1B2C3D4E5F,False,10,100\n").encode()
    graph.routes[("GET", "/download/mailbox_usage.csv")] = (200, {}, csv)
    inv = collect(http, graph_auth, graph, ckpt_path)
    assert inv.coverage["report_mailbox"].startswith("partial") and any("concealed" in w for w in inv.warnings)
    assert all(u.mailbox_bytes is None for u in inv.users)


def test_checkpoint_resume_does_not_refetch_completed_pages(http, graph_auth, graph, ckpt_path):
    # page 2 of users fails persistently -> stage fails, cursor to page 2 kept
    graph.routes[("GET", "/graph/v1.0/users")] = lambda r: (
        (500, {}, b"{}") if "PAGE2" in r.query.get("$skiptoken", [""])[0] else
        (200, {}, json.loads(fixture("graph/users_p1.json", graph.base).decode())))
    inv1 = collect(http, graph_auth, graph, ckpt_path)
    assert inv1.coverage["users"].startswith("failed")
    ck = json.load(open(ckpt_path))
    assert ck["stages"]["users"]["next"].endswith("PAGE2") and len(ck["stages"]["users"]["items"]) == 2
    # fix the server, resume with a new client/collector
    from fakeserver import install_graph as ig
    ig(graph)
    n_before = len(graph.seen("/graph/v1.0/organization"))
    inv2 = collect(http, graph_auth, graph, ckpt_path)
    assert len(inv2.users) == 5 and inv2.coverage["users"] == "ok"
    assert len(graph.seen("/graph/v1.0/organization")) == n_before      # completed stage not re-run
    p1_calls = [r for r in graph.seen("/graph/v1.0/users") if "PAGE2" not in r.query.get("$skiptoken", [""])[0]]
    assert len(p1_calls) == 1                                            # first page fetched exactly once overall


def test_resume_reapplies_completed_report_data(http, graph_auth, graph, ckpt_path):
    collect(http, graph_auth, graph, ckpt_path)
    n = len(graph.requests)
    inv = collect(http, graph_auth, graph, ckpt_path)       # everything done: no collection traffic
    assert len(graph.requests) == n
    assert inv.users[0].mailbox_bytes == 21474836480 and len(inv.sites) == 2 and inv.groups[0].members == 3


def test_checkpoint_refuses_other_tenant(ckpt_path):
    from ou_migration.checkpoint import CheckpointError
    c = make_ckpt(ckpt_path)
    c.stage("x")["done"] = True
    c.save()
    with pytest.raises(CheckpointError):
        make_ckpt(ckpt_path, tenant="other")
    assert oct(__import__("os").stat(ckpt_path).st_mode & 0o777) == "0o600"
    assert GRAPH_TOKEN not in open(ckpt_path).read()


def test_deep_counts_sampled(http, graph_auth, graph, ckpt_path):
    inv = collect(http, graph_auth, graph, ckpt_path, deep_counts=True, deep_max_users=2)
    assert inv.counts["sample_events_users"] == 2 and inv.counts["sample_events_total"] == 14
    assert any("sampled 2 of" in w for w in inv.warnings)


def test_token_failure_is_auth_error_without_secret(http, graph):
    a = GraphAuth(http, TENANT, "cid", "WRONG-SECRET-VALUE", login_base=graph.base + "/login")
    with pytest.raises(AuthError) as e:
        a.token()
    assert "WRONG-SECRET-VALUE" not in str(e.value) and "401" in str(e.value)


def test_token_cached_in_memory_only(http, graph_auth, graph):
    graph_auth.token(); graph_auth.token()
    assert len(graph.seen("/login")) == 1
