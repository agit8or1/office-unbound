import json
import os
import re
import stat

import pytest

from conftest import GRAPH_SECRET, TODAY, make_ckpt
from fakeserver import TENANT
from ou_migration import assess, cli, estimate, identity, report, scoring
from ou_migration.estimate import Assumptions
from ou_migration.model import Domain, Group, Inventory, User, VERIFIED
from ou_migration.sources.m365 import M365Collector


class FakeResolver:
    def query(self, name, rtype):
        if rtype == "MX":
            return ["0 contoso-example.mail.protection.outlook.com"] if name == "contoso.example" else []
        if rtype == "TXT":
            return ["v=spf1 -all"] if name == "contoso.example" else []
        return []


@pytest.fixture
def m365_report(http, graph_auth, graph, ckpt_path):
    inv = M365Collector(http, graph_auth, make_ckpt(ckpt_path), graph_base=graph.base + "/graph/v1.0", page_size=2).collect()
    return assess.build(inv, resolver=FakeResolver(), assumptions=Assumptions(bandwidth_mbps=200))


def walk(o, path=""):
    if isinstance(o, dict):
        if "tag" in o and "value" in o:
            yield path, o
        for k, v in o.items():
            yield from walk(v, f"{path}/{k}")
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from walk(v, f"{path}[{i}]")


def test_every_tagged_field_has_valid_tag_and_estimates_have_basis(m365_report):
    fields = list(walk(m365_report))
    assert len(fields) > 40
    for p, f in fields:
        assert f["tag"] in ("verified", "estimated", "assumption"), p
        if f["tag"] != "verified":
            assert f.get("basis"), p
    # separation: nothing under verified_inventory is estimated/assumption except the explicit heuristics
    bad = [p for p, f in walk(m365_report["verified_inventory"]) if f["tag"] != "verified"]
    assert bad == []
    assert all(f["tag"] in ("estimated", "assumption") for p, f in walk(m365_report["estimates"]["transfer"]) if "volumes" not in p)


def test_verified_numbers(m365_report):
    v = m365_report["verified_inventory"]
    assert v["users"]["total"]["value"] == 5 and v["users"]["guests"]["value"] == 1
    assert v["mailboxes"]["total_bytes"]["value"] == 21474836480 + 2147483648 + 64424509440
    assert v["sites"]["count"]["value"] == 2
    d = {x["name"]: x for x in v["domains"]}
    assert d["contoso.example"]["dns"]["spf_state"] == "hard-fail" and d["pending.example"]["dns"] is None
    assert m365_report["estimates"]["shared_mailbox_candidates"]["value"] == 1


def test_feature_mapping_uses_target_facts(m365_report):
    f = {x["id"]: x for x in m365_report["unsupported_features"]}
    assert f["U-TEAMS"]["count"] == 1 and f["U-TEAMS"]["target_status"] == "planned"
    assert f["U-SPLISTS"]["target_status"] == "none" and f["U-PAUTO"]["target_status"] == "none"
    assert f["U-HOLD"]["state"] == "not-assessed" and f["U-HOLD"]["impact"] == "blocker"
    assert f["U-DL"]["count"] == 1 and f["U-DYNGRP"]["count"] == 1
    assert "lab" in f["U-SHARED"]["target_fact"] or f["U-SHARED"]["target_status"] == "lab-verified"


def test_score_is_additive_and_transparent(m365_report):
    r = m365_report["risk"]
    assert r["score"] == max(0, min(100, sum(x["points"] for x in r["rules_fired"])))
    assert all({"rule", "points", "evidence", "tag"} <= set(x) for x in r["rules_fired"])
    assert any("hybrid identity" in x["rule"] for x in r["rules_fired"])
    assert any("unknown blocker-class" in x["rule"] for x in r["rules_fired"])
    assert r["band"] in ("low", "medium", "high", "very-high")


def test_score_band_and_coverage_penalty():
    inv = Inventory(provider="m365", coverage={"report_mailbox": "failed: HTTP 403"})
    s = scoring.score(inv, [], [])
    assert s["score"] == 4 and s["band"] == "low" and s["confidence"] == "medium"
    inv.users = [User(str(i), f"u{i}@x.test", mailbox_bytes=120 << 30) for i in range(1200)]
    s2 = scoring.score(inv, [], [])
    assert s2["score"] > 25 and s2["band"] in ("medium", "high")


def test_identity_mapping_collisions_and_guests(m365_report):
    im = m365_report["identity_mapping"]
    by = {u["source_id"]: u for u in im["users"]}
    assert by["u-0001"]["uid"] == "alice" and by["u-0005"]["uid"] != "alice" and by["u-0005"]["uid"].startswith("alice.")
    assert by["u-0004"]["action"] == "exclude" and by["u-0003"]["action"] == "create-disabled"
    assert im["issues"]["collisions"] == 1 and im["issues"]["unverified_domain"] >= 1   # other.example not verified
    assert next(g for g in im["groups"] if g["source_id"] == "g-3")["action"] == "needs-decision"
    assert len({u["uid"] for u in im["users"] if u["uid"]}) == len([u for u in im["users"] if u["uid"]])


def test_uid_sanitising():
    assert identity.sanitize_uid("Jörg O'Neil+tag") == "j.rg.o.neil.tag"
    assert len(identity.sanitize_uid("a" * 100)) == 32


def test_estimate_formula():
    inv = Inventory(provider="m365", users=[User("1", "a@x.test", mailbox_bytes=36 * 1048576 * 1024, mailbox_items=100000)])
    a = Assumptions(bandwidth_mbps=80, efficiency=0.5, parallel_streams=2, per_stream_mbytes_s=10)
    e = estimate.compute(inv, a)
    # rate = min(80/8*0.5=5, 20) = 5 MB/s ; 36 GiB = 36864 MiB -> 7372.8 s = 2.048 h ; items: 100000*0.05/2=2500 s
    assert e["hours"]["mail"]["value"]["expected"] == 2.0
    assert e["hours"]["mail"]["value"]["pessimistic"] == pytest.approx(5.1, abs=0.05)
    assert e["volumes"]["mailbox_items"]["tag"] == "verified"
    inv.users[0].mailbox_items = None
    e2 = estimate.compute(inv, a)
    assert e2["volumes"]["mailbox_items"]["tag"] == "estimated"


def test_html_is_self_contained_and_escaped(m365_report):
    m365_report["verified_inventory"]["tenant"]["name"]["value"] = "<script>alert(1)</script>"
    html = report.render_html(m365_report)
    assert "<script" not in html.lower().replace("<style", "")
    assert not re.search(r"(src|href)\s*=\s*['\"]?https?://", html) and "url(" not in html and "@import" not in html
    assert "&lt;script&gt;" in html
    for needle in ("Part A", "Part B", "Part C", "Part D", "Verified inventory", "Estimates and assumptions", "Limits of this assessment"):
        assert needle in html
    assert html.index("Part A") < html.index("Part B")


def test_write_reports_private(tmp_path, m365_report):
    jp, hp = report.write(m365_report, str(tmp_path / "out"))
    assert stat.S_IMODE(os.stat(jp).st_mode) == 0o600 and stat.S_IMODE(os.stat(hp).st_mode) == 0o600
    assert json.load(open(jp))["schema"] == assess.SCHEMA


def test_cli_run_end_to_end_no_secret_in_outputs(graph, tmp_path, http):
    env = {"OU_M365_TENANT_ID": TENANT, "OU_M365_CLIENT_ID": "cid", "OU_M365_CLIENT_SECRET": GRAPH_SECRET}
    jp, hp = cli.run("m365", str(tmp_path / "o"), environ=env, checkpoint=str(tmp_path / "ck.json"), resolver=None, http=http,
                     collector_kwargs={"graph_base": graph.base + "/graph/v1.0"}, auth_kwargs={"login_base": graph.base + "/login"})
    blob = open(jp).read() + open(hp).read() + open(tmp_path / "ck.json").read()
    assert GRAPH_SECRET not in blob and "FAKE-GRAPH-TOKEN" not in blob
    assert "DNS posture not checked" in blob


def test_cli_missing_credentials_exit_2(monkeypatch, tmp_path, capsys):
    for k in ("OU_M365_TENANT_ID", "OU_M365_CLIENT_ID", "OU_M365_CLIENT_SECRET", "OU_M365_CLIENT_SECRET_FILE"):
        monkeypatch.delenv(k, raising=False)
    rc = cli.main(["assess", "--provider", "m365", "--out", str(tmp_path / "o"), "--no-dns"])
    assert rc == 2 and "missing" in capsys.readouterr().err
