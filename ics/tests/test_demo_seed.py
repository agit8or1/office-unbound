"""Demo organisation seeding (ics/demo, docs/admin/demo-organization.md; owner brief 2026-11-26 section 18).

Pure tests (no database): the plan, the documents, every safeguard that needs no ICS state, the dry run.
Database tests: the demo marker action, the target resolution, the account plans, password storage, and a full seed / re-seed / reset
against the in-memory applications of test_demo_seed_fakes (no real service is contacted)."""
import argparse
import dataclasses
import datetime as dt
import io
import json
import os
import re
import stat
import uuid
import zipfile
from pathlib import Path
from xml.dom import minidom

import httpx
import pytest
from sqlalchemy import text

from ics import worker
from ics.demo import clients, guard, marker, officefiles, org, planner, seed
from ics.deploy import accounts, appaccess

from .test_demo_seed_fakes import DOMAIN, Apps, ImapServer

DEMO = os.path.join(os.path.dirname(__file__), "..", "ics", "demo")
ANCHOR = dt.date(2026, 11, 25)   # a Wednesday


def _sp(domain=DOMAIN):
    return planner.SeedPlan(domain, ANCHOR, "Europe/Berlin")


# ================================================================ the plan
def test_the_organization_is_fictional_and_sized_as_the_brief_asks():
    assert org.ORG_NAME == "Northstar Advisory Group"
    assert 15 <= len(org.PEOPLE) <= 25 and len(org.BY_UID) == len(org.PEOPLE)
    assert len({p.department for p in org.PEOPLE}) >= 5 and {p.department for p in org.PEOPLE} == set(org.DEPARTMENTS)
    for p in org.PEOPLE:   # what directory.account.set accepts (the same validators as the People panel)
        accounts.AccountSet(deployment="northstar-demo", username=p.uid, password="x" * 24, role=p.role, display_name=p.name)
        assert re.fullmatch(r"^[a-z][a-z0-9-]{1,40}$", seed.secret_name(p.uid))
    assert {p.role for p in org.PEOPLE} == {"admin", "user"}
    for _name, dom in org.CLIENTS.values():
        assert dom.endswith(".example")
    for t in org.MSP_TENANTS:
        assert t.name.endswith("(demo)") and t.contact_email.endswith(".example") and "demo" in t.slug.split("-")
    # every outside address in any text is a reserved .example name
    blob = json.dumps([[m.body for m in th.messages] for th in org.THREADS] + [d.paragraphs for d in org.FILES.values()]
                      + [r.messages for r in org.ROOMS])
    for addr in re.findall(r"[\w.+-]+@([\w.-]+)", blob):
        assert addr.endswith(".example"), addr


def test_summary_counts():
    s = _sp().summary()
    assert s["people"] == 20 and s["mail"]["threads"] == 12 and s["mail"]["messages"] == 22
    assert s["mail"]["mailbox_copies"] == len(_sp().deliveries()) == 101
    assert s["mail"]["attachments"] == 8 and s["mail"]["flagged_copies"] == 6 and s["mail"]["unread_copies"] == 5
    assert s["calendar"] == {"meetings": 10, "invitations": 27, "recurring": 2, "upcoming": 9, "team_calendar": "Northstar Team Calendar",
                             "team_events": 6, "tasks": 10}
    assert s["files"]["documents"] == 12 and s["files"]["shares"] == 16 and len(s["files"]["folders"]) == 8
    assert s["files"]["by_kind"] == {"document": 5, "spreadsheet": 4, "presentation": 3} and s["files"]["documents_with_comments"] == 3
    assert len(s["chat"]["rooms"]) == 6 and s["chat"]["direct_messages"] == 4 and s["chat"]["messages"] == 25
    assert len(s["msp_tenants"]) == 2


def test_the_plan_is_deterministic_and_dates_avoid_weekends():
    a, b = _sp(), _sp()
    assert [d.message for d in a.deliveries()] == [d.message for d in b.deliveries()]
    assert [c.ics for c in a.calendar()] == [c.ics for c in b.calendar()]
    for n in range(-15, 30):
        assert planner.bday(ANCHOR, n).weekday() < 5
    assert planner.bday(dt.date(2026, 11, 28), 0) == dt.date(2026, 11, 27)   # a Saturday anchor counts from Friday


def test_mail_messages_thread_and_carry_markers_and_attachments():
    from email import message_from_bytes
    sp = _sp()
    th = org.THREADS[0]
    m3 = message_from_bytes(sp.message(th, 2))
    assert m3["Subject"] == "Re: " + th.subject and m3["X-OU-Demo"] == org.SEED_TAG and m3["X-OU-Demo-Id"] == "t01m3"
    assert m3["In-Reply-To"] == f"<ou-demo-t01m2@{DOMAIN}>" and "<ou-demo-t01m1@" in m3["References"]
    att = [p for p in m3.walk() if p.get_filename()]
    assert [p.get_filename() for p in att] == ["brightwater-market-model.xlsx"]
    assert zipfile.ZipFile(io.BytesIO(att[0].get_payload(decode=True))).read("xl/worksheets/sheet1.xml")
    # sender keeps a \Seen copy in Sent; recipients get flags as written in org.py
    d = [x for x in sp.deliveries() if x.demo_id == "t01m3"]
    assert {(x.owner, x.folder, x.flags) for x in d} == {("tomas.brandvik", "SENT", ("\\Seen",)),
                                                         ("priya.raghunathan", "INBOX", ("\\Seen", "\\Flagged")),
                                                         ("marcus.oyelaran", "INBOX", ("\\Seen",))}


def test_meetings_are_valid_icalendar_with_internal_attendees_only():
    for c in _sp().calendar():
        lines = c.ics.split("\r\n")
        assert lines[0] == "BEGIN:VCALENDAR" and lines[-2] == "END:VCALENDAR" and all(len(x.encode()) <= 75 for x in lines)
        assert f"UID:{c.uid}" in c.ics and c.uid.startswith(org.UID_PREFIX) and c.href.startswith(org.UID_PREFIX)
        unfolded = c.ics.replace("\r\n ", "")
        for addr in re.findall(r"mailto:([^\r\n]+)", unfolded):
            guard.check_address(addr, DOMAIN)
    m04 = next(c for c in _sp().calendar() if c.uid.startswith("ou-demo-m04"))
    assert "RRULE:FREQ=WEEKLY;COUNT=12" in m04.ics and m04.ics.count("ATTENDEE") == 6


@pytest.mark.parametrize("key", sorted(org.FILES))
def test_documents_are_well_formed_packages(key):
    data = officefiles.render(org.FILES[key])
    z = zipfile.ZipFile(io.BytesIO(data))
    for n in z.namelist():
        if n != "mimetype":
            minidom.parseString(z.read(n))       # every XML part is well formed
    if key.endswith((".odt", ".ods", ".odp")):
        first = z.infolist()[0]
        assert first.filename == "mimetype" and first.compress_type == zipfile.ZIP_STORED and z.read("mimetype").decode() == officefiles.mime(key)
        if org.FILES[key].comments:
            assert b"<office:annotation>" in z.read("content.xml")
    else:
        assert "[Content_Types].xml" in z.namelist()
        if org.FILES[key].comments:
            assert b"<w:comment " in z.read("word/comments.xml")
    assert officefiles.render(org.FILES[key]) == data     # deterministic bytes


def test_odf_formulas():
    assert officefiles.odf_formula("=SUM(B2:E2)") == "of:=SUM([.B2:.E2])"
    assert officefiles.odf_formula("=B2*C2*D2*52") == "of:=[.B2]*[.C2]*[.D2]*52"


# ================================================================ safeguards without ICS state
@pytest.mark.parametrize("slug, domain, ok", [
    ("northstar-demo", "demo.example.org", True),
    ("demo-northstar", "northstar-demo.officeunbound.com", True),
    ("officeunbound8", "demo.example.org", False),              # the production deployment, whatever its domain
    ("northstar-demo", "officeunbound.com", False),             # the production domain
    ("northstar", "demo.example.org", False),                   # slug without a demo label
    ("northstar-demo", "northstar.example.org", False),         # domain without a demo label
    ("northstar-demo", "demonstration.example.org", False),     # 'demo' must be a whole label part
    ("demolition-crew", "demo.example.org", False),
])
def test_names_must_carry_a_demo_label(slug, domain, ok):
    if ok:
        guard.check_names(slug, domain)
    else:
        with pytest.raises(guard.DemoRefused):
            guard.check_names(slug, domain)


def test_confirmation_must_repeat_the_slug():
    guard.check_confirm("northstar-demo", "northstar-demo")
    for bad in (None, "", "northstar", "officeunbound8"):
        with pytest.raises(guard.DemoRefused):
            guard.check_confirm("northstar-demo", bad)


def test_http_requests_outside_the_demo_domain_are_refused_before_sending():
    sent = []
    h = clients.http_client(DOMAIN, transport=httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(200)))
    for url in ("https://evil.example/x", "https://officeunbound.com/", "https://app.officeunbound.com/", "http://cloud." + DOMAIN + "/",
                "https://" + DOMAIN + ".evil.example/", "https://notdemo.example.org/"):
        with pytest.raises(guard.DemoRefused):
            h.get(url)
    assert sent == []
    assert h.get(f"https://cloud.{DOMAIN}/").status_code == 200 and len(sent) == 1


def test_a_redirect_out_of_the_demo_domain_is_refused():
    def app(r):
        return httpx.Response(302, headers={"location": "https://login.evil.example/steal"})
    h = clients.http_client(DOMAIN, transport=httpx.MockTransport(app))
    with pytest.raises(guard.DemoRefused):
        clients.sign_in(h, f"https://auth.{DOMAIN}/start", "u", "p", clients.LOOPBACK)


def test_imap_outside_the_demo_domain_is_refused_before_connecting():
    calls = []
    with pytest.raises(guard.DemoRefused):
        clients.Imap("mail.officeunbound.com", DOMAIN, "a@x", "p", factory=lambda h, p: calls.append(h))
    assert calls == []


def test_every_recipient_is_a_seeded_person_at_the_demo_domain(monkeypatch):
    assert guard.check_addresses(_sp(), DOMAIN) > 200
    for addr in ("someone@gmail.example", f"stranger@{DOMAIN}", "avery.lindqvist@officeunbound.com", f"avery.lindqvist@sub.{DOMAIN}"):
        with pytest.raises(guard.DemoRefused):
            guard.check_address(addr, DOMAIN)
    # a plan that would address anyone who is not a seeded person is refused as a whole
    bad = org.Thread("tx", "x", (org._m("txm1", "avery.lindqvist", ["stranger"], 0, 9, "x"),))
    monkeypatch.setattr(org, "THREADS", [*org.THREADS, bad])
    with pytest.raises(guard.DemoRefused):
        guard.check_addresses(_sp(), DOMAIN)


def test_the_tool_has_no_smtp_and_no_tls_bypass():
    src = "".join(Path(DEMO, f).read_text() for f in os.listdir(DEMO) if f.endswith(".py"))
    assert "smtplib" not in src and "SMTP(" not in src
    assert "verify=False" not in src and "CERT_NONE" not in src and "check_hostname = False" not in src


def test_foreign_people_mean_the_deployment_is_in_real_use():
    seeded = set(org.BY_UID)
    guard.check_people([{"username": "ou-admin"}, {"username": "admin"}, {"username": "avery.lindqvist"}], seeded)
    with pytest.raises(guard.DemoRefused):
        guard.check_people([{"username": "doctest"}, {"username": "avery.lindqvist"}], seeded)


def _args(**kw):
    ap = argparse.ArgumentParser()
    seed.add_arguments(ap)
    argv = []
    for k, v in kw.items():
        flag = {"confirm": guard.CONFIRM_FLAG}.get(k, "--" + k.replace("_", "-"))
        argv += [flag] if v is True else [flag, v]
    return ap.parse_args(argv)


def test_dry_run_contacts_nothing_and_prints_no_secret(capsys):
    def boom(*a, **k):
        raise AssertionError("the dry run contacted something")
    out = io.StringIO()
    rc = seed.main(_args(dry_run=True, deployment="northstar-demo", domain=DOMAIN), rt_factory=boom, http_factory=boom, imap_factory=boom,
                   people_fn=boom, out=out)
    assert rc == 0
    res = json.loads(out.getvalue())
    assert res["plan"]["people"] == 20 and len(res["people"]) == 20 and res["people"][0]["email"].endswith("@" + DOMAIN)
    assert "password" not in out.getvalue().lower()
    assert seed.main(_args(dry_run=True, deployment="officeunbound8", domain=DOMAIN), rt_factory=boom, out=io.StringIO()) == seed.EXIT_REFUSED
    assert seed.main(_args(dry_run=True, domain="officeunbound.com"), rt_factory=boom, out=io.StringIO()) == seed.EXIT_REFUSED


def test_cli_refuses_without_target_or_confirmation():
    def boom(*a, **k):
        raise AssertionError("contacted")
    assert seed.main(_args(), rt_factory=boom, out=io.StringIO()) == seed.EXIT_REFUSED
    assert seed.main(_args(deployment="northstar-demo"), rt_factory=boom, out=io.StringIO()) == seed.EXIT_REFUSED   # no operator
    assert seed.main(_args(deployment="northstar-demo", operator="boss", domain=DOMAIN), rt_factory=boom, out=io.StringIO()) == seed.EXIT_REFUSED
    assert seed.main(_args(deployment="northstar-demo", operator="boss", only="mail,smtp"), rt_factory=boom, out=io.StringIO()) == seed.EXIT_REFUSED


def test_sharing_roles_come_from_the_server_list():
    allowed = [{"id": "v", "displayName": "Can view", "@libre.graph.weight": 1}, {"id": "u", "displayName": "Can upload", "@libre.graph.weight": 2},
               {"id": "e", "displayName": "Can edit", "@libre.graph.weight": 3}]
    assert clients.pick_role(allowed, "view") == "v" and clients.pick_role(allowed, "edit") == "e"
    with pytest.raises(clients.SeedError):
        clients.pick_role([], "edit")


def test_a_wrong_password_stops_the_sign_in():
    apps = Apps({"avery.lindqvist": "right-password-123"})
    h = clients.http_client(DOMAIN, transport=apps.transport())
    with pytest.raises(clients.LoginFailed):
        clients.oidc_token(h, f"https://auth.{DOMAIN}/realms/ou", "OpenCloudDesktop", "avery.lindqvist", "wrong")


# ================================================================ with the ICS database
def _demo_plan(domain=DOMAIN):
    return {"input": {"domain": domain}, "vms": [], "dns": [{"name": f"mail.{domain}", "type": "A", "component": "groupware"}]}


@pytest.fixture()
def demo_dep(rt, monkeypatch):
    """A deployment row with an applied plan on the demo domain (the plan itself is patched in, as test_deploy_accounts does)."""
    slug = "demo-" + uuid.uuid4().hex[:8]
    with rt.session() as db:
        dep_id = db.execute(text("INSERT INTO deployments (slug, customer_id, profile, profile_version, status, desired_spec) "
                                 "VALUES (:s, 'c-000000000000', 'small', '1', 'active', '{}'::jsonb) RETURNING id"), {"s": slug}).scalar()
        db.commit()
    plans = {slug: _demo_plan()}
    monkeypatch.setattr(appaccess, "_applied_plan", lambda db, d: plans.get(d.slug))
    return {"slug": slug, "id": str(dep_id), "plans": plans}


def _approve(rt, client, h, plan_id):
    a = client.post(f"/api/v1/plans/{plan_id}/approve", headers=h)
    assert a.status_code == 200, a.text
    while worker.run_once(rt):
        pass
    return a.json()


def _mark(rt, client, h, slug):
    r = client.post("/api/v1/plans", json={"action": "demo.deployment.mark", "params": {"deployment": slug, "confirm": slug}}, headers=h)
    assert r.status_code == 201, r.text
    assert r.json()["risk"] == "high"
    _approve(rt, client, h, r.json()["plan_id"])


@pytest.fixture()
def admin(rt, client, mk_user, login, monkeypatch):
    monkeypatch.setattr(rt, "settings", dataclasses.replace(rt.settings, approval_mode="single_admin"))   # ADR-0017: the owner approves own plans
    return login(mk_user("boss", "admin"))


def test_marking_needs_a_demo_name_and_is_refused_for_production(rt, client, admin, demo_dep):
    client, admin = admin
    slug = demo_dep["slug"]
    r = client.post("/api/v1/plans", json={"action": "demo.deployment.mark", "params": {"deployment": slug, "confirm": "other"}}, headers=admin)
    assert r.status_code == 422
    with rt.session() as db:
        db.execute(text("INSERT INTO deployments (slug, customer_id, profile, profile_version, status, desired_spec) "
                        "VALUES ('officeunbound8', 'c-000000000000', 'small', '1', 'active', '{}'::jsonb) ON CONFLICT DO NOTHING"))
        db.commit()
    demo_dep["plans"]["officeunbound8"] = _demo_plan("officeunbound.com")
    r = client.post("/api/v1/plans", json={"action": "demo.deployment.mark", "params": {"deployment": "officeunbound8", "confirm": "officeunbound8"}},
                    headers=admin)
    assert r.status_code == 422 and "production" in r.text
    demo_dep["plans"][slug] = _demo_plan("northstar.example.org")       # a demo slug on a non-demo domain
    r = client.post("/api/v1/plans", json={"action": "demo.deployment.mark", "params": {"deployment": slug, "confirm": slug}}, headers=admin)
    assert r.status_code == 422 and "demo label" in r.text


def test_the_marker_binds_id_and_domain_and_unmarking_removes_it(rt, client, admin, demo_dep):
    client, admin = admin
    slug = demo_dep["slug"]
    with rt.session() as db:
        with pytest.raises(guard.DemoRefused, match="not marked"):
            seed.resolve_target(db, slug, slug)
    _mark(rt, client, admin, slug)
    with rt.session() as db:
        t = seed.resolve_target(db, slug, slug)
        assert t.domain == DOMAIN and t.hosts == {"mail": f"mail.{DOMAIN}", "cloud": f"cloud.{DOMAIN}", "auth": f"auth.{DOMAIN}",
                                                  "matrix": f"matrix.{DOMAIN}"}
        with pytest.raises(guard.DemoRefused):
            seed.resolve_target(db, slug, "x")
        ev = db.execute(text("SELECT count(*) FROM audit_events WHERE action = 'deployment.demo_marked'")).scalar()
        assert ev == 1 and marker.marks(db)[slug]["deployment_id"] == demo_dep["id"]
    demo_dep["plans"][slug] = _demo_plan("other-demo.example.org")      # the domain changed after marking
    with rt.session() as db:
        with pytest.raises(guard.DemoRefused, match="another deployment or domain"):
            seed.resolve_target(db, slug, slug)
    demo_dep["plans"][slug] = _demo_plan()
    r = client.post("/api/v1/plans", json={"action": "demo.deployment.mark", "params": {"deployment": slug, "demo": False, "confirm": slug}}, headers=admin)
    _approve(rt, client, admin, r.json()["plan_id"])
    with rt.session() as db:
        with pytest.raises(guard.DemoRefused, match="not marked"):
            seed.resolve_target(db, slug, slug)


def _people_fn(present):
    def fn(rt, db, slug):
        return {"people": [{"username": u} for u in ["ou-admin", "admin", *present]]}
    return fn


def test_accounts_are_requested_once_with_vault_passwords_that_are_never_shown(rt, client, admin, demo_dep, capsys):
    client, admin = admin
    slug = demo_dep["slug"]
    _mark(rt, client, admin, slug)
    out = io.StringIO()
    rc = seed.main(_args(deployment=slug, confirm=slug, operator="boss"), rt_factory=lambda: rt, people_fn=_people_fn([]), out=out)
    assert rc == seed.EXIT_WAIT
    res = json.loads(out.getvalue().split("\napprove")[0])
    assert len(res["accounts"]["requested_plans"]) == 20 and res["accounts"]["present"] == 0
    with rt.session() as db:
        rows = db.execute(text("SELECT params, secret_enc, status FROM plans WHERE action = 'directory.account.set' AND params->>'deployment' = :s"),
                          {"s": slug}).all()
        pws = [seed.password(rt, seed.resolve_target(db, slug, slug), p.uid) for p in org.PEOPLE]
    assert len(rows) == 20 and all(r.secret_enc and "password" not in r.params and r.status == "pending_approval" for r in rows)
    assert {r.params["username"] for r in rows} == set(org.BY_UID) and {r.params["role"] for r in rows} == {"admin", "user"}
    assert len(set(pws)) == 20 and all(accounts.USER_PASSWORD.fullmatch(p) for p in pws)
    # idempotent: the same run again requests nothing new while the plans wait for approval
    out2 = io.StringIO()
    assert seed.main(_args(deployment=slug, confirm=slug, operator="boss"), rt_factory=lambda: rt, people_fn=_people_fn([]), out=out2) == seed.EXIT_WAIT
    assert json.loads(out2.getvalue().split("\napprove")[0])["accounts"]["waiting_plans"].__len__() == 20
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM plans WHERE action = 'directory.account.set'")).scalar() == 20
        dump = json.dumps([[str(v) for v in r] for r in db.execute(text("SELECT details FROM audit_events")).all()])
        dump += json.dumps([[str(v) for v in r] for r in db.execute(text("SELECT value FROM system_settings")).all()])
    cap = capsys.readouterr()
    for p in pws:
        assert p not in out.getvalue() + out2.getvalue() + cap.out + cap.err + dump
    # foreign people: refused before any plan
    assert seed.main(_args(deployment=slug, confirm=slug, operator="boss"), rt_factory=lambda: rt, people_fn=_people_fn(["doctest"]), out=io.StringIO()) == seed.EXIT_REFUSED


def test_password_export_is_0600_and_never_inside_a_git_checkout(rt, client, admin, demo_dep, tmp_path):
    client, admin = admin
    slug = demo_dep["slug"]
    _mark(rt, client, admin, slug)
    with rt.session() as db:
        t = seed.resolve_target(db, slug, slug)
    f = tmp_path / "pw.tsv"
    assert seed.export_passwords(rt, t, str(f)) == 20
    assert stat.S_IMODE(f.stat().st_mode) == 0o600 and len(f.read_text().splitlines()) == 20
    with pytest.raises(FileExistsError):
        seed.export_passwords(rt, t, str(f))              # never overwrites
    (tmp_path / "repo" / ".git").mkdir(parents=True)
    with pytest.raises(guard.DemoRefused):
        seed.export_passwords(rt, t, str(tmp_path / "repo" / "sub" / "pw.tsv"))


def _ready(rt, client, admin, demo_dep):
    slug = demo_dep["slug"]
    _mark(rt, client, admin, slug)
    with rt.session() as db:
        t = seed.resolve_target(db, slug, slug)
        sp = seed.seed_plan(db, t, "Europe/Berlin", today=ANCHOR)
    pws = {p.uid: seed.password(rt, t, p.uid) for p in org.PEOPLE}
    return t, sp, pws


def test_full_seed_is_idempotent_and_reset_removes_it(rt, client, admin, demo_dep):
    client, admin = admin
    t, sp, pws = _ready(rt, client, admin, demo_dep)
    imap = ImapServer({f"{u}@{DOMAIN}": p for u, p in pws.items()})
    apps = Apps(pws)
    with clients.http_client(DOMAIN, transport=apps.transport()) as h:
        c1 = seed.run_content(rt, t, sp, seed.PHASES, http=h, imap_factory=imap.factory)
    assert c1["mail"] == {"created": 101}
    assert c1["calendar"] == {"calendars_created": 1, "created": 26}
    assert c1["files"] == {"folders_created": 11, "created": 12, "shares_created": 16}
    assert c1["chat"] == {"rooms_created": 10, "joined": sum(len(r.members) - 1 for r in org.ROOMS), "messages_created": 25}
    # mail: in each person's own folders, with flags; threads intact
    box = imap.boxes[f"priya.raghunathan@{DOMAIN}"]
    flagged = [r for r in box["INBOX"] if "\\Flagged" in r[1]]
    assert len(flagged) == 1 and b"t01m3" in flagged[0][2]
    assert sum(len(b["INBOX"]) + len(b["Sent Items"]) for b in imap.boxes.values()) == 101
    assert {h_ for h_, _p in imap.logins} == {f"mail.{DOMAIN}"}
    # calendar: organizer copies, server scheduling copies for attendees, the team calendar, tasks
    assert any(k.startswith("ou-demo-m02@") for k in apps.cal[f"priya.raghunathan@{DOMAIN}"]["Calendar"])   # stored under its UID
    assert any("ou-demo-m02" in k for k in apps.cal[f"tomas.brandvik@{DOMAIN}"]["Calendar"])
    assert len(apps.cal[f"grace.abernathy@{DOMAIN}"][org.TEAM_CALENDAR["slug"]]) == 6
    assert any(k.startswith("ou-demo-k01@") for k in apps.cal[f"tomas.brandvik@{DOMAIN}"]["Tasks"])
    # files: generated documents in the owners' spaces, shares from the server's role list
    assert apps.dav["priya.raghunathan"]["Projects/Brightwater Foods/brightwater-proposal.docx"] == officefiles.render(org.FILES["brightwater-proposal.docx"])
    perms = apps.perms[("priya.raghunathan", "Projects%2FBrightwater%20Foods")]
    assert sorted((p["grantedToV2"]["user"]["id"], p["roles"][0]) for p in perms) == [
        ("id-leah.castellano", "role-viewer"), ("id-marcus.oyelaran", "role-editor"), ("id-tomas.brandvik", "role-editor")]
    # chat: everyone joined, messages sent by their authors, DMs marked direct, every session logged out
    gen = apps.rooms[apps.aliases[f"#ou-demo-general:matrix.{DOMAIN}"]]
    assert sum(1 for s in gen["members"].values() if s == "join") == 20 and len(gen["events"]) == 5
    assert gen["events"][1]["sender"] == f"@noah.petrakis:matrix.{DOMAIN}"
    dm = apps.aliases[f"#ou-demo-dm-priya-tomas:matrix.{DOMAIN}"]
    assert apps.acct[f"@priya.raghunathan:matrix.{DOMAIN}"] == {f"@tomas.brandvik:matrix.{DOMAIN}": [dm]}
    assert apps.tokens == {} and apps.logged_out == 20
    assert all(h_ == DOMAIN or h_.endswith("." + DOMAIN) for h_ in apps.hosts)
    with rt.session() as db:
        m = seed.manifest(db, t.slug)
        assert m["anchor"] == ANCHOR.isoformat() and len(m["rooms"]) == 10 and set(m["phases"]) == set(seed.PHASES)

    # second run: everything kept, nothing duplicated
    with clients.http_client(DOMAIN, transport=apps.transport()) as h:
        c2 = seed.run_content(rt, t, sp, seed.PHASES, http=h, imap_factory=imap.factory)
    assert c2["mail"] == {"kept": 101} and c2["calendar"] == {"kept": 26} and c2["files"] == {"folders_created": 0, "kept": 12, "shares_kept": 16}
    assert c2["chat"] == {"rooms_kept": 10, "messages_kept": 25}
    assert sum(len(b["INBOX"]) + len(b["Sent Items"]) for b in imap.boxes.values()) == 101 and len(gen["events"]) == 5

    # reset: what the seed named is gone; a person's own unrelated mail stays
    from email.message import EmailMessage
    own = EmailMessage()
    own["Subject"] = "lunch?"
    own.set_content("unrelated")
    imap.boxes[f"avery.lindqvist@{DOMAIN}"]["INBOX"].append([9999, set(), bytes(own)])
    with clients.http_client(DOMAIN, transport=apps.transport()) as h:
        c3 = seed.run_content(rt, t, sp, seed.PHASES, http=h, imap_factory=imap.factory, reset=True)
    assert c3["mail"]["removed"] == 101 and c3["files"]["folders_removed"] == 8 and c3["chat"]["rooms_removed"] == 10
    assert c3["calendar"]["calendars_removed"] == 1 and c3["calendar"]["removed"] == 26 + 27
    assert [len(b["INBOX"]) + len(b["Sent Items"]) for b in imap.boxes.values()].count(0) == len(imap.boxes) - 1
    assert imap.boxes[f"avery.lindqvist@{DOMAIN}"]["INBOX"][0][0] == 9999
    assert all(not any(k.startswith("ou-demo") or "ou-demo" in k for k in c) for u in apps.cal.values() for c in u.values())
    assert apps.aliases == {} and all(s == "leave" for r in apps.rooms.values() for s in r["members"].values())


def test_reset_requests_account_deletion_and_drops_passwords_of_people_already_gone(rt, client, admin, demo_dep):
    client, admin = admin
    t, _sp_, _pws = _ready(rt, client, admin, demo_dep)
    present = [p.uid for p in org.PEOPLE[:5]]
    res = seed.reset_accounts(rt, t, "boss", _people_fn(present))
    assert len(res["requested"]) == 5 and res["secrets_removed"] == 15
    with rt.session() as db:
        rows = db.execute(text("SELECT params, risk FROM plans WHERE action = 'directory.account.delete'")).all()
        assert sorted(r.params["username"] for r in rows) == sorted(present) and {r.risk for r in rows} == {"high"}
        assert sum(seed.has_password(db, t, p.uid) for p in org.PEOPLE) == 5
    again = seed.reset_accounts(rt, t, "boss", _people_fn(present))
    assert again["requested"] == [] and len(again["waiting"]) == 5


def test_msp_tenants_only_in_multi_tenant_mode(rt, client, admin, demo_dep):
    client, admin = admin
    t, _sp_, _pws = _ready(rt, client, admin, demo_dep)
    assert "skipped" in seed.tenants_phase(rt, t, "boss")
    with rt.session() as db:
        db.execute(text("INSERT INTO system_settings (key, value, updated_at, updated_by) VALUES ('system.tenancy', '{\"mode\": \"multi\"}'::jsonb, now(), 't') "
                        "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"))
        db.commit()
    res = seed.tenants_phase(rt, t, "boss")
    assert len(res["requested"]) == 2
    with rt.session() as db:
        rows = db.execute(text("SELECT params FROM plans WHERE action = 'customer.create'")).all()
    assert sorted(r.params["name"] for r in rows) == sorted(x.name for x in org.MSP_TENANTS)
    assert {r.params["provisioning_mode"] for r in rows} == {"monitoring_only"}
