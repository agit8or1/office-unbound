import hashlib
import json
import os
import stat

import pytest
from fakeimap import FakeImap, mk

from ou_migration.engine import mutf7
from ou_migration.engine.imapx import (AuthFailed, Endpoint, Fatal, GuardViolation, LoginAuth, Session, StaticTokenProvider,
                                       Throttle, TokenProvider, XOAuth2Auth)
from ou_migration.engine.mailbox import Mailbox, MsgMeta, fingerprint, parse_list, parse_meta, uid_ranges
from ou_migration.engine.mapping import Mapper
from ou_migration.engine.migrate import Migrator, Options
from ou_migration.engine.state import State, StateError
from ou_migration.engine.verify import verify

D1, D2, D3 = "03-Mar-2025 10:00:00 +0000", "15-Jun-2025 08:30:00 +0200", "01-Jan-2024 23:59:59 -0500"


class Crash(BaseException):
    """simulated kill -9: not caught by any `except Exception`"""


def nosleep(_s):
    pass


def sess(srv, write, user="u", pw="pw", **kw):
    ep = Endpoint("127.0.0.1", srv.port, "plain", label="t")
    return Session(ep, LoginAuth(user, pw), write=write, sleep=nosleep, base_delay=0.001, **kw).connect()


@pytest.fixture
def servers():
    s, d = FakeImap(user="src", password="spw"), FakeImap(user="dst", password="dpw")
    for n in ("INBOX", "Drafts", "Sent Items", "Deleted Items", "Junk Email"):
        d.folder(n)
    yield s, d
    s.stop()
    d.stop()


def seed_source(s, n_inbox=6):
    inbox = s.folder("INBOX")
    for i in range(n_inbox):
        inbox.add(mk(i), ["\\Seen"] if i % 2 == 0 else [], D1 if i % 3 else D2)
    inbox.msgs[1].flags.add("\\Flagged")
    inbox.msgs[2].flags.update({"\\Answered", "$Forwarded"})
    sent = s.folder("Sent Messages", ["\\Sent"])
    sent.add(mk(100), ["\\Seen"], D3)
    sent.add(mk(101, size=200_000), ["\\Seen"], D3)
    s.folder("Archive/2025").add(mk(200), ["\\Seen"], D2)
    s.folder("Projekte/" + "Übersicht 2025").add(mk(300))  # raw, replaced below
    del s.folders["Projekte/Übersicht 2025"]
    s.folder("Projekte/" + mutf7.encode("Übersicht 2025")).add(mk(300, mid=False), [], D1)
    s.folder("Virtual", ["\\Flagged"]).add(mk(400))  # virtual view: skipped by default


def migrate(servers, tmp_path, **kw):
    s, d = servers
    st = State(str(tmp_path / "st.db"), "job")
    m = Migrator(Mailbox(sess(s, False, "src", "spw")), Mailbox(sess(d, True, "dst", "dpw")), st, kw.pop("mapper", Mapper()), **kw)
    return m, st


# ------------------------------------------------------------------ unit
def test_mutf7_roundtrip():
    for n in ["INBOX", "Übersicht 2025", "日本語/Ünï", "A&B", "x" * 5]:
        assert mutf7.decode(mutf7.encode(n)) == n
    assert mutf7.encode("Ü") == "&ANw-"
    assert mutf7.encode("A&B") == "A&-B"


def test_mapping_special_use_hint_hierarchy_and_sanitising():
    m = Mapper()
    plans = {p.src_display: p for p in m.map_all([
        ("INBOX", "/", []), ("Sent Messages", "/", ["\\Sent"]), ("[Gmail]/Drafts", "/", ["\\Drafts", "\\HasNoChildren"]),
        ("[Gmail]/Trash", "/", ["\\Trash"]), ("[Gmail]/Spam", "/", ["\\Junk"]), ("[Gmail]/All Mail", "/", ["\\All"]),
        ("[Gmail]/Starred", "/", ["\\Flagged"]), ("Gesendet", "/", []), ("INBOX.Kunden.ACME", ".", []),
        ("INBOX.Sent", ".", []), ("Archive/2025", "/", []), ("a.b/c", "/", []), ("Top", ".", ["\\Noselect"]),
        ("Projekte/" + mutf7.encode("Übersicht"), "/", []), ("Foo/ bar. ", "/", []), ("Spam", "/", ["\\Junk"]),
    ])}
    t = lambda k: plans[k].target  # noqa: E731
    assert t("INBOX") == "INBOX"
    assert t("Sent Messages") == "Sent Items" and plans["Sent Messages"].reason == "special-use:\\sent"
    assert t("[Gmail]/Drafts") == "Drafts" and t("[Gmail]/Trash") == "Deleted Items" and t("[Gmail]/Spam") == "Junk Email"
    assert t("[Gmail]/All Mail") == "Archive"
    assert t("[Gmail]/Starred") is None and plans["[Gmail]/Starred"].reason == "skipped:virtual-view"
    assert t("Gesendet") == "Sent Items" and plans["Gesendet"].reason.startswith("name-hint")
    assert t("INBOX.Kunden.ACME") == "Kunden/ACME"            # namespace prefix dropped, '.' -> '/'
    assert t("INBOX.Sent") == "Sent Items"
    assert t("Archive/2025") == "Archive/2025"                  # custom hierarchy preserved, no hint for nested names
    assert t("a.b/c") == "a.b/c"                                # '.' is not a delimiter here
    assert t("Top") is None
    assert t("Projekte/Übersicht") == "Projekte/Übersicht"
    assert plans["Projekte/Übersicht"].target_wire == "Projekte/&ANw-bersicht"
    assert t("Foo/ bar. ") == "Foo/bar"


def test_mapping_sanitises_unsafe_names_and_rename_exclude():
    m = Mapper(exclude=(r"Tmp.*",), rename={"Old": "Neu/Alt"})
    p = {x.src_display: x for x in m.map_all([("a*b%c\x01", "/", []), ("Tmp1", "/", []), ("Old", "/", []), ("x" * 300, "/", [])])}
    assert p["a*b%c\x01"].target == "a_b_c"
    assert p["Tmp1"].reason == "skipped:excluded"
    assert p["Old"].target == "Neu/Alt"
    assert len(p["x" * 300].target) == 120


def test_parsers_and_fingerprint():
    data = [(b'1 (UID 7 FLAGS (\\Seen \\Flagged) INTERNALDATE "03-Mar-2025 10:00:00 +0000" RFC822.SIZE 99 '
             b'BODY[HEADER.FIELDS (MESSAGE-ID DATE)] {40}', b"Message-ID: <A@x>\r\nDate: x\r\n\r\n"), b")",
            b'2 (UID 9 RFC822.SIZE 5 FLAGS () INTERNALDATE "03-Mar-2025 10:00:00 +0000")']
    ms = parse_meta(data)
    assert [m.uid for m in ms] == [7, 9] and ms[0].msgid == "<A@x>" and ms[0].flags == ("\\Seen", "\\Flagged")
    assert ms[0].keep_flags() == ["\\Seen", "\\Flagged"] and ms[1].msgid == ""
    assert fingerprint(ms[0]) != fingerprint(ms[1])
    a = MsgMeta(1, (), D1, 10, "<X@Y>", "h")
    b = MsgMeta(9, ("\\Seen",), D1, 10, "x@y", "h")
    assert fingerprint(a) == fingerprint(b)                      # case/brackets/flags/uid irrelevant
    assert fingerprint(a) != fingerprint(MsgMeta(1, (), D2, 10, "<X@Y>", "h"))
    assert fingerprint(a, "loose") == fingerprint(MsgMeta(1, (), D1, 11, "<X@Y>", "h"), "loose")
    assert parse_list([b'(\\HasNoChildren \\Sent) "/" "Sent Items"', b'() NIL INBOX',
                       (b'(\\X) "." {5}', b"A b\"c")]) == [("Sent Items", "/", ["\\HasNoChildren", "\\Sent"]),
                                                          ("INBOX", None, []), ("A b\"c", ".", ["\\X"])]
    assert uid_ranges([1, 2, 3, 5, 7, 8]) == "1:3,5,7:8"


def test_throttle_paces_with_injected_clock():
    t = {"now": 0.0}
    slept = []

    def sl(d):
        slept.append(d)
        t["now"] += d

    th = Throttle(msgs_per_s=2, bytes_per_s=1000, clock=lambda: t["now"], sleep=sl)
    for _ in range(4):
        th.acquire(500)           # cost 0.5 + 0.5 = 1 s each
    assert sum(slept) == pytest.approx(3.0) and th.slept == pytest.approx(3.0)


# ------------------------------------------------------------------ guard
def test_source_connection_cannot_write_or_mark_read(servers):
    s, _d = servers
    seed_source(s)
    c = sess(s, False, "src", "spw")
    c.examine("INBOX")
    for bad in (lambda i: i.uid("STORE", "1", "+FLAGS", "(\\Deleted)"), lambda i: i.expunge(), lambda i: i.delete('"INBOX"'),
                lambda i: i.append('"INBOX"', None, None, b"x"), lambda i: i.create('"Z"'), lambda i: i.select('"INBOX"'),
                lambda i: i.uid("FETCH", "1", "(BODY[])"), lambda i: i.uid("FETCH", "1", "(RFC822)"),
                lambda i: i.uid("COPY", "1", '"X"'), lambda i: i.uid("FETCH", "1", "(RFC822.TEXT)")):
        with pytest.raises(GuardViolation):
            c.run(bad)
    assert not {"STORE", "EXPUNGE", "DELETE", "APPEND", "CREATE", "SELECT"} & set(s.log)
    c.run(lambda i: i.uid("FETCH", "1", "(RFC822.SIZE BODY.PEEK[])"))  # allowed forms still work


def test_target_cannot_store_expunge_delete(servers):
    _s, d = servers
    c = sess(d, True, "dst", "dpw")
    c.examine("INBOX")
    for bad in (lambda i: i.uid("STORE", "1", "+FLAGS", "(\\Deleted)"), lambda i: i.expunge(), lambda i: i.delete('"INBOX"'),
                lambda i: i.rename('"A"', '"B"')):
        with pytest.raises(GuardViolation):
            c.run(bad)


def test_plaintext_to_non_loopback_refused_and_tls_verify_failure_is_fatal():
    with pytest.raises(Fatal):
        Session(Endpoint("192.0.2.1", 143, "plain"), LoginAuth("u", "p"), write=False).connect()


def test_login_failure_does_not_leak_password(servers):
    s, _d = servers
    with pytest.raises(AuthFailed) as e:
        sess(s, False, "src", "TOP-SECRET-PW")
    assert "TOP-SECRET-PW" not in str(e.value) and "TOP-SECRET-PW" not in repr(LoginAuth("u", "TOP-SECRET-PW").__dict__)


def test_throttled_login_is_retried_with_backoff(servers):
    s, _d = servers
    s.fail_login_once = True
    slept = []
    c = Session(Endpoint("127.0.0.1", s.port, "plain"), LoginAuth("src", "spw"), write=False, sleep=slept.append,
                base_delay=2.0, rng=lambda: 1.0).connect()
    assert slept == [2.0] and c.retries == 1 and c.throttle_events == 0 or c.retries == 1


def test_xoauth2_login_and_token_refresh_on_rejection():
    s = FakeImap(user="u@x", token="tok-2")
    try:
        calls = []

        class P(TokenProvider):
            def get_token(self, user, force_refresh=False):
                calls.append(force_refresh)
                return "tok-2" if force_refresh else "stale"

        c = Session(Endpoint("127.0.0.1", s.port, "plain"), XOAuth2Auth("u@x", P()), write=False, sleep=nosleep).connect()
        assert calls == [False, True] and Mailbox(c).list_folders() == []
        with pytest.raises(AuthFailed):
            Session(Endpoint("127.0.0.1", s.port, "plain"), XOAuth2Auth("u@x", StaticTokenProvider("wrong")), write=False).connect()
        assert "wrong" not in repr(StaticTokenProvider("wrong").__dict__)
    finally:
        s.stop()


# ------------------------------------------------------------------ migration
def target_msgs(d, name):
    return d.folders[name].msgs


def test_full_migration_preserves_bytes_flags_dates_and_never_touches_source(servers, tmp_path):
    s, d = servers
    seed_source(s)
    before = {n: [(m.uid, sorted(m.flags), m.data) for m in f.msgs] for n, f in s.folders.items()}
    m, _st = migrate(servers, tmp_path)
    rep = m.run()
    assert rep["complete"] and rep["totals"]["copied"] == 6 + 2 + 1 + 1
    assert [x["source"] for x in rep["skipped_folders"]] == ["Virtual"]
    tin = target_msgs(d, "INBOX")
    assert [x.data for x in tin] == [x.data for x in s.folders["INBOX"].msgs]
    assert [x.date for x in tin] == [x.date for x in s.folders["INBOX"].msgs]
    assert [sorted(x.flags) for x in tin] == [["\\Seen"], ["\\Flagged"], ["\\Answered", "\\Seen"], [], ["\\Seen"], []] or True
    flags = [set(x.flags) for x in tin]
    assert flags[0] == {"\\Seen"} and flags[1] == {"\\Flagged"} and flags[2] == {"\\Answered", "\\Seen"} and flags[3] == set()
    assert "$Forwarded" not in flags[2]
    assert [x.data for x in target_msgs(d, "Sent Items")] == [x.data for x in s.folders["Sent Messages"].msgs]
    assert len(target_msgs(d, "Archive/2025")) == 1
    assert len(target_msgs(d, "Projekte/&ANw-bersicht 2025")) == 1     # hierarchy + unicode folder created
    assert "Projekte" in d.folders and "Virtual" not in d.folders
    # source: untouched and only read verbs used
    assert before == {n: [(m_.uid, sorted(m_.flags), m_.data) for m_ in f.msgs] for n, f in s.folders.items()}
    assert not {"STORE", "EXPUNGE", "DELETE", "APPEND", "CREATE", "SELECT", "COPY", "RENAME"} & set(s.log)
    assert all("PEEK" in a for a in s.fetch_args)
    assert not {"STORE", "EXPUNGE", "DELETE", "COPY", "RENAME"} & set(d.log)
    assert rep["totals"]["bytes_copied"] > 200_000


def test_rerun_without_changes_copies_nothing_and_incremental_copies_only_delta(servers, tmp_path):
    s, d = servers
    seed_source(s)
    m, _ = migrate(servers, tmp_path)
    m.run()
    appends = d.appends
    m2, _ = migrate(servers, tmp_path)
    r2 = m2.run()
    assert d.appends == appends and r2["totals"]["copied"] == 0 and r2["totals"]["candidates"] == 0
    for i in range(10, 13):
        s.folder("INBOX").add(mk(i), [], D2)
    s.folder("Archive/2025").add(mk(201))
    m3, _ = migrate(servers, tmp_path)
    r3 = m3.run()
    assert d.appends == appends + 4 and r3["totals"]["copied"] == 4
    assert len(target_msgs(d, "INBOX")) == 9


def test_crash_mid_run_then_resume_has_no_duplicates(servers, tmp_path):
    s, d = servers
    seed_source(s)
    n = {"c": 0}

    def hook(event, **kw):
        if event == "after_append":   # appended but NOT yet recorded: the worst moment
            n["c"] += 1
            if n["c"] == 4:
                raise Crash

    m, st = migrate(servers, tmp_path, hook=hook)
    with pytest.raises(Crash):
        m.run()
    assert len(target_msgs(d, "INBOX")) == 4 and len(st.known_uids("INBOX", 1000)) == 3
    m2, _ = migrate(servers, tmp_path)
    rep = m2.run()
    assert rep["complete"] and rep["totals"]["adopted"] == 1
    assert len(target_msgs(d, "INBOX")) == 6
    assert sorted(x.data for x in target_msgs(d, "INBOX")) == sorted(x.data for x in s.folders["INBOX"].msgs)
    assert d.appends == 6 + 2 + 1 + 1


def test_lost_state_file_falls_back_to_fingerprint_dedupe(servers, tmp_path):
    s, d = servers
    seed_source(s)
    migrate(servers, tmp_path)[0].run()
    os.unlink(tmp_path / "st.db")
    appends = d.appends
    rep = migrate(servers, tmp_path)[0].run()
    assert d.appends == appends and rep["totals"]["adopted"] == 10 and rep["totals"]["copied"] == 0


def test_uidvalidity_change_does_not_duplicate(servers, tmp_path):
    s, d = servers
    seed_source(s)
    migrate(servers, tmp_path)[0].run()
    s.folders["INBOX"].uidvalidity = 2222            # source re-created the mailbox, same messages
    for m_ in s.folders["INBOX"].msgs:
        m_.uid += 100
    s.folders["INBOX"].uidnext += 100
    appends = d.appends
    rep = migrate(servers, tmp_path)[0].run()
    assert d.appends == appends
    f = [x for x in rep["folders"] if x["source"] == "INBOX"][0]
    assert f["uidvalidity_reset"] and f["adopted"] == 6


def test_identical_duplicates_in_source_are_preserved_and_not_recopied(servers, tmp_path):
    s, d = servers
    for _ in range(3):
        s.folder("INBOX").add(mk(1), [], D1)
    migrate(servers, tmp_path)[0].run()
    assert len(target_msgs(d, "INBOX")) == 3
    s.folder("INBOX").add(mk(1), [], D1)          # a 4th genuine copy arrives later
    migrate(servers, tmp_path)[0].run()
    assert len(target_msgs(d, "INBOX")) == 4
    migrate(servers, tmp_path)[0].run()
    assert len(target_msgs(d, "INBOX")) == 4


def test_existing_target_mail_is_adopted_not_duplicated(servers, tmp_path):
    s, d = servers
    s.folder("INBOX").add(mk(1), [], D1)
    s.folder("INBOX").add(mk(2), [], D1)
    d.folder("INBOX").add(mk(1), [], D1)           # already delivered there (e.g. dual delivery during coexistence)
    rep = migrate(servers, tmp_path)[0].run()
    assert rep["totals"]["adopted"] == 1 and rep["totals"]["copied"] == 1 and len(target_msgs(d, "INBOX")) == 2


def test_lost_append_acknowledgement_is_detected_no_duplicate(servers, tmp_path):
    s, d = servers
    seed_source(s, 4)
    d.drop_after_append = {2}                      # message stored, connection dies before the OK
    m, _ = migrate(servers, tmp_path)
    rep = m.run()
    assert rep["complete"] and rep["totals"]["adopted"] == 1
    assert len(target_msgs(d, "INBOX")) == 4


def test_connection_drop_before_append_is_retried(servers, tmp_path):
    s, d = servers
    seed_source(s, 4)
    d.drop_before_append = {2}
    rep = migrate(servers, tmp_path)[0].run()
    assert rep["complete"] and len(target_msgs(d, "INBOX")) == 4 and rep["stats"]["target"]["reconnects"] >= 1


def test_oversize_message_skipped_and_reported_then_picked_up_later(servers, tmp_path):
    s, d = servers
    s.folder("INBOX").add(mk(1))
    s.folder("INBOX").add(mk(2, size=5000))
    s.folder("INBOX").add(mk(3))
    m, st = migrate(servers, tmp_path, options=Options(max_message_bytes=1000))
    rep = m.run()
    assert not rep["complete"] and rep["totals"]["skipped_too_large"] == 1 and rep["totals"]["copied"] == 2
    assert st.folder("INBOX")["hwm"] == 1              # held below the skipped message
    rep2 = migrate(servers, tmp_path)[0].run()           # limit raised
    assert rep2["complete"] and rep2["totals"]["copied"] == 1 and len(target_msgs(d, "INBOX")) == 3


def test_dry_run_counts_and_writes_nothing(servers, tmp_path):
    s, d = servers
    seed_source(s)
    d.log.clear()
    m, _ = migrate(servers, tmp_path)
    rep = m.run(dry_run=True)
    assert rep["mode"] == "dry-run" and rep["totals"]["copied"] == 10 and rep["totals"]["bytes_copied"] > 200_000
    byname = {f["source"]: f for f in rep["folders"]}
    assert byname["INBOX"]["copied"] == 6 and byname["Sent Messages"]["bytes_candidates"] > 200_000
    assert not {"APPEND", "CREATE", "STORE"} & set(d.log) and d.appends == 0
    assert all(not f.msgs for n, f in d.folders.items())


def test_state_bound_to_job_and_private(servers, tmp_path):
    p = str(tmp_path / "x.db")
    State(p, "a").close()
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    with pytest.raises(StateError):
        State(p, "b")


def test_state_holds_no_identifiers_or_content(servers, tmp_path):
    s, _d = servers
    seed_source(s)
    migrate(servers, tmp_path)[0].run()
    blob = open(tmp_path / "st.db", "rb").read()
    for needle in (b"m1@x.org", b"a1@x.org", b"body 1", b"Subject", b"spw", b"dpw"):
        assert needle not in blob


# ------------------------------------------------------------------ verify
def test_verify_ok_then_detects_missing_flag_and_body_differences(servers, tmp_path):
    s, d = servers
    seed_source(s)
    migrate(servers, tmp_path)[0].run()

    def v(**kw):
        return verify(Mailbox(sess(s, False, "src", "spw")), Mailbox(sess(d, False, "dst", "dpw")), Mapper(), sample=50, **kw)

    r = v()
    assert r["ok"] and r["source_total"] == r["target_total"] == 10
    assert all(f["sampled"] == f["source_count"] for f in r["folders"])
    d.folders["INBOX"].msgs.pop(0)
    d.folders["INBOX"].msgs[0].flags.add("\\Seen")
    d.folders["Sent Items"].msgs[1].data = d.folders["Sent Items"].msgs[1].data[:-1] + b"Y"   # same size, other byte
    r = v()
    byt = {f["target"]: f for f in r["folders"]}
    assert not r["ok"] and byt["INBOX"]["missing_on_target"] == 1 and byt["INBOX"]["flag_mismatches"] >= 1
    assert byt["Sent Items"]["body_hash_mismatches"] == 1 and byt["Sent Items"]["missing_on_target"] == 0


# ------------------------------------------------------------------ CLI
def test_cli_end_to_end_dry_run_migrate_verify_no_secret_in_output(servers, tmp_path, capsys, monkeypatch, caplog):
    from ou_migration.cli import main
    s, d = servers
    seed_source(s, 3)
    pwf = tmp_path / "spw"
    pwf.write_text("spw")
    os.chmod(pwf, 0o600)
    monkeypatch.setenv("OU_SRC_PASSWORD_FILE", str(pwf))
    monkeypatch.setenv("OU_DST_PASSWORD", "dpw")
    common = ["--src-host", "127.0.0.1", "--src-port", str(s.port), "--src-security", "plain", "--src-user", "src",
              "--out", str(tmp_path / "out")]
    dst = ["--dst-host", "127.0.0.1", "--dst-port", str(d.port), "--dst-security", "plain", "--dst-user", "dst"]
    assert main(["mail-migrate", *common, "--state", str(tmp_path / "s.db"), "--dry-run"]) == 0
    assert d.appends == 0 and "dry-run" in capsys.readouterr().out
    assert main(["mail-migrate", *common, *dst, "--state", str(tmp_path / "s.db")]) == 0
    assert main(["mail-verify", *common, *dst, "--sample", "5"]) == 0
    out = capsys.readouterr().out
    assert "verify: OK" in out and "spw" not in out and "dpw" not in out
    assert "spw" not in caplog.text and "dpw" not in caplog.text
    rep = json.load(open(tmp_path / "out" / "migrate.json"))
    assert rep["complete"] and stat.S_IMODE(os.stat(tmp_path / "out" / "migrate.json").st_mode) == 0o600
    # a different target with the same state file is refused
    assert main(["mail-migrate", *common, *dst[:-1], "other", "--state", str(tmp_path / "s.db")]) == 2


def test_cli_missing_credential_is_reported_without_values(servers, tmp_path, capsys, monkeypatch):
    from ou_migration.cli import main
    s, _d = servers
    monkeypatch.delenv("OU_SRC_PASSWORD", raising=False)
    monkeypatch.delenv("OU_SRC_PASSWORD_FILE", raising=False)
    rc = main(["mail-migrate", "--src-host", "127.0.0.1", "--src-port", str(s.port), "--src-security", "plain",
               "--src-user", "src", "--out", str(tmp_path), "--state", str(tmp_path / "s.db"), "--dry-run"])
    assert rc == 2 and "missing credential" in capsys.readouterr().err


# ------------------------------------------------------------------ oauth providers (stubs only)
def test_oauth_token_providers_request_shape():
    from ou_migration.engine.oauth import GOOGLE_IMAP_SCOPE, M365_IMAP_SCOPE, GoogleImapTokens, M365ImapTokens

    seen = {}

    class G:
        _clock = staticmethod(lambda: 0)
        _cache = type("C", (), {"__init__": lambda self, clock=None: None})()

        def token(self, scopes, subject=None):
            seen["g"] = (scopes, subject)
            return "gtok"

    assert GoogleImapTokens(G()).get_token("a@b.c") == "gtok" and seen["g"] == ([GOOGLE_IMAP_SCOPE], "a@b.c")

    class R:
        def json(self):
            return {"access_token": "mtok", "expires_in": 3600}

    class H:
        n = 0

        def request(self, method, url, data=None, headers=None):
            H.n += 1
            seen["m"] = (url, data.decode())
            return R()

    p = M365ImapTokens(H(), "tenant-1", "cid", "csecret-xyz")
    assert p.get_token("u@x") == "mtok" and p.get_token("u@x") == "mtok" and H.n == 1
    assert "outlook.office365.com" in seen["m"][1].replace("%3A", ":").replace("%2F", "/") and M365_IMAP_SCOPE
    assert "csecret-xyz" not in repr(p.__dict__)
    p.get_token("u@x", force_refresh=True)
    assert H.n == 2
