"""Security review 4: M5 (IMAP command injection through folder names) and M6 (unbounded source literals), L6 date handling."""
import random

import pytest
from fakeimap import mk
from test_engine import D1, migrate, sess, seed_source, servers  # noqa: F401  (fixture re-export)

from ou_migration.engine.imapx import ImapError, TooLarge, UnsafeName, quote
from ou_migration.engine.mailbox import Mailbox, internaldate_epoch, safe_internaldate
from ou_migration.engine.migrate import Options

EVIL = 'x"\r\nZ2 UID STORE 1:* +FLAGS (\\Deleted)\r\nZ3 EXPUNGE\r\nZ4 DELETE "INBOX'
WRITE_VERBS = {"STORE", "EXPUNGE", "DELETE", "APPEND", "CREATE", "SELECT", "UID STORE", "UID COPY", "COPY", "RENAME"}


def test_crlf_folder_name_is_skipped_and_never_reaches_the_source(servers, tmp_path):
    s, d = servers
    seed_source(s)
    s.list_literal = True
    s.folder(EVIL).add(mk(500))
    m, st = migrate(servers, tmp_path)
    rep = m.run()
    assert any(f["reason"] == "skipped:unsafe-name" for f in rep["skipped_folders"])
    assert not WRITE_VERBS & set(s.log), s.log
    assert not any(v.startswith("Z") for v in s.log)
    assert len(s.folders["INBOX"].msgs) == 6 and all("\\Deleted" not in x.flags for x in s.folders["INBOX"].msgs)


@pytest.mark.parametrize("bad", ["a\r\nb", "a\nb", "a\rb", "a\x00b", "a\x1bb", "a\x7fb", EVIL])
def test_atoms_with_control_chars_are_refused_before_transmission(servers, bad):
    s, d = servers
    seed_source(s)
    c = sess(s, False, "src", "spw")
    before = list(s.log)
    for call in (lambda i: i.select(bad, readonly=True), lambda i: i.status(bad, "(MESSAGES)"), lambda i: i.list(bad),
                 lambda i: i.uid("FETCH", "1", bad), lambda i: i.login("u" + bad, "p")):
        with pytest.raises(ImapError):
            c.run(call)
    with pytest.raises(UnsafeName):
        quote(bad)
    with pytest.raises(UnsafeName):
        c.examine(bad)
    assert s.log == before          # nothing was sent for any of them
    t = sess(d, True, "dst", "dpw")
    with pytest.raises(ImapError):
        Mailbox(t).ensure_folder(bad, bad, set())
    with pytest.raises(ImapError):
        Mailbox(t).append(bad, [], None, b"x")


def test_fuzzed_folder_names_never_cause_a_write_verb_on_the_source(servers, tmp_path):
    rnd = random.Random(1234)
    s, d = servers
    seed_source(s)
    s.list_literal = True
    alphabet = ['"', "\\", "\r", "\n", "\x00", " ", "Z", "9", "UID STORE 1 +FLAGS (\\Deleted)", "EXPUNGE", "{", "}", "(", ")", "é", "&", "-", "/"]
    for _ in range(150):
        name = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(1, 12)))
        s.folder(name).add(mk(7))
    m, st = migrate(servers, tmp_path)
    m.run()
    assert not WRITE_VERBS & set(s.log), sorted(set(s.log))
    assert set(s.log) <= {"CAPABILITY", "LOGIN", "LIST", "EXAMINE", "UID FETCH", "UID SEARCH", "NOOP", "LOGOUT", "STATUS"}, sorted(set(s.log))
    assert all("\\Deleted" not in x.flags for f in s.folders.values() for x in f.msgs)


def test_literal_larger_than_advertised_size_is_refused_before_it_is_read(servers, tmp_path):
    s, d = servers
    s.folder("INBOX").add(mk(1, size=3_000_000), ["\\Seen"], D1)
    s.advertised_size = 1000
    m, st = migrate(servers, tmp_path)
    rep = m.run()
    assert rep["totals"]["failed"] == 1 and rep["totals"]["copied"] == 0 and not rep["complete"]
    assert len(d.folders["INBOX"].msgs) == 0


def test_hard_message_cap_is_enforced_on_the_wire_not_only_on_the_advertised_size(servers, tmp_path):
    s, d = servers
    s.folder("INBOX").add(mk(1, size=500_000), [], D1)
    s.advertised_size = 100
    m, st = migrate(servers, tmp_path, options=Options(max_message_bytes=100_000))
    rep = m.run()
    assert rep["totals"]["failed"] == 1 and len(d.folders["INBOX"].msgs) == 0


def test_oversized_non_body_literal_is_refused(servers):
    s, d = servers
    s.list_literal = True
    s.folder("L" * 2_000_000)
    c = Mailbox(sess(s, False, "src", "spw"))
    with pytest.raises(TooLarge):
        c.list_folders()


def test_bad_internaldate_does_not_crash_or_reach_the_target():
    assert internaldate_epoch("31-Foo-2025 10:00:00 +0000") == 0
    assert internaldate_epoch("31-Feb-2025 10:00:00 +0000") == 0
    assert safe_internaldate('03-Mar-2025 10:00:00 +0000" x\\') is None
    assert safe_internaldate(D1) == D1
