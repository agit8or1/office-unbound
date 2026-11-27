"""Dashboard and app shell (concept alignment 2026-11-26): preferences, the groupware reader contract and the agenda rules, rendered against
the mock identity provider / OpenCloud of test_portal plus a mock groupware reader. No network."""
import dataclasses
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_portal as T  # noqa: E402
from app import dashboard as D  # noqa: E402
from app.config import _https_url  # noqa: E402
from app.main import create_app  # noqa: E402

TZ = timezone(timedelta(hours=1))
NOW = datetime(2026, 11, 16, 8, 52, tzinfo=TZ)
READER = "https://mail.test/ou-dashboard/v1"


def ev(subject, h1, m1, h2, m2, day=16, **kw):
    e = {"subject": subject, "start": datetime(2026, 11, day, h1, m1, tzinfo=TZ).isoformat(), "end": datetime(2026, 11, day, h2, m2, tzinfo=TZ).isoformat()}
    e.update(kw)
    return e


def summary(**over):
    s = {"version": 1, "mailbox": "bob@example.test", "unread": 12, "events": [
        ev("Team stand-up", 9, 0, 9, 15, location="Meet", attendees=["Dana Whitlock", "Priya Nair"], join_url="https://meet.test/abc"),
        ev("Harbor Street Dental", 10, 30, 11, 0, attendees=["Grace Lin"]),
        ev("Focus: accrual review", 10, 45, 12, 0),                                            # overlaps the 10:30
        ev("Declined thing", 13, 0, 14, 0, response="declined", attendees=["X Y"]),
        ev("Out of office", 0, 0, 0, 0, day=17, all_day=True) | {"start": "2026-11-16T00:00:00+01:00"},
        ev("Brightwater onboarding", 11, 0, 12, 0, day=17, attendees=["A B", "C D"], join_url="javascript:alert(1)"),
        ev("Year-end planning", 10, 0, 11, 0, day=19, location="Board room", join_url="https://meet.test/ye", organizer="Ana Petrov", attendees=["A"]),
        ev("Solo block next week", 9, 0, 10, 0, day=18)],                                       # no attendees, no link: not a meeting
        "attention": [
            {"kind": "invitation", "from": "Ana Petrov", "subject": "Invitation: Year-end planning", "received": "2026-11-16T08:12:00+01:00"},
            {"kind": "flagged", "from": "Grace Lin", "subject": "October statement", "received": "2026-11-15T10:00:00+01:00", "due": "2026-11-18T00:00:00+01:00"},
            {"kind": "spam", "from": "x", "subject": "y", "received": "2026-11-16T08:00:00+01:00"},
            {"kind": "flagged", "from": "No time", "subject": "z", "received": "2026-11-16T08:00:00"}]}     # floating time: dropped
    s.update(over)
    return s


# ---- preferences --------------------------------------------------------------------------------------------------------------------
def test_prefs_round_trip_keeps_order_rail_and_density_and_reads_the_old_cookie():
    p = D.parse_prefs("dark:recent:notifications.meetings.agenda:xc")
    assert p["theme"] == "dark" and p["hidden"] == ["recent"] and p["rail"] == "expanded" and p["density"] == "compact"
    assert p["order"][:3] == ["notifications", "meetings", "agenda"] and sorted(p["order"]) == sorted(D.WIDGETS)
    assert D.parse_prefs(D.dump_prefs(p)) == p
    assert D.dump_prefs(D.parse_prefs("light:shared")) == "light:shared"                     # defaults add nothing to the cookie
    assert D.parse_prefs("system:inbox.create")["hidden"] == []                              # 0.13 widgets that no longer exist
    assert re.fullmatch(r"[a-z:.]+", D.dump_prefs({**p, "hidden": list(D.WIDGETS)}))


def test_moving_a_widget_stays_inside_its_column():
    order = list(D.DEFAULT_ORDER)
    moved = D.move(order, "shared", "up")
    assert D.columns({"order": moved, "hidden": []})["main"] == ["attention", "shared", "recent"]
    assert D.move(order, "attention", "up") == order                                          # already first in its column
    assert D.move(order, "agenda", "down") == order                                           # alone in its column
    assert D.move(order, "nope", "up") == order and D.move(order, "recent", "sideways") == order
    assert D.columns({"order": order, "hidden": ["recent", "meetings"]}) == {"side": ["agenda"], "main": ["attention", "shared"],
                                                                            "aside": ["notifications", "favorites"]}


# ---- reader contract and agenda rules -------------------------------------------------------------------------------------------------
def test_the_reader_answer_must_name_the_users_own_mailbox_and_version():
    assert D.normalise(summary(), "bob@example.test", TZ) is not None
    assert D.normalise(summary(), "BOB@example.test", TZ) is not None
    assert D.normalise(summary(mailbox="anna@example.test"), "bob@example.test", TZ) is None     # never another mailbox's data
    assert D.normalise(summary(), "", TZ) is None
    assert D.normalise(summary(version=2), "bob@example.test", TZ) is None
    assert D.normalise(["x"], "bob@example.test", TZ) is None
    s = D.normalise(summary(unread=True), "bob@example.test", TZ)
    assert s["unread"] is None                                                                 # a bool is not a count
    assert [a["kind"] for a in s["attention"]] == ["invitation", "flagged"]                    # unknown kind and floating time dropped
    links = {e["subject"]: e["join_url"] for e in s["events"]}
    assert links["Brightwater onboarding"] is None and links["Team stand-up"] == "https://meet.test/abc"   # only https links


def test_agenda_now_line_conflicts_next_meeting_and_upcoming():
    s = D.normalise(summary(), "bob@example.test", TZ)
    ag = D.agenda(s, NOW)
    assert [e["subject"] for e in ag["timed"]] == ["Team stand-up", "Harbor Street Dental", "Focus: accrual review"]   # declined left out
    assert [e["subject"] for e in ag["all_day"]] == ["Out of office"]
    assert ag["now_at"] == 0 and ag["next"]["subject"] == "Team stand-up" and ag["next_in"] == "in 8 minutes"
    assert [e["conflict"] for e in ag["timed"]] == [False, True, True] and ag["conflicts"] == 2
    assert [e["subject"] for e in ag["upcoming"]] == ["Brightwater onboarding", "Year-end planning"]
    assert D.headline(NOW.date(), ag) == "Monday 16 November · three meetings today, the next in 8 minutes"
    later = D.agenda(s, NOW.replace(hour=10, minute=40))
    assert later["now_at"] == 2 and later["next"]["subject"] == "Harbor Street Dental" and later["next_in"] == "now"
    assert later["timed"][0]["past"] and later["timed"][1]["current"]
    assert D.agenda(s, NOW.replace(hour=20))["next"] is None
    assert D.agenda(None, NOW) is None and D.headline(NOW.date(), None) == "Monday 16 November"
    assert D.headline(NOW.date(), D.agenda(D.normalise(summary(events=[]), "bob@example.test", TZ), NOW)).endswith("no meetings today")


def test_attention_feed_merges_mail_items_and_recent_shares_newest_first():
    s = D.normalise(summary(), "bob@example.test", TZ)
    shared = [{"name": "Budget.xlsx", "mtime": datetime(2026, 11, 16, 7, 0, tzinfo=timezone.utc), "by": "Anna", "url": "https://cloud.test/f/1", "kind": "spreadsheet"},
              {"name": "Old.docx", "mtime": datetime(2026, 10, 1, tzinfo=timezone.utc), "by": "Anna", "url": "https://cloud.test/f/2", "kind": "document"}]
    feed = D.attention_feed(s, shared, NOW)
    assert [(i["kind"], i["subject"]) for i in feed] == [("invitation", "Invitation: Year-end planning"), ("share", "Budget.xlsx"),
                                                       ("flagged", "October statement")]                         # 6 weeks old share: not news
    assert D.attention_feed(None, None, NOW) == []


def test_greeting_initials_and_countdown():
    assert [D.greeting(NOW.replace(hour=h)) for h in (6, 13, 19, 2)] == ["Good morning", "Good afternoon", "Good evening", "Good evening"]
    assert D.initials("Maya Okafor") == "MO" and D.initials("bob") == "B" and D.initials("") == "?" and D.initials("Anna van der Berg") == "AB"
    assert D.countdown(NOW, NOW + timedelta(minutes=1)) == "in 1 minute" and D.countdown(NOW, NOW + timedelta(hours=3)) == "at 11:52"


def test_reader_url_must_be_plain_https():
    assert _https_url("https://mail.test/ou-dashboard/v1/") == "https://mail.test/ou-dashboard/v1"
    for bad in ("http://mail.test/x", "https://", "https://u:p@mail.test", "https://mail.test/x?y=1", "", None, "ftp://x"):
        assert _https_url(bad) == "", bad


# ---- rendered against mocks -----------------------------------------------------------------------------------------------------------
class Reader(T.Mock):
    def __init__(self):
        super().__init__()
        self.answer = (200, summary())
        self.reader_auth = []

    def handler(self, req):
        if str(req.url).startswith(READER + "/summary"):
            self.reader_auth.append(req.headers.get("authorization"))
            st, body = self.answer
            return httpx.Response(st, json=body)
        return super().handler(req)


@pytest.fixture()
def reader_env(monkeypatch):
    m = Reader()
    m.notes = [{"datetime": "2026-11-16T07:41:00Z", "subject": "Priya Nair shared Accruals with you", "message": ""}]
    from app import services
    async def chat_up(cfg, http):
        return True
    monkeypatch.setattr(services, "chat_available", chat_up)
    monkeypatch.setattr(D, "agenda", lambda s, now, _a=D.agenda: _a(s, NOW) if s is not None else None)   # a fixed "now" for the page
    app = create_app(dataclasses.replace(T.CFG, groupware_reader_url=READER, chat_url="https://chat.test"), transport=httpx.MockTransport(m.handler))
    with TestClient(app, base_url=T.BASE) as c:
        c.follow_redirects = False
        _, q = T.login(c, m)
        T.finish(c, q)
        yield c, m


def test_dashboard_shows_the_users_own_agenda_read_with_their_own_token(reader_env):
    c, m = reader_env
    html = c.get("/").text
    assert m.reader_auth and set(m.reader_auth) == {"Bearer AT1"}                         # the user's access token, nothing else
    nxt = html.split('class="nextcard', 1)[1].split('id="h-agenda"', 1)[0]
    assert "Team stand-up" in nxt and 'href="https://meet.test/abc"' in nxt and ">DW<" in nxt
    agenda = html.split('id="h-agenda"', 1)[1].split("</section>", 1)[0]
    assert agenda.count('class="ev') == 3 and agenda.count('class="nowline"') == 1 and "Overlaps another event" in agenda
    assert agenda.index('class="nowline"') < agenda.index("Team stand-up")
    assert "Declined thing" not in html and "javascript:" not in html
    meet = html.split('id="h-meetings"', 1)[1].split("</section>", 1)[0]
    assert "Brightwater onboarding" in meet and "Year-end planning" in meet and 'href="https://meet.test/ye"' in meet and "Solo block" not in meet
    att = html.split('id="h-attention"', 1)[1].split("</section>", 1)[0]
    assert "Needs a response" in att and "Flagged · due " in att and "Anna Meyer shared a file with you" in att
    assert "not on the dashboard yet" not in html
    notes = html.split('id="h-notes"', 1)[1].split("</section>", 1)[0]
    assert "Priya Nair shared Accruals with you" in notes


def test_a_reader_answer_for_another_mailbox_or_an_error_is_never_shown(reader_env):
    c, m = reader_env
    m.answer = (200, summary(mailbox="anna@example.test"))
    html = c.get("/").text
    assert "Team stand-up" not in html and html.count("Calendar did not answer") == 2
    m.answer = (500, {})
    html = c.get("/").text
    assert "Team stand-up" not in html and "Mail could not be read just now" in html


def test_hidden_calendar_widgets_do_not_ask_the_reader(reader_env):
    c, m = reader_env
    tok = T._csrf(c.get("/").text)
    m.reader_auth.clear()
    c.post("/prefs", data={"csrf": tok, "widgets_form": "1", "show": ["recent", "notifications"]})
    html = c.get("/").text
    assert m.reader_auth == [] and 'id="h-agenda"' not in html and 'id="h-recent"' in html


def test_shell_rail_bar_and_bottom_bar(reader_env):
    c, m = reader_env
    html = c.get("/").text
    rail = html.split('<nav class="rail" aria-label="Apps">', 1)[1].split("</nav>", 1)[0]
    keys = re.findall(r'<a class="ri([^"]*)" href="[^"]*" data-app="(\w+)"', rail)
    assert [k for _, k in keys] == ["home", "mail", "calendar", "contacts", "files", "docs", "chat", "settings"]
    assert [k for cls, k in keys if "extra" in cls] == ["docs", "chat"]                        # the phone bar: first five, the rest under More
    assert re.search(r'data-app="home" title="Home" aria-current="page"', rail)
    assert 'class="badge' not in rail                                                         # no count the portal cannot read
    assert '<span class="appname">Home</span>' in html and 'placeholder="Search files and folders"' in html
    assert 'aria-label="All apps"' in html and 'aria-label="Help"' in html and '<span class="avatar" aria-hidden="true">LB</span>' in html
    assert "rail-collapsed" in html and "dens-comfortable" in html
    assert "<script" not in html


def test_rail_density_order_and_reset_are_saved_per_user_with_csrf(reader_env):
    c, m = reader_env
    tok = T._csrf(c.get("/settings").text)
    assert c.post("/prefs", data={"csrf": "x", "rail": "expanded"}).status_code == 403
    r = c.post("/prefs", data={"csrf": tok, "rail": "expanded", "next": "/docs"})
    assert r.status_code == 303 and r.headers["location"] == "/docs"
    assert "rail-expanded" in c.get("/docs").text
    c.post("/prefs", data={"csrf": tok, "density": "compact"})
    c.post("/prefs", data={"csrf": tok, "widgets_form": "1", "show": list(D.WIDGETS), "move": "shared:up"})
    html = c.get("/").text
    assert "dens-compact" in html and html.index('id="h-shared"') < html.index('id="h-recent"')
    s = c.get("/settings").text
    assert re.search(r'name="move" value="attention:up" disabled', s) and 'value="favorites:down" disabled' in s
    c.post("/prefs", data={"csrf": tok, "reset": "1"})
    html = c.get("/").text
    assert "dens-comfortable" in html and "rail-expanded" in html and html.index('id="h-recent"') < html.index('id="h-shared"')


def test_docs_page_lists_office_files_only_and_creates_new_ones(reader_env):
    c, m = reader_env
    html = c.get("/docs").text
    assert 'data-file="new.xlsx"' in html and 'data-file="old.docx"' in html and 'data-file="dir"' not in html
    assert all(f'action="/new/{k}"' in html for k in ("document", "spreadsheet", "presentation"))
    assert 'data-app="docs" title="Docs" aria-current="page"' in html and '<span class="appname">Docs</span>' in html


def test_account_and_devices_pages_sit_under_settings_in_the_rail(reader_env):
    c, m = reader_env
    assert 'data-app="settings" title="Settings" aria-current="page"' in c.get("/devices").text
    assert 'class="rail"' in c.get("/account").text and 'data-app="settings" title="Settings" aria-current="page"' in c.get("/account").text
