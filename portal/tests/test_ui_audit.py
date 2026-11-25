"""UI audit 2026-11-25: data fallbacks and the markup the responsive layout relies on (record-card tables, admin section menu).
The layout itself is checked in a browser by e2e/layout-check.cjs (no page-level horizontal scroll at 320/390 px)."""
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from app import services  # noqa: E402
from test_admin import env, signin  # noqa: E402,F401
from test_portal import login, finish, env as penv  # noqa: E402,F401


def test_session_times_never_fall_back_to_1970():
    assert services._epoch(None) is None and services._epoch(0) is None and services._epoch("x") is None
    assert services._epoch(2) is None                                              # implausible: unknown, not 1 Jan 1970
    assert services._epoch(1_763_000_000) == datetime.fromtimestamp(1_763_000_000, timezone.utc)
    assert services._epoch(1_763_000_000_000) == datetime.fromtimestamp(1_763_000_000, timezone.utc)   # milliseconds


def test_account_shows_unknown_instead_of_an_epoch_date(penv):
    c, m, _ = penv
    _, q = login(c, m)
    finish(c, q)
    t = c.get("/account").text                                                     # the mock's lastAccess is 2 (seconds)
    assert "1970" not in t and "Unknown" in t


def test_storage_data_does_not_leak_into_the_file_search_box(env):
    c, m, _ = env
    signin(c, m)
    t = c.get("/admin/storage").text
    box = re.search(r'<input id="q" name="q" type="search"[^>]*>', t).group(0)
    assert 'value=""' in box and "available" not in box
    people = c.get("/admin/users", params={"q": "anna"}).text
    assert re.search(r'<input id="q" name="q" type="search"[^>]*value=""', people)   # the people filter is not the file search
    assert people.count('id="q"') == 1 and 'id="pq"' in people


def test_admin_tables_carry_labels_for_the_phone_layout(env):
    c, m, _ = env
    signin(c, m)
    for path, labels in (("/admin", ("Asked by", "When", "Status")), ("/admin/requests", ("Asked by", "When", "Status")),
                         ("/admin/users", ("E-mail", "Apps", "Access")), ("/admin/groups", ("Gives access to", "People")),
                         ("/admin/storage", ("Mailbox", "Files", "New limits (MB)"))):
        t = c.get(path).text
        assert 'class="rt"' in t or 'rt">' in t, path
        for td in re.findall(r"<td[ >][^>]*", t):
            assert "data-label=" in td or "colspan" in td, (path, td)
        for lab in labels:
            assert f'data-label="{lab}"' in t, (path, lab)


def test_admin_navigation_has_a_compact_menu_naming_the_current_section(env):
    c, m, _ = env
    signin(c, m)
    t = c.get("/admin/storage").text
    assert '<details class="subnav-m">' in t
    assert re.search(r'<summary><span class="muted">Administration</span><b>Storage</b></summary>', t)
    assert t.count('href="/admin/storage" aria-current="page"') == 2           # tab row and menu agree


def test_overview_figures_link_to_their_lists(env):
    c, m, _ = env
    signin(c, m)
    t = c.get("/admin").text
    assert 'href="/admin/users?show=active"' in t and 'href="/admin/users?show=disabled"' in t
    assert '<li class="dom"><a class="stat" href="/admin/domains"><span class="t">example.test</span>' in t


def test_devices_tables_carry_labels_and_the_start_link_targets_the_dashboard(penv):
    c, m, _ = penv
    _, q = login(c, m)
    finish(c, q)
    t = c.get("/devices").text
    assert 'data-label="SHA-256"' in t and 'data-label="Server"' in t and 'class="appmatrix rt"' in t
    assert 'href="/#h-create"' in t and 'href="/#h-new"' not in t
    home = c.get("/").text
    assert 'id="h-create"' in home


def test_admin_app_choices_keep_their_names_when_branding_lists_apps(env):
    c, m, _ = env
    signin(c, m)
    assert m.branding["apps"]                                                      # the shell's app list is set
    for path in ("/admin/users/anna", "/admin/users/new", "/admin/groups"):
        t = c.get(path).text
        assert "<b>Mail, calendar and contacts</b>" in t and "<span><b></b></span>" not in t, path
