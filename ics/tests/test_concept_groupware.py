"""Concept alignment 2026-11-26, groupware (grommunio-web 5.2): calendar grid, primary action, dark parity.

Concept: docs/design/concepts/calendar.webp, mail-concept-page.png; frame: docs/design/app-shell.md. Supported hooks only: the brand stylesheet
(blueprints/catalog/templates/brand/grommunio.css, served as /brand/brand.css) and the Office Unbound plugin (debian/ou-plugins/oudashboard,
upstream insertion points). Upstream facts are checked against the 5.2 source when it is on this host (read-only).
"""
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
GW = ROOT / "blueprints/build/grommunio-web"
SKIN = ROOT / "blueprints/catalog/templates/brand/grommunio.css"
PLUGIN_JS = GW / "debian/ou-plugins/oudashboard/js/oudashboard.js"
UPSTREAM = Path("/var/lib/office-unbound/pkgbuild/src/grommunio-web")
CAL = "body.grommunio-webclient #grommunio-mainpanel-contentpanel-calendar"


def _css() -> str:
    return re.sub(r"/\*.*?\*/", "", SKIN.read_text(), flags=re.S)


def _rules(css: str) -> list[tuple[str, str]]:
    return [(sel.strip(), body) for sel, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css)]


def test_calendar_rules_change_colours_not_geometry():
    """ExtJS and the calendar views position every cell, header and appointment from their own measurements (inline left/top/width/height);
    the calendar and primary-action rules may only paint."""
    layout = re.compile(r"(?<![\w-])((min-|max-)?(width|height)|margin(-\w+)?|padding(-\w+)?|position|top|left|right|bottom|display|flex[\w-]*|"
                        r"grid[\w-]*|float|border(-(top|right|bottom|left))?-width)\s*:")
    hits = [(s, b) for s, b in _rules(_css()) if ("contentpanel-calendar" in s or "ou-primary-new" in s) and layout.search(b)]
    assert not hits, hits


def test_calendar_colours_are_tokens_and_cover_both_themes():
    css = _css()
    for s, b in _rules(css):
        if "contentpanel-calendar" in s:
            assert not re.search(r"#[0-9a-fA-F]{3,8}\b|rgba?\(", b), (s, b)   # tokens only (the [style*="#ffffff"] matcher is in the selector)
    light = css.split(CAL + " {", 1)[1].split("}", 1)[0]
    dark = css.split("body.grommunio-webclient.dark-mode #grommunio-mainpanel-contentpanel-calendar {", 1)[1].split("}", 1)[0]
    for prop in ("--ou-cal-off", "--ou-cal-today", "--ou-cal-tint"):
        assert prop in light and prop in dark, prop
    assert "--theme-primary-color: var(--ou-a);" in light   # today markers in the (organisation) accent, like the concept


def test_dark_grid_drops_upstreams_invert_filter_for_cells_and_month():
    css = _css()
    for sel in ('.k-html-body-background > div[class*="k-line-"] {', ".grommunio-calendar-boxview .k-html-body-background > div {"):
        body = css.split(sel, 1)[1].split("}", 1)[0]
        assert "filter: none !important" in body and "border-color: var(--ou-cal-line) !important" in body, sel
    up = UPSTREAM / "client/resources/css/darkmode.css"
    if up.exists():   # the rule being neutralised: upstream inverts inline-coloured cells and sets all four border longhands !important
        d = up.read_text()
        assert re.search(r'body\.dark-mode \[class\*="k-day-"\]\[class\*="k-line-"\] \{[^}]*filter: invert\(0\.85\) hue-rotate\(180deg\)', d)


def test_working_hours_are_found_by_the_schemes_fixed_working_colour():
    """Working-hours cells carry the scheme's `stripworking` colour, fixed #ffffff for every scheme (ColorSchemes.js), as an inline style."""
    assert '[class*="k-line-"][style*="#ffffff" i] {' in _css()
    up = UPSTREAM / "client/grommunio/calendar/ui/ColorSchemes.js"
    if up.exists():
        assert re.search(r"name: 'stripworking',\s*color: '#ffffff'", up.read_text())


def test_half_hour_rules_list_every_first_half_hour_line():
    css = _css()
    lines = re.search(r"div:is\(([^)]*)\) \{ border-bottom-color: var\(--ou-cal-half\) !important; \}", css)
    assert lines
    assert [int(n) for n in re.findall(r"\.k-line-(\d+)", lines.group(1))] == list(range(0, 48, 2))


def test_now_line_and_today_use_the_accent():
    css = _css()
    assert re.search(r"k-calendar-timestrip-indicator-line \{ background-color: var\(--ou-a\) !important;", css)
    assert "radial-gradient(circle, var(--ou-a) 0 4px, transparent 4.5px) !important" in css   # the sprite arrow as a dot
    assert "inset 0 3px 0 var(--ou-a)" in css   # today's header bar
    assert "td.x-date-today a { background: var(--ou-a) !important; color: var(--ou-a-ink) !important;" in css
    up = UPSTREAM / "client/grommunio/calendar/ui/html/CalendarDaysView.js"
    if up.exists():   # the indicator the rules restyle exists upstream (CalendarDaysView#drawCurrentTimeIndicator)
        js = up.read_text()
        assert "k-calendar-timestrip-indicator-line" in js and "drawCurrentTimeIndicator" in js


def test_appointments_keep_their_calendar_colour_as_a_bar_and_a_tint():
    css = _css()
    box = css.split(CAL + " .k-appointment-box {", 1)[1].split("}", 1)[0]
    assert "linear-gradient(90deg, transparent 6px, var(--ou-cal-tint) 6px) !important" in box   # inline calendar colour shows through
    assert "color: var(--ou-ink) !important" in box
    # the white icon variants of dark colours (AppointmentDaysView: icon_<name>_white) stay visible on the light tint
    assert ".k-appointment-box.k-dark [class*=\"icon_\"] { filter: brightness(0)" in css


def test_primary_action_plugin_uses_only_upstream_insertion_points_and_actions():
    js = PLUGIN_JS.read_text()
    assert re.findall(r"registerInsertionPoint\('([^']+)'", js) == ["navigation.north", "main.maintabbar.left"]
    for ctx, label, fn in (("mail", "New message", "openCreateMailContent"), ("calendar", "New event", "openCreateAppointmentContent"),
                           ("contact", "New contact", "openCreateContactContent"), ("task", "New task", "openCreateTaskContent"),
                           ("note", "New note", "openCreateNoteContent")):
        assert f"['{ctx}', _('{label}'), " in js and f"'{fn}']" in js, ctx
    assert "navigationContext: context" in js   # upstream shows the button only while its context is active
    assert "height: 36" in js and "margins: '12 12 6 12'" in js   # geometry through ExtJS, never through the stylesheet
    assert "p.insert(0, c)" in js and "'beforerender'" in js   # moved before render, through the container API
    assert not re.search(r"\.style\.|innerHTML|setStyle\(|document\.", js)   # no DOM scripting
    if (UPSTREAM / "client/grommunio").exists():
        up = UPSTREAM / "client/grommunio"
        nav = (up / "core/ui/NavigationPanel.js").read_text()
        assert "populateInsertionPoint('navigation.north', this)" in nav and "item.navigationContext == this.activeContext" in nav
        for path, fn in (("mail/Actions.js", "openCreateMailContent"), ("calendar/Actions.js", "openCreateAppointmentContent"),
                         ("contact/Actions.js", "openCreateContactContent"), ("task/Actions.js", "openCreateTaskContent"),
                         ("note/Actions.js", "openCreateNoteContent")):
            assert re.search(rf"\b{fn}\s*:\s*function", (up / path).read_text()), fn


def test_toolbar_new_steps_back_only_when_the_primary_action_exists():
    css = _css()
    assert re.search(r":has\(\.ou-primary-new\) #grommunio-maintoolbar-newitem", css)   # an ou6 client (no plugin button) keeps the copper New
    assert not re.search(r"#grommunio-maintoolbar-newitem[^{]*\{[^}]*display\s*:", css)


def test_the_plugin_revision_is_packaged_and_pinned():
    rev = yaml.safe_load((GW / "recipe.yaml").read_text())["ou_revision"]
    assert rev >= "ou7"
    comp = yaml.safe_load((ROOT / "blueprints/catalog/components/groupware.yaml").read_text())
    assert next(a["version"] for a in comp["artifacts"] if a.get("package") == "ou-grommunio-web") == f"5.2-{rev}"
    rules = (GW / "debian/rules").read_text()
    assert "cp -a debian/ou-plugins/oudashboard $(APP)/plugins/oudashboard" in rules


@pytest.mark.skipif(not (UPSTREAM / "client/grommunio/core/ui/MainViewport.js").exists(), reason="upstream 5.2 source not here")
def test_the_bar_height_and_west_region_are_fixed_upstream():
    """Evidence for the documented limits (docs/design/upstream-modifications.md): the main tab bar is 36px by constructor constants and the
    viewport's west region holds the navigation panel; there is no insertion point or setting for a 48px bar or a 64px app rail."""
    vp = (UPSTREAM / "client/grommunio/core/ui/MainViewport.js").read_text()
    assert re.search(r"name: 'main\.maintabbar',\s*region: 'center',\s*height: 36,\s*boxMinHeight: 36,\s*boxMaxHeight: 36", vp)
    assert "region: 'west'" in vp and "populateInsertionPoint('main.content.tabpanel'" in vp
    assert "populateInsertionPoint('main.west" not in vp and "populateInsertionPoint('main.viewport" not in vp
