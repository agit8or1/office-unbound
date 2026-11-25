"""Files (OpenCloud Web 8.2.2 on OpenCloud 9.1) UI audit 2026-11-25: the skin fixes of blueprints/catalog/templates/brand/opencloud.css.

Selectors and mechanisms were read from the deployed web build (assets/style-*.css, js/chunks/*.mjs of officeunbound8) and checked in the
live app with the candidate stylesheet injected in the browser (docs/screenshots/uiaudit-files/)."""
import json
import re
from pathlib import Path

from ics.deploy import brand

ROOT = Path(__file__).resolve().parents[2]
CSS = (ROOT / "blueprints/catalog/templates/brand/opencloud.css").read_text()
AUDIT_HEAD = "/* Files UI audit (2026-11-25)"
STAGE2_HEAD = "/* Suite redesign"


def _strip(css: str) -> str:
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S)


def _rules(css: str) -> list[tuple[str, str]]:
    """(selector, declarations) of the plain and @media-nested rules."""
    css = re.sub(r"@media[^{]*\{((?:[^{}]*\{[^{}]*\})*)\s*\}", r"\1", _strip(css))
    return [(s.strip(), d.strip()) for s, d in re.findall(r"([^{}]+)\{([^{}]*)\}", css)]


def _audit_block() -> str:
    assert AUDIT_HEAD in CSS
    return AUDIT_HEAD + CSS.split(AUDIT_HEAD, 1)[1].split(STAGE2_HEAD, 1)[0]


def _topbar_rule() -> str:
    return next(d for s, d in _rules(CSS) if s == "#oc-topbar")


def test_the_top_bar_redefines_the_chrome_role_for_the_tailwind_utilities_too():
    """bg-role-chrome / text-role-on-chrome read --color-role-chrome, which :root resolves from --oc-role-chrome once (style.css:
    --color-role-chrome:var(--oc-role-chrome)); redefining only --oc-role-chrome left the phone search bar paper-coloured under the bar's
    light text (its Cancel button was invisible)."""
    d = _topbar_rule()
    for role, token in (("chrome", "bar-bg"), ("on-chrome", "bar-text")):
        assert f"--oc-role-{role}: var(--ou-{token})" in d
        assert f"--color-role-{role}: var(--ou-{token})" in d


def test_the_search_controls_in_the_bar_use_the_bar_colours():
    """The scope chip ("All files", a raw-inverse surface button: --oc-button-on-color) and the search button (raw: --oc-button-color) were
    the page's ink, invisible on the navy field in the light theme."""
    d = next(d for s, d in _rules(CSS) if s == "#oc-topbar #files-global-search-bar .oc-button")
    assert "--oc-button-on-color: var(--ou-bar-text)" in d and "--oc-button-color: var(--ou-bar-muted)" in d
    light, dark = brand.tokens()
    for t in (light, dark):   # the field is --ou-bar-2 (the bar's search input rule)
        assert brand.contrast(t["bar-text"], t["bar-2"]) >= 4.5
        assert brand.contrast(t["bar-muted"], t["bar-2"]) >= 4.5
    # the field's focus ring in the bar: the bar text (the action teal is < 3:1 on the light navy)
    ring = next(d for s, d in _rules(CSS) if s.startswith("#oc-topbar .oc-search-input:focus"))
    assert "outline-color: var(--ou-bar-text) !important" in ring
    assert brand.contrast(light["action"], light["bar-bg"]) < 3
    for t in (light, dark):
        assert brand.contrast(t["bar-text"], t["bar-bg"]) >= 3 and brand.contrast(t["bar-text"], t["bar-2"]) >= 3


def test_phones_show_the_mark_once():
    """<= 640px the Dashboard control is icon-only with the mark; the upstream logo link beside it is hidden, not the Dashboard control."""
    m = re.search(r"@media \(max-width: 640px\) \{(.*?)\n\}", _strip(CSS), flags=re.S)
    assert m and "#oc-topbar .oc-logo-wrapper > a:not(.ou-home) { display: none; }" in m.group(1)
    assert ".ou-home {" not in m.group(1).replace("#oc-topbar .ou-home {", "")


# what the audit block may set: spacing, the illustration size, type, colours, the pencil's visibility; no positioning, no transforms
AUDIT_PROPS = {"height", "min-height", "padding-block", "width", "font-size", "line-height", "font-weight", "color", "opacity", "display",
               "box-shadow", "--oc-button-color"}
AUDIT_SCOPES = (".no-content-message", "#web-nav-sidebar .oc-sidebar-nav-item-link", ".oc-table ", ".oc-resource img", ".oc-tile-card-preview img")


def test_the_audit_block_is_small_scoped_and_keeps_every_control():
    block = _audit_block()
    rules = _rules(block)
    assert rules
    for sel, decl in rules:
        for part in sel.split(","):
            assert part.strip().startswith(AUDIT_SCOPES), part
        props = {p.split(":", 1)[0].strip() for p in decl.split(";") if p.strip()}
        assert props <= AUDIT_PROPS, (sel, props - AUDIT_PROPS)
        if "display" in props:   # the only removal: the inline rename pencil on phones (Rename stays in the row's menu)
            assert sel == ".oc-table .resource-table-edit-name" and "display: none" in decl
        if props & {"width", "height", "min-height"}:   # sizes only for the empty state and its illustration
            assert sel.startswith(".no-content-message"), sel
    # the pencil is hidden only where a pointer can hover, and comes back on hover, keyboard focus and selection
    m = re.search(r"@media \(hover: hover\) and \(pointer: fine\) \{(.*?)\n\}", _strip(block), flags=re.S)
    assert m
    for state in ("tr:hover", "tr:focus-within", "tr.oc-table-highlighted"):
        assert f".oc-table {state} .resource-table-edit-name" in m.group(1)
    assert re.search(r"@media \(max-width: 640px\) \{ \.oc-table \.resource-table-edit-name \{ display: none; \} \}", block)


def test_the_audit_block_precedes_the_colour_only_stage_2_block():
    """test_brand.py keeps the stage-2 block (everything after its header) to colours, borders and shadows; the audit's spacing rules live
    in their own block before it."""
    assert CSS.index(AUDIT_HEAD) < CSS.index(STAGE2_HEAD)
    assert AUDIT_HEAD not in CSS.split(STAGE2_HEAD, 1)[1]


def test_empty_states_are_compact_but_keep_the_message_and_the_illustration():
    rules = dict(_rules(_audit_block()))
    assert "height: auto !important" in rules[".no-content-message"] and "min-height:" in rules[".no-content-message"]
    img = rules[".no-content-message .no-content-message-image"]
    assert "display" not in img and re.search(r"width: (\d+)px", img) and 48 <= int(re.search(r"width: (\d+)px", img).group(1)) < 120
    assert "color: var(--ou-ink)" in rules[".no-content-message .text-xl"]


def test_the_shipped_files_skin_carries_the_fixes():
    files = {x["path"]: x["content"] for x in brand.opencloud_files("https://app.e2e.example/")}
    css = files["themes/ou/ou.css"]
    assert AUDIT_HEAD in css and "--color-role-chrome: var(--ou-bar-bg)" in css and "#files-global-search-bar .oc-button" in css
    # theme.json can only carry colours and the font (web-runtime designSystem install: roles -> --oc-role-*, fontFamily ->
    # --oc-font-family): nothing of the audit could have been a theme token
    t = json.loads(files["themes/ou/theme.json"])
    for th in t["clients"]["web"]["themes"]:
        assert set(th["designTokens"]) == {"roles", "fontFamily"}
