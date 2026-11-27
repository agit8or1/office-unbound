"""Concept alignment 2026-11-26, Files (OpenCloud Web 8.2.2) and Chat (Element Web 1.12.35): docs/design/app-shell.md,
docs/design/concepts/{files,chat}.webp, docs/design/upstream-modifications.md. Mechanisms were read from the deployed builds (officeunbound8)
and checked in the live apps with the generated files served to the browser only (docs/screenshots/concept-files-chat/)."""
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ics" / "agent"))
from ou_agent import cfgspec  # noqa: E402

from ics.deploy import brand, configure  # noqa: E402
from ics.deploy.catalog import load_catalog  # noqa: E402

CSS = (ROOT / "blueprints/catalog/templates/brand/opencloud.css").read_text()
PORTAL = "https://app.e2e.example/"
HOSTS = {"CHAT_HOST": "chat.example.org", "MATRIX_HOST": "matrix.example.org", "MAS_HOST": "mas.example.org", "SERVER_NAME": "matrix.example.org"}
CONCEPT_HEAD = "/* Concept alignment (2026-11-26)"


def _block() -> str:
    return CONCEPT_HEAD + CSS.split(CONCEPT_HEAD, 1)[1].split("/* Files UI audit (2026-11-25)", 1)[0]


def _files(portal=PORTAL) -> dict:
    return {f["path"]: f["content"] for f in brand.opencloud_files(portal)}


# ---------------------------------------------------------------- Files
def test_the_concept_block_sits_before_the_audit_and_colour_only_blocks_and_uses_tokens_only():
    assert CSS.index(CONCEPT_HEAD) < CSS.index("/* Files UI audit (2026-11-25)") < CSS.index("/* Suite redesign")
    body = re.sub(r"/\*.*?\*/", "", _block(), flags=re.S)
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b(?![-\w])", body.replace("#oc-topbar", "").replace("#web-nav-sidebar", "")
                         .replace("#files-global-search-bar", "").replace("#files-global-search", "").replace("#applications-menu", "")
                         .replace("#web-content-main", "")), "literal colour in the concept block"
    assert "rgb(" not in body and "hsl(" not in body


def test_the_top_bar_is_48px_with_a_centred_520px_search_on_the_bar_field():
    assert re.search(r"#oc-topbar \{ height: 48px; grid-template-rows: 48px auto;", CSS)
    assert "#oc-topbar .oc-logo-image { height: 20px; }" in CSS
    assert "max-width: 520px; height: 30px;" in CSS and "border-radius: var(--ou-radius-lg)" in CSS
    assert "background: var(--ou-bar-field, var(--ou-bar-2))" in CSS
    for t in brand.tokens():   # AA for the typed text and the placeholder on the field (the fallback token until --ou-bar-field exists)
        field = t.get("bar-field", t["bar-2"])
        assert brand.contrast(t["bar-text"], field) >= 4.5 and brand.contrast(t["bar-muted"], field) >= 4.5


def test_the_lockup_names_the_product_and_the_app_and_links_back_to_the_portal():
    js = _files()["themes/ou/home.js"]
    assert f'var HOME = "{PORTAL}";' in js and 'var APP = "Files";' in js and 'brand.textContent = "Office Unbound";' in js
    assert 'brand.title = "Back to your Office Unbound dashboard";' in js and 'app.className = "ou-app-name";' in js
    # no portal: the lockup stays, as text without a link (previously the whole script was a comment)
    assert 'var HOME = "";' in _files(None)["themes/ou/home.js"]
    # the upstream logo link (the same mark) is hidden only where the lockup exists; phones keep the mark only
    assert "#oc-topbar .oc-logo-wrapper:has(.ou-home) > a:not(.ou-home) { display: none; }" in CSS
    assert "@media (max-width: 640px) { #oc-topbar .ou-app-name { display: none; } #oc-topbar .ou-home { font-size: 0; gap: 0; } }" in CSS


def test_the_list_view_is_seeded_once_and_a_users_choice_wins():
    """OpenCloud Web 8.2.2 hard-codes resource-tiles as the default view (useRouteQueryPersisted, localStorage oc-options_view-mode,
    removed again when the choice equals the default): the list is written once per browser, guarded by a marker of our own."""
    js = _files()["themes/ou/home.js"]
    seed = js.split("try {", 1)[1].split("} catch", 1)[0]
    assert 'if (!localStorage.getItem("ou-view-mode-default"))' in seed
    assert 'if (!localStorage.getItem("oc-options_view-mode")) { localStorage.setItem("oc-options_view-mode", "resource-table"); }' in seed
    assert seed.count("setItem") == 2 and "removeItem" not in js


def test_custom_translations_rename_only_what_the_concept_names_differently():
    f = _files()
    assert {"url": brand.OC_TRANSLATIONS_URL} in yaml.safe_load(f["web.yaml"])["web"]["config"]["custom_translations"]
    tr = json.loads(f["themes/ou/translations.json"])
    assert set(tr) == {"en"} and tr["en"] == {"Personal": "My files", "Shares": "Shared", "Enter search term": "Search files and folders"}
    assert not any(n in v.lower() for v in tr["en"].values() for n in brand.UPSTREAM_NAMES)


def test_the_primary_action_is_the_full_width_copper_button():
    rule = next(d for s, d in re.findall(r"([^{}]+)\{([^{}]*)\}", _block()) if "oc-button-primary" in s)
    assert "width: 100%" in rule and "height: 36px" in rule and "border-radius: var(--ou-radius-lg)" in rule and "600 13px" in rule


def test_the_files_config_volume_stays_within_the_agents_limits():
    vol = [{"path": p, "mode": 0o644, "content": "x"} for p in ("ou.env", "csp.yaml", "app-registry.yaml")] + brand.opencloud_files(PORTAL)
    assert len(vol) <= cfgspec.MAX_FILES
    assert sum(len(f["content"].encode()) for f in vol) <= cfgspec.MAX_TOTAL_BYTES


# ---------------------------------------------------------------- Chat
def _element() -> dict:
    return json.loads(configure.element_config(HOSTS, PORTAL))


def test_element_gets_the_home_page_the_consent_logo_and_one_room_list():
    c = _element()
    assert c["embedded_pages"] == {"home_url": "https://chat.example.org/ou/home.html"}
    assert c["oidc_metadata"] == {"logo_uri": "https://chat.example.org/ou/ou-mark.svg"}   # same origin as the client: Element keeps it
    assert c["setting_defaults"]["Spaces.allRoomsInHome"] is True
    # encryption, verification and recovery are not configured here at all: their behaviour is Element's and Synapse's own
    flat = json.dumps({k: v for k, v in c.items() if k != "setting_defaults"} | {"sd": {k: v for k, v in c["setting_defaults"].items() if k != "custom_themes"}})
    assert not re.search(r"encrypt|e2ee|cross.?sign|secret_storage|key_backup|recovery", flat, flags=re.I)


def test_element_themes_use_the_suite_fonts_without_font_faces():
    """Element adds `faces` as <style title="custom-theme-font-faces"> before <style title="custom-theme-compound">; Chromium then treats the
    compound sheet as an alternate style sheet and drops every compound override (primary buttons near-black: officeunbound8 preview
    2026-11-27). The stacks name Element's bundled Inter / Fira Code right after Plex."""
    for t in _element()["setting_defaults"]["custom_themes"]:
        assert set(t["fonts"]) == {"general", "monospace"}
        assert t["fonts"]["general"].startswith('"Plex Sans", Inter, ') and t["fonts"]["monospace"].startswith('"Plex Mono", "Fira Code", ')
        assert t["compound"]["--cpd-color-bg-action-primary-rest"].startswith("#")


def test_element_home_page_survives_elements_sanitiser_and_explains_encryption_plainly():
    html = brand.element_home_html(PORTAL)
    assert not re.search(r"<(img|svg|style|script|iframe)\b|\sclass=|\sstyle=|\son\w+=", html)   # EmbeddedPage strips these anyway
    assert set(re.findall(r'href="(#/[a-z]+)"', html)) == {"#/dm", "#/new", "#/directory"}         # MatrixChat.showScreen routes
    assert f'<a href="{PORTAL}">Back to your Office Unbound Dashboard</a>' in html
    assert "end-to-end encrypted" in html and "recovery key" in html and "Element" not in html
    assert "Back to your" not in brand.element_home_html(None)


def test_the_chat_front_serves_the_element_files_without_dropping_its_security_headers():
    rbs_files = brand.element_files(PORTAL)
    assert {f["path"] for f in rbs_files} == {"ou/home.html", "ou/ou-mark.svg", "ou/OFL.txt"}
    front = (ROOT / "blueprints/catalog/templates/chat/front.conf").read_text()
    loc = re.search(r"location \^~ /ou/ \{([^}]*)\}", front)
    assert loc and "alias /ou-element/ou/;" in loc.group(1) and "add_header" not in loc.group(1)   # inherits CSP frame-ancestors, nosniff
    cfg = configure.element_config(HOSTS, PORTAL)
    assert len(cfg.encode()) <= cfgspec.MAX_FILE_BYTES
    vol = [{"path": "nginx.conf", "mode": 0o644, "content": front}, {"path": "config.json", "mode": 0o644, "content": cfg}, *rbs_files]
    assert cfgspec.check_volume_files({"component": "chat", "volume": "front", "image": "registry.ou.invalid/ou/element-web@sha256:" + "a" * 64,
                                       "owner": "10030:10030", "files": vol}, {"enabled": True})["files"] == vol
    src = (ROOT / "ics/ics/deploy/configure.py").read_text()
    assert '"content": element_config(hosts, portal)},\n' in src and "*brand.element_files(portal)]" in src


def test_the_changes_reach_running_deployments_through_config_revisions():
    cat = load_catalog()
    assert cat.components["files"].config_revision >= 3 and cat.components["chat"].config_revision >= 2
