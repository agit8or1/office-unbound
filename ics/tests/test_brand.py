"""The shared Office Unbound skin (ics/ics/deploy/brand.py + blueprints/catalog/templates/brand): one design system, rendered per app for that
app's own theming hook, shipped through the closed cfg runbooks. Upstream references (pinned versions): Keycloak 26.8.2 keycloak.v2 login /
keycloak.v3 account themes; OpenCloud 9.1.0 services/web/pkg/config (web.config.styles/scripts, WEB_ASSET_THEMES_PATH) with Web v8.2.2 (theme
roles, web-app-external css_variables for Collabora); grommunio-web 5.2 /brand/brand.css --brand-* hook."""
import json
import os
import re
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
from ou_agent import cfghelper as h  # noqa: E402
from ou_agent import cfgspec as c  # noqa: E402
from ou_agent.proto import Reject  # noqa: E402

from ics.deploy import brand, configure  # noqa: E402

PORTAL = "https://app.e2e.example/"
ROOT = Path(__file__).resolve().parents[2]
# the role keys of OpenCloud 9.1.0's built-in theme (services/web/assets/themes/opencloud/theme.json): a missing one would fall back to the
# upstream lilac/petrol palette
OC_ROLES = {"background", "error", "errorContainer", "inverseOnSurface", "inversePrimary", "inverseSurface", "onBackground", "onError",
            "onErrorContainer", "onPrimary", "onPrimaryContainer", "onPrimaryFixed", "onSecondary", "onSecondaryContainer", "onSecondaryFixed",
            "onSurface", "onSurfaceVariant", "onTertiary", "onTertiaryContainer", "onTertiaryFixed", "outline", "outlineVariant", "primary",
            "primaryContainer", "primaryFixed", "scrim", "secondary", "secondaryContainer", "secondaryFixed", "shadow", "surface", "surfaceBright",
            "surfaceContainer", "surfaceContainerHigh", "surfaceContainerHighest", "surfaceContainerLow", "surfaceContainerLowest", "surfaceDim",
            "surfaceVariant", "tertiary", "tertiaryContainer", "tertiaryFixed"}
VF = {"component": "identity", "volume": "themes", "image": "registry.ou.invalid/ou/keycloak@sha256:" + "a" * 64, "owner": "10130:10130"}


def test_the_design_system_is_the_portals_look():
    """ou-brand.css is derived from portal.css; a change to one without the other fails here."""
    light, dark = brand.tokens()
    css = (ROOT / "portal/app/static/portal.css").read_text()
    pl, _, pd = css.partition("@media (prefers-color-scheme: dark)")
    pl, pd = dict(re.findall(r"--([a-z0-9-]+):\s*([^;]+);", pl.split("}", 1)[0])), dict(re.findall(r"--([a-z0-9-]+):\s*([^;]+);", pd.split("}", 1)[0]))
    for k in ("bg", "bg2", "surface", "text", "muted", "line", "accent", "accent-ink", "accent-soft", "radius"):
        assert light[k] == pl[k], k
    for k in ("bg", "bg2", "surface", "text", "muted", "line", "accent", "accent-ink", "accent-soft"):
        assert dark[k] == pd[k], k
    assert brand.mark_svg() == (ROOT / "portal/app/static/favicon.svg").read_text()      # the portal's mark is the logo everywhere


@pytest.mark.parametrize("dark", ["media", "body.dark-mode"])
def test_every_skin_imports_the_live_org_branding_first_and_falls_back_to_the_deployment_tokens(dark):
    css = brand.skin("grommunio.css", portal=PORTAL, dark=dark, mark_url="/brand/ou-mark.svg")
    assert css.startswith(f'@import url("{PORTAL}brand/org.css");\n')                    # @import is only valid before every other rule
    assert "--ou-a: var(--ou-org-accent, var(--ou-accent));" in css and "--ou-a: var(--ou-org-accent-dark, var(--ou-accent));" in css
    assert 'var(--ou-org-logo, url("/brand/ou-mark.svg"))' in css and ".ou-home" in css
    assert (dark == "media") == ("@media (prefers-color-scheme: dark)" in css)
    assert "@import" not in brand.skin("grommunio.css", portal=None, dark=dark, mark_url="m.svg")
    assert css.count("{") == css.count("}")


def test_keycloak_theme_fits_the_volume_files_schema_and_links_the_portal():
    files = brand.keycloak_theme(PORTAL)
    assert c.check_volume_files({**VF, "files": files}, {"enabled": True})["files"] == files
    f = {x["path"]: x["content"] for x in files}
    assert "parent=keycloak.v2" in f["ou/login/theme.properties"] and "styles=css/styles.css ou.css" in f["ou/login/theme.properties"]
    acc = f["ou/account/theme.properties"]
    assert "parent=keycloak.v3" in acc and f"logoUrl={PORTAL}" in acc and "logo=/ou-mark.svg" in acc
    assert ".pf-v5-theme-dark {" in f["ou/login/resources/ou.css"] and f["ou/login/resources/ou-mark.svg"].startswith("<svg")
    assert "logoUrl" not in {x["path"]: x["content"] for x in brand.keycloak_theme(None)}["ou/account/theme.properties"]


def test_opencloud_theme_is_complete_and_its_config_is_what_opencloud_reads():
    files = brand.opencloud_files(PORTAL)
    assert c.check_volume_files({**VF, "files": files}, {"enabled": True})["files"] == files
    f = {x["path"]: x["content"] for x in files}
    t = json.loads(f["themes/ou/theme.json"])
    themes = t["clients"]["web"]["themes"]
    assert [x["isDark"] for x in themes] == [False, True]
    light, dark = brand.tokens()
    for th, tok in zip(themes, (light, dark)):
        roles = th["designTokens"]["roles"]
        assert OC_ROLES <= set(roles) and {"chrome", "onChrome"} <= set(roles)          # Collabora's toolbar = chrome (web-app-external)
        assert roles["primary"] == tok["accent"] and roles["chrome"] == tok["bg"] and all(v.startswith("#") for v in roles.values())
    assert t["clients"]["web"]["defaults"]["logo"] == "themes/ou/ou-mark.svg"
    web = yaml.safe_load(f["web.yaml"])
    assert web == {"web": {"config": {"styles": [{"href": "/themes/ou/ou.css"}], "scripts": [{"src": "/themes/ou/home.js"}]}}}
    assert f'var HOME = "{PORTAL}";' in f["themes/ou/home.js"] and "@PORTAL_URL@" not in f["themes/ou/home.js"]
    assert "html[data-color-scheme=dark] {" in f["themes/ou/ou.css"] and "--oc-role-primary: var(--ou-a) !important;" in f["themes/ou/ou.css"]


def test_grommunio_brand_passes_the_agent_schema_and_bad_input_is_refused():
    b = brand.grommunio_brand(PORTAL)
    assert c.check_brand(b) == b and b["portal_url"] == PORTAL and "--brand-primary: var(--ou-a);" in b["css"]
    assert "portal_url" not in brand.grommunio_brand(None)
    for bad in ({**b, "portal_url": "http://app.e2e.example/"}, {**b, "portal_url": "https://app.e2e.example/x"},
                {**b, "mark_svg": '<svg onload="alert(1)"></svg>'}, {**b, "mark_svg": "<svg><script>x</script></svg>"},
                {**b, "mark_svg": '<svg><image href="https://evil.example/x.png"/></svg>'}, {**b, "mark_svg": "<html></html>"},
                {**b, "css": "a{}\x00"}, {**b, "css": "x" * (c.MAX_BRAND_CSS + 1)}, {**b, "extra": 1}, {"css": "a{}"}):
        with pytest.raises(Reject):
            c.check_brand(bad)


def test_the_groupware_node_serves_the_brand_hook_and_the_dashboard_target(tmp_path, monkeypatch):
    monkeypatch.setattr(h.os, "chown", lambda *a, **k: None)
    monkeypatch.setattr(h, "BRAND_ROOT", str(tmp_path / "ou-brand"))
    monkeypatch.setattr(h, "GW_DASHBOARD", str(tmp_path / "gw" / "ou-dashboard.json"))
    b = brand.grommunio_brand(PORTAL)
    h._brand(b)
    assert (tmp_path / "ou-brand/brand/brand.css").read_text() == b["css"]
    assert (tmp_path / "ou-brand/brand/ou-mark.svg").stat().st_mode & 0o777 == 0o644
    assert json.loads((tmp_path / "gw/ou-dashboard.json").read_text()) == {"url": PORTAL, "label": "Dashboard"}
    h._brand(None)                                                                         # brand withdrawn: nothing left behind
    assert not (tmp_path / "ou-brand/brand/brand.css").exists() and not (tmp_path / "gw/ou-dashboard.json").exists()
    site = h.GW_NGINX.format(names="mail.e2e.example", tls="/t", brand_root="/etc/ou-brand")
    assert "location = /brand/brand.css {" in site and "try_files $uri @ou_brand_none;" in site and "sandbox" in site


def test_configure_ships_the_skin_to_every_app(monkeypatch):
    plan = {"input": {"domain": "e2e.example"},
            "vms": [{"name": "id", "components": ["identity", "edge", "portal"]}, {"name": "files", "components": ["files", "office"]},
                    {"name": "gw", "components": ["groupware"]}],
            "dns": [{"name": n, "type": "A", "value": "vm:id"} for n in ("auth.e2e.example", "portal.e2e.example", "cloud.e2e.example")]
                   + [{"name": "mail.e2e.example", "type": "A", "value": "vm:gw"}],
            "containers": [{"vm": "id", "component": "identity", "image": "registry.ou.invalid/ou/keycloak", "digest": "sha256:" + "a" * 64},
                           {"vm": "files", "component": "files", "image": "registry.ou.invalid/ou/opencloud", "digest": "sha256:" + "b" * 64}],
            "firewall": []}
    key = configure._rsa_key()
    monkeypatch.setattr(configure, "secret", lambda rt, dep, name, make=None: (make() if make and "ca" in name else f"{name}-" + "x" * 20))
    monkeypatch.setattr(configure, "realm_key", lambda rt, dep, t=None: key)
    monkeypatch.setattr(configure, "_tls", lambda ctx, vm, *a: {"runbook": "cfg.tls", "params": {}})
    monkeypatch.setattr(configure, "scope_ca", lambda ctx, t: {"cert": "CA"})
    agent = type("A", (), {"address": lambda self, vm: {"id": "10.0.0.1", "files": "10.0.0.2", "gw": "10.0.0.3"}[vm]})()
    ctx = type("Ctx", (), {"deployment_id": "d1", "rt": None, "slug": "e2e", "plan": plan, "env": type("E", (), {"agent": agent})()})()
    P2 = "https://portal.e2e.example/"
    assert configure.portal_url(plan, None) == P2
    idrb = configure.identity_runbooks(ctx, "id")
    themes = next(r["params"] for r in idrb if r["runbook"] == "cfg.volume_files" and r["params"]["volume"] == "themes")
    assert themes["owner"] == configure.KEYCLOAK_UID and themes["files"] == brand.keycloak_theme(P2)
    realm = json.loads(next(f["content"] for r in idrb if r["runbook"] == "cfg.volume_files" for f in r["params"]["files"]
                            if f["path"].startswith("import/")))
    assert realm["loginTheme"] == "ou" and realm["accountTheme"] == "ou"
    frb = configure.files_runbooks(ctx, "files")
    cfgvol = {f["path"]: f["content"] for r in frb if r["runbook"] == "cfg.volume_files" and r["params"]["volume"] == "config" for f in r["params"]["files"]}
    assert "WEB_UI_THEME_PATH=/themes/ou/theme.json" in cfgvol["ou.env"] and "WEB_ASSET_THEMES_PATH=/var/lib/opencloud-config/themes" in cfgvol["ou.env"]
    csp = yaml.safe_load(cfgvol["csp.yaml"])["directives"]
    assert P2 in csp["style-src"] and P2 in csp["img-src"] and P2 not in csp["script-src"]   # styles/logo only, never script
    assert {"web.yaml", "themes/ou/theme.json", "themes/ou/home.js"} <= set(cfgvol)
    g = next(r["params"] for r in configure.groupware_runbooks(ctx, "gw") if r["runbook"] == "cfg.gromox")
    assert c.check_gromox(g, {"enabled": True}) == g and g["brand"] == brand.grommunio_brand(P2)
    red = configure.redact("cfg.gromox", g)
    assert red["brand"]["css"].endswith(" bytes]") and red["brand"]["portal_url"] == P2


def test_the_keycloak_unit_mounts_the_theme_volume_read_only():
    kc = next(a for a in yaml.safe_load((ROOT / "blueprints/catalog/components/identity.yaml").read_text())["artifacts"] if a["name"] == "keycloak")
    assert {"name": "themes", "path": "/opt/keycloak/themes", "read_only": True} in kc["unit"]["volumes"]


# ---------------------------------------------------------------- rebrand: users see Office Unbound, never the upstream product names
def _leaks(text: str) -> list[str]:
    low = text.lower()
    return [n for n in brand.UPSTREAM_NAMES if n in low]


def _props(text: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in text.splitlines() if line and not line.startswith("#"))


def test_keycloak_pages_and_mails_say_office_unbound_not_the_realm_or_keycloak():
    f = {x["path"]: x["content"] for x in brand.keycloak_theme(PORTAL)}
    login = _props(f["ou/login/messages/messages_en.properties"])
    # upstream: loginTitle=Sign in to {0} with {0} = realm display name ("Sign in to ou" when the realm has none)
    assert login["loginTitle"] == "Sign in - Office Unbound" and login["loginTitleHtml"] == "Office Unbound" and "{0}" not in login["loginTitle"]
    assert "favicons=ou-mark.svg" in f["ou/login/theme.properties"]
    acc = _props(f["ou/account/theme.properties"])
    assert acc["title"] == "Your account - Office Unbound" and acc["favicons"] == "ou-mark.svg"
    assert _props(f["ou/email/theme.properties"]) == {"parent": "base"}
    mail = _props(f["ou/email/messages/messages_en.properties"])
    assert mail["emailTestSubject"] == "[Office Unbound] SMTP test message"                      # upstream: [KEYCLOAK] - SMTP test message
    for k in ("passwordResetBody", "executeActionsBody", "emailVerificationBody", "emailUpdateConfirmationBody"):
        assert "Office Unbound account" in mail[k] and "{2}" not in mail[k] and "{0}" in mail[k]   # {2} = realm name, {0} = the link
    for k in ("passwordResetBodyHtml", "executeActionsBodyHtml", "emailVerificationBodyHtml"):
        assert '<a href="{0}">' in mail[k] and "{2}" not in mail[k]
    for path in ("ou/login/messages/messages_en.properties", "ou/email/messages/messages_en.properties"):
        assert _leaks("\n".join(_props(f[path]).values())) == [], path
    assert _leaks(acc["title"]) == []                                  # (parent=keycloak.v3 is the theme it builds on, not shown)
    # every apostrophe doubled (java.text.MessageFormat): a single one would swallow the {n} placeholders behind it
    assert not re.search(r"(?<!')'(?!')", "".join(mail.values()))
    css = f["ou/login/resources/ou.css"]
    assert '#kc-header-wrapper::after { content: var(--ou-org-name, "Office Unbound");' in css


def test_the_realm_is_named_office_unbound_and_uses_the_ou_mail_theme():
    r = json.loads(configure.realm_json("e2e.example", "pw" * 10, clients=configure.sso_clients("portal.e2e.example", "mail.e2e.example", "s" * 20, "w" * 20)))
    assert r["displayName"] == "Office Unbound" and r["displayNameHtml"] == "Office Unbound"
    assert (r["loginTheme"], r["accountTheme"], r["emailTheme"]) == ("ou", "ou", "ou")
    assert "smtpServer" not in r                                       # no mail from Keycloak today (resetPasswordAllowed false)
    for cl in r["clients"]:
        if cl["clientId"] in (configure.PORTAL_CLIENT, configure.WEBMAIL_CLIENT):
            assert cl["name"].startswith("Office Unbound") and _leaks(cl["name"]) == []


def _oc_env() -> dict[str, str]:
    hosts = dict(FILES_HOST="cloud.e2e.example", IDP_HOST="auth.e2e.example", OFFICE_HOST="office.e2e.example", REALM="ou",
                 LDAP_HOST="ldap.e2e.example", BASE_DN="dc=e2e,dc=example", PORTAL_ORIGIN=PORTAL)
    return _props(configure._template("files/opencloud.env", **hosts))


def test_opencloud_shows_office_unbound_and_offers_no_upstream_links():
    env = _oc_env()
    assert env["COLLABORATION_APP_NAME"] == brand.EDITOR_APP == "Documents"                 # "Open in Documents", was "Open in CollaboraOnline"
    assert re.fullmatch(r"[A-Za-z0-9]+", env["COLLABORATION_APP_NAME"])                     # OpenCloud: one word, it is also a route
    assert env["COLLABORATION_APP_DESCRIPTION"] == brand.EDITOR_DESCRIPTION
    assert env["COLLABORATION_APP_ICON"] == "https://cloud.e2e.example/themes/ou/ou-mark.svg"
    for k in ("COLLABORATION_APP_NAME", "COLLABORATION_APP_DESCRIPTION", "COLLABORATION_APP_ICON", "WEB_UI_THEME_PATH"):
        assert _leaks(env[k]) == [], k
    assert env["WEB_OPTION_DISABLE_FEEDBACK_LINK"] == "true"                                 # "Share improvement ideas" (opencloud.eu survey)
    assert env["WEB_OPTION_DISABLE_SPONSOR_LINK"] == "true"                                  # "Support OpenCloud" card
    assert env["FRONTEND_CHECK_FOR_UPDATES"] == "false"                                      # update.opencloud.eu
    assert "app-store" not in env["WEB_UI_CORE_APPS"].split(",") and "admin-settings" not in env["WEB_UI_CORE_APPS"].split(",")
    assert env["NOTIFICATIONS_EMAIL_TEMPLATE_PATH"] == brand.OC_THEMES_DIR.rsplit("/", 1)[0]  # the config volume root
    t = json.loads({x["path"]: x["content"] for x in brand.opencloud_files(PORTAL)}["themes/ou/theme.json"])
    assert t["common"]["name"] == "Office Unbound Files" and _leaks(json.dumps(t["common"])) == []
    assert t["clients"]["web"]["defaults"]["favicon"] == "themes/ou/ou-mark.svg"
    css = {x["path"]: x["content"] for x in brand.opencloud_files(PORTAL)}["themes/ou/ou.css"]
    assert "#web-nav-sidebar .text-xs > span:first-child { display: none; }" in css and 'a[href^="https://docs.opencloud.eu"]' in css


def test_opencloud_mail_templates_are_complete_and_branded():
    files = {x["path"]: x["content"] for x in brand.opencloud_mail_templates()}
    # what OpenCloud 9.1.0 reads from a custom template folder (services/notifications/pkg/email/email.go, templates.go)
    assert set(files) == {"templates/text/email.text.tmpl", "templates/html/layout.html.tmpl", "templates/html/message.html.tmpl",
                          "templates/html/digest.html.tmpl", "templates/html/img/README.txt"}
    text, layout = files["templates/text/email.text.tmpl"], files["templates/html/layout.html.tmpl"]
    assert "{{ .Greeting }}" in text and "{{ .MessageBody }}" in text and brand.MAIL_FOOTER in text and _leaks(text) == []
    assert '{{ block "content" . }}{{ end }}' in layout and "{{ .Subject }}" in layout and brand.MAIL_FOOTER in layout
    assert "cid:" not in layout and "@PRODUCT@" not in layout and "@FOOTER@" not in layout
    body = layout.split("*/}}", 1)[1]                                                        # past the attribution comment
    assert _leaks(body) == []
    for child in ("message", "digest"):
        tpl = files[f"templates/html/{child}.html.tmpl"]
        assert '{{ define "content" }}' in tpl and tpl.count("{{") == tpl.count("}}")
        assert "Apache-2.0" in tpl.split("*/}}", 1)[0]                                       # upstream attribution kept
        assert _leaks(tpl.split("*/}}", 1)[1]) == []
    allf = brand.opencloud_files(PORTAL)
    assert c.check_volume_files({**VF, "files": allf}, {"enabled": True})["files"] == allf    # within MAX_FILES / sizes, 4 path levels
    kc = brand.keycloak_theme(PORTAL)
    assert c.check_volume_files({**VF, "files": kc}, {"enabled": True})["files"] == kc


def test_the_editor_route_is_the_same_in_opencloud_the_ics_and_the_portal():
    """COLLABORATION_APP_NAME forms OpenCloud Web's editor route external-<name lower case> (web-app-external index.ts); the portal's
    "New document" link must use exactly that route (its fallback when it cannot ask OpenCloud's /app/list)."""
    env = _oc_env()
    assert brand.editor_route() == "external-documents" == brand.editor_route(env["COLLABORATION_APP_NAME"])
    cfg_src = (ROOT / "portal/app/config.py").read_text()
    defaults = re.findall(r'editor_app(?::\s*str)?\s*=\s*(?:_env\("PORTAL_EDITOR_APP",\s*)?"([^"]+)"', cfg_src)
    assert defaults == [brand.editor_route(), brand.editor_route()]


def test_the_calendar_server_password_prompt_names_office_unbound():
    """grommunio-dav's Basic auth realm (shown by calendar/contacts apps and browsers) is rewritten in its config.php by cfg.gromox."""
    upstream = ("<?php\ndefine('MAPI_SERVER', 'default:');\n// Authentication realm\ndefine('SABRE_AUTH_REALM', 'grommunio dav');\n"
                "define('DEVELOPER_MODE', true);\n")
    t = upstream
    for path, pat, rep in h.GW_PHP_EDITS:
        if path == "/etc/grommunio-dav/config.php":
            t = re.sub(pat, rep, t)
    assert "define('SABRE_AUTH_REALM', 'Office Unbound');" in t and "grommunio dav" not in t and "define('DEVELOPER_MODE', false);" in t
    again = t
    for path, pat, rep in h.GW_PHP_EDITS:
        if path == "/etc/grommunio-dav/config.php":
            again = re.sub(pat, rep, again)
    assert again == t                                                                        # idempotent: no rewrite on the next run
