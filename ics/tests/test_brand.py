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


def _contrast(a: str, b: str) -> float:
    def lum(h):
        c = [int(h.lstrip("#")[i:i + 2], 16) / 255 for i in (0, 2, 4)]
        c = [x / 12.92 if x <= 0.04045 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
        return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]
    x, y = sorted((lum(a), lum(b)), reverse=True)
    return (x + 0.05) / (y + 0.05)


def _css_blocks(css: str) -> tuple[dict[str, str], dict[str, str]]:
    """(light, dark) custom properties of a stylesheet: its first :root block and the first block inside prefers-color-scheme: dark."""
    light_part, _, dark_part = css.partition("@media (prefers-color-scheme: dark)")
    pick = lambda part: dict(re.findall(r"--([a-z0-9-]+):\s*([^;]+);", part[part.index(":root"):].split("}", 1)[0]))  # noqa: E731
    return pick(light_part), pick(dark_part)


def test_the_design_system_is_the_website_concepts_and_the_portal_carries_it_verbatim():
    """ou-brand.css holds the officeunbound.com interface concept tokens; portal.css carries the two token blocks verbatim (the portal is
    packaged on its own and cannot read the catalog), and the same mark and fonts."""
    light, dark = brand.tokens()
    # the website's product system (concepts.css .ux tokens): paper, navy bar, copper accent, Plex
    assert (light["bg"], light["surface"], light["ink"], light["text"], light["muted"]) == ("#f7f5f0", "#ffffff", "#18212d", "#2e3540", "#5c6470")
    assert (light["bar-bg"], light["navy"], light["accent"], light["accent-soft"]) == ("#14243a", "#14243a", "#a9481f", "#f6e3d8")
    assert light["font"].startswith('"Plex Sans"') and light["mono"].startswith('"Plex Mono"')
    src = (ROOT / "blueprints/catalog/templates/brand/ou-brand.css").read_text()
    tok = src[src.index(":root {"):src.index("/* components */")]
    portal = (ROOT / "portal/app/static/portal.css").read_text()
    assert tok in portal                                                                    # one source, copied verbatim
    assert brand.mark_svg() == (ROOT / "portal/app/static/favicon.svg").read_text()      # the mark is the logo everywhere
    for name, *_ in brand.FONTS:
        assert brand.font_bytes(name) == (ROOT / "portal/app/static/fonts" / name).read_bytes()
        assert f'url("fonts/{name}")' in portal
    assert (ROOT / "portal/app/static/fonts/OFL.txt").read_text() == (ROOT / "blueprints/catalog/templates/brand/fonts/OFL.txt").read_text()


# console name -> shared token (ics/frontend/src/style.css follows the ICS concept: its own graphite bar and light navigation, the rest shared)
CONSOLE_SHARED = {"bg": "bg", "surface": "surface", "surface2": "side", "ink": "ink", "text": "text", "muted": "muted", "line": "line",
                  "line-strong": "line-2", "sel": "sel", "accent": "accent", "accent-text": "accent-ink", "accent-soft": "accent-soft",
                  "teal": "teal", "teal-soft": "teal-soft", "ok": "ok", "ok-bg": "ok-bg", "warn": "warn", "warn-bg": "warn-bg", "bad": "bad", "bad-bg": "bad-bg"}


def test_the_console_shares_the_tokens_and_ships_the_fonts():
    css = (ROOT / "ics/frontend/src/style.css").read_text()
    cl, cd = _css_blocks(css)
    forced = dict(re.findall(r"--([a-z0-9-]+):\s*([^;]+);", css.split(':root[data-theme="dark"] {', 1)[1].split("}", 1)[0]))
    assert forced == cd                                                                     # the theme switch and the system setting agree
    light, dark = brand.tokens()
    for k, t in CONSOLE_SHARED.items():
        assert cl[k] == light[t], k
        assert cd[k] == dark[t], k
    assert cl["sans"] == light["font"] and cl["mono"] == light["mono"]
    for name, *_ in brand.FONTS:
        assert brand.font_bytes(name) == (ROOT / "ics/frontend/src/assets/fonts" / name).read_bytes()
        assert f'url("./assets/fonts/{name}")' in css
    assert (ROOT / "ics/frontend/public/fonts/OFL.txt").read_text() == (ROOT / "blueprints/catalog/templates/brand/fonts/OFL.txt").read_text()


def test_text_colours_meet_wcag_aa_in_light_and_dark():
    """Text on its surfaces >= 4.5:1 (WCAG 2.x AA, normal text), for the shared tokens and the console's own (axe runs on the pages too)."""
    for t in brand.tokens():
        for fg in ("ink", "text", "muted", "accent"):
            for bg in ("bg", "bg2", "side", "surface"):
                assert _contrast(t[fg], t[bg]) >= 4.5, (fg, bg, t[fg], t[bg])
        pairs = [("accent-ink", "accent"), ("ink", "accent-soft"), ("teal", "surface"), ("teal", "bg"), ("teal", "teal-soft"), ("ink", "sel"),
                 ("ok", "ok-bg"), ("warn", "warn-bg"), ("bad", "bad-bg"), ("bar-text", "bar-bg"), ("bar-muted", "bar-bg"), ("bar-text", "bar-2"),
                 ("bar-muted", "bar-2"), ("ok", "surface"), ("warn", "surface"), ("bad", "surface")]
        for fg, bg in pairs:
            assert _contrast(t[fg], t[bg]) >= 4.5, (fg, bg, t[fg], t[bg])
    css = (ROOT / "ics/frontend/src/style.css").read_text()
    for c in _css_blocks(css):
        for fg in ("ink", "text", "muted", "faint", "link", "accent"):
            for bg in ("bg", "surface", "surface2", "sunken"):
                assert _contrast(c[fg], c[bg]) >= 4.5, (fg, bg, c[fg], c[bg])
        for fg, bg in (("accent-text", "accent"), ("nav-text", "nav"), ("nav-muted", "nav"), ("nav-text", "nav-sel"), ("nav-muted", "nav-2"),
                       ("info", "info-bg"), ("idle", "idle-bg"), ("ok", "ok-bg"), ("warn", "warn-bg"), ("bad", "bad-bg")):
            assert _contrast(c[fg], c[bg]) >= 4.5, (fg, bg, c[fg], c[bg])
        bar = {**_css_blocks(css)[0], **c}
        for fg in ("bar-text", "bar-muted"):
            assert _contrast(bar[fg], bar["bar"]) >= 4.5 and _contrast(bar[fg], bar["bar-2"]) >= 4.5


def test_fonts_are_self_hosted_with_their_licence_and_never_from_a_cdn():
    data = brand.fonts_css()
    assert data.startswith("/*\n") and "SIL OPEN FONT LICENSE Version 1.1" in data and "Reserved Font Name \"Plex\"" in data
    assert data.count("@font-face") == len(brand.APP_FONTS) and data.count("data:font/woff2;base64,") == len(brand.APP_FONTS)
    every = [data, brand.skin("grommunio.css", portal=PORTAL, dark="body.dark-mode", mark_url="m.svg", fonts_url="/brand/ou-fonts.css"),
             (ROOT / "portal/app/static/portal.css").read_text(), (ROOT / "ics/frontend/src/style.css").read_text()]
    for css in every:
        for src in re.findall(r"@font-face \{[^}]*\}", css):
            src = re.sub(r"data:font/woff2;base64,[A-Za-z0-9+/=]+", "", src)
            assert "http" not in src and "//" not in src
        assert "googleapis" not in css and "fonts.gstatic" not in css and "@import url(\"http" not in css.replace(f'@import url("{PORTAL}brand/org.css")', "")


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
    login_v, account_v = brand.versioned("ou.css", f["ou/login/resources/ou.css"]), brand.versioned("ou.css", f["ou/account/resources/ou.css"])
    assert "parent=keycloak.v2" in f["ou/login/theme.properties"] and f"styles=css/styles.css ou-fonts.css {login_v}\n" in f["ou/login/theme.properties"]
    acc = f["ou/account/theme.properties"]
    assert "parent=keycloak.v3" in acc and f"logoUrl={PORTAL}" in acc and "logo=/ou-mark.svg" in acc and f"styles=ou-fonts.css {account_v}\n" in acc
    assert f[f"ou/login/resources/{login_v}"] == f["ou/login/resources/ou.css"] and f[f"ou/account/resources/{account_v}"] == f["ou/account/resources/ou.css"]
    for t in ("login", "account"):                                                         # the fonts travel with each theme type
        assert f[f"ou/{t}/resources/ou-fonts.css"] == brand.fonts_css()
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
    assert web == {"web": {"config": {"styles": [{"href": "/themes/ou/ou-fonts.css"}, {"href": "/themes/ou/ou.css"}],
                                      "scripts": [{"src": "/themes/ou/home.js"}]}}}
    assert f["themes/ou/ou-fonts.css"] == brand.fonts_css() and "#oc-topbar {" in f["themes/ou/ou.css"]          # navy top bar
    assert t["clients"]["web"]["themes"][0]["designTokens"]["fontFamily"].startswith('"Plex Sans"')
    assert f'var HOME = "{PORTAL}";' in f["themes/ou/home.js"] and "@PORTAL_URL@" not in f["themes/ou/home.js"]
    assert "html[data-color-scheme=dark] {" in f["themes/ou/ou.css"] and "--oc-role-primary: var(--ou-a) !important;" in f["themes/ou/ou.css"]


def test_grommunio_brand_passes_the_agent_schema_and_bad_input_is_refused():
    b = brand.grommunio_brand(PORTAL)
    assert c.check_brand(b) == b and b["portal_url"] == PORTAL and "--brand-primary: var(--ou-a);" in b["css"]
    assert "portal_url" not in brand.grommunio_brand(None)
    assert "fonts_css" not in b and '@import url("/brand/ou-fonts.css")' not in b["css"]                        # an agent without the feature gets no new field
    bf = brand.grommunio_brand(PORTAL, fonts=True)
    assert c.check_brand(bf) == bf and bf["css"].startswith(f'@import url("{PORTAL}brand/org.css");\n@import url("/brand/ou-fonts.css");\n')
    assert "brand_fonts" in c.FEATURES["cfg.gromox"] and brand.GW_FONTS_FEATURE == "brand_fonts"
    for bad_fonts in ("body{display:none}", bf["fonts_css"] + "a{}", bf["fonts_css"].replace("data:font/woff2", "https://cdn.example/x"),
                      '@font-face { font-family: "Plex Sans"; src: url("data:font/woff2;base64,AA==") format("woff2"); font-weight: 400; '
                      'font-style: normal; font-display: swap; }\n@import url("https://evil.example/x.css");\n'):
        with pytest.raises(Reject):
            c.check_brand({**bf, "fonts_css": bad_fonts})
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
    assert not (tmp_path / "ou-brand/brand/ou-fonts.css").exists()
    h._brand(brand.grommunio_brand(PORTAL, fonts=True))
    assert (tmp_path / "ou-brand/brand/ou-fonts.css").read_text() == brand.fonts_css()
    h._brand(b)                                                                            # fonts withdrawn with the field
    assert not (tmp_path / "ou-brand/brand/ou-fonts.css").exists()
    h._brand(brand.grommunio_brand(PORTAL, fonts=True))
    h._brand(None)                                                                         # brand withdrawn: nothing left behind
    assert not (tmp_path / "ou-brand/brand/brand.css").exists() and not (tmp_path / "gw/ou-dashboard.json").exists()
    assert not (tmp_path / "ou-brand/brand/ou-fonts.css").exists()
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
    assert csp["font-src"] == ["'self'", "data:"]                                          # the embedded Plex of ou-fonts.css, no font host
    assert {"web.yaml", "themes/ou/theme.json", "themes/ou/home.js"} <= set(cfgvol)
    g = next(r["params"] for r in configure.groupware_runbooks(ctx, "gw") if r["runbook"] == "cfg.gromox")
    assert c.check_gromox(g, {"enabled": True}) == g and g["brand"] == brand.grommunio_brand(P2)
    red = configure.redact("cfg.gromox", g)
    assert red["brand"]["css"].endswith(" bytes]") and red["brand"]["portal_url"] == P2
    # an agent that reports cfg.gromox brand_fonts gets the webmail fonts too (an older one would refuse the field)
    monkeypatch.setattr(configure, "agent_features", lambda ctx_, vm_, rb: ["brand_fonts"] if (vm_, rb) == ("gw", "cfg.gromox") else [])
    g = next(r["params"] for r in configure.groupware_runbooks(ctx, "gw") if r["runbook"] == "cfg.gromox")
    assert c.check_gromox(g, {"enabled": True}) == g and g["brand"] == brand.grommunio_brand(P2, fonts=True)
    assert configure.redact("cfg.gromox", g)["brand"]["fonts_css"].endswith(" bytes]")


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


def test_the_webmail_redesign_restyles_without_touching_extjs_layout():
    """grommunio-web is ExtJS: every panel is sized in pixels from its own measurements, so the suite restyle (portal 0.5.0) may only change
    colours, borders, type and shadows; a size, margin, padding or position rule would misalign panes the framework already laid out."""
    css = (ROOT / "blueprints/catalog/templates/brand/grommunio.css").read_text()
    redesign = css[css.index("/* Suite redesign"):]
    decls = re.findall(r"(?<![\w-])([a-z-]+)\s*:", re.sub(r"/\*.*?\*/", "", redesign, flags=re.S).split("{", 1)[1])
    layout = {d for d in decls if re.fullmatch(r"(min-|max-)?(width|height)|margin(-\w+)?|padding(-\w+)?|position|top|left|right|bottom|display|flex.*", d)}
    assert not layout, layout
    for token in ("--ou-side", "--ou-sel", "--ou-action"):   # the shared layering and the muted-teal selection
        assert token in redesign


def test_element_accent_fills_carry_white_text_and_still_read_as_text_on_the_dark_timeline():
    """Element 1.12.35's custom dark theme (theme-dark-custom.css, read from the deployed image) paints white text on --accent-color
    (home page buttons, toasts, search highlights) and uses the same accent 29 times as text. The dark action teal gave white 2.3:1."""
    light, dark = brand.tokens()
    for theme, t in zip(brand.element_themes(), (light, dark)):
        accent = theme["colors"]["accent-color"]
        assert brand.contrast("#ffffff", accent) >= 3.0, theme["name"]
        assert brand.contrast(accent, t["surface"]) >= 4.5 and brand.contrast(accent, t["side"]) >= 4.5, theme["name"]
    assert brand.element_themes()[0]["colors"]["accent-color"] == light["action"]   # light: the action teal itself (6.2:1 with white)


def test_field_borders_reach_3_to_1_on_every_surface_a_field_sits_on():
    """WCAG 1.4.11: a text field's boundary is a UI component (>= 3:1). The line tokens are for separators (light 2.1:1, dark 1.7:1);
    fields in the portal, the sign-in page and Files use --ou-field."""
    for t in brand.tokens():
        for bg in ("bg", "bg2", "side", "surface", "raised"):
            assert _contrast(t["field"], t[bg]) >= 3.0, (bg, t["field"], t[bg])
    for f in ("keycloak-login.css", "keycloak-account.css", "opencloud.css", "grommunio.css"):
        assert "var(--ou-field)" in (ROOT / "blueprints/catalog/templates/brand" / f).read_text(), f
    assert "border: 1px solid var(--ou-field)" in (ROOT / "portal/app/static/portal.css").read_text()


def test_the_files_redesign_restyles_without_touching_opencloud_layout():
    """Stage 2 for Files (OpenCloud Web) changes colours, borders, outlines and shadows only, like the webmail block."""
    css = (ROOT / "blueprints/catalog/templates/brand/opencloud.css").read_text().split("/* Suite redesign", 1)[1]
    props = {m.strip() for m in re.findall(r"[{;]\s*([a-z-]+)\s*:", re.sub(r"/\*.*?\*/", "", css, flags=re.S))}
    assert props and not props & {"width", "height", "margin", "padding", "position", "top", "left", "right", "bottom", "display", "flex", "gap"}, props
    assert props <= {"border-color", "border-bottom-color", "outline-color", "background", "color", "box-shadow"}, props


def test_webmail_follows_the_browser_theme_unless_the_user_chose_one():
    """The portal's default is the browser's light/dark; webmail's upstream default is light. The Office Unbound plugin sets the sysadmin
    default main/dark_mode = 'system' (upstream DarkMode.js and webclient.php honour it; a stored user choice wins over a sysadmin default),
    and the pinned package is the revision that carries it."""
    gw = ROOT / "blueprints/build/grommunio-web"
    php = (gw / "debian/ou-plugins/oudashboard/php/plugin.oudashboard.php").read_text()
    assert re.search(r"'main'\s*=>\s*\[\s*'dark_mode'\s*=>\s*'system'\s*\]", php)
    assert "addSysAdminDefaults" in php and "setSetting" not in php and "->set(" not in php   # a default, never an overwrite of a user's choice
    rev = yaml.safe_load((gw / "recipe.yaml").read_text())["ou_revision"]
    assert rev >= "ou5"
    comp = yaml.safe_load((ROOT / "blueprints/catalog/components/groupware.yaml").read_text())
    pin = next(a["version"] for a in comp["artifacts"] if a.get("package") == "ou-grommunio-web")
    assert pin == f"5.2-{rev}"
    up = ROOT.parent / "office-unbound/reference/upstream/grommunio-web/client/grommunio/core/DarkMode.js"
    if up.exists():   # the upstream reading the default (read-only reference clone)
        assert "get('grommunio/v1/main/dark_mode')" in up.read_text()
