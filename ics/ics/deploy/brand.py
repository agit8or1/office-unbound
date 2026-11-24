"""One look for every app of a deployment (owner 2026-11-21: "skinned the same and uniform across all apps", "no easy way to get back to dashboard").

The design system is written ONCE: blueprints/catalog/templates/brand/ou-brand.css (the tokens of the officeunbound.com interface concepts + the
shared "Dashboard" control), ou-mark.svg (the three-square mark on a navy tile) and fonts/ (IBM Plex Sans/Mono, SIL OFL 1.1, self-hosted: never a
font CDN). This module renders each app's skin from it, for that app's own supported theming hook; configure.py ships the results through the
existing closed runbooks (cfg.volume_files, cfg.gromox):

  * Keycloak 26.8 (sign-in + account console): theme folder "ou" (login parent keycloak.v2, account parent keycloak.v3) in the identity volume
    `themes` mounted at /opt/keycloak/themes; realm loginTheme/accountTheme "ou"; the account logo links to the portal (logoUrl).
  * OpenCloud 9.1 / Web 8.2.2: a theme ("ou", WEB_ASSET_THEMES_PATH + WEB_UI_THEME_PATH) whose design tokens are the portal's, plus web.yaml
    styles/scripts (the Dashboard link in the top bar). Collabora inherits the theme: OpenCloud Web posts it as `css_variables` when it opens a
    document (web-app-external App.vue getCollaboraCss).
  * grommunio-web 5.2: /brand/brand.css (its documented --brand-* hook, served by the groupware nginx) + the oudashboard plugin (tab bar button).

Organisation branding (portal admin: accent, logo) is live, not baked: every skin @imports https://<portal>/brand/org.css, which defines
--ou-org-accent(-dark), --ou-org-soft(-dark) and --ou-org-logo when the organisation set them; the derived --ou-a / --ou-a-soft / --ou-logo
fall back to the deployment tokens otherwise."""
import base64
import colorsys
import hashlib
import json
import re

from .catalog import default_dir as catalog_dir

TOKEN_RE = re.compile(r"--ou-([a-z0-9-]+):\s*([^;]+);")
HOME_LABEL = "Dashboard"

# ---- product names users see (owner 2026-11-21: "make sure to rebrand ALL applications"). Upstream names (Keycloak, OpenCloud, Collabora,
# grommunio) stay only in licence/attribution texts, never as the product a user is working in. tests/test_brand.py asserts no upstream
# name leaks into the user-visible fields generated here.
PRODUCT = "Office Unbound"
FILES_NAME = "Office Unbound Files"
# OpenCloud's name of the office app (COLLABORATION_APP_NAME): shown as "Open in Documents", in the tab title and the app switcher. OpenCloud
# allows one word, no whitespace (services/collaboration/pkg/config/app.go), and derives the editor's web route from it:
# web-app-external `external-${appName.toLowerCase()}` -> /external-documents/... (the portal's "New document" link, portal/app/config.py).
EDITOR_APP = "Documents"
EDITOR_DESCRIPTION = "Open office documents with Office Unbound Docs"
UPSTREAM_NAMES = ("keycloak", "opencloud", "collabora", "grommunio", "gromox", "sabre", "libreoffice")


def editor_route(app: str = EDITOR_APP) -> str:
    """OpenCloud Web's route (and URL path segment) of the office app named `app` (web-app-external index.ts)."""
    return f"external-{app.lower()}"


def _src(name: str) -> str:
    return (catalog_dir() / "templates" / "brand" / name).read_text()


def tokens() -> tuple[dict[str, str], dict[str, str]]:
    """(light, dark) --ou-* tokens of ou-brand.css: the first :root block and the one inside the prefers-color-scheme: dark rule."""
    css = _src("ou-brand.css").split("/* components */", 1)[0]
    light_part, _, dark_part = css.partition("@media (prefers-color-scheme: dark)")
    light = dict(TOKEN_RE.findall(light_part))
    dark = {**light, **dict(TOKEN_RE.findall(dark_part))}
    return light, dark


def components() -> str:
    return _src("ou-brand.css").split("/* components */", 1)[1].strip() + "\n"


def mark_svg() -> str:
    return _src("ou-mark.svg")


# ---- fonts: IBM Plex, self-hosted. The skins of the other apps carry them as data: URIs in a stylesheet of their own (ou-fonts.css), because
# their configuration channels (cfg.volume_files, cfg.gromox brand) carry text only; the portal and the console ship the woff2 files.
FONTS = (  # (file in fonts/, family, weight, style); the portal and the console ship all of them, the app skins APP_FONTS
    ("ibm-plex-sans-latin-400-normal.woff2", "Plex Sans", 400, "normal"),
    ("ibm-plex-sans-latin-400-italic.woff2", "Plex Sans", 400, "italic"),
    ("ibm-plex-sans-latin-500-normal.woff2", "Plex Sans", 500, "normal"),
    ("ibm-plex-sans-latin-600-normal.woff2", "Plex Sans", 600, "normal"),
    ("ibm-plex-mono-latin-400-normal.woff2", "Plex Mono", 400, "normal"),
    ("ibm-plex-mono-latin-500-normal.woff2", "Plex Mono", 500, "normal"),
)
APP_FONTS = tuple(f for f in FONTS if f[0] in ("ibm-plex-sans-latin-400-normal.woff2", "ibm-plex-sans-latin-500-normal.woff2",
                                               "ibm-plex-sans-latin-600-normal.woff2", "ibm-plex-mono-latin-400-normal.woff2"))
FONTS_CSS = "ou-fonts.css"


def font_bytes(name: str) -> bytes:
    return (catalog_dir() / "templates" / "brand" / "fonts" / name).read_bytes()


def fonts_css(faces=APP_FONTS, url_prefix: str | None = None) -> str:
    """@font-face rules: data: URIs (default; for the app skins) or `url_prefix` + file name (portal, console)."""
    if url_prefix is None:   # the fonts travel inside this file: so does their licence (OFL 1.1 condition 2, as a human-readable header)
        out = ["/*\n" + (catalog_dir() / "templates" / "brand" / "fonts" / "OFL.txt").read_text() + "*/\n"]
    else:                    # the woff2 files are shipped with fonts/OFL.txt next to them
        out = ["/* IBM Plex Sans / Plex Mono, Copyright 2017 IBM Corp. with Reserved Font Name \"Plex\"; SIL Open Font License 1.1 (OFL.txt) */\n"]
    for name, family, weight, style in faces:
        src = (url_prefix + name) if url_prefix is not None else "data:font/woff2;base64," + base64.b64encode(font_bytes(name)).decode()
        out.append(f'@font-face {{ font-family: "{family}"; src: url("{src}") format("woff2"); font-weight: {weight}; font-style: {style}; '
                   "font-display: swap; }\n")
    return "".join(out)


def _block(selector: str, values: dict[str, str]) -> str:
    return selector + " {\n" + "".join(f"  --ou-{k}: {v};\n" for k, v in values.items()) + "}\n"


def token_css(dark: str, mark_url: str) -> str:
    """The tokens for one app. `dark`: "media" (follow the system, like the portal) or the selector by which the app marks its own dark mode
    (OpenCloud html[data-color-scheme=dark], grommunio body.dark-mode, Keycloak .pf-v5-theme-dark), so the skin follows the app's switch."""
    light, dk = tokens()
    logo = f'var(--ou-org-logo, url("{mark_url}"))'
    lv = {**light, "a": "var(--ou-org-accent, var(--ou-accent))", "a-ink": "var(--ou-accent-ink)",
          "a-soft": "var(--ou-org-soft, var(--ou-accent-soft))", "logo": logo}
    dv = {**dk, "a": "var(--ou-org-accent-dark, var(--ou-accent))", "a-ink": "var(--ou-accent-ink)",
          "a-soft": "var(--ou-org-soft-dark, var(--ou-accent-soft))"}
    out = _block(":root", lv)
    if dark == "media":
        out += "@media (prefers-color-scheme: dark) {\n" + _block(":root", dv) + "}\n"
    else:
        out += _block(dark, dv)
    return out


def skin(adapter: str, *, portal: str | None, dark: str, mark_url: str, fonts_url: str | None = None) -> str:
    """A complete stylesheet: the organisation's live branding and the fonts (@import must come first), the tokens, the shared components, the
    app adapter. `fonts_url`: where the app's ou-fonts.css is, when the skin imports it itself (grommunio: one stylesheet hook only)."""
    head = (f'@import url("{portal}brand/org.css");\n' if portal else "") + (f'@import url("{fonts_url}");\n' if fonts_url else "")
    return (head + "/* Office Unbound skin, generated by ics/ics/deploy/brand.py from blueprints/catalog/templates/brand; do not edit */\n"
            + token_css(dark, mark_url) + components() + _src(adapter))


# ---------------------------------------------------------------- rollout
BRAND_COMPONENTS = ("identity", "files", "groupware", "chat")   # write brand-derived configuration (sign-in theme, Files theme, webmail skin, chat themes)


def digest() -> str:
    """One fingerprint of everything the brand sources put into an app's configuration (the templates and the generated chat themes).
    plan.py records it on the BRAND_COMPONENTS, so a palette or skin change reconfigures exactly those components of a running
    deployment in place (state.component_steps), with no manual config_revision bump to forget (0.13.0 shipped without one)."""
    h, root = hashlib.sha256(), catalog_dir() / "templates" / "brand"
    for f in sorted(p for p in root.rglob("*") if p.is_file()):
        h.update(f.relative_to(root).as_posix().encode() + b"\0" + f.read_bytes() + b"\0")
    h.update(json.dumps(element_themes(), sort_keys=True).encode())
    return h.hexdigest()[:16]


# ---------------------------------------------------------------- Element (chat)
ELEMENT_THEME = "Office Unbound"


def _luminance(hexcolor: str) -> float:
    r, g, b = (int(hexcolor.lstrip("#")[i:i + 2], 16) / 255 for i in (0, 2, 4))
    f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4   # noqa: E731 (WCAG 2.x relative luminance)
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def contrast(a: str, b: str) -> float:
    x, y = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (x + 0.05) / (y + 0.05)


def fill_shade(color: str, on: str = "#ffffff", ratio: float = 3.0) -> str:
    """The lightest shade of `color` (same hue and saturation) that `on`-coloured text reaches `ratio` against; `color` itself when it
    already does. Element's dark theme puts white text on its accent (home page buttons, toasts, search highlights) and also uses the same
    accent as text on the dark timeline: no single teal reaches 4.5:1 for both, so the fill gets 3:1 (WCAG large text and UI components)
    and stays readable as text (ics/tests/test_brand.py)."""
    if contrast(on, color) >= ratio:
        return color
    h, l, s = colorsys.rgb_to_hls(*(int(color.lstrip("#")[i:i + 2], 16) / 255 for i in (0, 2, 4)))
    while l > 0:
        l = round(l - 0.002, 3)
        c = "#%02x%02x%02x" % tuple(round(v * 255) for v in colorsys.hls_to_rgb(h, l, s))
        if contrast(on, c) >= ratio:
            return c
    return "#000000"


def element_themes() -> list[dict]:
    """Element Web custom themes (config.json setting_defaults.custom_themes; docs/theming.md of element-web 1.12.35): the suite's
    layering in light and dark, the action teal as Element's accent. Literal colours: Element sets them as its own properties and
    has no access to the suite's tokens. The app keeps its own fonts (the theme's font faces need font files on the chat front)."""
    def theme(name: str, t: dict, dark: bool) -> dict:
        return {"name": name, "is_dark": dark,
                "colors": {"accent-color": fill_shade(t["action"]), "primary-color": t["action"], "warning-color": t["bad"],
                           "sidebar-color": t["bar-bg"], "roomlist-background-color": t["side"], "roomlist-text-color": t["ink"],
                           "roomlist-text-secondary-color": t["muted"], "roomlist-highlights-color": t["sel"],
                           "roomlist-separator-color": t["line"], "timeline-background-color": t["surface"],
                           "timeline-text-color": t["ink"], "timeline-text-secondary-color": t["muted"], "timeline-highlights-color": t["bg2"]},
                "compound": {"--cpd-color-text-action-accent": t["action"], "--cpd-color-icon-accent-tertiary": t["action"],
                             "--cpd-color-bg-accent-rest": t["action"], "--cpd-color-border-focused": t["action"]}}
    light, dark = tokens()
    return [theme(ELEMENT_THEME, light, False), theme(f"{ELEMENT_THEME} Dark", dark, True)]


# ---------------------------------------------------------------- Keycloak
def keycloak_theme(portal: str | None) -> list[dict]:
    """Files of the theme folder "ou" (paths relative to /opt/keycloak/themes; at most 4 levels: cfg.volume_files RELPATH_RE)."""
    login = ("parent=keycloak.v2\nimport=common/keycloak\n"
             f"# the parent's stylesheet first, the fonts, the skin last so it wins\nstyles=css/styles.css {FONTS_CSS} ou.css\ndarkMode=true\n"
             # the tab icon (ThemeResourcesParser `favicons`, href = resourcesPath + "/" + path); without it keycloak.v2's img/favicon.ico
             "favicons=ou-mark.svg\n")
    account = (f"parent=keycloak.v3\nstyles={FONTS_CSS} ou.css\nlogo=/ou-mark.svg\ndarkMode=true\n"
               # index.ftl: <title>${properties.title!'Account Management'}</title>, favicon from `favicons` (resourceUrl + "/" + path)
               f"title=Your account - {PRODUCT}\nfavicons=ou-mark.svg\n" + (f"logoUrl={portal}\n" if portal else ""))
    mark, fonts = mark_svg(), fonts_css()
    return [
        {"path": "ou/login/theme.properties", "mode": 0o644, "content": login},
        {"path": "ou/login/messages/messages_en.properties", "mode": 0o644, "content": keycloak_login_messages()},
        {"path": "ou/login/resources/ou.css", "mode": 0o644,
         "content": skin("keycloak-login.css", portal=portal, dark=".pf-v5-theme-dark", mark_url="ou-mark.svg")},
        {"path": "ou/login/resources/ou-mark.svg", "mode": 0o644, "content": mark},
        {"path": f"ou/login/resources/{FONTS_CSS}", "mode": 0o644, "content": fonts},
        {"path": "ou/account/theme.properties", "mode": 0o644, "content": account},
        {"path": "ou/account/resources/ou.css", "mode": 0o644,
         "content": skin("keycloak-account.css", portal=portal, dark=".pf-v5-theme-dark", mark_url="ou-mark.svg")},
        {"path": "ou/account/resources/ou-mark.svg", "mode": 0o644, "content": mark},
        {"path": f"ou/account/resources/{FONTS_CSS}", "mode": 0o644, "content": fonts},
        {"path": "ou/email/theme.properties", "mode": 0o644, "content": "parent=base\n"},
        {"path": "ou/email/messages/messages_en.properties", "mode": 0o644, "content": keycloak_email_messages()},
    ]


def keycloak_login_messages() -> str:
    """Overrides of keycloak base/login messages_en.properties (Keycloak 26.8.2). The upstream texts put the realm's display name ({0}) in the
    page title and the header; a realm imported without one shows its technical name ("Sign in to ou"). The product name is fixed here, so
    it is right for realms that already exist too (Keycloak imports a realm only once). The header text is replaced by the organisation's
    name from the portal when it has one (CSS --ou-org-name, keycloak-login.css)."""
    return ("# Office Unbound sign-in texts (generated by ics/ics/deploy/brand.py; overrides of the keycloak.v2/base login messages)\n"
            f"loginTitle=Sign in - {PRODUCT}\n"
            f"loginTitleHtml={PRODUCT}\n"
            "loginAccountTitle=Sign in to your account\n")


# base/email/messages/messages_en.properties (Keycloak 26.8.2) keys whose text names the realm ({2} = realm display name) or the upstream
# product; the realm uses emailTheme "ou". No SMTP is configured for the realm today, so Keycloak sends no mail; this is for when it does.
_KC_MAIL = {
    "emailTestSubject": "[{p}] SMTP test message",
    "emailTestBody": "This is a test message from {p}.",
    "emailTestBodyHtml": "<p>This is a test message from {p}.</p>",
    "emailVerificationSubject": "{p}: verify your e-mail address",
    "emailVerificationBody": "Someone has created an {p} account with this e-mail address. If this was you, open the link below to verify your "
                             "e-mail address.\\n\\n{{0}}\\n\\nThis link will expire within {{3}}.\\n\\nIf you didn''t create this account, just ignore this message.",
    "emailVerificationBodyHtml": "<p>Someone has created an {p} account with this e-mail address. If this was you, open the link below to verify "
                                 "your e-mail address.</p><p><a href=\"{{0}}\">Verify your e-mail address</a></p><p>This link will expire within "
                                 "{{3}}.</p><p>If you didn''t create this account, just ignore this message.</p>",
    "emailUpdateConfirmationSubject": "{p}: verify your new e-mail address",
    "emailUpdateConfirmationBody": "To change the e-mail address of your {p} account to {{1}}, open the link below.\\n\\n{{0}}\\n\\nThis link will "
                                   "expire within {{3}}.\\n\\nIf you don''t want to make this change, just ignore this message.",
    "emailUpdateConfirmationBodyHtml": "<p>To change the e-mail address of your {p} account to {{1}}, open the link below.</p><p><a href=\"{{0}}\">"
                                       "{{0}}</a></p><p>This link will expire within {{3}}.</p><p>If you don''t want to make this change, just "
                                       "ignore this message.</p>",
    "passwordResetSubject": "{p}: reset your password",
    "passwordResetBody": "Someone just asked to change the password of your {p} account. If this was you, open the link below to set a new "
                         "one.\\n\\n{{0}}\\n\\nThis link and code will expire within {{3}}.\\n\\nIf you don''t want to change your password, just "
                         "ignore this message and nothing will be changed.",
    "passwordResetBodyHtml": "<p>Someone just asked to change the password of your {p} account. If this was you, open the link below to set a "
                             "new one.</p><p><a href=\"{{0}}\">Set a new password</a></p><p>This link will expire within {{3}}.</p><p>If you "
                             "don''t want to change your password, just ignore this message and nothing will be changed.</p>",
    "executeActionsSubject": "{p}: update your account",
    "executeActionsBody": "Your administrator asks you to update your {p} account: {{3}}. Open the link below to start.\\n\\n{{0}}\\n\\nThis "
                          "link will expire within {{4}}.\\n\\nIf you did not expect this, just ignore this message and nothing will be changed.",
    "executeActionsBodyHtml": "<p>Your administrator asks you to update your {p} account: {{3}}. Open the link below to start.</p><p><a "
                              "href=\"{{0}}\">Update your account</a></p><p>This link will expire within {{4}}.</p><p>If you did not expect "
                              "this, just ignore this message and nothing will be changed.</p>",
    "accountNotificationSignatureFrom": "{p}",
}


def keycloak_email_messages() -> str:
    return ("# Office Unbound e-mail texts (generated by ics/ics/deploy/brand.py; overrides of keycloak base/email messages)\n"
            + "".join(f"{k}={v.format(p=PRODUCT)}\n" for k, v in _KC_MAIL.items()))


# ---------------------------------------------------------------- OpenCloud (+ Collabora through it)
OC_THEMES_DIR = "/var/lib/opencloud-config/themes"     # WEB_ASSET_THEMES_PATH: the files config volume
OC_THEME_URL = "/themes/ou/theme.json"                  # WEB_UI_THEME_PATH


def _roles(t: dict[str, str], dark: bool) -> dict[str, str]:
    """OpenCloud Web design-token roles (Material-style, the keys of the built-in opencloud theme.json) from the portal tokens. Collabora gets
    primary/chrome/onChrome/surfaceContainer*/outlineVariant/primaryContainerLow from these (web-app-external getCollaboraCss)."""
    a, ink, soft, bg, bg2, surf, text, muted, line = (t[k] for k in ("accent", "accent-ink", "accent-soft", "bg", "bg2", "surface", "text", "muted", "line"))
    shade = "#000000"
    return {
        "primary": a, "onPrimary": ink, "primaryContainer": soft, "onPrimaryContainer": text, "primaryContainerLow": soft,
        "secondary": muted, "onSecondary": surf, "secondaryContainer": t["sel"], "onSecondaryContainer": t["ink"],
        "tertiary": muted, "onTertiary": surf, "tertiaryContainer": bg2, "onTertiaryContainer": text,
        "error": t["bad"], "onError": surf, "errorContainer": t["bad-bg"], "onErrorContainer": t["bad"],
        "background": bg, "onBackground": text, "surface": surf, "onSurface": text, "surfaceVariant": bg2, "onSurfaceVariant": muted,
        "outline": muted, "outlineVariant": line, "shadow": shade, "scrim": shade,
        "inverseSurface": text, "inverseOnSurface": bg, "inversePrimary": a,
        "primaryFixed": soft, "onPrimaryFixed": text, "secondaryFixed": bg2, "onSecondaryFixed": text, "tertiaryFixed": bg2, "onTertiaryFixed": text,
        "surfaceDim": bg2, "surfaceBright": surf, "surfaceContainerLowest": surf, "surfaceContainerLow": surf if not dark else bg,
        "surfaceContainer": bg, "surfaceContainerHigh": bg2, "surfaceContainerHighest": line,
        "chrome": bg, "onChrome": text,
    }


def opencloud_theme_json() -> str:
    light, dark = tokens()
    font = light["font"]
    logo, mark = "themes/ou/ou-mark.svg", "themes/ou/ou-mark.svg"
    t = {"common": {"name": FILES_NAME, "slogan": "Your files on your organisation's own servers", "logo": logo,
                    "urls": {"accessDeniedHelp": "", "imprint": "", "privacy": "", "accessibility": ""}},
         "clients": {"android": {}, "desktop": {}, "ios": {}, "web": {
             "defaults": {"logo": logo, "logoMobile": mark, "favicon": mark},
             "themes": [{"isDark": False, "label": "Light Theme", "designTokens": {"roles": _roles(light, False), "fontFamily": font}},
                        {"isDark": True, "label": "Dark Theme", "designTokens": {"roles": _roles(dark, True), "fontFamily": font}}]}}}
    return json.dumps(t, indent=2) + "\n"


def opencloud_web_yaml() -> str:
    """$OC_CONFIG_DIR/web.yaml (services/web/pkg/config: web.config.styles / web.config.scripts, loaded by BindSourcesToStructs("web"))."""
    return ("# generated by the ICS (ics/ics/deploy/brand.py): the Office Unbound skin and the Dashboard link\n"
            "web:\n  config:\n    styles:\n      - href: /themes/ou/ou-fonts.css\n      - href: /themes/ou/ou.css\n    scripts:\n      - src: /themes/ou/home.js\n")


# NOTIFICATIONS_EMAIL_TEMPLATE_PATH (opencloud.env) = the config volume root: OpenCloud 9.1.0 reads <path>/templates/text/email.text.tmpl,
# <path>/templates/html/{layout,message,digest}.html.tmpl and the inline images in <path>/templates/html/img (services/notifications/pkg/email/
# email.go). The Office Unbound layout has no images; the folder must exist, so it holds a note (not an image: skipped by validateMime).
MAIL_FOOTER = f"{PRODUCT} - your organisation's own mail, files and documents"


def opencloud_mail_templates() -> list[dict]:
    def fill(name: str) -> str:
        return _src(f"opencloud-mail/{name}").replace("@PRODUCT@", PRODUCT).replace("@FOOTER@", MAIL_FOOTER)
    return [
        {"path": "templates/text/email.text.tmpl", "mode": 0o644, "content": fill("email.text.tmpl")},
        {"path": "templates/html/layout.html.tmpl", "mode": 0o644, "content": fill("layout.html.tmpl")},
        {"path": "templates/html/message.html.tmpl", "mode": 0o644, "content": fill("message.html.tmpl")},
        {"path": "templates/html/digest.html.tmpl", "mode": 0o644, "content": fill("digest.html.tmpl")},
        {"path": "templates/html/img/README.txt", "mode": 0o644, "content": "Office Unbound e-mail layout: no inline images.\n"},
    ]


def opencloud_files(portal: str | None) -> list[dict]:
    """Files for the files `config` volume (relative to /var/lib/opencloud-config)."""
    home = _src("opencloud-home.js").replace("@PORTAL_URL@", portal) if portal else "/* no portal in this deployment */\n"
    return [*opencloud_mail_templates(),
        {"path": "web.yaml", "mode": 0o644, "content": opencloud_web_yaml()},
        {"path": "themes/ou/theme.json", "mode": 0o644, "content": opencloud_theme_json()},
        {"path": "themes/ou/ou.css", "mode": 0o644,
         "content": skin("opencloud.css", portal=portal, dark="html[data-color-scheme=dark]", mark_url="/themes/ou/ou-mark.svg")},
        {"path": "themes/ou/ou-mark.svg", "mode": 0o644, "content": mark_svg()},
        {"path": f"themes/ou/{FONTS_CSS}", "mode": 0o644, "content": fonts_css()},
        {"path": "themes/ou/home.js", "mode": 0o644, "content": home},
    ]


# ---------------------------------------------------------------- grommunio-web
GW_FONTS_FEATURE = "brand_fonts"   # cfg.gromox feature of agents that write brand.fonts_css (/brand/ou-fonts.css; ou_agent cfgspec.FEATURES)


def grommunio_brand(portal: str | None, fonts: bool = False) -> dict:
    """cfg.gromox `brand`: /brand/brand.css + /brand/ou-mark.svg on the mail host, and the Dashboard target of the oudashboard plugin. `fonts`
    (the groupware node's agent reports GW_FONTS_FEATURE): also /brand/ou-fonts.css, imported by brand.css; an older agent's closed schema
    would refuse the field, so without it the webmail falls back to the system fonts of the --ou-font stack."""
    out = {"css": skin("grommunio.css", portal=portal, dark="body.dark-mode", mark_url="/brand/ou-mark.svg",
                       fonts_url=f"/brand/{FONTS_CSS}" if fonts else None), "mark_svg": mark_svg()}
    if fonts:
        out["fonts_css"] = fonts_css()
    if portal:
        out["portal_url"] = portal
    return out
