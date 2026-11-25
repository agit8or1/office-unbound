"""UI audit 2026-11-25, shared visual system: the roles and scales added to the one token file (blueprints/catalog/templates/brand/ou-brand.css)
are complete in both themes, readable where they are used, and the sign-in and account themes use them instead of ad-hoc colours."""
import re
from pathlib import Path

from ics.deploy import brand

ROOT = Path(__file__).resolve().parents[2]
BRAND = ROOT / "blueprints/catalog/templates/brand"
SURFACES = ("bg", "bg2", "side", "surface", "raised", "sel")
COLOUR_ROLES = ("focus", "link", "action-hover", "accent-hover", "info", "info-bg", "scrim")
SCALES = {"fs": ("xs", "sm", "md", "lg", "xl", "2xl"), "sp": ("1", "2", "3", "4", "5", "6", "8", "12")}


def _px(v: str) -> float:
    m = re.fullmatch(r"(\d+(?:\.\d+)?)px", v.strip())
    assert m, v
    return float(m.group(1))


def test_the_new_roles_exist_in_both_themes_and_the_forced_dark_block_matches_the_system_one():
    src = (BRAND / "ou-brand.css").read_text().split("/* components */", 1)[0]
    media = dict(re.findall(r"--ou-([a-z0-9-]+):\s*([^;]+);", src.split("@media (prefers-color-scheme: dark)", 1)[1].split(':root[data-theme="dark"]', 1)[0]))
    forced = dict(re.findall(r"--ou-([a-z0-9-]+):\s*([^;]+);", src.split(':root[data-theme="dark"] {', 1)[1]))
    assert media == forced                                       # the portal's Appearance switch and the system setting agree
    light, dark = brand.tokens()
    for role in COLOUR_ROLES:
        assert role in light and role in media, role            # every colour role has its dark value, not the light one inherited


def test_focus_links_and_hover_fills_are_readable_on_every_surface():
    for t in brand.tokens():
        for bg in SURFACES:
            assert brand.contrast(t["focus"], t[bg]) >= 3.0, ("focus", bg)          # WCAG 2.2 1.4.11 / 2.4.13: the ring against its surroundings
            assert brand.contrast(t["link"], t[bg]) >= 4.5, ("link", bg)
            assert brand.contrast(t["info"], t[bg]) >= 4.5, ("info", bg)
        assert brand.contrast(t["action-ink"], t["action-hover"]) >= 4.5
        assert brand.contrast(t["accent-ink"], t["accent-hover"]) >= 4.5
        assert brand.contrast(t["info"], t["info-bg"]) >= 4.5 and brand.contrast(t["ink"], t["info-bg"]) >= 4.5
        for k in ("ok", "warn", "bad"):                                                 # status text on its own tint and on the selection
            assert brand.contrast(t[k], t[f"{k}-bg"]) >= 4.5 and brand.contrast(t[k], t["raised"]) >= 4.5, k


def test_type_and_spacing_scales_are_ordered_and_on_the_grid():
    light, _ = brand.tokens()
    sizes = [_px(light[f"fs-{k}"]) for k in SCALES["fs"]]
    assert sizes == sorted(sizes) and len(set(sizes)) == len(sizes) and sizes[0] >= 12      # nothing smaller than 12px
    steps = [_px(light[f"sp-{k}"]) for k in SCALES["sp"]]
    assert steps == sorted(steps) and all(s % 4 == 0 for s in steps)
    for k in ("control-h", "control-h-sm", "nav-item-h", "toolbar-h", "row-h", "row-h-dense"):
        assert _px(light[k]) % 2 == 0, k
    assert [_px(light[k]) for k in ("icon-sm", "icon", "icon-lg")] == [16, 18, 20]       # the icon standard (design-system.md "Icons")
    assert _px(light["radius-sm"]) <= _px(light["radius"]) <= _px(light["radius-lg"]) <= 8


def test_sign_in_and_account_use_the_roles_not_the_brand_accent_for_actions_links_and_focus():
    for name in ("keycloak-login.css", "keycloak-account.css"):
        css = (BRAND / name).read_text()
        assert not re.search(r"#[0-9a-fA-F]{3,8}\b", re.sub(r"/\*.*?\*/", "", css, flags=re.S)), name   # colours only through tokens
        assert "--pf-v5-c-button--m-primary--BackgroundColor: var(--ou-action)" in css
        assert "--pf-v5-global--link--Color: var(--ou-link)" in css
        assert ":focus-visible { outline: var(--ou-focus-w) solid var(--ou-focus)" in css
        assert ".pf-v5-c-form-control:focus-within { outline:" in css                      # one ring around the field
    login = (BRAND / "keycloak-login.css").read_text()
    assert "@media (max-width: 575px)" in login and "padding-inline: var(--ou-sp-4)" in login   # the phone gutter


def test_keycloak_skin_urls_change_with_the_content():
    """Keycloak's gzip cache and the 30-day max-age kept an old ou.css in browsers: the theme names the skin by content."""
    a, b = brand.versioned("ou.css", "x"), brand.versioned("ou.css", "y")
    assert a != b and re.fullmatch(r"ou-[0-9a-f]{10}\.css", a)
    files = {x["path"]: x["content"] for x in brand.keycloak_theme("https://app.e2e.example/")}
    for t in ("login", "account"):
        props = files[f"ou/{t}/theme.properties"]
        name = re.search(r"styles=.* (ou-[0-9a-f]{10}\.css)\n", props).group(1)
        assert files[f"ou/{t}/resources/{name}"] == files[f"ou/{t}/resources/ou.css"]
    msgs = files["ou/login/messages/messages_en.properties"]
    assert "doLogIn=Sign in\n" in msgs                                                       # sentence case, like the rest of the suite
