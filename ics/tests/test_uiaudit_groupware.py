"""UI audit 2026-11-25, groupware (grommunio-web 5.2): calendar root cause, skin rules, sysadmin defaults.

Root cause of the "calendar without day columns" (officeunbound8, 5.2-ou5): the portal's Calendar tile opens
/web/?action=context&view=calendar; patch 0002's handler called container.switchContext(context) WITHOUT a folder, so the
calendar's appointment store was never loaded (no 'appointmentlistmodule' request) and CalendarMultiView, which creates its
day views only in onLoad, drew only the time strip. A click on the Calendar tab passes the folders (MainTab#selectContext)
and renders normally. Reproduced and the patched handler verified in the live app, browser only.
"""
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
GW = ROOT / "blueprints/build/grommunio-web"
SKIN = ROOT / "blueprints/catalog/templates/brand/grommunio.css"
UPSTREAM = Path("/var/lib/office-unbound/pkgbuild/src/grommunio-web")


def _handler() -> str:
    patch = (GW / "patches/0002-context-deep-link.patch").read_text()
    js = patch.split("+++ b/client/grommunio/core/ContextURLAction.js", 1)[1].split("--- a/", 1)[0]
    return "\n".join(l[1:] for l in js.splitlines() if l.startswith("+"))


def test_the_deep_link_opens_the_context_with_its_folder_like_the_main_tab():
    js = _handler()
    body = js[js.index("handleContext: function"):]
    assert "model.getFolders()" in body and "model.getDefaultFolder()" in body
    assert re.search(r"container\.switchContext\(context, folder\)", body)
    assert not re.search(r"container\.switchContext\(context\)", body)   # the 5.2-ou5 call that left the calendar empty


def test_the_deep_link_patch_hunk_counts_match():
    patch = (GW / "patches/0002-context-deep-link.patch").read_text()
    m = re.search(r"\+\+\+ b/client/grommunio/core/ContextURLAction\.js\n@@ -0,0 \+1,(\d+) @@\n", patch)
    assert m and int(m.group(1)) == len(_handler().splitlines())


@pytest.mark.skipif(not (UPSTREAM / "server/includes/util.php").exists() or not shutil.which("patch"), reason="upstream 5.2 source not here")
def test_the_deep_link_patch_applies_to_upstream_5_2(tmp_path):
    (tmp_path / "server/includes").mkdir(parents=True)
    shutil.copy(UPSTREAM / "server/includes/util.php", tmp_path / "server/includes/util.php")
    r = subprocess.run(["patch", "-p1", "--dry-run", "-i", str(GW / "patches/0002-context-deep-link.patch")], cwd=tmp_path, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    main_tab = (UPSTREAM / "client/grommunio/core/ui/MainTab.js").read_text()   # the behaviour the handler copies
    assert "contextModel.getDefaultFolder()" in main_tab and "container.switchContext(context, contextFolder)" in main_tab


def test_the_package_revision_and_the_catalog_pin_carry_the_fix():
    rev = yaml.safe_load((GW / "recipe.yaml").read_text())["ou_revision"]
    assert rev >= "ou6"
    comp = yaml.safe_load((ROOT / "blueprints/catalog/components/groupware.yaml").read_text())
    assert next(a["version"] for a in comp["artifacts"] if a.get("package") == "ou-grommunio-web") == f"5.2-{rev}"


# ---------------------------------------------------------------- skin (blueprints/catalog/templates/brand/grommunio.css)
def test_the_calendar_grid_is_painted_from_the_tokens_not_through_upstreams_dark_filter():
    """Superseded 2026-11-26 (concept alignment): the 2026-11-25 skin kept upstream dark mode's `filter: invert(.85) hue-rotate(180deg)` on
    the grid cells and gave pre-inverted colours (#005e56). The cells are now painted from the tokens in both themes and the filter is
    dropped, so no pre-image colour remains; today and the now-line use the accent like the concept (test_concept_groupware.py)."""
    css = SKIN.read_text()
    assert "#005e56" not in css and "rgba(0, 94, 86," not in css
    cell = css.split('.k-html-body-background > div[class*="k-line-"] {', 1)[1].split("}", 1)[0]
    assert "filter: none !important" in cell and "background-color: var(--ou-cal-off) !important" in cell
    assert "#grommunio-mainpanel-contentpanel-calendar {\n  --theme-primary-color: var(--ou-a);" in css
    # the 0.13 rule painted today's title teal on upstream's copper header and covered the working-hours shading
    assert "color: var(--ou-action) !important; font-weight: 600;" not in css
    assert not re.search(r"k-html-body-background \.k-today \{ background-color", css)
    assert "box-shadow: inset 0 0 0 100vmax var(--ou-cal-today)" in css


def test_upstream_dark_mode_greys_point_at_the_shared_dark_tokens():
    css = SKIN.read_text()
    block = css.split("body.grommunio-webclient.dark-mode {", 1)[1].split("}", 1)[0]
    for prop in ("--dm-bg", "--dm-bg-paper", "--dm-bg-elevated", "--dm-fg", "--dm-border", "--dm-selected", "--dm-hover"):
        assert re.search(rf"{prop}: var\(--ou-[a-z0-9-]+\);", block), prop
    assert "#" not in block   # tokens only, no colour of its own
    up = UPSTREAM / "client/resources/css/darkmode.css"
    if up.exists():   # every property mapped is one upstream defines
        defined = set(re.findall(r"(--dm-[a-z-]+):", up.read_text()))
        assert set(re.findall(r"(--dm-[a-z-]+):", block)) <= defined


def test_toolbar_icons_and_empty_states_shrink_the_drawing_not_the_measured_box():
    css = SKIN.read_text()
    audit = css[css.index("/* toolbar icons (UI audit"):]
    props = set(re.findall(r"[{;]\s*([a-z-]+)\s*:", re.sub(r"/\*.*?\*/", "", audit, flags=re.S)))
    assert not props & {"width", "height", "margin", "padding", "position", "top", "left", "right", "bottom", "display", "flex",
                        "font-size", "line-height"}, props
    assert "background-size: 20px 20px !important" in audit and "mask-size: 48px 48px" in audit
