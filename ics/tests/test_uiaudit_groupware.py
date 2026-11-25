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
