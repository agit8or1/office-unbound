#!/usr/bin/env python3
"""Regenerate the grommunio-web patch queue from a pristine checkout of the pinned tag (run after every upstream rebase).
  regen-patches.py <pristine-source-dir> <output-patch-dir>
0001  user-visible product name/title/manifest/templates -> "Office Unbound Web" (hand-selected, small)
0002  mechanical sweep of the translatable English product string "grommunio Web" in .po files and in gettext
      calls of the JS/PHP sources, so msgids stay consistent between code and catalogues
Logos/icons are not patched (binary): debian/branding/*.{svg,png,ico} are copied over upstream files at install time.
Not changed on purpose: copyright/SPDX headers, namespaces (Grommunio.*), cookie name, paths, grommunio-sync/-files
product names inside strings, docs and README (they describe upstream)."""
import os
import re
import shutil
import subprocess
import sys
import tempfile

src, out = sys.argv[1:3]
NEW = "Office Unbound Web"
OLD = "grommunio Web"
tmp = tempfile.mkdtemp()
shutil.copytree(src, tmp + "/a", ignore=shutil.ignore_patterns(".git", "node_modules"), symlinks=True)
shutil.copytree(tmp + "/a", tmp + "/b", symlinks=True)


def rw(base, rel, fn):
    p = os.path.join(tmp, base, rel)
    s = open(p, encoding="utf8").read()
    s2 = fn(s)
    assert s != s2, rel
    open(p, "w", encoding="utf8").write(s2)


def mkpatch(a, b, hdr, name):
    r = subprocess.run(["diff", "-ruN", a, b], cwd=tmp, capture_output=True, text=True)
    lines = []
    for l in r.stdout.split("\n"):
        if l.startswith("--- ") or l.startswith("+++ "):
            tag, path = l[:4], l[4:].split("\t")[0]
            l = tag + ("a/" if tag == "--- " else "b/") + path.split("/", 1)[1]
        lines.append(l)
    open(os.path.join(out, name), "w", encoding="utf8").write(hdr + "\n" + "\n".join(lines))


# ---- 0001
rw("b", "config.php.dist", lambda s: s.replace('define("WEBAPP_TITLE", "grommunio Web");', 'define("WEBAPP_TITLE", "Office Unbound Web");'))
rw("b", "index.php", lambda s: s.replace("'grommunio Web';", "'Office Unbound Web';").replace("$version = 'grommunio Web ' .", "$version = 'Office Unbound Web ' ."))
rw("b", "manifest.webmanifest", lambda s: s.replace('"name": "grommunio Web"', '"name": "Office Unbound Web"')
   .replace('"short_name": "grommunioWeb"', '"short_name": "OUWeb"')
   .replace("make full use of grommunio through", "make full use of Office Unbound through"))
rw("b", "server/includes/templates/deskapp.php", lambda s: s.replace("<title>grommunio Web</title>", "<title>Office Unbound Web</title>"))
rw("b", "server/includes/templates/webclient.php", lambda s: s.replace('aria-label="grommunio"', 'aria-label="Office Unbound"'))
mkpatch("a", "b", """Description: Rebrand user-visible product name, page title and web manifest
 Default WEBAPP_TITLE, fallback title, version banner, PWA manifest name, desktop
 app title and the logo aria-label say "Office Unbound Web" instead of the
 trademarked "grommunio Web". Logos and icons are replaced at package build time
 from debian/branding (binary files cannot be carried in a quilt patch).
 Upstream copyright/SPDX headers are untouched.
Author: Office Unbound
Forwarded: not-needed
Last-Update: 2026-11-15
""", "0001-branding-product-name.patch")

# ---- 0002
shutil.rmtree(tmp + "/a")
shutil.copytree(tmp + "/b", tmp + "/a", symlinks=True)
GETTEXT = re.compile(r"\b(?:_|pgettext|ngettext|npgettext|dgettext|dngettext)\(")
SKIP = ("/vendor/", "/extjs/", "/tinymce/", "/test/", "/tests/", "/doc/", "/node_modules/")
n = 0
for dp, dn, fn in os.walk(tmp + "/b"):
    for f in fn:
        p = os.path.join(dp, f)
        rel = os.path.relpath(p, tmp + "/b")
        if any(x in "/" + rel for x in SKIP) or f.endswith("-debug.js"):
            continue
        if rel.endswith(".po") and "/LC_MESSAGES/" in rel:
            mode = "po"
        elif rel.endswith((".js", ".php")):
            mode = "code"
        else:
            continue
        try:
            s = open(p, encoding="utf8").read()
        except UnicodeDecodeError:
            continue
        if OLD not in s:
            continue
        if mode == "po":
            s2 = "\n".join(l.replace(OLD, NEW) if l.startswith(("msgid", "msgstr", '"')) else l for l in s.split("\n"))
        else:
            s2 = "\n".join(l.replace(OLD, NEW) if (GETTEXT.search(l) and OLD in l) else l for l in s.split("\n"))
        if s2 != s:
            open(p, "w", encoding="utf8").write(s2)
            n += 1
mkpatch("a", "b", f"""Description: Rename the translatable product string "grommunio Web" to "Office Unbound Web"
 Mechanical sweep ({n} files): msgid/msgstr lines of every .po catalogue and the
 gettext calls (_(), ngettext(), pgettext() ...) in the JS/PHP sources, so code
 strings and catalogues stay in sync. Regenerate with patches/regen-patches.py
 after each upstream rebase. Comments, copyright/SPDX headers, docs and
 identifiers are not touched.
Author: Office Unbound
Forwarded: not-needed
Last-Update: 2026-11-15
""", "0003-branding-translatable-strings.patch")
shutil.rmtree(tmp)
print("patches written to", out)
