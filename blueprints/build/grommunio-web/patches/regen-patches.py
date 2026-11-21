#!/usr/bin/env python3
"""Regenerate the grommunio-web patch queue from a pristine checkout of the pinned tag (run after every upstream rebase).
  regen-patches.py <pristine-source-dir> <output-patch-dir>
0001  user-visible product name/title/manifest/templates -> "Office Unbound Web" (hand-selected, small)
0003  mechanical sweep of the translatable English product strings (PAIRS: "grommunio Web", and since ou4 the
      grommunio-sync/-files names and "grommunio credentials" users see in the mobile-devices and files settings)
      in .po files and in gettext calls of the JS/PHP sources, so msgids stay consistent between code and catalogues
Logos/icons are not patched (binary): debian/branding/*.{svg,png,ico} are copied over upstream files at install time.
Not changed on purpose: copyright/SPDX headers, the About/licence notice (client/grommunio/ABOUT.js, AGPL attribution),
plugin manifest author/authorURL (attribution), namespaces (Grommunio.*), cookie name, paths, docs and README (they describe upstream)."""
import os
import re
import shutil
import subprocess
import sys
import tempfile

src, out = sys.argv[1:3]
NEW = "Office Unbound Web"
OLD = "grommunio Web"
# 0003: translatable strings, replaced in this order (the longer/more specific ones first)
PAIRS = ((OLD, NEW), ("grommunio Content Panel", "Content Panel"), ("grommunio-sync", "Office Unbound Sync"), ("grommunio-files", "Office Unbound Files"),
         ("grommunio credentials", "Office Unbound credentials"))
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
# ou4: the fallback login and welcome pages (meta description/author, logo label), the iconset description in Settings, and the Help
# button, whose target is the upstream product manual (docs.grommunio.com): hidden by default (users can still switch it on in Settings)
rw("b", "server/includes/templates/login.php", lambda s: s.replace(
    'content="grommunio-web is the ultimate frontend client for grommunio. A rich collaboration platform utilizing e-mail, calendars, webmeetings, file sharing and more."',
    'content="Office Unbound Web: mail, calendar, contacts and tasks"').replace('content="grommunio.com"', 'content="Office Unbound"')
   .replace('aria-label="grommunio"', 'aria-label="Office Unbound"'))
rw("b", "server/includes/templates/welcome.php", lambda s: s.replace('aria-label="grommunio"', 'aria-label="Office Unbound"'))
rw("b", "client/resources/iconsets/breeze/iconset.json", lambda s: s.replace("the default grommunio Iconset", "the default iconset"))


def _help_off(s):
    head, sep, tail = s.partition("'help_manual': {")
    assert sep and "show: true" in tail
    return head + sep + tail.replace("show: true", "show: false", 1)


rw("b", "client/grommunio/settings/data/SettingsDefaultValues.js", _help_off)
mkpatch("a", "b", """Description: Rebrand user-visible product name, page title and web manifest
 Default WEBAPP_TITLE, fallback title, version banner, PWA manifest name, desktop
 app title and the logo aria-label say "Office Unbound Web" instead of the
 trademarked "grommunio Web". Since ou4 also the fallback login/welcome pages
 (meta description and author, logo label), the iconset description, and the
 Help button (upstream product manual) is off by default. Logos and icons are replaced at package build time
 from debian/branding (binary files cannot be carried in a quilt patch).
 Upstream copyright/SPDX headers are untouched.
Author: Office Unbound
Forwarded: not-needed
Last-Update: 2026-11-21
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
        if not any(o in s for o, _ in PAIRS):
            continue

        def sweep(line):
            for o, nw in PAIRS:
                line = line.replace(o, nw)
            return line
        if mode == "po":
            s2 = "\n".join(sweep(l) if l.startswith(("msgid", "msgstr", '"')) else l for l in s.split("\n"))
        else:
            s2 = "\n".join(sweep(l) if GETTEXT.search(l) else l for l in s.split("\n"))
        if s2 != s:
            open(p, "w", encoding="utf8").write(s2)
            n += 1
mkpatch("a", "b", f"""Description: Rename the translatable product strings ("grommunio Web" -> "Office Unbound Web", ou4: -sync/-files names)
 Mechanical sweep ({n} files): msgid/msgstr lines of every .po catalogue and the
 gettext calls (_(), ngettext(), pgettext() ...) in the JS/PHP sources, so code
 strings and catalogues stay in sync. Regenerate with patches/regen-patches.py
 after each upstream rebase. Comments, copyright/SPDX headers, docs and
 identifiers are not touched.
Author: Office Unbound
Forwarded: not-needed
Last-Update: 2026-11-21
""", "0003-branding-translatable-strings.patch")
shutil.rmtree(tmp)
print("patches written to", out)
