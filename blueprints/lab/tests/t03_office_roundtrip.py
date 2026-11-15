#!/usr/bin/env python3
"""T03 DOCX / XLSX / PPTX create -> upload -> content verify -> restart -> re-verify.

Implements files-identity-eval.md test plan items 2 (scripted verification
half) and 4 (restart persistence). Needs: requests, python-docx, openpyxl,
python-pptx (pinned in requirements.txt).

PROVES: Office files generated with known content survive storage in
OpenCloud byte-for-byte AND parse back with the expected headings, table
cells, formulas (incl. a cross-sheet reference), slide text/notes and image,
before and after an OpenCloud (and optionally Collabora) restart.
DOES NOT PROVE: that Collabora can open/edit/save these files, that edits
made in Collabora keep fidelity, formula cached-values (openpyxl writes none;
only an editor save creates them), co-editing, or MS-authored file fidelity.
Those are UI tests: see MANUAL-CHECKLIST.md section A.
"""
import io
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ou_lab as L

rep = L.Report("T03 Office document round-trip")
if not L.need_requests(rep):
    rep.finish()
import requests
try:
    import docx
    import openpyxl
    import pptx
except ImportError as e:
    rep.skipped("dependencies", "missing %s (pip install -r requirements.txt)" % e.name)
    rep.finish()

user, pw = "bob", L.password_for("bob")
if not (L.CA_FILE and pw):
    rep.skipped("config", "need OU_CA_FILE and OU_PASSWORD_BOB")
    rep.finish()


def png(w=8, h=8, rgb=(200, 30, 30)):
    raw = b"".join(b"\x00" + bytes(rgb) * w for _ in range(h))
    def chunk(t, d):
        c = struct.pack(">I", len(d)) + t + d
        return c + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))

TOKEN = "OU-%s" % L.RUN_ID

def make_docx():
    d = docx.Document()
    d.add_heading("Heading %s" % TOKEN, level=1)
    d.add_paragraph("Body paragraph %s with unicode: Grüße 世界" % TOKEN)
    t = d.add_table(rows=2, cols=2)
    t.cell(0, 0).text, t.cell(0, 1).text, t.cell(1, 0).text, t.cell(1, 1).text = "a", "b", "c", TOKEN
    b = io.BytesIO(); d.save(b); return b.getvalue()

def check_docx(b):
    d = docx.Document(io.BytesIO(b))
    heads = [p.text for p in d.paragraphs if p.style.name.startswith("Heading")]
    body = " ".join(p.text for p in d.paragraphs)
    cells = [c.text for r in d.tables[0].rows for c in r.cells]
    return (("Heading %s" % TOKEN) in heads and "Grüße 世界" in body and cells == ["a", "b", "c", TOKEN],
            "heads=%s cells=%s" % (heads, cells))

def make_xlsx():
    wb = openpyxl.Workbook()
    s1 = wb.active; s1.title = "Data"
    s1["A1"], s1["A2"], s1["A3"] = 10, 20, 30
    s1["B1"] = "=SUM(A1:A3)"; s1["B2"] = "=AVERAGE(A1:A3)"
    s2 = wb.create_sheet("Calc")
    s2["A1"] = "=Data!B1*2"; s2["B1"] = TOKEN
    b = io.BytesIO(); wb.save(b); return b.getvalue()

def check_xlsx(b):
    wb = openpyxl.load_workbook(io.BytesIO(b))
    f = (wb["Data"]["B1"].value, wb["Data"]["B2"].value, wb["Calc"]["A1"].value, wb["Calc"]["B1"].value)
    return f == ("=SUM(A1:A3)", "=AVERAGE(A1:A3)", "=Data!B1*2", TOKEN), "formulas=%s" % (f,)

def make_pptx():
    p = pptx.Presentation()
    s = p.slides.add_slide(p.slide_layouts[1])
    s.shapes.title.text = "Slide one %s" % TOKEN
    s.placeholders[1].text = "bullet text"
    s.notes_slide.notes_text_frame.text = "notes %s" % TOKEN
    s2 = p.slides.add_slide(p.slide_layouts[5])
    s2.shapes.title.text = "Slide two"
    s2.shapes.add_picture(io.BytesIO(png()), 0, 0)
    b = io.BytesIO(); p.save(b); return b.getvalue()

def check_pptx(b):
    p = pptx.Presentation(io.BytesIO(b))
    sl = list(p.slides)
    t1 = sl[0].shapes.title.text if sl else None
    notes = sl[0].notes_slide.notes_text_frame.text if sl else None
    pics = [x for x in sl[1].shapes if x.shape_type == 13] if len(sl) > 1 else []
    return (len(sl) == 2 and t1 == "Slide one %s" % TOKEN and notes == "notes %s" % TOKEN and len(pics) == 1,
            "slides=%d title=%r notes=%r pics=%d" % (len(sl), t1, notes, len(pics)))

DOCS = {"test.docx": (make_docx, check_docx), "test.xlsx": (make_xlsx, check_xlsx), "test.pptx": (make_pptx, check_pptx)}
try:
    tok = L.get_token(requests, user, pw)["access_token"]
except Exception as e:  # noqa: BLE001
    rep.failed("token", str(e)[:200]); rep.finish()
dav = L.OcDav(requests, user, tok)
if not rep.check("webdav base path", bool(dav.discover()), "using %s" % dav.base, "no WebDAV base path answered 207"):
    rep.finish()
d = "ou-lab-office-%s" % L.RUN_ID
dav.mkcol(d)
originals = {}
for name, (mk, chk) in DOCS.items():
    originals[name] = mk()
    ok_local, det = chk(originals[name])
    rep.check("%s local self-check" % name, ok_local, det, "generator/checker bug: " + det)
    r = dav.put("%s/%s" % (d, name), originals[name])
    rep.check("upload %s" % name, r.status_code in (201, 204), "HTTP %s" % r.status_code, "HTTP %s" % r.status_code)

def reverify(phase):
    for name, (mk, chk) in DOCS.items():
        g = dav.get("%s/%s" % (d, name))
        same = g.status_code == 200 and g.content == originals[name]
        rep.check("%s bytes identical (%s)" % (name, phase), same, "sha256 %s" % L.sha256(originals[name])[:12],
                  "HTTP %s, bytes differ (server modified the file?)" % g.status_code)
        if g.status_code == 200:
            ok, det = chk(g.content)
            rep.check("%s content (%s)" % (name, phase), ok, det, det)

reverify("after upload")

for role, unit in (("files", "opencloud"), ("office", "collabora")):
    ok, detail = L.ssh_restart(role, unit)
    if ok is None:
        rep.skipped("restart %s" % unit, detail)
    elif not ok:
        rep.failed("restart %s" % unit, detail)
if os.environ.get("OU_SSH_FILES"):
    try:
        L.wait_http(requests, "https://%s/.well-known/openid-configuration" % L.HOST_FILES, 120)
        tok = L.get_token(requests, user, pw)["access_token"]
        dav = L.OcDav(requests, user, tok); dav.discover()
        reverify("after restart")
    except Exception as e:  # noqa: BLE001
        rep.failed("re-verify after restart", str(e)[:200])
else:
    rep.skipped("re-verify after restart", "OU_SSH_FILES not set; restart + re-verify not executed")
dav.delete(d)
rep.finish()
