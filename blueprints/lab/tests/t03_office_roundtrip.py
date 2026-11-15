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

for role, unit in (("files", "opencloud"), ("office", "coolwsd")):
    ok, detail = L.ssh_restart(role, unit)
    if ok is None:
        rep.skipped("restart %s" % unit, detail)
    elif not ok:
        rep.failed("restart %s" % unit, detail)
restarted = any(os.environ.get(k) for k in ("OU_SSH_FILES", "OU_MACHINE_FILES"))
if restarted:
    try:
        L.wait_http(requests, "https://%s/.well-known/openid-configuration" % L.HOST_FILES, 120)
        L.wait_http(requests, "https://%s/hosting/discovery" % L.HOST_OFFICE, 120)
        L.wait_app_ready(requests)  # KI-1
        tok = L.get_token(requests, user, pw)["access_token"]
        dav = L.OcDav(requests, user, tok); dav.discover()
        reverify("after restart")
    except Exception as e:  # noqa: BLE001
        rep.failed("re-verify after restart", str(e)[:200])
else:
    rep.skipped("re-verify after restart", "no OU_SSH_FILES / OU_MACHINE_FILES; restart + re-verify not executed")

# ---- Collabora editor save fidelity (VERIFIED approach, see T04): open each file in a real Collabora session, edit,
# save (PutFile), re-read via WebDAV and check what survived the LibreOffice re-export.
import time
try:
    import websocket
except ImportError:
    websocket = None

def collabora_edit(name, mutate):
    fid = dav.fileid("%s/%s" % (d, name))
    S = L.CollaboraSession(requests, websocket, tok, fid)
    if not S.ok_open:
        return False, "app/open HTTP %s %s" % (S.open_status, S.open_text[:100])
    try:
        if not S.connect_and_load():
            return False, "load failed: %s" % S.messages[-3:]
        mutate(S)
        ok = S.save()
        return ok, "" if ok else "save failed: %s" % S.messages[-3:]
    finally:
        S.close()

def mut_docx(S):
    S.ws.send("textinput id=0 text=EDITED-"); time.sleep(1)

def mut_xlsx(S):
    S.ws.send('uno .uno:GoToCell {"ToPoint":{"type":"string","value":"D5"}}'); time.sleep(1)
    S.ws.send("textinput id=0 text=EDITED-%s" % TOKEN); time.sleep(1)
    S.ws.send("key type=input char=13 key=1280"); S.ws.send("key type=up char=13 key=1280"); time.sleep(1)

def mut_pptx(S):
    time.sleep(1)  # re-save only: slide text editing needs object selection (manual checklist)

def after_edit_docx(b):
    dd = docx.Document(io.BytesIO(b))
    heads = [p.text for p in dd.paragraphs if p.style.name.startswith("Heading")]
    body = " ".join(p.text for p in dd.paragraphs)
    cells = [c.text for r in dd.tables[0].rows for c in r.cells]
    return (any(TOKEN in h and "EDITED-" in h for h in heads) and "Grüße 世界" in body and cells == ["a", "b", "c", TOKEN],
            "heads=%s cells=%s" % (heads, cells))

def after_edit_xlsx(b):
    wb = openpyxl.load_workbook(io.BytesIO(b)); wv = openpyxl.load_workbook(io.BytesIO(b), data_only=True)
    f = (wb["Data"]["B1"].value, wb["Data"]["B2"].value, wb["Calc"]["A1"].value, wb["Calc"]["B1"].value)
    cv = (wv["Data"]["B1"].value, wv["Data"]["B2"].value, wv["Calc"]["A1"].value)
    ed = wb["Data"]["D5"].value
    return (f == ("=SUM(A1:A3)", "=AVERAGE(A1:A3)", "=Data!B1*2", TOKEN) and cv == (60, 20, 120) and ed == "EDITED-" + TOKEN,
            "formulas=%s cached=%s D5=%r" % (f, cv, ed))

def after_edit_pptx(b):
    ok, det = check_pptx(b)
    return ok, det

if websocket is None:
    rep.skipped("collabora edit fidelity", "websocket-client missing")
else:
    for name, mut, chk in (("test.docx", mut_docx, after_edit_docx), ("test.xlsx", mut_xlsx, after_edit_xlsx),
                           ("test.pptx", mut_pptx, after_edit_pptx)):
        ok, det = collabora_edit(name, mut)
        if not rep.check("%s edited+saved in Collabora" % name, ok, "PutFile ok", det):
            continue
        time.sleep(2)
        g = dav.get("%s/%s" % (d, name))
        ok2, det2 = chk(g.content)
        rep.check("%s content after Collabora save" % name, ok2, det2, det2)
        rep.check("%s bytes changed by editor save" % name, g.content != originals[name], "%d -> %d bytes" % (len(originals[name]), len(g.content)),
                  "file unchanged: save was a no-op")

dav.delete(d)
rep.finish()
