#!/usr/bin/env python3
"""Document-data integrity checks for the document-tier upgrade drill (docs-upgrade-drill-results.md).

  seed             create bob's folder docdrill/ with canary documents (each written twice => one old version) and record sha256 + version count
  check <label>    re-read every canary through OpenCloud WebDAV: sha256 must equal the recorded one, version list must not shrink
  edit <marker>    REAL edit/save of docdrill/edit-target.docx through OpenCloud /app/open -> Collabora websocket (PutFile), then asks the same
                   session for a PDF export and prints the PDF /Producer; updates the recorded sha256/version count for the intended edit
Env: OU_CA_FILE, OU_PASSWORD_BOB (from ou-id1, not printed), OU_DRILL_STATE = path of the state file.
"""
import io, json, os, re, sys, time, xml.etree.ElementTree as ET
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests"))
import ou_lab as L
import requests

STATE = os.environ["OU_DRILL_STATE"]
D = "docdrill"
tok = L.get_token(requests, "bob", L.password_for("bob"))["access_token"]
dav = L.OcDav(requests, "bob", tok)
assert dav.discover()


def versions(fid):
    r = dav.s.request("PROPFIND", "https://%s/remote.php/dav/meta/%s/v" % (L.HOST_FILES, fid), headers={"Depth": "1"}, timeout=30)
    if r.status_code != 207:
        return -1
    return len([h.text for h in ET.fromstring(r.content).iter("{DAV:}href") if ".REV." in h.text])


def make_docs():
    import docx, openpyxl, pptx
    out = {}
    for i in (1, 2):
        d = docx.Document(); d.add_paragraph("canary document %d revision 1" % i); b = io.BytesIO(); d.save(b); out["canary-%d.docx" % i] = b.getvalue()
    w = openpyxl.Workbook(); w.active["A1"] = 7; w.active["A2"] = "=A1*6"; b = io.BytesIO(); w.save(b); out["canary-3.xlsx"] = b.getvalue()
    p = pptx.Presentation(); p.slides.add_slide(p.slide_layouts[0]).shapes.title.text = "canary slide"; b = io.BytesIO(); p.save(b); out["canary-4.pptx"] = b.getvalue()
    out["canary-5.txt"] = b"plain text canary\n" * 50
    d = docx.Document(); d.add_paragraph("edit target original"); b = io.BytesIO(); d.save(b); out["edit-target.docx"] = b.getvalue()
    return out


def seed():
    dav.mkcol(D)
    st = {}
    for n, data in make_docs().items():
        assert dav.put("%s/%s" % (D, n), b"first version of " + n.encode()).status_code in (201, 204)
        assert dav.put("%s/%s" % (D, n), data).status_code in (201, 204)
        fid = dav.fileid("%s/%s" % (D, n))
        st[n] = {"sha256": L.sha256(data), "fileid": fid, "versions": versions(fid)}
    json.dump(st, open(STATE, "w"), indent=1)
    print("seeded", {k: (v["sha256"][:12], v["versions"]) for k, v in st.items()})


def check(label):
    st = json.load(open(STATE)); bad = 0
    for n, e in st.items():
        r = dav.get("%s/%s" % (D, n)); h = L.sha256(r.content) if r.status_code == 200 else "HTTP%s" % r.status_code
        v = versions(e["fileid"]); ok = h == e["sha256"] and v >= e["versions"]
        bad += not ok
        print("%s %s [%s] sha256 %s %s recorded, versions %s (recorded %s)" % ("PASS" if ok else "FAIL", n, label, h[:12], "==" if h == e["sha256"] else "!=", v, e["versions"]))
    print("-- integrity [%s]: %d files, %d FAIL" % (label, len(st), bad))
    sys.exit(1 if bad else 0)


def edit(marker):
    import websocket
    st = json.load(open(STATE)); n = "edit-target.docx"; e = st[n]
    S = L.CollaboraSession(requests, websocket, tok, e["fileid"])
    assert S.ok_open, S.open_text
    assert S.connect_and_load(), S.messages[-5:]
    assert S.insert_text_and_save(marker), S.messages[-5:]
    # PDF export through OpenCloud: Collabora "saveas" with a .pdf name = WOPI PutRelativeFile, the PDF lands in bob's docdrill/ folder.
    # (downloadas is silently ignored here: OpenCloud's CheckFileInfo does not allow the export download)
    pdfname = "export-%s.pdf" % marker
    time.sleep(3)
    S.ws.send("saveas url=wopi:%s format=pdf options=" % pdfname)
    got = S._until(lambda m: m.startswith(("saveas:", "error:")), 60)
    print("saveas reply:", got, S.messages[-1][:100])
    time.sleep(2)
    r = dav.get("%s/%s" % (D, pdfname)); pdf = r.content if r.status_code == 200 and r.content[:4] == b"%PDF" else None
    print("PDF via PutRelativeFile:", pdfname, r.status_code, len(r.content))
    S.close()
    time.sleep(2)
    data = dav.get("%s/%s" % (D, n)).content
    import docx
    txt = "\n".join(p.text for p in docx.Document(io.BytesIO(data)).paragraphs)
    ok = marker in txt
    print("PASS" if ok else "FAIL", "stored DOCX contains the Collabora edit:", marker, "|", txt[:80].replace("\n", " / "))
    e["sha256"] = L.sha256(data); e["versions"] = versions(e["fileid"]); json.dump(st, open(STATE, "w"), indent=1)
    print("edit-target now sha256 %s versions %s" % (e["sha256"][:12], e["versions"]))
    if pdf:
        prod = []
        for x in re.findall(rb"/Producer\s*(?:<([0-9A-Fa-f]+)>|\(([^)]*)\))", pdf):
            prod.append(bytes.fromhex(x[0].decode()).decode("utf-16") if x[0] else x[1].decode("latin1"))
        print("PDF Producer:", prod)
    else:
        print("FAIL no PDF obtained")
    sys.exit(0 if ok and pdf else 1)


{"seed": lambda: seed(), "check": lambda: check(sys.argv[2]), "edit": lambda: edit(sys.argv[2])}[sys.argv[1]]()
