#!/usr/bin/env python3
"""REST convert-to round-trips with content verification. Runs against coolwsd at 127.0.0.1:9980."""
import subprocess, sys, os, io, zipfile, json
W = "/tmp/conv"; os.makedirs(W, exist_ok=True)
def mk_inputs():
    import docx, openpyxl
    d = docx.Document(); d.add_heading("OU Roundtrip Heading", 1); d.add_paragraph("OU-DOCX-BODY-ALPHA table below")
    t = d.add_table(rows=2, cols=2); t.cell(0,0).text="c00"; t.cell(1,1).text="OU-CELL-11"; d.save(f"{W}/in.docx")
    wb = openpyxl.Workbook(); ws = wb.active; ws["A1"]="OU-XLSX-TEXT"; ws["A2"]=21; ws["A3"]=21; ws["B1"]="=A2+A3"; wb.save(f"{W}/in.xlsx")
    from pptx import Presentation
    p = Presentation(); s = p.slides.add_slide(p.slide_layouts[1]); s.shapes.title.text="OU-PPTX-TITLE"; s.placeholders[1].text="OU-PPTX-BODY"; p.save(f"{W}/in.pptx")
def conv(src, fmt, out):
    r = subprocess.run(["curl","-s","-S","-o",out,"-w","%{http_code}","-F",f"data=@{src}",f"http://127.0.0.1:9980/cool/convert-to/{fmt}"],capture_output=True,text=True)
    return r.stdout.strip(), (os.path.getsize(out) if os.path.exists(out) else 0)
results = []
def check(name, ok, detail): results.append(ok); print(("PASS " if ok else "FAIL ")+name+" :: "+detail)
mk_inputs()
def pdftext(f): return subprocess.run(["pdftotext",f,"-"],capture_output=True,text=True).stdout
for src, mark in (("in.docx","OU-DOCX-BODY-ALPHA"),("in.xlsx","OU-XLSX-T"),("in.pptx","OU-PPTX-TITLE")):
    code, sz = conv(f"{W}/{src}","pdf",f"{W}/{src}.pdf"); t = pdftext(f"{W}/{src}.pdf")
    check(f"{src} -> pdf", code=="200" and mark in t, f"http={code} bytes={sz} marker_in_pdf_text={mark in t} (xlsx cell text is clipped by adjacent cell in print layout)")
rt = {"in.docx":("odt","docx"),"in.xlsx":("ods","xlsx"),"in.pptx":("odp","pptx")}
for src,(mid,back) in rt.items():
    code,sz = conv(f"{W}/{src}",mid,f"{W}/{src}.{mid}")
    z = zipfile.ZipFile(f"{W}/{src}.{mid}"); mt = z.read("mimetype").decode()
    content = z.read("content.xml").decode()
    marker = {"in.docx":"OU-DOCX-BODY-ALPHA","in.xlsx":"OU-XLSX-TEXT","in.pptx":"OU-PPTX-TITLE"}[src]
    check(f"{src} -> {mid}", code=="200" and marker in content, f"http={code} bytes={sz} mimetype={mt}")
    code2,sz2 = conv(f"{W}/{src}.{mid}",back,f"{W}/rt.{back}")
    ok=False; det=""
    if back=="docx":
        import docx; d=docx.Document(f"{W}/rt.docx"); txt="\n".join(p.text for p in d.paragraphs); cells=[c.text for t in d.tables for r in t.rows for c in r.cells]
        ok = "OU-DOCX-BODY-ALPHA" in txt and "OU-CELL-11" in cells; det=f"paras={txt[:60]!r} cells={cells}"
    elif back=="xlsx":
        import openpyxl; wb=openpyxl.load_workbook(f"{W}/rt.xlsx"); ws=wb.active; wv=openpyxl.load_workbook(f"{W}/rt.xlsx",data_only=True).active
        ok = ws["A1"].value=="OU-XLSX-TEXT" and str(ws["B1"].value).replace(" ","") in ("=A2+A3",) and wv["B1"].value==42; det=f"A1={ws['A1'].value!r} B1formula={ws['B1'].value!r} B1cached={wv['B1'].value!r}"
    else:
        from pptx import Presentation; p=Presentation(f"{W}/rt.pptx"); texts=[sh.text_frame.text for s in p.slides for sh in s.shapes if sh.has_text_frame]
        ok = "OU-PPTX-TITLE" in texts and "OU-PPTX-BODY" in texts; det=f"texts={texts}"
    check(f"{src} -> {mid} -> {back}", code2=="200" and ok, f"http={code2} bytes={sz2} {det}")
print("RESULT:", "PASS" if all(results) else "FAIL", f"({sum(results)}/{len(results)})")
