"""Small, valid office documents generated in memory (stdlib zipfile only): ODF text/spreadsheet/presentation (.odt/.ods/.odp) and
OOXML (.docx/.xlsx/.pptx). Content comes from org.Doc. Document comments are real annotations (ODF office:annotation, OOXML
word/comments.xml), so the office editor shows them as comments. Deterministic: the same Doc gives the same bytes (fixed zip times),
which keeps a re-upload a no-op for the content."""
from __future__ import annotations

import io
import re
import zipfile
from xml.sax.saxutils import escape as _x

from . import org

DATE = "2026-01-05T09:00:00"
ZTIME = (2026, 1, 5, 9, 0, 0)
MIME = {
    ".odt": "application/vnd.oasis.opendocument.text",
    ".ods": "application/vnd.oasis.opendocument.spreadsheet",
    ".odp": "application/vnd.oasis.opendocument.presentation",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}


def ext(key: str) -> str:
    return key[key.rfind("."):]


def mime(key: str) -> str:
    return MIME[ext(key)]


def render(doc: org.Doc) -> bytes:
    e = ext(doc.key)
    fn = {".odt": _odt, ".ods": _ods, ".odp": _odp, ".docx": _docx, ".xlsx": _xlsx, ".pptx": _pptx}[e]
    kinds = {".odt": "document", ".docx": "document", ".ods": "spreadsheet", ".xlsx": "spreadsheet", ".odp": "presentation", ".pptx": "presentation"}
    if kinds[e] != doc.kind:
        raise ValueError(f"{doc.key}: extension does not match kind {doc.kind}")
    return fn(doc)


def _zip(parts: list[tuple[str, str | bytes]], odf_mime: str | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        if odf_mime:   # ODF: "mimetype" first and stored uncompressed (ODF 1.2 part 3, 3.3)
            z.writestr(zipfile.ZipInfo("mimetype", ZTIME), odf_mime, compress_type=zipfile.ZIP_STORED)
        for name, data in parts:
            z.writestr(zipfile.ZipInfo(name, ZTIME), data, compress_type=zipfile.ZIP_DEFLATED)
    return buf.getvalue()


def _author(uid: str) -> str:
    return org.BY_UID[uid].name


# ---------------------------------------------------------------- ODF
_ODF_NS = ('xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" '
           'xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" '
           'xmlns:presentation="urn:oasis:names:tc:opendocument:xmlns:presentation:1.0" xmlns:dc="http://purl.org/dc/elements/1.1/" '
           'xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" xmlns:of="urn:oasis:names:tc:opendocument:xmlns:of:1.2" '
           'xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" '
           'xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0"')


def _odf(doc: org.Doc, body: str, odf_mime: str) -> bytes:
    content = (f'<?xml version="1.0" encoding="UTF-8"?>\n<office:document-content {_ODF_NS} office:version="1.3">'
               f'<office:body>{body}</office:body></office:document-content>')
    meta = (f'<?xml version="1.0" encoding="UTF-8"?>\n<office:document-meta {_ODF_NS} office:version="1.3"><office:meta>'
            f'<dc:title>{_x(doc.title)}</dc:title><meta:generator>Office Unbound demo seed</meta:generator>'
            f'<meta:creation-date>{DATE}</meta:creation-date></office:meta></office:document-meta>')
    manifest = ('<?xml version="1.0" encoding="UTF-8"?>\n<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" '
                f'manifest:version="1.3"><manifest:file-entry manifest:full-path="/" manifest:media-type="{odf_mime}"/>'
                '<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>'
                '<manifest:file-entry manifest:full-path="meta.xml" manifest:media-type="text/xml"/></manifest:manifest>')
    return _zip([("content.xml", content), ("meta.xml", meta), ("META-INF/manifest.xml", manifest)], odf_mime)


def _odt(doc: org.Doc) -> bytes:
    at = 1 if len(doc.paragraphs) > 1 else 0          # comments sit on the second paragraph (the first when there is only one)
    out = [f'<text:h text:outline-level="1">{_x(doc.title)}</text:h>']
    for i, p in enumerate(doc.paragraphs):
        ann = "".join(f'<office:annotation><dc:creator>{_x(_author(uid))}</dc:creator><dc:date>{DATE}</dc:date>'
                      f'<text:p>{_x(c)}</text:p></office:annotation>' for uid, c in (doc.comments if i == at else ()))
        out.append(f"<text:p>{ann}{_x(p)}</text:p>")
    return _odf(doc, "<office:text>" + "".join(out) + "</office:text>", MIME[".odt"])


_REF = re.compile(r"\b([A-Z]{1,2}[0-9]{1,4})(?::([A-Z]{1,2}[0-9]{1,4}))?\b")


def odf_formula(f: str) -> str:
    """=SUM(B2:E2) -> of:=SUM([.B2:.E2]); =B2*C2 -> of:=[.B2]*[.C2]"""
    body = _REF.sub(lambda m: f"[.{m.group(1)}:.{m.group(2)}]" if m.group(2) else f"[.{m.group(1)}]", f[1:])
    return "of:=" + body


def _ods_cell(v) -> str:
    if isinstance(v, str) and v.startswith("="):
        return f'<table:table-cell table:formula="{_x(odf_formula(v))}" office:value-type="float"/>'
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return f'<table:table-cell office:value-type="float" office:value="{v}"><text:p>{v}</text:p></table:table-cell>'
    return f'<table:table-cell office:value-type="string"><text:p>{_x(str(v))}</text:p></table:table-cell>'


def _ods(doc: org.Doc) -> bytes:
    rows = "".join("<table:table-row>" + "".join(_ods_cell(v) for v in r) + "</table:table-row>" for r in doc.rows)
    ncol = max(len(r) for r in doc.rows)
    body = (f'<office:spreadsheet><table:table table:name="{_x(doc.title[:31])}"><table:table-column table:number-columns-repeated="{ncol}"/>'
            f"{rows}</table:table></office:spreadsheet>")
    return _odf(doc, body, MIME[".ods"])


def _odp(doc: org.Doc) -> bytes:
    pages = []
    for i, (title, text) in enumerate(doc.slides, 1):
        pages.append(f'<draw:page draw:name="page{i}" draw:master-page-name="Default">'
                     f'<draw:frame svg:x="2cm" svg:y="1.5cm" svg:width="24cm" svg:height="3cm"><draw:text-box><text:p>{_x(title)}</text:p></draw:text-box></draw:frame>'
                     f'<draw:frame svg:x="2cm" svg:y="5.5cm" svg:width="24cm" svg:height="10cm"><draw:text-box><text:p>{_x(text)}</text:p></draw:text-box></draw:frame>'
                     "</draw:page>")
    return _odf(doc, "<office:presentation>" + "".join(pages) + "</office:presentation>", MIME[".odp"])


# ---------------------------------------------------------------- OOXML
_RELS_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
_OD = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_XML = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'


def _rels(items: list[tuple[str, str, str]]) -> str:
    return _XML + f'<Relationships xmlns="{_RELS_NS}">' + "".join(
        f'<Relationship Id="{i}" Type="{_OD}/{t}" Target="{tg}"/>' for i, t, tg in items) + "</Relationships>"


def _types(defaults: dict[str, str], overrides: dict[str, str]) -> str:
    d = {"rels": "application/vnd.openxmlformats-package.relationships+xml", "xml": "application/xml", **defaults}
    return (_XML + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            + "".join(f'<Default Extension="{k}" ContentType="{v}"/>' for k, v in d.items())
            + "".join(f'<Override PartName="{k}" ContentType="{v}"/>' for k, v in overrides.items()) + "</Types>")


def _core(doc: org.Doc) -> str:
    return (_XML + '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            f'<dc:title>{_x(doc.title)}</dc:title><dc:creator>Office Unbound demo seed</dc:creator>'
            f'<dcterms:created xsi:type="dcterms:W3CDTF">{DATE}Z</dcterms:created></cp:coreProperties>')


_CORE_T = "application/vnd.openxmlformats-package.core-properties+xml"


def _pkg_rels(main_type: str, target: str) -> str:
    return (_XML + f'<Relationships xmlns="{_RELS_NS}"><Relationship Id="rId1" Type="{_OD}/{main_type}" Target="{target}"/>'
            '<Relationship Id="rId9" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" '
            'Target="docProps/core.xml"/></Relationships>')


_W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'


def _docx(doc: org.Doc) -> bytes:
    def run(t: str) -> str:
        return f'<w:r><w:t xml:space="preserve">{_x(t)}</w:t></w:r>'
    paras = [f'<w:p><w:pPr><w:pStyle w:val="Title"/></w:pPr>{run(doc.title)}</w:p>']
    for i, p in enumerate(doc.paragraphs):
        if i == 1 and doc.comments:
            starts = "".join(f'<w:commentRangeStart w:id="{n}"/>' for n in range(len(doc.comments)))
            ends = "".join(f'<w:commentRangeEnd w:id="{n}"/><w:r><w:commentReference w:id="{n}"/></w:r>' for n in range(len(doc.comments)))
            paras.append(f"<w:p>{starts}{run(p)}{ends}</w:p>")
        else:
            paras.append(f"<w:p>{run(p)}</w:p>")
    body = _XML + f"<w:document {_W}><w:body>" + "".join(paras) + "<w:sectPr/></w:body></w:document>"
    parts = [("word/document.xml", body), ("docProps/core.xml", _core(doc)),
             ("_rels/.rels", _pkg_rels("officeDocument", "word/document.xml"))]
    over = {"/word/document.xml": "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml", "/docProps/core.xml": _CORE_T}
    if doc.comments:
        cm = "".join(f'<w:comment w:id="{n}" w:author="{_x(_author(uid))}" w:date="{DATE}Z" w:initials="{org.BY_UID[uid].initials}">'
                     f"<w:p>{run(c)}</w:p></w:comment>" for n, (uid, c) in enumerate(doc.comments))
        parts.append(("word/comments.xml", _XML + f"<w:comments {_W}>{cm}</w:comments>"))
        parts.append(("word/_rels/document.xml.rels", _rels([("rId1", "comments", "comments.xml")])))
        over["/word/comments.xml"] = "application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml"
    parts.insert(0, ("[Content_Types].xml", _types({}, over)))
    return _zip(parts)


def _col(i: int) -> str:
    s = ""
    i += 1
    while i:
        i, r = divmod(i - 1, 26)
        s = chr(65 + r) + s
    return s


def _xlsx(doc: org.Doc) -> bytes:
    rows = []
    for r, row in enumerate(doc.rows, 1):
        cells = []
        for c, v in enumerate(row):
            ref = f"{_col(c)}{r}"
            if isinstance(v, str) and v.startswith("="):
                cells.append(f'<c r="{ref}"><f>{_x(v[1:])}</f></c>')
            elif isinstance(v, (int, float)) and not isinstance(v, bool):
                cells.append(f'<c r="{ref}"><v>{v}</v></c>')
            elif v != "":
                cells.append(f'<c r="{ref}" t="inlineStr"><is><t>{_x(str(v))}</t></is></c>')
        rows.append(f'<row r="{r}">' + "".join(cells) + "</row>")
    sheet = (_XML + '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'
             + "".join(rows) + "</sheetData></worksheet>")
    name = re.sub(r"[\\/?*\[\]:]", " ", doc.title)[:31]
    wb = (_XML + '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
          f'xmlns:r="{_OD}"><sheets><sheet name="{_x(name)}" sheetId="1" r:id="rId1"/></sheets>'
          '<calcPr fullCalcOnLoad="1"/></workbook>')
    over = {"/xl/workbook.xml": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
            "/xl/worksheets/sheet1.xml": "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml",
            "/docProps/core.xml": _CORE_T}
    return _zip([("[Content_Types].xml", _types({}, over)), ("_rels/.rels", _pkg_rels("officeDocument", "xl/workbook.xml")),
                 ("docProps/core.xml", _core(doc)), ("xl/workbook.xml", wb),
                 ("xl/_rels/workbook.xml.rels", _rels([("rId1", "worksheet", "worksheets/sheet1.xml")])),
                 ("xl/worksheets/sheet1.xml", sheet)])


_P = ('xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
      'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"')
_GRP = ('<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/>'
        '<a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>')
_THEME = (_XML + '<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="Northstar"><a:themeElements>'
          '<a:clrScheme name="Northstar"><a:dk1><a:srgbClr val="1B2A41"/></a:dk1><a:lt1><a:srgbClr val="FFFFFF"/></a:lt1>'
          '<a:dk2><a:srgbClr val="24344D"/></a:dk2><a:lt2><a:srgbClr val="F4F1EA"/></a:lt2><a:accent1><a:srgbClr val="2F6FDE"/></a:accent1>'
          '<a:accent2><a:srgbClr val="3BA99C"/></a:accent2><a:accent3><a:srgbClr val="E0A43A"/></a:accent3><a:accent4><a:srgbClr val="8E5BD6"/></a:accent4>'
          '<a:accent5><a:srgbClr val="D9534F"/></a:accent5><a:accent6><a:srgbClr val="5B8C3A"/></a:accent6><a:hlink><a:srgbClr val="2F6FDE"/></a:hlink>'
          '<a:folHlink><a:srgbClr val="8E5BD6"/></a:folHlink></a:clrScheme>'
          '<a:fontScheme name="Northstar"><a:majorFont><a:latin typeface="Calibri"/><a:ea typeface=""/><a:cs typeface=""/></a:majorFont>'
          '<a:minorFont><a:latin typeface="Calibri"/><a:ea typeface=""/><a:cs typeface=""/></a:minorFont></a:fontScheme>'
          '<a:fmtScheme name="Northstar"><a:fillStyleLst>' + '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>' * 3 + '</a:fillStyleLst>'
          '<a:lnStyleLst>' + '<a:ln w="9525"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln>' * 3 + '</a:lnStyleLst>'
          '<a:effectStyleLst>' + '<a:effectStyle><a:effectLst/></a:effectStyle>' * 3 + '</a:effectStyleLst>'
          '<a:bgFillStyleLst>' + '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>' * 3 + '</a:bgFillStyleLst></a:fmtScheme>'
          '</a:themeElements></a:theme>')


def _sp(n: int, name: str, text: str, y: int, cy: int, size: int) -> str:
    return (f'<p:sp><p:nvSpPr><p:cNvPr id="{n}" name="{name}"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr><p:spPr><a:xfrm>'
            f'<a:off x="685800" y="{y}"/><a:ext cx="10820400" cy="{cy}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr>'
            f'<p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:rPr lang="en-GB" sz="{size}"/><a:t>{_x(text)}</a:t></a:r></a:p></p:txBody></p:sp>')


def _pptx(doc: org.Doc) -> bytes:
    n = len(doc.slides)
    master = (_XML + f'<p:sldMaster {_P}><p:cSld><p:spTree>{_GRP}</p:spTree></p:cSld>'
              '<p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" '
              'accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>'
              '<p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst></p:sldMaster>')
    layout = (_XML + f'<p:sldLayout {_P} type="blank" preserve="1"><p:cSld name="Blank"><p:spTree>{_GRP}</p:spTree></p:cSld>'
              '<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>')
    pres = (_XML + f'<p:presentation {_P}><p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst>'
            '<p:sldIdLst>' + "".join(f'<p:sldId id="{256 + i}" r:id="rId{10 + i}"/>' for i in range(n)) + '</p:sldIdLst>'
            '<p:sldSz cx="12192000" cy="6858000"/><p:notesSz cx="6858000" cy="9144000"/></p:presentation>')
    prels = [("rId1", "slideMaster", "slideMasters/slideMaster1.xml"), ("rId2", "theme", "theme/theme1.xml")]
    prels += [(f"rId{10 + i}", "slide", f"slides/slide{i + 1}.xml") for i in range(n)]
    over = {"/ppt/presentation.xml": "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
            "/ppt/slideMasters/slideMaster1.xml": "application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml",
            "/ppt/slideLayouts/slideLayout1.xml": "application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml",
            "/ppt/theme/theme1.xml": "application/vnd.openxmlformats-officedocument.theme+xml", "/docProps/core.xml": _CORE_T}
    parts = [("_rels/.rels", _pkg_rels("officeDocument", "ppt/presentation.xml")), ("docProps/core.xml", _core(doc)),
             ("ppt/presentation.xml", pres), ("ppt/_rels/presentation.xml.rels", _rels(prels)),
             ("ppt/slideMasters/slideMaster1.xml", master),
             ("ppt/slideMasters/_rels/slideMaster1.xml.rels", _rels([("rId1", "slideLayout", "../slideLayouts/slideLayout1.xml"),
                                                                     ("rId2", "theme", "../theme/theme1.xml")])),
             ("ppt/slideLayouts/slideLayout1.xml", layout),
             ("ppt/slideLayouts/_rels/slideLayout1.xml.rels", _rels([("rId1", "slideMaster", "../slideMasters/slideMaster1.xml")])),
             ("ppt/theme/theme1.xml", _THEME)]
    for i, (title, text) in enumerate(doc.slides, 1):
        s = (_XML + f'<p:sld {_P}><p:cSld><p:spTree>{_GRP}{_sp(2, "Title", title, 457200, 1143000, 3600)}'
             f'{_sp(3, "Body", text, 1828800, 4114800, 2400)}</p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>')
        parts.append((f"ppt/slides/slide{i}.xml", s))
        parts.append((f"ppt/slides/_rels/slide{i}.xml.rels", _rels([("rId1", "slideLayout", "../slideLayouts/slideLayout1.xml")])))
        over[f"/ppt/slides/slide{i}.xml"] = "application/vnd.openxmlformats-officedocument.presentationml.slide+xml"
    parts.insert(0, ("[Content_Types].xml", _types({}, over)))
    return _zip(parts)
