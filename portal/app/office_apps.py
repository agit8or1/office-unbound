"""Office applications people may use with their Office Unbound files ("Choose how you work", devices page). Facts checked against the
publishers' official pages on 2026-11-23 (docs/user/office-applications.md lists the sources); update VERIFIED when re-checked.

Values in the matrix are words, never ticks: "Yes", "No", "Partial", "Requires server", "Depends on edition", "Not verified". Only the
built-in editor is integrated with Office Unbound; every other entry is an external download from its publisher, not tested by the project
with Office Unbound unless `integration` says otherwise."""

VERIFIED = "2026-11-23"

APPS = [
    {"id": "builtin", "name": "Office Unbound Documents", "group": "included", "best_for": "Integrated cloud experience",
     "summary": "Create and edit documents, spreadsheets and presentations in your browser, inside Files. No separate desktop application required.",
     "publisher": "Office Unbound (built from the open-source Collabora Online code, MPL-2.0)", "licence": "Included with Office Unbound",
     "maturity": "Alpha (part of Office Unbound)", "integration": "Integrated: opens from Files and from Start something new",
     "website": None, "download": None,
     "matrix": {"free": "Included", "open_source": "Yes", "windows": "Browser", "macos": "Browser", "linux": "Browser", "offline": "No",
                "browser": "Yes", "status": "Alpha"},
     "good": ["Document, spreadsheet and presentation editing in the browser (tested by the project)",
              "Saves straight back into your Files; sharing and permissions are those of Files",
              "One sign-in for portal, Files and the editor"],
     "limits": ["Several people editing the same document at once has not been tested by the project yet",
                "Version history is kept by Files; restoring a version from the web interface has not been tested by the project",
                "Needs a connection: no offline editing"]},
    {"id": "libreoffice", "name": "LibreOffice", "group": "foss", "best_for": "Mature free desktop suite",
     "summary": "A mature, free and open-source office suite: Writer, Calc, Impress, Draw and more.",
     "publisher": "The Document Foundation", "licence": "Free, open source (MPL-2.0)", "maturity": "Stable, long established",
     "integration": "Not integrated. Use it with files from the desktop sync app or downloaded from Files",
     "website": "https://www.libreoffice.org/", "download": "https://www.libreoffice.org/download/",
     "matrix": {"free": "Yes", "open_source": "Yes", "windows": "Yes", "macos": "Yes", "linux": "Yes", "offline": "Yes", "browser": "No",
                "status": "Stable"},
     "good": ["Full desktop office suite that works offline", "No subscription", "Strong OpenDocument support; opens and saves Microsoft Office formats"],
     "limits": ["Microsoft Office formatting does not always translate perfectly", "Some advanced Excel functions and VBA macros may not work",
                "No simultaneous cloud co-editing like Microsoft 365"]},
    {"id": "onlyoffice", "name": "ONLYOFFICE Desktop Editors", "group": "foss", "best_for": "Microsoft Office-style workflow",
     "summary": "Free desktop editors for documents, spreadsheets, presentations and PDFs, with an interface familiar to Microsoft Office users.",
     "publisher": "Ascensio System SIA", "licence": "Free, open source (AGPL-3.0)", "maturity": "Stable",
     "integration": "Not integrated. Use it with files from the desktop sync app or downloaded from Files",
     "website": "https://www.onlyoffice.com/", "download": "https://www.onlyoffice.com/download-desktop",
     "matrix": {"free": "Yes", "open_source": "Yes", "windows": "Yes", "macos": "Yes", "linux": "Yes", "offline": "Yes",
                "browser": "Requires server", "status": "Stable"},
     "good": ["Familiar Microsoft Office-style interface", "Focus on DOCX, XLSX and PPTX", "Works offline"],
     "limits": ["Some advanced Microsoft Office functions behave differently",
                "The desktop editors are not the ONLYOFFICE Docs server: browser co-editing needs that separate server, which Office Unbound does not use",
                "ONLYOFFICE Docs Community Edition (server) was limited to 20 simultaneous connections before version 9.4; the publisher removed the "
                "limit in 9.4 (May 2026). Commercial editions are paid."]},
    {"id": "collabora", "name": "Collabora Office", "group": "foss", "best_for": "Open-source office collaboration",
     "summary": "LibreOffice-based desktop office suite from Collabora, the company behind Collabora Online, which Office Unbound's built-in editor is built from.",
     "publisher": "Collabora Productivity", "licence": "Free, open source (MPL-2.0); paid support available", "maturity": "Stable (Classic); newer desktop edition",
     "integration": "Not integrated. Use it with files from the desktop sync app or downloaded from Files",
     "website": "https://www.collaboraonline.com/collabora-office/", "download": "https://www.collaboraonline.com/collabora-office/",
     "matrix": {"free": "Depends on edition", "open_source": "Yes", "windows": "Yes", "macos": "Yes", "linux": "Yes", "offline": "Yes",
                "browser": "Requires server", "status": "Stable"},
     "good": ["Open-source foundations shared with the built-in editor", "Strong OpenDocument support", "Works offline"],
     "limits": ["Collabora Online (browser editing) is server software; Office Unbound already runs its own build of it for you",
                "The free CODE edition of Collabora Online is not recommended by its publisher for production",
                "Desktop and online products are different products"]},
    {"id": "artcraft", "name": "ArtCraft: WordCraft, GridCraft, DeckCraft", "group": "experimental", "best_for": "Emerging experimental alternatives",
     "summary": "Emerging open-source word processor (WordCraft), spreadsheet (GridCraft) and presentation (DeckCraft) applications.",
     "publisher": "ArtCraft", "licence": "Free, open source (MIT or Apache-2.0)", "maturity": "Experimental / in development",
     "integration": "Not integrated and not tested with Office Unbound",
     "website": "https://getartcraft.com/", "download": "https://getartcraft.com/apps",
     "matrix": {"free": "Yes", "open_source": "Yes", "windows": "Yes", "macos": "Yes", "linux": "Yes", "offline": "Yes", "browser": "Not verified",
                "status": "Experimental"},
     "good": ["Free and open source", "Modern, lightweight desktop applications"],
     "limits": ["Still in active development: features are incomplete", "File-format compatibility has not been evaluated by the project",
                "Not suitable for business-critical documents yet", "GridCraft does not run Excel (VBA) macros"]},
]

OS_KEYS = {"windows": "Windows", "macos": "macOS", "linux": "Linux"}
KINDS = {"foss": "Free and open source", "included": "Included with Office Unbound", "experimental": "Experimental"}
MATRIX_COLS = [("free", "Free"), ("open_source", "Open source"), ("windows", "Windows"), ("macos", "macOS"), ("linux", "Linux"),
               ("offline", "Offline"), ("browser", "Browser editing"), ("status", "Status")]


def filtered(os_key: str | None, kind: str | None) -> list[dict]:
    """Apps for the filter form (plain GET, no script): unknown values are ignored. The built-in editor always stays first and visible."""
    os_key = os_key if os_key in OS_KEYS else None
    kind = kind if kind in KINDS else None
    out = []
    for a in APPS:
        if a["id"] != "builtin":
            if os_key and a["matrix"][os_key] not in ("Yes", "Partial"):
                continue
            if kind == "foss" and a["matrix"]["open_source"] != "Yes":
                continue
            if kind and kind != "foss" and a["group"] != kind:
                continue
        out.append(a)
    return out
