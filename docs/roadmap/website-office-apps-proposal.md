# Website proposal: "Your Office. Your Choice." (paste-ready)

The public website is managed by the owner; this file holds the exact copy to paste into the website platform. Facts match
[docs/user/office-applications.md](../user/office-applications.md) and the portal's *Choose how you work* section (checked 2026-11-23).
Re-check the third-party facts before publishing if more than a month has passed.

## Paste this into the website platform's assistant

```
Add one section to the existing Features (or Product) page, and a short entry on the existing Downloads/Resources page. Do NOT add a new
top-level navigation item. Keep the current Office Unbound branding (IBM Plex, Source Serif headline, paper background, navy/copper, 3-4 px
corners, hairline borders). No illustrations, no gradients, no ticks (✓) for capabilities: use the words given. External links open the
publisher's official site, with rel="noopener noreferrer", and carry a small "External site" label. Do not use third-party logos (use a
simple neutral document icon for each card). Office Unbound's own card comes first and is visually the primary one.

SECTION HEADING: Your Office. Your Choice.
INTRO: Office Unbound gives you a complete, integrated productivity experience without forcing you into a single application ecosystem.
Prefer LibreOffice? ONLYOFFICE? Another compatible editor? Keep the tools you love while your files stay in Office Unbound, under your control.

SUB-HEADING: Choose how you work
TEXT: Office Unbound includes office applications in your browser. If you prefer desktop software on Windows, macOS or Linux, use it with the
same files through the Office Unbound desktop sync app.

CARD 1 (primary) — Office Unbound Documents · Included · Alpha
Create and edit documents, spreadsheets and presentations in your browser, inside Office Unbound Files. Built by Office Unbound from the
open-source Collabora Online code. Best for: an integrated cloud experience.
Works today: browser editing; saved straight into Files with Files sharing and permissions; one sign-in.
Being verified: several people editing the same document at once; restoring versions from the web interface.

CARD 2 — LibreOffice · Free and open source (MPL-2.0) · Windows, macOS, Linux
A mature free office suite: Writer, Calc, Impress, Draw and more. Works offline. Best for: a mature free desktop suite.
Good to know: Microsoft Office formatting may not always translate perfectly; some advanced Excel features and macros may not work.
Links: https://www.libreoffice.org/ · Download: https://www.libreoffice.org/download/

CARD 3 — ONLYOFFICE Desktop Editors · Free and open source (AGPL-3.0) · Windows, macOS, Linux
Free desktop editors for documents, spreadsheets, presentations and PDFs with a Microsoft Office-style interface. Works offline.
Best for: a Microsoft Office-style workflow.
Good to know: the desktop editors are separate from the ONLYOFFICE Docs server, which Office Unbound does not use.
Links: https://www.onlyoffice.com/ · Download: https://www.onlyoffice.com/download-desktop

CARD 4 — Collabora Office · Open source (MPL-2.0) · Windows, macOS, Linux
LibreOffice-based desktop suite from Collabora, whose open-source Collabora Online code Office Unbound builds its browser editor from.
Best for: open-source office collaboration.
Links: https://www.collaboraonline.com/collabora-office/

CARD 5 — ArtCraft: WordCraft, GridCraft, DeckCraft · Free and open source (MIT or Apache-2.0) · EXPERIMENTAL / IN DEVELOPMENT
Emerging open-source word processor, spreadsheet and presentation applications. Interesting to try; not yet suitable for business-critical
documents. Best for: emerging experimental alternatives.
Links: https://getartcraft.com/apps   (use getartcraft.com only, not getartcraft.app)

COMPARISON TABLE (responsive: on phones show one application per block with label/value rows):
Application | Free | Open source | Windows | macOS | Linux | Offline | Browser editing | Status
Office Unbound Documents | Included | Yes | Browser | Browser | Browser | No | Yes | Alpha
LibreOffice | Yes | Yes | Yes | Yes | Yes | Yes | No | Stable
ONLYOFFICE Desktop Editors | Yes | Yes | Yes | Yes | Yes | Yes | Requires server | Stable
Collabora Office | Depends on edition | Yes | Yes | Yes | Yes | Yes | Requires server | Stable
ArtCraft apps | Yes | Yes | Yes | Yes | Yes | Yes | Not verified | Experimental

FOOTNOTE: Other applications are listed for your convenience; they are made by their publishers, are not integrated with Office Unbound, and
are not provided or supported by Office Unbound. Mapped drives (an "O:" drive) are planned, not available yet.

DOWNLOADS/RESOURCES PAGE ENTRY: "Office applications — Office Unbound includes browser editing. Prefer desktop software? See Your Office.
Your Choice for free and open-source options." (link to the section above)
```

## Do not publish

- Real-time co-editing as a feature (not tested by the project yet).
- "Works with LibreOffice/ONLYOFFICE" as an integration: they work with synced or downloaded files, nothing more.
- The ONLYOFFICE "20-connection limit" as current: ONLYOFFICE removed it from the Community Edition in Docs 9.4 (May 2026).
- Mapped drives or the Desktop Connector as available: planned only ([desktop-connector.md](../requirements/desktop-connector.md)).
