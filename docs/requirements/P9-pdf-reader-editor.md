# P9 — Full PDF Reader, Editor and Document Management

**Status: DEFERRED — FINAL DEVELOPMENT PRIORITY** (owner directive, 2026-11-16).

Do not start this until all earlier alpha-readiness and MSP pilot objectives are complete and verified:
1. security remediation
2. production-grade Proxmox deployment
3. complete deployment profile
4. customer isolation and encrypted backups
5. operational maturity
6. internal alpha acceptance
7. MSP pilot readiness

Until then:
- no agents, worktrees or development resources go to P9
- it must not delay any release objective
- it stays under the existing controller's coordination; no separate controller or project session

**When it starts, the order is:**
1. Technology and licensing evaluation (§13).
2. A detailed implementation plan and concept designs (§14).
3. Implementation through the existing agent structure.

## 1. Objective

Build a fully integrated, comprehensive PDF reader and editor, comparable to Adobe Acrobat Pro. It must be a real PDF application, not an embedded viewer.

It must be:
- open source and self-hosted
- free of mandatory commercial licensing
- free of page, file-size, user or concurrent-session limits
- integrated with Office Unbound authentication, permissions and Files
- part of the unified interface
- responsive on desktop, tablet and mobile
- designed for business use

Do not sacrifice functionality to save development time. Build whatever the FOSS components lack.

## 2. Reader

### Viewing modes and navigation
- Fast rendering.
- Single-page and continuous scrolling.
- Single-page and two-page spreads.
- Thumbnails, outline and bookmarks, page navigation, table of contents.
- Zoom and fit-to-width/page.
- Rotation and full screen.
- Dark and light modes.

### Search, selection and content
- Full-text search with highlighting.
- Text selection and copy.
- Embedded image viewing.
- Hyperlinks.

### Output, metadata and history
- Print, download and export.
- Document properties and metadata.
- Keyboard shortcuts.
- Reading history and recent documents.

### Performance and quality
- Large documents load without holding the whole file in browser memory.
- Text and vector quality are kept when zooming.

## 3. Full PDF editing (one of the most important parts)

### Text
- Edit, add and delete existing text.
- Change font, size, colour, alignment, position and spacing.
- Add text boxes and edit text blocks.
- Preserve layout as accurately as possible.
- Keep an embedded original font where possible.
- When a font is unavailable, substitute sensibly and warn about layout changes.

### Images and objects
- Insert, replace, delete, resize, crop, move and rotate images.
- Reposition graphical elements.
- Add shapes, lines and arrows, rectangles and circles, callouts, stamps and watermarks.

### Pages
- Insert, delete, duplicate, reorder (drag and drop), rotate, crop, resize, extract and replace pages.
- Insert pages from another PDF.
- Organise large documents through a visual page manager with thumbnails and drag and drop.

## 4. Annotations and review

### Markup
- Highlight, underline, strikethrough and freehand drawing.

### Notes, comments and callouts
- Text annotations, sticky notes, comments and callouts.

### Shapes, arrows and stamps
- Shapes, arrows and stamps, including approval/rejection stamps.

### Reviewer metadata
- Reviewer identity and timestamps.

### Display controls
- Colours, filtering and visibility controls.

### Multi-reviewer behaviour
- Multiple reviewers, with each annotation keeping its owner.
- Comments and permissions integrated with Office Unbound accounts.
- Shared review sessions and collaborative annotation that never overwrite another user's work.

## 5. Forms

### Filling
- AcroForm fields: text, checkboxes, radio buttons, dropdowns, lists, dates and signature fields.
- Validation and required fields.
- Save and reopen partly completed forms.
- Export completed forms.

### Creating (authorised users)
- Add, resize and move fields.
- Names, default values, required flags and validation rules.
- Dropdown options, calculated fields where supported, and formatting.
- Templates.

XFA compatibility is investigated separately. Its limits are documented, never claimed.

## 6. Signatures and document execution

### A. Electronic signatures
- Draw, type or upload a signature; initials and date fields.
- Place signature fields.
- Multiple signers in a set order, with requests, reminders and completion notifications.
- Signing history and audit trail.
- Final signed document stored in Files.
- Integrated with Office Unbound identity and permissions.

### B. Cryptographic digital signatures
- PKCS#12 and X.509 certificates.
- Certificate validation, signature verification and tamper detection.
- Signing timestamps.
- Expiry checks, and OCSP/CRL revocation checks where available.
- Multiple signatures.
- PAdES signing and validation where feasible.
- Invalid or modified signatures are clearly flagged.

### Rules
- A visual signature and a cryptographic signature are always distinguished. A typed or drawn signature is never presented as cryptographic.
- Users are warned when an edit would invalidate an existing digital signature.

## 7. Secure redaction

Real redaction, not black rectangles.

### Marking and confirming
- Select text, draw regions and redact images.
- Preview, then confirm permanent redaction.

### What applying a redaction must do
- Remove the underlying text, covered image content, related metadata and recoverable hidden content.
- Rebuild the affected structures.
- Verify the content can't be recovered by text extraction or ordinary object inspection.

### Audit and testing
- Keep an audit record of the operation, never the removed content.
- Redaction gets dedicated security testing.

## 8. OCR and scanned documents

### OCR processing
- OCR existing PDFs to create searchable, selectable text layers.
- Keep the original visual appearance.
- Multiple languages and batch OCR.
- Automatic orientation detection, deskewing and image cleanup.
- Confidence reporting.

### Output
- Searchable PDF output.
- Conversion to editable documents where possible.
- OCR text is always distinguishable from original text.

## 9. Conversion

### Import
- DOCX, DOC, ODT, XLSX, XLS, ODS, PPTX, PPT, ODP.
- Images: TIFF, JPEG, PNG.
- HTML and TXT.
- Supported scanned formats.

### Export
- PDF and PDF/A, including archival variants where supported.
- DOCX, ODT, RTF, TXT and HTML.
- JPEG, PNG and TIFF.

### Operations
- Merge, split and extract pages.
- Compress and optimise.
- Images to PDF, Office documents to PDF, PDF to images.
- Extract text, images and, where possible, tables.

### Fidelity
- Preserve layout, fonts, links and formatting as accurately as possible.
- Never silently claim perfect fidelity.

## 10. Security and protection

### Protection features
- Passwords, encryption and decryption.
- Permission restrictions on printing, copying and editing.

### Metadata and content inspection
- Metadata removal and editing.
- Inspection of embedded attachments.
- JavaScript detection and warnings about suspicious content.
- Safe handling of external links.
- Integrity checks.

### Hard rules
- Never execute embedded JavaScript or auto-launch attachments.
- Treat every uploaded PDF as untrusted.
- Process PDFs in isolated workers with resource limits and sandboxing.
- A malicious PDF must not be able to compromise the application or the server.

## 11. Advanced tools

- Comparison (visual and text differences).
- Watermarks, headers and footers, Bates numbering, page numbering, custom stamps and backgrounds.
- Optimisation, metadata management, flattening and attachment management.
- PDF/A validation.
- Accessibility checks, tagged PDF and remediation tools where feasible.
- Batch processing and templates.

## 12. Office Unbound integration

### User interface
- Native to Office Unbound, with no separate login.
- Open a PDF from Files, then preview, edit, annotate, fill, request signatures, export and save back to Files.
- Create PDFs from Office documents.
- PDF actions in the file context menu.
- Open from search results, recent documents and shared folders.

### Storage
- Native storage with version history and revision recovery.
- Permission enforcement.
- Locking or safe concurrent editing.
- Atomic saves, autosave, and recovery from interrupted sessions.
- Audit logging and per-customer storage isolation.
- **Never overwrite an original without a recoverable revision.**

### APIs
- Creation, conversion, OCR, page operations, metadata, forms, signing, redaction, comparison and batch operations.
- ICS and approved automation can call authorised operations without unrestricted server access.

## 13. Technology and licensing evaluation (first step when P9 starts)

Candidates, not decisions:
- PDF.js
- Apache PDFBox
- qpdf
- Tesseract
- OCRmyPDF
- FOSS PDF editing engines and libraries
- Collabora/LibreOffice

For each, evaluate licence, functionality, maintenance, security history, compatibility and deployment. Pay particular attention to AGPL and GPL obligations and to commercial-licensing traps and usage restrictions.

Constraints:
- No mandatory commercial licences.
- No user or concurrency limits.
- No external SaaS dependency.
- If no library can truly edit existing content, evaluate alternatives or build it ourselves.
- Use modular backend engines that can be replaced individually.

## 14. UX and design

Polished and professional, not generic.

### Layout
- Canvas in the centre.
- Thumbnails on the left.
- Context-sensitive tools.
- Properties on the right.
- Document actions at the top.
- Minimal clutter.

### Interaction
- Keyboard shortcuts, drag and drop, context menus.
- Undo/redo.
- Autosave, save and export indicators.
- Tools appear when they are relevant.

### Platform and design process
- Desktop-first, but responsive on mobile and tablet.
- Concept designs are produced and reviewed before implementation.

## 15. Testing and acceptance

### Coverage
- **Viewing and editing:** rendering, large documents, text editing, image editing, page operations.
- **Review and forms:** annotations, forms.
- **Signatures:** electronic signatures, cryptographic signatures and their validation.
- **Content processing:** redaction, OCR, conversion, encryption, PDF/A, metadata removal.
- **Safety and robustness:** malicious PDFs, concurrent editing, autosave, version restore.
- **Isolation and access:** tenant isolation, permissions.
- **Platforms:** mobile and browser compatibility.

### Method
- Use a varied set of real-world PDFs: scans, complex forms, embedded fonts, tables, images and signed documents.
- Verify the saved output, not just the browser display.

### Proofs required
- **Redaction:** must prove the content can't be recovered.
- **Digital signatures:** must prove cryptographic verification.
- **Conversion:** must measure real fidelity.

## 16. Final acceptance standard

P9 is not complete because a PDF.js viewer works or basic annotation exists.

The finished product must cover:
- professional reading, editing, creation and review
- signing, conversion and OCR
- security and document management

It must be a credible open-source alternative to Acrobat Pro for ordinary business workflows. All limits are documented honestly.
