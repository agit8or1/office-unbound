# ADR-0005 Files and documents
Status: Proposed — pending spike (2026-11-15)
OpenCloud 9.x (Apache-2.0, posix storage) + its built-in collaboration/WOPI service + Collabora Online. OpenCloud is the authoritative file store and WOPI host; no second document store (clientst0r WOPI code is reference only).
Per ADR-0007 no Collabora subscription. Vendor CODE images are lab-only; production path = Office Unbound's own build of Collabora Online (MPL-2.0 source, to be verified) with connection/document limits configured off, our own branding, signed images and release channel — pending docs/status/docengine-source-eval.md. Alternatives if blocked: other LibreOffice-based or unrestricted engines. Seafile CE = file-platform fallback if OpenCloud fails mandatory tests.
