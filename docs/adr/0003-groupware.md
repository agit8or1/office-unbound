# ADR-0003 Groupware backend
Status: Integrated in lab (2026-11-15) — own source build of gromox 3.13 + sync 2.7 + dav 1.9 + web 5.2 passes 57 automated protocol checks (docs/status/groupware-lab-results.md, re-run by lead). Real Outlook/mobile clients untested.
Candidate: grommunio (gromox AGPL-3.0 + web/sync/dav/admin AGPL-3.0). Only evaluated open stack offering MAPI/HTTP + EWS + ActiveSync + Autodiscover. Single authoritative mailbox store (gromox).
Fallback for non-Outlook deployments: mailcow/SOGo (GPL; IMAP/SMTP/DAV/ActiveSync, no MAPI/EWS).
Blocking gates before acceptance:
- Licensing (ADR-0007): the vendor's Community *package* is advertised as "up to 5 users". Subscription is NOT an option. Decision depends on source-level evaluation (docs/status/groupware-source-eval.md): whether any limit/licence check exists in the AGPL source, and whether we can build, patch and distribute our own packages under AGPL with required renaming. Trademark: our build must not use grommunio/gromox marks beyond nominative attribution unless permitted.
- Lab tests per docs/status/groupware-eval.md §lab plan.
Known client limitations (Microsoft-documented, not fixable by us): New Outlook for Windows → IMAP/SMTP only for non-Microsoft servers; Outlook iOS/Android → on-prem only via Hybrid Modern Auth through Microsoft cloud, so expect IMAP only. Classic Outlook (MAPI/HTTP) and Outlook for Mac (EWS) are the realistic native targets — to be tested.

## Source evaluation result (docs/status/groupware-source-eval.md, 2026-11-15)
- The "5 users" limit exists only in admin-api (`tools/license.py`, enforced in `orm/users.py`) as an unsigned certificate check; gromox/web/sync/dav contain no limits. All repos AGPL-3.0-or-later (some gromox files GPL-2.0-only w/ linking exception — legal review item).
- Decision direction: Office Unbound builds its own packages from public tags (gromox, libHX ≥4.28, wmime, web, sync, dav, admin-api with the cap removed by a small patch), our own apt repo, renamed branding; AGPL §13 source offer for modified network services.
- Gaps we must build or source elsewhere: Debian packaging (not public), archiving/journaling (not in public source), backup product (only CLI tooling exists). Anti-spam = rspamd + clamav (upstream, unrestricted).
- Not chosen: grommunio subscription or vendor repos (ADR-0007).
