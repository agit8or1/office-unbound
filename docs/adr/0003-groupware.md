# ADR-0003 Groupware backend
Status: Proposed — pending lab validation and licensing clarification (2026-11-15)
Candidate: grommunio (gromox AGPL-3.0 + web/sync/dav/admin AGPL-3.0). Only evaluated open stack offering MAPI/HTTP + EWS + ActiveSync + Autodiscover. Single authoritative mailbox store (gromox).
Fallback for non-Outlook deployments: mailcow/SOGo (GPL; IMAP/SMTP/DAV/ActiveSync, no MAPI/EWS).
Blocking gates before acceptance:
- Licensing: grommunio pricing says Community = up to 5 users, no support; GTC unclear whether >5 is permitted. Trademark terms (no rebranding policy found). → Requires written answer from grommunio GmbH or a partner/subscription decision. **Owner decision.**
- Lab tests per docs/status/groupware-eval.md §lab plan.
Known client limitations (Microsoft-documented, not fixable by us): New Outlook for Windows → IMAP/SMTP only for non-Microsoft servers; Outlook iOS/Android → on-prem only via Hybrid Modern Auth through Microsoft cloud, so expect IMAP only. Classic Outlook (MAPI/HTTP) and Outlook for Mac (EWS) are the realistic native targets — to be tested.
