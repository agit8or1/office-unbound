"""Demonstration organisation seeding (owner brief 2026-11-26, section 18; docs/admin/demo-organization.md).

Fills an ISOLATED deployment that an administrator explicitly marked as a demo (demo.deployment.mark) with the entirely fictional
organisation "Northstar Advisory Group": directory people through the typed directory.account.set plans, then mail, calendars, tasks,
files, shares and chat written through the applications' own client protocols, signed in as each person. Nothing here talks SMTP or any
host outside the demo deployment's own domain; guard.py holds every safeguard.

    org.py          the fictional organisation (people, threads, meetings, files, rooms); pure data
    officefiles.py  small ODF / OOXML documents generated in memory (stdlib zipfile)
    guard.py        the safeguards (marker, names, confirmation, host and address allowlists, foreign people)
    planner.py      the seed plan (deterministic ids) and the dry-run summary
    clients.py      IMAP, CalDAV, OIDC sign-in, OpenCloud WebDAV/Graph and Matrix clients (host-pinned to the demo domain)
    seed.py         the orchestrator: accounts phase, content phase, manifest, reset
    marker.py       the typed action demo.deployment.mark (the ICS-side demo marker)
"""
