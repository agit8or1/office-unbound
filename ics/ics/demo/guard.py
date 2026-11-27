"""Every safeguard of the demo seeding tool, in one place (docs/admin/demo-organization.md, "Safeguards"). A refusal raises DemoRefused
before anything is contacted or changed.

1. Names: the deployment slug and its domain must both carry a demo label (`demo`, `demo-*` or `*-demo`); the production deployment and
   domain (DENY_SLUGS / DENY_DOMAINS) are refused whatever their labels.
2. ICS marker: the deployment is marked as a demo by the approved typed action demo.deployment.mark (marker.py). The marker is bound to
   the deployment's id AND domain: a deployment recreated under the same slug, or a changed domain, is no longer marked.
3. Confirmation: the operator types `--i-understand-this-is-the-demo <slug>` with exactly the target slug.
4. Foreign people: the deployment's directory holds only the built-in accounts and the people this tool seeds. Anyone else means the
   deployment is in real use: refused.
5. Hosts: every request goes to the demo domain or one of its subdomains (HostGuard, installed as an httpx event hook and checked by the
   IMAP client before connecting); anything else is refused before a connection is made.
6. Addresses: every address that receives anything (mail To/Cc, meeting organizer/attendees, share recipients, chat invitations) is a
   seeded person at the demo domain (check_addresses). Outside organisations appear only in text, with .example domains.
7. No SMTP: the tool never submits mail. Messages are placed with IMAP APPEND into each person's own mailbox, signed in as that person.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from sqlalchemy import text

from . import org

MARK_KEY = "deployment.demo"
DENY_SLUGS = frozenset({"officeunbound8"})
DENY_DOMAINS = frozenset({"officeunbound.com"})
SYSTEM_UIDS = frozenset({"ou-admin", "admin"})     # the deployment's built-in accounts (configure.identity_runbooks, accounts.PROTECTED)
CONFIRM_FLAG = "--i-understand-this-is-the-demo"
_DEMO_LABEL = re.compile(r"^(demo|demo-[a-z0-9-]+|[a-z0-9-]+-demo)$")


class DemoRefused(Exception):
    """The target is not (provably) the demo deployment, or a step would leave it."""


def demo_label(name: str, sep: str) -> bool:
    return any(_DEMO_LABEL.fullmatch(x) for x in name.lower().split(sep))


def check_names(slug: str, domain: str) -> None:
    d = (domain or "").lower().rstrip(".")
    if slug in DENY_SLUGS:
        raise DemoRefused(f"{slug} is a production deployment: never a demo target")
    if d in DENY_DOMAINS:
        raise DemoRefused(f"{d} is a production domain: never a demo target")
    if "demo" not in slug.lower().split("-"):
        raise DemoRefused(f"the deployment slug {slug!r} has no demo label (a '-'-separated part 'demo', e.g. northstar-demo)")
    if not demo_label(d, "."):
        raise DemoRefused(f"the domain {d!r} has no demo label (a DNS label 'demo', 'demo-*' or '*-demo', e.g. demo.example.org)")


def check_confirm(slug: str, confirm: str | None) -> None:
    if not confirm or confirm != slug:
        raise DemoRefused(f"confirm the target explicitly: {CONFIRM_FLAG} {slug}")


def marker(db, slug: str) -> dict | None:
    row = db.execute(text("SELECT value FROM system_settings WHERE key = :k"), {"k": MARK_KEY}).first()
    return (dict(row.value or {}).get(slug)) if row else None


def check_marker(db, deployment_id: str, slug: str, domain: str) -> dict:
    m = marker(db, slug)
    if not m:
        raise DemoRefused(f"{slug} is not marked as a demo deployment (typed action demo.deployment.mark, approved in the console)")
    if m.get("deployment_id") != str(deployment_id) or (m.get("domain") or "").lower() != domain.lower():
        raise DemoRefused(f"the demo marker of {slug} belongs to another deployment or domain: mark this deployment again")
    return m


def check_people(people: list[dict], seeded: set[str]) -> None:
    foreign = sorted(p.get("username") or "?" for p in people if (p.get("username") not in SYSTEM_UIDS and p.get("username") not in seeded))
    if foreign:
        raise DemoRefused(f"the directory has {len(foreign)} account(s) this tool did not create: the deployment is in real use "
                          f"(first: {', '.join(foreign[:3])})")


def host_allowed(host: str | None, domain: str) -> bool:
    h, d = (host or "").lower().rstrip("."), domain.lower().rstrip(".")
    return bool(h) and (h == d or h.endswith("." + d))


class HostGuard:
    """httpx request hook: refuses (before any connection) every URL that is not https on the demo domain."""

    def __init__(self, domain: str, extra_loopback: str | None = None):
        self.domain = domain
        self.loopback = extra_loopback      # the OIDC redirect target: never requested, only recognised in a Location header

    def check_url(self, url: str) -> None:
        u = urlsplit(str(url))
        if u.scheme != "https" or not host_allowed(u.hostname, self.domain):
            raise DemoRefused(f"refusing a request outside the demo deployment: {u.scheme}://{u.hostname}")

    def __call__(self, request) -> None:
        self.check_url(str(request.url))


def person_addr(uid: str, domain: str) -> str:
    return f"{uid}@{domain}"


def check_address(addr: str, domain: str) -> None:
    local, _, dom = addr.rpartition("@")
    if dom.lower() != domain.lower() or local not in org.BY_UID:
        raise DemoRefused(f"refusing to address {addr!r}: only seeded people at {domain} receive anything")


def check_addresses(seed, domain: str) -> int:
    """Every recipient in the seed plan (planner.SeedPlan) is a seeded person at the demo domain. Returns the number checked."""
    n = 0
    for a in seed.recipients():
        check_address(a, domain)
        n += 1
    return n
