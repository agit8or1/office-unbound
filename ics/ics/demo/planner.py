"""The seed plan: every object the tool creates, with a deterministic id, built from org.py for one demo domain and anchor day. Pure (no
I/O): the dry run prints it, the seeder executes it, the reset removes what it names. Re-running with the same domain and anchor gives
the same plan, which is what makes seeding idempotent."""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import format_datetime
from zoneinfo import ZoneInfo

from . import officefiles, org

PRODID = "-//Office Unbound//Demo seed " + org.SEED_TAG + "//EN"


def bday(anchor: dt.date, n: int) -> dt.date:
    """anchor + n business days (weekends skipped; n may be negative). Weekend anchors count from the previous Friday."""
    d = anchor
    while d.weekday() >= 5:
        d -= dt.timedelta(days=1)
    step = 1 if n >= 0 else -1
    for _ in range(abs(n)):
        d += dt.timedelta(days=step)
        while d.weekday() >= 5:
            d += dt.timedelta(days=step)
    return d


@dataclass(frozen=True)
class Delivery:
    owner: str          # uid whose mailbox receives the copy (signed in as them)
    folder: str         # "INBOX" or "SENT" (resolved to the special-use Sent folder)
    demo_id: str        # X-OU-Demo-Id
    flags: tuple[str, ...]
    when: dt.datetime
    message: bytes


@dataclass(frozen=True)
class CalObject:
    owner: str
    collection: str     # "events", "tasks" or the team calendar slug
    uid: str
    href: str           # file name in the collection
    ics: str
    attendees: tuple[str, ...] = ()


class SeedPlan:
    def __init__(self, domain: str, anchor: dt.date, tz: str = "UTC"):
        self.domain, self.anchor, self.tzname = domain.lower(), anchor, tz
        self.tz = ZoneInfo(tz)

    # ---------- helpers
    def addr(self, uid: str) -> str:
        return f"{uid}@{self.domain}"

    def at(self, day: int, hour: int, minute: int = 0) -> dt.datetime:
        d = bday(self.anchor, day)
        return dt.datetime(d.year, d.month, d.day, hour, minute, tzinfo=self.tz)

    def _who(self, uid: str) -> str:
        p = org.BY_UID[uid]
        return f'"{p.name}" <{self.addr(uid)}>'

    # ---------- accounts
    def accounts(self) -> list[dict]:
        return [{"username": p.uid, "display_name": p.name, "role": p.role, "email": self.addr(p.uid), "department": p.department,
                 "title": p.title} for p in org.PEOPLE]

    # ---------- mail
    def message(self, th: org.Thread, i: int) -> bytes:
        m = th.messages[i]
        msg = EmailMessage()
        msg["From"] = self._who(m.sender)
        msg["To"] = ", ".join(self._who(u) for u in m.to)
        if m.cc:
            msg["Cc"] = ", ".join(self._who(u) for u in m.cc)
        msg["Subject"] = th.subject if i == 0 else "Re: " + th.subject
        msg["Date"] = format_datetime(self.at(m.day, m.hour, 7 * i % 60))
        msg["Message-ID"] = f"<{org.UID_PREFIX}{m.id}@{self.domain}>"
        if i:
            refs = " ".join(f"<{org.UID_PREFIX}{x.id}@{self.domain}>" for x in th.messages[:i])
            msg["In-Reply-To"] = f"<{org.UID_PREFIX}{th.messages[i - 1].id}@{self.domain}>"
            msg["References"] = refs
        msg["X-OU-Demo"] = org.SEED_TAG
        msg["X-OU-Demo-Id"] = m.id
        sig = f"\n--\n{org.BY_UID[m.sender].name}\n{org.BY_UID[m.sender].title}, {org.ORG_NAME}\n"
        msg.set_content(m.body + sig)
        for key in m.attachments:
            data = officefiles.render(org.FILES[key])
            maintype, subtype = officefiles.mime(key).split("/", 1)
            msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=key)
        if msg.is_multipart():
            msg.set_boundary(f"=_ou-demo-{m.id}")       # deterministic bytes (the default boundary is random)
        return bytes(msg)

    def deliveries(self) -> list[Delivery]:
        out = []
        for th in org.THREADS:
            for i, m in enumerate(th.messages):
                raw = self.message(th, i)
                when = self.at(m.day, m.hour, 7 * i % 60)
                out.append(Delivery(m.sender, "SENT", m.id, ("\\Seen",), when, raw))
                for r in dict.fromkeys(m.to + m.cc):
                    if r == m.sender:
                        continue
                    flags = tuple(f for f, on in (("\\Seen", r not in m.unread_by), ("\\Flagged", r in m.flagged_by)) if on)
                    out.append(Delivery(r, "INBOX", m.id, flags, when, raw))
        return out

    # ---------- calendar and tasks
    def _utc(self, t: dt.datetime) -> str:
        return t.astimezone(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    def _vevent(self, mt: org.Meeting, team: bool = False) -> str:
        start = self.at(mt.day, mt.hour)
        end = start + dt.timedelta(minutes=mt.minutes)
        uid = f"{org.UID_PREFIX}{mt.id}@{self.domain}"
        lines = ["BEGIN:VEVENT", f"UID:{uid}", f"DTSTAMP:{self._utc(dt.datetime.combine(self.anchor, dt.time(7), self.tz))}",
                 f"DTSTART:{self._utc(start)}", f"DTEND:{self._utc(end)}", f"SUMMARY:{_esc(mt.title)}", "SEQUENCE:0"]
        if mt.location:
            lines.append(f"LOCATION:{_esc(mt.location)}")
        if mt.description:
            lines.append(f"DESCRIPTION:{_esc(mt.description)}")
        if mt.rrule:
            lines.append(f"RRULE:{mt.rrule}")
        if mt.attendees and not team:
            o = org.BY_UID[mt.organizer]
            lines.append(f'ORGANIZER;CN="{o.name}":mailto:{self.addr(mt.organizer)}')
            for a in mt.attendees:
                ps = "ACCEPTED" if a in mt.accepted_by else "NEEDS-ACTION"
                lines.append(f'ATTENDEE;CN="{org.BY_UID[a].name}";ROLE=REQ-PARTICIPANT;PARTSTAT={ps};RSVP=TRUE:mailto:{self.addr(a)}')
        lines += [f"X-OU-DEMO:{org.SEED_TAG}", "END:VEVENT"]
        return _cal(lines)

    def _vtodo(self, t: org.Task) -> str:
        due = self.at(t.due_day, 17)
        lines = ["BEGIN:VTODO", f"UID:{org.UID_PREFIX}{t.id}@{self.domain}",
                 f"DTSTAMP:{self._utc(dt.datetime.combine(self.anchor, dt.time(7), self.tz))}", f"SUMMARY:{_esc(t.title)}",
                 f"DUE:{self._utc(due)}", f"STATUS:{'COMPLETED' if t.done else 'NEEDS-ACTION'}"]
        if t.done:
            lines.append("PERCENT-COMPLETE:100")
        if t.assigned_by:
            lines.append(f"DESCRIPTION:{_esc('Assigned by ' + org.BY_UID[t.assigned_by].name)}")
        lines += [f"X-OU-DEMO:{org.SEED_TAG}", "END:VTODO"]
        return _cal(lines)

    def calendar(self) -> list[CalObject]:
        out = [CalObject(m.organizer, "events", f"{org.UID_PREFIX}{m.id}@{self.domain}", f"{org.UID_PREFIX}{m.id}.ics", self._vevent(m),
                         m.attendees) for m in org.MEETINGS]
        out += [CalObject(org.TEAM_CALENDAR["owner"], org.TEAM_CALENDAR["slug"], f"{org.UID_PREFIX}{m.id}@{self.domain}",
                          f"{org.UID_PREFIX}{m.id}.ics", self._vevent(m, team=True)) for m in org.TEAM_EVENTS]
        out += [CalObject(t.owner, "tasks", f"{org.UID_PREFIX}{t.id}@{self.domain}", f"{org.UID_PREFIX}{t.id}.ics", self._vtodo(t))
                for t in org.TASKS]
        return out

    # ---------- files
    def files(self) -> list[tuple[str, str, str]]:
        """(owner uid, path, FILES key)"""
        return [(f.owner, f"{f.path}/{k}", k) for f in org.FOLDERS for k in f.files]

    def shares(self) -> list[tuple[str, str, str, str]]:
        """(owner uid, folder path, recipient uid, edit|view)"""
        return [(f.owner, f.path, u, r) for f in org.FOLDERS for u, r in f.shares]

    # ---------- chat
    def rooms(self) -> list[org.Room]:
        return list(org.ROOMS)

    def chat_messages(self) -> list[tuple[str, str, str, str]]:
        """(room key, demo id, sender uid, text)"""
        return [(r.key, f"{r.key}-{i:02d}", s, t) for r in org.ROOMS for i, (s, t) in enumerate(r.messages)]

    # ---------- safety
    def recipients(self):
        """Every address that receives or is granted anything (guard.check_addresses)."""
        for th in org.THREADS:
            for m in th.messages:
                yield from (self.addr(u) for u in (m.sender, *m.to, *m.cc))
        for m in [*org.MEETINGS, *org.TEAM_EVENTS]:
            yield from (self.addr(u) for u in (m.organizer, *m.attendees))
        for t in org.TASKS:
            yield self.addr(t.owner)
        for o, _p, u, _r in self.shares():
            yield from (self.addr(o), self.addr(u))
        for r in org.ROOMS:
            yield from (self.addr(u) for u in (r.creator, *r.members))

    # ---------- dry run
    def summary(self) -> dict:
        dels = self.deliveries()
        cal = self.calendar()
        msgs = [m for th in org.THREADS for m in th.messages]
        return {
            "organization": org.ORG_NAME, "domain": self.domain, "anchor": self.anchor.isoformat(), "timezone": self.tzname,
            "people": len(org.PEOPLE), "departments": {d: [p.name for p in org.PEOPLE if p.department == d] for d in org.DEPARTMENTS},
            "organization_admins": [p.uid for p in org.PEOPLE if p.role == "admin"],
            "mail": {"threads": len(org.THREADS), "messages": len(msgs), "mailbox_copies": len(dels),
                     "attachments": sum(len(m.attachments) for m in msgs),
                     "flagged_copies": sum("\\Flagged" in d.flags for d in dels),
                     "unread_copies": sum(d.folder == "INBOX" and "\\Seen" not in d.flags for d in dels)},
            "calendar": {"meetings": len(org.MEETINGS), "invitations": sum(len(m.attendees) for m in org.MEETINGS),
                         "recurring": sum(bool(m.rrule) for m in org.MEETINGS),
                         "upcoming": sum(bday(self.anchor, m.day) >= self.anchor for m in org.MEETINGS),
                         "team_calendar": org.TEAM_CALENDAR["name"], "team_events": len(org.TEAM_EVENTS),
                         "tasks": sum(c.collection == "tasks" for c in cal)},
            "files": {"folders": [f"{f.owner}:/{f.path}" for f in org.FOLDERS], "documents": len(self.files()),
                      "by_kind": {k: sum(org.FILES[x].kind == k for _o, _p, x in self.files()) for k in ("document", "spreadsheet", "presentation")},
                      "shares": len(self.shares()), "documents_with_comments": sum(bool(org.FILES[x].comments) for _o, _p, x in self.files())},
            "chat": {"rooms": [r.name for r in org.ROOMS if not r.direct], "direct_messages": sum(r.direct for r in org.ROOMS),
                     "messages": len(self.chat_messages())},
            "msp_tenants": [t.name for t in org.MSP_TENANTS],
        }


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\n", "\\n")


def _fold(line: str) -> str:
    b = line.encode()
    if len(b) <= 75:
        return line
    out, cur = [], ""
    for ch in line:
        if len((cur + ch).encode()) > (75 if not out else 74):
            out.append(cur)
            cur = ""
        cur += ch
    out.append(cur)
    return "\r\n ".join(out)


def _cal(lines: list[str]) -> str:
    return "\r\n".join(_fold(x) for x in ["BEGIN:VCALENDAR", "VERSION:2.0", f"PRODID:{PRODID}", "CALSCALE:GREGORIAN", *lines,
                                         "END:VCALENDAR"]) + "\r\n"
