"""The dashboard's model: per-user preferences (the ou_prefs cookie), the widgets and their columns, and the calendar/mail summary the
groupware reader returns for the signed-in user (services.groupware_summary) turned into the agenda, the next meeting, upcoming meetings and
the "Needs your attention" feed. Pure functions: no I/O, so every rule here is unit-tested (tests/test_dashboard.py).

Data rules (owner brief 2026-11-26, section 4): only the signed-in user's own data, read with that user's own token; nothing is invented. A
source that cannot be read gives `None` and the widget says so; an empty list means "read, and there is nothing"."""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

THEMES = ("system", "light", "dark")
# key -> (title, column). Columns of the concept (docs/design/concepts/home.webp): side (agenda), main (attention feed and files), aside
# (meetings and notifications). The order inside a column is the user's (Settings > Dashboard); a widget never moves to another column.
WIDGETS = {
    "agenda": ("Today's agenda", "side"),
    "attention": ("Needs your attention", "main"),
    "recent": ("Recent files", "main"),
    "shared": ("Shared with me", "main"),
    "meetings": ("Upcoming meetings", "aside"),
    "notifications": ("Notifications", "aside"),
    "favorites": ("Favourites", "aside"),
}
ZONES = ("side", "main", "aside")
DEFAULT_ORDER = tuple(WIDGETS)
DENSITIES = ("comfortable", "compact")


def parse_prefs(raw: str | None) -> dict:
    """`<theme>:<hidden>.<...>:<order>.<...>:<flags>`, cookie-safe characters only (RFC 6265 cookie-octets). The first two fields are the
    0.13 format, so an old cookie keeps its theme and hidden widgets. Anything unknown is dropped: it is a preference, never trusted.
    flags: `x` = navigation rail expanded, `c` = compact dashboard."""
    parts = (raw or "")[:400].split(":")
    parts += [""] * (4 - len(parts))
    theme, hidden, order, flags = parts[:4]
    seen: list[str] = []
    for w in order.split(".") + list(DEFAULT_ORDER):            # the user's order first, then any widget they have not placed yet
        if w in WIDGETS and w not in seen:
            seen.append(w)
    return {"theme": theme if theme in THEMES else "system",
            "hidden": [w for w in dict.fromkeys(hidden.split(".")) if w in WIDGETS],
            "order": seen, "rail": "expanded" if "x" in flags else "collapsed", "density": "compact" if "c" in flags else "comfortable"}


def dump_prefs(p: dict) -> str:
    order = "" if list(p.get("order") or DEFAULT_ORDER) == list(DEFAULT_ORDER) else ".".join(p["order"])
    flags = ("x" if p.get("rail") == "expanded" else "") + ("c" if p.get("density") == "compact" else "")
    return ":".join((p.get("theme", "system"), ".".join(p.get("hidden") or []), order, flags)).rstrip(":")


def move(order: list[str], key: str, direction: str) -> list[str]:
    """Move a widget one place up or down among the widgets of ITS column (the layout keeps columns fixed)."""
    if key not in WIDGETS or direction not in ("up", "down"):
        return order
    zone = WIDGETS[key][1]
    col = [w for w in order if WIDGETS[w][1] == zone]
    i = col.index(key)
    j = i - 1 if direction == "up" else i + 1
    if not 0 <= j < len(col):
        return order
    col[i], col[j] = col[j], col[i]
    it = iter(col)
    return [next(it) if WIDGETS[w][1] == zone else w for w in order]


def columns(p: dict) -> dict[str, list[str]]:
    """The visible widgets per column, in the user's order."""
    return {z: [w for w in p["order"] if WIDGETS[w][1] == z and w not in p["hidden"]] for z in ZONES}


def greeting(now: datetime) -> str:
    h = now.hour
    return "Good morning" if 5 <= h < 12 else "Good afternoon" if 12 <= h < 18 else "Good evening"


def initials(name: str) -> str:
    words = [w for w in name.replace(".", " ").replace("@", " ").split() if w[:1].isalnum()]
    if not words:
        return "?"
    return (words[0][0] + (words[-1][0] if len(words) > 1 else "")).upper()


# ---- groupware summary -> agenda ----------------------------------------------------------------------------------------------------
def _ts(v, tz) -> datetime | None:
    if not isinstance(v, str) or len(v) > 40:
        return None
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    if d.tzinfo is None:
        return None                                              # the contract requires an offset: a floating time is ambiguous
    return d.astimezone(tz)


def _s(v, n: int) -> str:
    return v.strip()[:n] if isinstance(v, str) else ""


def _https(v) -> str | None:
    """Only an https:// link is shown as a Join button (never javascript:, data:, http:)."""
    if isinstance(v, str) and v.startswith("https://") and len(v) <= 500 and not any(c in v for c in ' "<>\\\n\r\t'):
        return v
    return None


RESPONSES = ("organizer", "accepted", "tentative", "declined", "none")   # "none" = invited, not answered; missing = "unknown"
ATTENTION_KINDS = ("invitation", "flagged", "important")


def normalise(raw, mailbox: str, tz) -> dict | None:
    """Validate the reader's answer (contract: docs/design/design-system.md "Portal"). The answer must name the signed-in user's own
    mailbox; any other mailbox, a wrong version or a malformed body is treated as "not available" (None), never shown."""
    if not isinstance(raw, dict) or raw.get("version") != 1:
        return None
    if not isinstance(raw.get("mailbox"), str) or raw["mailbox"].strip().lower() != (mailbox or "").strip().lower() or not mailbox:
        return None
    events = []
    for e in (raw.get("events") if isinstance(raw.get("events"), list) else [])[:200]:
        if not isinstance(e, dict):
            continue
        start, end = _ts(e.get("start"), tz), _ts(e.get("end"), tz)
        subject = _s(e.get("subject"), 200)
        if not start or not end or end < start:
            continue
        att = [_s(a, 80) for a in (e.get("attendees") if isinstance(e.get("attendees"), list) else [])[:50] if _s(a, 80)]
        events.append({"subject": subject or "(no title)", "start": start, "end": end, "all_day": e.get("all_day") is True,
                       "location": _s(e.get("location"), 120), "organizer": _s(e.get("organizer"), 80), "attendees": att,
                       "join_url": _https(e.get("join_url")),
                       "response": e.get("response") if e.get("response") in RESPONSES else "unknown",
                       "free": e.get("busy") == "free"})
    events.sort(key=lambda e: (e["start"], e["end"]))
    attention = []
    for a in (raw.get("attention") if isinstance(raw.get("attention"), list) else [])[:100]:
        if not isinstance(a, dict) or a.get("kind") not in ATTENTION_KINDS:
            continue
        when = _ts(a.get("received"), tz)
        subject = _s(a.get("subject"), 200)
        if not when or not (subject or _s(a.get("from"), 80)):
            continue
        attention.append({"kind": a["kind"], "from": _s(a.get("from"), 80), "subject": subject or "(no subject)", "when": when,
                          "due": _ts(a.get("due"), tz), "unread": a.get("unread") is True, "attachments": a.get("attachments") is True})
    unread = raw.get("unread")
    return {"events": events, "attention": attention,
            "unread": unread if isinstance(unread, int) and not isinstance(unread, bool) and 0 <= unread < 10**7 else None}


def minutes_until(now: datetime, then: datetime) -> int:
    return max(0, int((then - now).total_seconds() // 60))


def countdown(now: datetime, start: datetime) -> str:
    m = minutes_until(now, start)
    if start <= now:
        return "now"
    if m < 60:
        return f"in {m} minute{'s' if m != 1 else ''}" if m else "in less than a minute"
    if start.date() == now.date():
        return "at " + start.strftime("%H:%M")
    return start.strftime("%a %-d %b, %H:%M")


def agenda(summary: dict | None, now: datetime) -> dict | None:
    """Today's events (all-day apart), conflicts, the now-line position, the next meeting and the upcoming meetings of the next 7 days."""
    if summary is None:
        return None
    today = now.date()
    live = [e for e in summary["events"] if e["response"] != "declined"]
    todays = [e for e in live if e["start"].date() <= today <= (e["end"] - timedelta(seconds=1)).date()]
    all_day = [e for e in todays if e["all_day"]]
    timed = [dict(e) for e in todays if not e["all_day"]]
    for i, e in enumerate(timed):                                    # a conflict: two busy timed events overlap
        e["conflict"] = not e["free"] and any(o is not e and not o["free"] and o["start"] < e["end"] and e["start"] < o["end"]
                                              for o in timed)
        e["past"] = e["end"] <= now
        e["current"] = e["start"] <= now < e["end"]
    now_at = next((i for i, e in enumerate(timed) if e["start"] > now), len(timed))   # the now-line goes before this index
    nxt = next((e for e in timed if e["end"] > now), None)
    tomorrow = datetime.combine(today + timedelta(days=1), datetime.min.time(), tzinfo=now.tzinfo)
    week_end = tomorrow + timedelta(days=7)
    upcoming = [e for e in live if not e["all_day"] and tomorrow <= e["start"] < week_end and (e["attendees"] or e["join_url"])][:4]
    return {"timed": timed, "all_day": all_day, "now_at": now_at, "next": nxt, "next_in": countdown(now, nxt["start"]) if nxt else "",
            "count": len(timed), "conflicts": sum(1 for e in timed if e["conflict"]), "upcoming": upcoming}


def headline(day: date, ag: dict | None) -> str:
    """The line under the greeting: the date, then what the calendar says (only when it could be read)."""
    s = day.strftime("%A %-d %B")
    if ag is None:
        return s
    n = ag["count"]
    if not n:
        return s + " · no meetings today"
    words = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine"}
    s += f" · {words.get(n, str(n))} meeting{'s' if n != 1 else ''} today"
    if ag["next"]:
        s += ", the next " + ag["next_in"] if ag["next_in"] != "now" else ", one is on now"
    return s


def attention_feed(summary: dict | None, shared: list | None, now: datetime, limit: int = 6) -> list[dict]:
    """Mail items the reader marked (invitations awaiting a response, flagged, important and unread) and files shared with the user in the
    last 14 days (OpenCloud, the user's token), newest first."""
    items = []
    for a in (summary or {}).get("attention", []):
        items.append({**a, "source": "mail"})
    cutoff = now - timedelta(days=14)
    for f in shared or []:
        when = f["mtime"].astimezone(now.tzinfo) if f["mtime"].tzinfo else f["mtime"].replace(tzinfo=timezone.utc)
        if when >= cutoff:
            items.append({"kind": "share", "source": "files", "from": f.get("by") or "", "subject": f["name"], "when": when, "url": f["url"],
                          "file_kind": f.get("kind", "file"), "due": None, "unread": False, "attachments": False})
    items.sort(key=lambda i: i["when"], reverse=True)
    return items[:limit]
