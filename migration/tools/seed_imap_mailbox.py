#!/usr/bin/env python3
"""LAB ONLY: fill a test IMAP mailbox with a realistic, deterministic corpus (plain/HTML/multipart, attachments incl. one
5 MB, mixed flags, spread INTERNALDATEs, nested unicode folder). Not part of the engine; it WRITES to the mailbox it is
pointed at, so it is never used with a customer source.

  OU_SEED_PASSWORD_FILE=pw python3 tools/seed_imap_mailbox.py --host 192.168.186.22 --user carol --cafile msrc1.pem seed
  ... --user carol add --count 25 --start 1000        # later delta for the incremental test
"""
from __future__ import annotations

import argparse
import datetime as dt
import imaplib
import os
import random
import ssl
import sys
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from ou_migration.engine import mutf7  # noqa: E402
from ou_migration.secrets import load_secret  # noqa: E402

PEOPLE = ["anna.keller@example.org", "tom@example.net", "billing@vendor.example", "jose.garcia@example.es", "mei.lin@example.cn",
          "newsletter@news.example", "support@saas.example", "dr.mueller@praxis.example"]
SUBJECTS = ["Quarterly report", "Re: Meeting notes", "Invoice 2025-{n}", "Neue Preisliste für Müller & Söhne", "Fwd: Contract draft",
            "Lunch on Friday?", "Reisekostenabrechnung März", "Your order has shipped", "Security notice", "Projektstatus 日本語テスト",
            "Re: Re: schedule", "Weekly digest"]
FOLDERS = [("INBOX", 175), ("Sent", 70), ("Drafts", 5), ("Trash", 5), ("Junk", 5), ("Archive/2025", 55),
           ("Projekte/Übersicht & Pläne/日本語", 22)]


def build(i: int, rng: random.Random, big=False) -> tuple[bytes, dt.datetime]:
    m = EmailMessage()
    when = dt.datetime(2024, 1, 5, 8, 0, tzinfo=dt.timezone.utc) + dt.timedelta(hours=rng.randint(0, 24 * 600), minutes=i % 60)
    sender, rcpt = rng.sample(PEOPLE, 2)
    m["From"], m["To"] = sender, rcpt
    m["Subject"] = rng.choice(SUBJECTS).format(n=i)
    m["Date"] = format_datetime(when)
    m["Message-ID"] = make_msgid(idstring=f"seed{i}", domain="msrc1.ou-lab.internal")
    body = "".join(f"Zeile {k} / line {k}: {rng.getrandbits(64):x} äöü ß €\n" for k in range(rng.randint(3, 40)))
    m.set_content(body)
    if i % 4 == 0:
        m.add_alternative(f"<html><body><h1>Msg {i}</h1><p>{body[:80]}</p></body></html>", subtype="html")
    if big:
        m.add_attachment(rng.randbytes(5 * 1024 * 1024), maintype="application", subtype="pdf", filename="Jahresabschluss-5MB.pdf")
    elif i % 9 == 0:
        m.add_attachment(rng.randbytes(rng.randint(20_000, 250_000)), maintype="application", subtype="octet-stream",
                         filename=f"anlage-{i}.bin")
    return m.as_bytes(), when


def flags_for(i: int, folder: str) -> str:
    if folder in ("Sent", "Archive/2025") or folder.startswith("Projekte"):
        return "(\\Seen)" if i % 7 else "(\\Seen \\Flagged)"
    if folder == "Drafts":
        return "(\\Draft \\Seen)"
    f = []
    if i % 5 != 0:
        f.append("\\Seen")
    if i % 11 == 0:
        f.append("\\Flagged")
    if i % 13 == 0:
        f.append("\\Answered")
    return "(" + " ".join(f) + ")"


def connect(ns):
    ctx = ssl.create_default_context(cafile=ns.cafile)
    c = imaplib.IMAP4_SSL(ns.host, ns.port, ssl_context=ctx)
    c.login(ns.user, load_secret("OU_SEED_PASSWORD"))
    return c


def put(c, folder, i, big=False, seed_base=7):
    rng = random.Random(seed_base * 100003 + i)
    data, when = build(i, rng, big)
    wire = '"' + mutf7.encode(folder) + '"'
    c.append(wire, flags_for(i, folder), imaplib.Time2Internaldate(when.timestamp()), data)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=993)
    ap.add_argument("--user", required=True)
    ap.add_argument("--cafile")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("seed")
    a = sub.add_parser("add")
    a.add_argument("--count", type=int, default=25)
    a.add_argument("--start", type=int, default=1000)
    a.add_argument("--folder", default="INBOX")
    ns = ap.parse_args(argv)
    c = connect(ns)
    if ns.cmd == "seed":
        n = 0
        for folder, cnt in FOLDERS:
            if folder != "INBOX":
                parts = folder.split("/")
                for k in range(1, len(parts) + 1):
                    c.create('"' + mutf7.encode("/".join(parts[:k])) + '"')
            for j in range(cnt):
                n += 1
                put(c, folder, n, big=(folder == "INBOX" and j == 17))
        print(f"seeded {n} messages")
    else:
        for j in range(ns.count):
            put(c, ns.folder, ns.start + j)
        print(f"added {ns.count} messages to {ns.folder}")
    c.logout()


if __name__ == "__main__":
    main()
