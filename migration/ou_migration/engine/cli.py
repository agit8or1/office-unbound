"""CLI glue: ``python -m ou_migration mail-migrate|mail-verify ...``

Credentials only from the environment / 0600 files (never argv):
  source:  OU_SRC_PASSWORD | OU_SRC_PASSWORD_FILE        (--src-auth login)
           OU_SRC_TOKEN    | OU_SRC_TOKEN_FILE           (--src-auth xoauth2, a pre-obtained access token; short lived)
           OU_GOOGLE_SA_KEY_FILE + OU_GOOGLE_ADMIN_SUBJECT   (--src-auth xoauth2-google)
           OU_M365_TENANT_ID, OU_M365_CLIENT_ID, OU_M365_CLIENT_SECRET[_FILE]   (--src-auth xoauth2-m365)
  target:  OU_DST_PASSWORD | OU_DST_PASSWORD_FILE
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sys

from ..http import HttpClient
from ..secrets import SecretError, load_secret
from .imapx import Endpoint, Fatal, ImapError, LoginAuth, Session, StaticTokenProvider, Throttle, XOAuth2Auth
from .mailbox import Mailbox
from .mapping import Mapper
from .migrate import Migrator, Options
from .state import State, StateError
from .verify import verify


def add_parsers(sub):
    for name, h in (("mail-migrate", "IMAP -> Gromox mail migration (incremental, resumable)"),
                    ("mail-verify", "compare source and target mailboxes (read-only)")):
        p = sub.add_parser(name, help=h)
        p.add_argument("--src-host", required=True)
        p.add_argument("--src-port", type=int, default=993)
        p.add_argument("--src-security", choices=["tls", "starttls", "plain"], default="tls")
        p.add_argument("--src-ca", help="PEM file: pinned CA or the server's self-signed certificate")
        p.add_argument("--src-user", required=True)
        p.add_argument("--src-auth", choices=["login", "xoauth2", "xoauth2-google", "xoauth2-m365"], default="login")
        p.add_argument("--dst-host")
        p.add_argument("--dst-port", type=int, default=993)
        p.add_argument("--dst-security", choices=["tls", "starttls", "plain"], default="tls")
        p.add_argument("--dst-ca")
        p.add_argument("--dst-user")
        p.add_argument("--out", required=True, help="report directory")
        p.add_argument("--exclude", action="append", default=[], help="regex on the decoded source folder name")
        p.add_argument("--include-virtual", action="store_true", help="also import \\Flagged/\\Important virtual folders")
        p.add_argument("--map", action="append", default=[], metavar="SRC=DST", help="explicit folder mapping")
        p.add_argument("--dedupe-mode", choices=["strict", "loose"], default="strict")
        if name == "mail-migrate":
            p.add_argument("--state", required=True, help="SQLite state file (created 0600; an existing file is resumed)")
            p.add_argument("--dry-run", action="store_true", help="count messages/bytes per folder; writes nothing")
            p.add_argument("--max-msgs-per-sec", type=float, default=0)
            p.add_argument("--max-bytes-per-sec", type=float, default=0)
            p.add_argument("--max-message-bytes", type=int, default=64 * 1024 * 1024)
        else:
            p.add_argument("--sample", type=int, default=10, help="messages per folder whose full body hash is compared")
            p.add_argument("--seed", type=int, default=1)


def _src_auth(ns, environ):
    if ns.src_auth == "login":
        return LoginAuth(ns.src_user, load_secret("OU_SRC_PASSWORD", environ=environ))
    if ns.src_auth == "xoauth2":
        return XOAuth2Auth(ns.src_user, StaticTokenProvider(load_secret("OU_SRC_TOKEN", environ=environ)))
    from .oauth import GoogleImapTokens, M365ImapTokens
    http = HttpClient()
    if ns.src_auth == "xoauth2-google":
        from ..auth import GoogleAuth
        return XOAuth2Auth(ns.src_user, GoogleImapTokens(GoogleAuth.from_env(http, environ)))
    try:
        return XOAuth2Auth(ns.src_user, M365ImapTokens(http, environ["OU_M365_TENANT_ID"], environ["OU_M365_CLIENT_ID"],
                                                       load_secret("OU_M365_CLIENT_SECRET", environ=environ)))
    except KeyError as e:
        raise SecretError(f"missing {e.args[0]}") from None


def _write_report(out, name, rep):
    os.makedirs(out, mode=0o700, exist_ok=True)
    jp = os.path.join(out, name + ".json")
    fd = os.open(jp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(rep, f, indent=1, sort_keys=True)
    return jp


def format_text(rep) -> str:
    lines = []
    if "totals" in rep:
        lines.append(f"{rep['mode']}: {'complete' if rep.get('complete') else 'INCOMPLETE'}")
        lines.append(f"{'source -> target':<44}{'src':>6}{'new':>6}{'copy':>6}{'adopt':>6}{'MiB':>9}")
        for f in rep["folders"]:
            lines.append(f"{f['source'][:20] + ' -> ' + f['target'][:20]:<44}{f['source_messages']:>6}{f['candidates']:>6}"
                         f"{f['copied']:>6}{f['adopted']:>6}{f['bytes_candidates'] / 1048576:>9.2f}")
        t = rep["totals"]
        lines.append(f"TOTAL candidates={t['candidates']} copied={t['copied']} adopted={t['adopted']} failed={t['failed']} "
                     f"too_large={t['skipped_too_large']}")
    else:
        lines.append(f"verify: {'OK' if rep['ok'] else 'MISMATCH'}  source={rep['source_total']} target={rep['target_total']}")
        for f in rep["folders"]:
            lines.append(f"  {f['target'][:30]:<30} src={f['source_count']:>4} dst={f['target_count']:>4} missing={f['missing_on_target']} "
                         f"extra={f['extra_on_target']} flags!={f['flag_mismatches']} hash!={f['body_hash_mismatches']}/{f['sampled']}")
    return "\n".join(lines)


def run(ns, environ=None, *, sleep=None) -> int:
    environ = os.environ if environ is None else environ
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    try:
        mapper = Mapper(include_virtual=ns.include_virtual, exclude=tuple(ns.exclude),
                        rename=dict(m.split("=", 1) for m in ns.map))
        kw = {"sleep": sleep} if sleep else {}
        src = Session(Endpoint(ns.src_host, ns.src_port, ns.src_security, ns.src_ca, label="source"),
                      _src_auth(ns, environ), write=False, **kw).connect()
        dst = None
        dry = getattr(ns, "dry_run", False)
        if ns.dst_host:
            dst = Session(Endpoint(ns.dst_host, ns.dst_port, ns.dst_security, ns.dst_ca, label="target"),
                          LoginAuth(ns.dst_user, load_secret("OU_DST_PASSWORD", environ=environ)), write=(ns.cmd == "mail-migrate" and not dry), **kw).connect()
        elif ns.cmd == "mail-verify" or not dry:
            print("--dst-host is required (except for --dry-run)", file=sys.stderr)
            return 2
        if ns.cmd == "mail-verify":
            rep = verify(Mailbox(src), Mailbox(dst), mapper, mode=ns.dedupe_mode, sample=ns.sample, seed=ns.seed)
            name, rc = "verify", 0 if rep["ok"] else 1
        else:
            key = hashlib.sha256(f"{ns.src_host}|{ns.src_user}|{ns.dst_host}|{ns.dst_user}".encode()).hexdigest()
            state = None if (dry and not dst) else State(ns.state, key)
            mig = Migrator(Mailbox(src), Mailbox(dst) if dst else None, state, mapper,
                           options=Options(dedupe_mode=ns.dedupe_mode, max_message_bytes=ns.max_message_bytes),
                           throttle=Throttle(ns.max_msgs_per_sec, ns.max_bytes_per_sec))
            rep = mig.run(dry_run=dry)
            name, rc = ("dry-run" if dry else "migrate"), 0 if rep["complete"] else 1
        print(_write_report(ns.out, name, rep))
        print(format_text(rep))
        return rc
    except (SecretError, StateError, Fatal, ImapError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    finally:
        for sess in (locals().get("src"), locals().get("dst")):
            if sess is not None:
                sess.close()
