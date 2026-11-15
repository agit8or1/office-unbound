"""Identity mapping PROPOSAL (source login -> LDAP uid/mail; groups -> LDAP groups).

Target model: OpenLDAP is authoritative; the immutable id is entryUUID (assigned by the directory,
docs/status/user-lifecycle-results.md), so the source object id is only recorded for traceability.
Nothing is created by the assessment. The proposal is tagged ``assumption`` (rules below are our defaults).
"""
from __future__ import annotations

import re

UID_MAX = 32
_BAD = re.compile(r"[^a-z0-9._-]+")


def _local(addr: str) -> str:
    return addr.split("@", 1)[0]


def sanitize_uid(s: str) -> str:
    s = _BAD.sub(".", s.lower()).strip("._-")
    s = re.sub(r"\.{2,}", ".", s)
    return s[:UID_MAX] or "user"


def propose(inv, verified_domains: set[str]) -> dict:
    users, used = [], {}
    issues = {"collisions": 0, "unverified_domain": 0, "guest_excluded": 0, "disabled_import_disabled": 0,
              "no_mail": 0, "uid_sanitized": 0, "login_concealed": 0}
    # verified-domain addresses win the plain uid; then alphabetical (deterministic)
    for u in sorted(inv.users, key=lambda x: ((x.mail or x.login).lower().split("@")[-1] not in verified_domains,
                                              (x.mail or x.login).lower(), x.source_id)):
        mail = (u.mail or u.login).lower()
        row = {"source_id": u.source_id, "source_login": u.login, "mail": mail, "aliases": [a.lower() for a in u.aliases]}
        if "@" not in mail:
            issues["no_mail"] += 1
            issues["login_concealed"] += 1
            row.update(action="needs-decision", reason="no usable email address", uid=None)
            users.append(row)
            continue
        if u.user_type == "guest":
            issues["guest_excluded"] += 1
            row.update(action="exclude", reason="guest/external identity: no mailbox migration by default", uid=None)
            users.append(row)
            continue
        base = sanitize_uid(_local(mail))
        if base != _local(mail).lower():
            issues["uid_sanitized"] += 1
        uid = base
        dom = mail.split("@", 1)[1]
        if uid in used and used[uid] != mail:
            issues["collisions"] += 1
            uid = sanitize_uid(f"{base}.{dom.split('.')[0]}")[:UID_MAX]
            n = 2
            while uid in used and used[uid] != mail:
                uid = f"{base[:UID_MAX - 3]}.{n}"
                n += 1
        used[uid] = mail
        if dom not in verified_domains:
            issues["unverified_domain"] += 1
        action = "create"
        if not u.enabled:
            issues["disabled_import_disabled"] += 1
            action = "create-disabled"
        row.update(uid=uid, action=action, groups=[])
        users.append(row)
    groups, gused = [], {}
    for g in sorted(inv.groups, key=lambda x: (x.name.lower(), x.source_id)):
        cn = sanitize_uid(g.name) if g.name else sanitize_uid(g.mail)
        if cn in gused:
            cn = f"{cn[:UID_MAX - 9]}.{g.source_id[:8]}"
        gused[cn] = True
        groups.append({"source_id": g.source_id, "name": g.name, "mail": g.mail.lower(), "kind": g.kind,
                       "members": g.members, "cn": cn,
                       "action": "needs-decision" if g.dynamic else "create"})
    return {"rules": [
        f"uid = lower-case local part of primary SMTP address, characters outside [a-z0-9._-] become '.', max {UID_MAX}",
        "collision: append first label of the mail domain, then a numeric suffix",
        "mail = primary SMTP address (M365 proxyAddresses SMTP:, Google primaryEmail); other addresses = aliases",
        "guests/external users excluded by default; disabled sources are created disabled",
        "groups: cn from display name with the same sanitising; dynamic groups need a decision (materialise members)",
        "LDAP entryUUID, not the source id, becomes the stable id (assigned at creation)"],
        "issues": issues, "users": users, "groups": groups}
