"""Typed, strictly validated parameters for the Gromox mailbox-administration runbooks (aliases, shared mailboxes, quotas, usage).
Pure functions, stdlib only. Used twice: by the agent (before anything is spooled) and again by the node-side helper `mbxhelper`, which never trusts
the spool file. No free-form argument exists: every field has a closed shape and a tight character class; the helper builds SQL with bound parameters
and file contents from validated addresses only (no shell, no string commands anywhere).

Gromox facts these runbooks rely on (gromox source, reference/upstream/gromox):
  * aliases: SQL table `aliases(aliasname -> mainname)`; the delivery agent resolves them, postfix needs a lookup map (see docs/status/mailbox-admin-results.md)
  * shared mailbox: `users.address_status = 4` (SHARED), no login (authmgr refuses), store created with gromox-mkprivate
  * access to a shared mailbox: folder rights in the store's sqlite `permissions` table (exch/exmdb/store.cpp) + `config/delegates.txt`
    (Send-on-behalf) and `config/sendas.txt` (Send-As), one address per line (exch/exmdb/message.cpp defer_check_repr, store2.cpp write_delegates)
  * quotas: store properties PR_STORAGE_QUOTA_LIMIT 0x3FF5, PR_PROHIBIT_SEND_QUOTA 0x666E, PR_PROHIBIT_RECEIVE_QUOTA 0x666A (PT_LONG, KiB),
    usage = PR_MESSAGE_SIZE_EXTENDED 0x0E08 (PT_I8, bytes)"""
import re

from .proto import Reject

MBX_RUNBOOKS = ("gromox.set_aliases", "gromox.shared_create", "gromox.shared_delete", "gromox.shared_access", "gromox.shared_state",
                "gromox.set_quota", "gromox.mail_usage")
FAMILY = "gromox-mbx"          # template unit ou-rb-gromox-mbx@<rid>.service, result dir /run/ou-rb-gromox-mbx/
LOCAL_RE = re.compile(r"^[a-z][a-z0-9._-]{1,31}$")                      # a mailbox / user name (same shape as the directory uid)
ADDR_RE = re.compile(r"^[a-z0-9][a-z0-9._+-]{0,63}@[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?){1,6}$")
KINDS = ("full_access", "send_as", "send_on_behalf")
MAX_ALIASES = 20
MAX_USAGE_USERS = 100
MAX_KB = 2_000_000_000            # < 2**31 (PT_LONG), 1.9 TB in KiB: quotas are stored as int32 KiB
DISPLAY_RE = re.compile(r"^[^\x00-\x1f\x7f<>]{1,100}$")

# folder rights (MAPI frights*): ReadAny, Create, EditOwned, DeleteOwned, EditAny, DeleteAny, CreateSubfolder, Owner, Visible
RIGHTS_FULL = 0x01 | 0x02 | 0x08 | 0x10 | 0x20 | 0x40 | 0x80 | 0x100 | 0x400   # 1531, the value the lab ACLs (GW05) use


def _exact(p, keys, required=None):
    if not isinstance(p, dict) or not set(p) <= set(keys) or not set(keys if required is None else required) <= set(p):
        raise Reject("bad_params", "unexpected or missing parameters")


def _s(v, rx, what):
    if not isinstance(v, str) or not rx.fullmatch(v):
        raise Reject("bad_params", f"invalid {what}")
    return v


def _kb(v, what):
    if v is None:
        return None
    if type(v) is not int or not 1 <= v <= MAX_KB:
        raise Reject("bad_params", f"invalid {what}")
    return v


def check_set_aliases(p, cfg=None):
    _exact(p, ("user", "aliases"))
    al = p["aliases"]
    if not isinstance(al, list) or len(al) > MAX_ALIASES:
        raise Reject("bad_params", f"aliases: list of at most {MAX_ALIASES}")
    out = sorted({_s(a, ADDR_RE, "alias address") for a in al})
    if len(out) != len(al):
        raise Reject("bad_params", "duplicate alias")
    return {"user": _s(p["user"], LOCAL_RE, "user"), "aliases": out}


def check_shared_create(p, cfg=None):
    _exact(p, ("name", "display_name"))
    return {"name": _s(p["name"], LOCAL_RE, "mailbox name"), "display_name": _s(p["display_name"], DISPLAY_RE, "display name")}


def check_shared_delete(p, cfg=None):
    _exact(p, ("name",))
    return {"name": _s(p["name"], LOCAL_RE, "mailbox name")}


def check_shared_access(p, cfg=None):
    _exact(p, ("name", "user", "kind", "grant"))
    if p["kind"] not in KINDS:
        raise Reject("bad_params", "kind must be one of " + ", ".join(KINDS))
    if type(p["grant"]) is not bool:
        raise Reject("bad_params", "grant must be boolean")
    out = {"name": _s(p["name"], LOCAL_RE, "mailbox name"), "user": _s(p["user"], LOCAL_RE, "user"), "kind": p["kind"], "grant": p["grant"]}
    if out["name"] == out["user"]:
        raise Reject("bad_params", "a mailbox cannot be granted to itself")
    return out


def check_shared_state(p, cfg=None):
    _exact(p, ("name",))
    return {"name": _s(p["name"], LOCAL_RE, "mailbox name")}


def check_set_quota(p, cfg=None):
    _exact(p, ("user", "send_kb", "receive_kb", "storage_kb"))
    out = {"user": _s(p["user"], LOCAL_RE, "user"), "send_kb": _kb(p["send_kb"], "send limit"), "receive_kb": _kb(p["receive_kb"], "receive limit"),
           "storage_kb": _kb(p["storage_kb"], "storage limit")}
    return out


def check_mail_usage(p, cfg=None):
    _exact(p, ("users",))
    us = p["users"]
    if not isinstance(us, list) or not 1 <= len(us) <= MAX_USAGE_USERS:
        raise Reject("bad_params", f"users: 1..{MAX_USAGE_USERS} entries")
    out = sorted({_s(u, LOCAL_RE, "user") for u in us})
    return {"users": out}


CHECKS = {"gromox.set_aliases": check_set_aliases, "gromox.shared_create": check_shared_create, "gromox.shared_delete": check_shared_delete,
          "gromox.shared_access": check_shared_access, "gromox.shared_state": check_shared_state, "gromox.set_quota": check_set_quota,
          "gromox.mail_usage": check_mail_usage}
