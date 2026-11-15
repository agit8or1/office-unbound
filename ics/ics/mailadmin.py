"""Mailbox and storage administration for one customer stack (typed actions, same machinery as identity.py).

  idm.user.set_aliases          add / remove alternative addresses of a user (only the customer's verified domains; unique across the customer)
  idm.shared_mailbox.create     a mailbox nobody logs in to (Gromox address_status 4, created by the fixed runbook gromox.shared_create)
  idm.shared_mailbox.delete     suspend it and drop every grant (data is RETAINED: there is no purge action)
  idm.shared_mailbox.grant      full access (folder rights) / send-as (sendas.txt) / send-on-behalf (delegates.txt) for one user
  idm.shared_mailbox.revoke
  idm.user.set_mail_quota       Gromox store properties (storage warning, prohibit send, prohibit receive)
  idm.user.set_storage_quota    OpenCloud personal-drive quota through the Graph API as ONE narrowly used directory user (see the results doc)

Everything the node does goes through fixed runbooks with closed-shape parameters (agent/ou_agent/mbxspec.py); the ICS keeps its own record
(migration 0010b) so uniqueness across the customer and the portal views never need a node round-trip. Nothing here sends a shell string."""
import json
import re
import ssl
import time
from typing import Literal, Self
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import text

from . import audit, identity
from .identity import GROUP_RE, IdentityError, MAIL_RE, NAME_RE, UID_RE, Stack, _guard, _step, _users_row, load_stack
from .runtime import Runtime

ACTIONS = ("idm.user.set_aliases", "idm.shared_mailbox.create", "idm.shared_mailbox.delete", "idm.shared_mailbox.grant", "idm.shared_mailbox.revoke",
           "idm.user.set_mail_quota", "idm.user.set_storage_quota")
KINDS = ("full_access", "send_as", "send_on_behalf")
KIND_LABELS = {"full_access": "full access", "send_as": "send as", "send_on_behalf": "send on behalf"}
MAX_ALIASES = 20
MAX_MB = 10_000_000          # 10 TB; keeps KiB inside int32 (mbxspec.MAX_KB) and bytes inside int64


# ---- models -------------------------------------------------------------------------------------------------------------------------
def _addr(v: str) -> str:
    v = v.strip().lower()
    if not re.fullmatch(MAIL_RE, v) or len(v) > 254:
        raise ValueError("not a valid e-mail address")
    return v


class SetAliases(identity._UserRef):
    add: list[str] = Field(default_factory=list, max_length=MAX_ALIASES)
    remove: list[str] = Field(default_factory=list, max_length=MAX_ALIASES)

    _a = field_validator("add", "remove")(lambda cls, v: sorted({_addr(x) for x in v}))

    @model_validator(mode="after")
    def _chk(self) -> Self:
        if not self.add and not self.remove:
            raise ValueError("nothing to change")
        if set(self.add) & set(self.remove):
            raise ValueError("add and remove overlap")
        return self


class _Shared(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stack: str = Field(pattern=NAME_RE)
    name: str = Field(pattern=UID_RE, description="local part of the shared mailbox address")


class SharedCreate(_Shared):
    display_name: str = Field(min_length=1, max_length=100)

    @field_validator("display_name")
    @classmethod
    def _dn(cls, v: str) -> str:
        if not v.strip() or re.search(r"[\x00-\x1f\x7f<>]", v) or v != v.strip():
            raise ValueError("display_name must be non-empty printable text without leading/trailing spaces or < >")
        return v


class SharedDelete(_Shared):
    reason: str = Field(min_length=3, max_length=200)


class SharedAccess(_Shared):
    uid: str = Field(pattern=UID_RE, description="the user who gets (or loses) the right")
    kind: Literal["full_access", "send_as", "send_on_behalf"]


class SetMailQuota(identity._UserRef):
    limit_mb: int | None = Field(default=None, ge=1, le=MAX_MB, description="one number for the whole mailbox: warning, send and receive limit (None = unlimited)")
    send_mb: int | None = Field(default=None, ge=1, le=MAX_MB, description="override: refuse SENDING above this size")
    receive_mb: int | None = Field(default=None, ge=1, le=MAX_MB, description="override: refuse RECEIVING above this size")
    storage_mb: int | None = Field(default=None, ge=1, le=MAX_MB, description="override: refuse saving/moving mail above this size")

    @model_validator(mode="after")
    def _chk(self) -> Self:
        if self.limit_mb is None and (self.send_mb or self.receive_mb or self.storage_mb):
            raise ValueError("overrides need limit_mb")
        return self

    def effective(self) -> dict:
        if self.limit_mb is None:
            return {"send_kb": None, "receive_kb": None, "storage_kb": None}
        pick = lambda x: (x or self.limit_mb) * 1024  # noqa: E731
        return {"send_kb": pick(self.send_mb), "receive_kb": pick(self.receive_mb), "storage_kb": pick(self.storage_mb)}


class SetStorageQuota(identity._UserRef):
    quota_mb: int | None = Field(ge=1, le=MAX_MB, description="personal drive size limit; None = unlimited")


MODELS = {"idm.user.set_aliases": SetAliases, "idm.shared_mailbox.create": SharedCreate, "idm.shared_mailbox.delete": SharedDelete,
          "idm.shared_mailbox.grant": SharedAccess, "idm.shared_mailbox.revoke": SharedAccess, "idm.user.set_mail_quota": SetMailQuota,
          "idm.user.set_storage_quota": SetStorageQuota}


# ---- policy -------------------------------------------------------------------------------------------------------------------------
def alias_domains(cfg: dict) -> list[str]:
    return sorted({cfg["mail_domain"].lower(), *(d.lower() for d in cfg.get("alias_domains", []))})


def risk_for(db, action: str, p) -> str:
    return "high" if action == "idm.shared_mailbox.delete" else "normal"


def _customer_stacks(db, stack_row) -> list[str]:
    return [str(r.id) for r in db.execute(text("SELECT id FROM idm_stacks WHERE customer_id = :c"), {"c": str(stack_row.customer_id)}).all()]


def address_owner(db, stack_row, addr: str) -> str | None:
    """Who already uses this address anywhere in the customer (any of its stacks): 'user:<uid>', 'alias:<uid>', 'shared:<name>' or None.
    Deleted users / deleted shared mailboxes still count: their mailbox data is retained, so the address can never be reused."""
    ids = _customer_stacks(db, stack_row)
    r = db.execute(text("SELECT uid FROM idm_users WHERE stack_id = ANY(CAST(:s AS uuid[])) AND lower(mail) = :a LIMIT 1"), {"s": ids, "a": addr}).first()
    if r:
        return f"user:{r.uid}"
    r = db.execute(text("SELECT uid FROM idm_aliases WHERE stack_id = ANY(CAST(:s AS uuid[])) AND alias = :a LIMIT 1"), {"s": ids, "a": addr}).first()
    if r:
        return f"alias:{r.uid}"
    r = db.execute(text("SELECT name FROM idm_shared_mailboxes WHERE stack_id = ANY(CAST(:s AS uuid[])) AND lower(mail) = :a LIMIT 1"), {"s": ids, "a": addr}).first()
    return f"shared:{r.name}" if r else None


def _active_mail_user(db, stack_row, uid: str):
    row = _user_row_any(db, stack_row.id, uid)
    if row.state != "active" or stack_row.config["entitlement_group"] not in (row.groups or []):
        raise ValueError("this person is not active or has no mailbox")
    return row


def _user_row_any(db, stack_id, uid: str):
    row = db.execute(text("SELECT * FROM idm_users WHERE stack_id = :s AND uid = :u AND state <> 'deleted'"), {"s": str(stack_id), "u": uid}).first()
    if row is None:
        raise KeyError("user not found in this stack (not managed by the ICS or already deleted)")
    return row


def _shared_row(db, stack_id, name: str, active=True):
    row = db.execute(text("SELECT * FROM idm_shared_mailboxes WHERE stack_id = :s AND name = :n"), {"s": str(stack_id), "n": name}).first()
    if row is None or (active and row.state != "active"):
        raise KeyError("shared mailbox not found")
    return row


def current_aliases(db, stack_id, uid: str) -> list[str]:
    return [r.alias for r in db.execute(text("SELECT alias FROM idm_aliases WHERE stack_id = :s AND uid = :u ORDER BY alias"), {"s": str(stack_id), "u": uid}).all()]


def precheck(db, rt: Runtime, action: str, p) -> dict:
    row = identity._stack_row(db, p.stack)
    cfg = row.config
    if not cfg.get("gromox_node_id") and action != "idm.user.set_storage_quota":
        raise ValueError("this organisation has no mail server connected")
    if action == "idm.user.set_aliases":
        u = _active_mail_user(db, row, p.uid)
        have = set(current_aliases(db, row.id, p.uid))
        doms = alias_domains(cfg)
        if set(p.remove) - have:
            raise ValueError("cannot remove an address that is not an alias of this person: " + ", ".join(sorted(set(p.remove) - have)))
        new = set(p.add) - have
        for a in sorted(new):
            if a.split("@", 1)[1] not in doms:
                raise ValueError(f"{a}: the domain is not one of your verified domains ({', '.join(doms)})")
            who = address_owner(db, row, a)
            if who:
                raise LookupError(f"{a} is already in use ({who.split(':')[0]})")
        if len((have | new) - set(p.remove)) > MAX_ALIASES:
            raise ValueError(f"at most {MAX_ALIASES} aliases per person")
        return {"mail": u.mail, "aliases_after": sorted((have | new) - set(p.remove))}
    if action == "idm.shared_mailbox.create":
        addr = f"{p.name}@{cfg['mail_domain']}"
        if _user_row_any_or_none(db, row.id, p.name):
            raise LookupError("a person with this name exists")
        who = address_owner(db, row, addr)
        if who:
            raise LookupError(f"{addr} is already in use ({who.split(':')[0]}); addresses of deleted mailboxes are retained and cannot be reused")
        return {"mail": addr}
    if action in ("idm.shared_mailbox.delete", "idm.shared_mailbox.grant", "idm.shared_mailbox.revoke"):
        sm = _shared_row(db, row.id, p.name)
        if action == "idm.shared_mailbox.delete":
            return {"mail": sm.mail}
        _active_mail_user(db, row, p.uid) if action == "idm.shared_mailbox.grant" else _user_row_any(db, row.id, p.uid)
        has = db.execute(text("SELECT 1 FROM idm_shared_grants WHERE shared_id = :s AND uid = :u AND kind = :k"), {"s": str(sm.id), "u": p.uid, "k": p.kind}).first()
        if action == "idm.shared_mailbox.revoke" and not has:
            raise ValueError("this person does not have that right")
        return {"mail": sm.mail}
    if action == "idm.user.set_mail_quota":
        _active_mail_user(db, row, p.uid)
        return {"effective": p.effective()}
    if action == "idm.user.set_storage_quota":
        if not (cfg.get("oc_quota_user") and cfg.get("files_url")):
            raise ValueError("storage quotas are not set up for this organisation (no OpenCloud quota identity configured)")
        _user_row_any(db, row.id, p.uid)
        return {}
    raise ValueError("unknown action")


def _user_row_any_or_none(db, stack_id, uid):
    return db.execute(text("SELECT 1 FROM idm_users WHERE stack_id = :s AND uid = :u"), {"s": str(stack_id), "u": uid}).first()


# ---- OpenCloud: personal drive quota ----------------------------------------------------------------------------------------------
class OpenCloudQuota:
    """ONE dedicated directory user with the OpenCloud *Admin* role, used for exactly three Graph calls: list personal drives (quota + usage),
    PATCH a personal drive's quota.total, and read it back. Why Admin: OpenCloud's built-in roles are fixed; `Drives.ReadWriteQuota.Personal`
    (needed to change a PERSONAL space quota) is only part of the Admin role, Space Admin covers project spaces only (see results doc).
    The password sits in the stack's vault secrets; the token is obtained with the stack's direct-grant client and never stored."""

    def __init__(self, rt: Runtime, stack: Stack):
        c = stack.cfg
        if not (c.get("oc_quota_user") and stack.oc_pw and c.get("files_url") and c.get("probe_client_id")):
            raise IdentityError("storage quota identity is not configured for this stack")
        self.kc, self.realm, self.client = c["kc_url"].rstrip("/"), c["kc_realm"], c["probe_client_id"]
        self.files, self.user, self._pw = c["files_url"].rstrip("/"), c["oc_quota_user"], stack.oc_pw
        _guard(rt, urlparse(self.files).hostname)
        _guard(rt, urlparse(self.kc).hostname)
        ctx = ssl.create_default_context(cadata=c["identity_ca_pem"])
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.http = httpx.Client(verify=ctx, timeout=httpx.Timeout(15.0), follow_redirects=False, trust_env=False)
        self._tok = None

    def close(self) -> None:
        self.http.close()

    def _token(self) -> str:
        if self._tok:
            return self._tok
        try:
            r = self.http.post(f"{self.kc}/realms/{self.realm}/protocol/openid-connect/token",
                               data={"grant_type": "password", "client_id": self.client, "username": self.user, "password": self._pw, "scope": "openid"})
        except (httpx.HTTPError, ssl.SSLError, OSError) as e:
            raise IdentityError(f"sign-in service unreachable: {type(e).__name__}") from None
        if r.status_code != 200:
            raise IdentityError(f"the storage quota identity was refused by the sign-in service (HTTP {r.status_code})")
        self._tok = r.json()["access_token"]
        return self._tok

    def _req(self, method: str, path: str, **kw):
        try:
            r = self.http.request(method, f"{self.files}{path}", headers={"Authorization": f"Bearer {self._token()}", "Accept": "application/json"}, **kw)
        except (httpx.HTTPError, ssl.SSLError, OSError) as e:
            raise IdentityError(f"files service request failed: {type(e).__name__}") from None
        if r.status_code not in (200, 201, 204):
            raise IdentityError(f"files service refused {method} {path.split('?')[0].rsplit('/', 1)[0][:40]} (HTTP {r.status_code})")
        return r

    def personal_drives(self) -> dict[str, dict]:
        """entry_uuid (owner id) -> {drive_id, total, used}"""
        out: dict[str, dict] = {}
        r = self._req("GET", "/graph/v1.0/drives", params={"$filter": "driveType eq 'personal'"})
        for d in r.json().get("value", []):
            owner = (((d.get("owner") or {}).get("user")) or {}).get("id")
            q = d.get("quota") or {}
            if owner and d.get("id"):
                out[owner] = {"drive_id": d["id"], "total": int(q.get("total") or 0), "used": int(q.get("used") or 0)}
        return out

    def set_total(self, drive_id: str, total_bytes: int) -> None:
        if not re.fullmatch(r"[A-Za-z0-9$!._:=-]{1,200}", drive_id):
            raise IdentityError("unexpected drive id")
        from urllib.parse import quote
        self._req("PATCH", f"/graph/v1.0/drives/{quote(drive_id, safe='')}", json={"quota": {"total": int(total_bytes)}})


def _oc(rt, stack):   # indirection: tests replace it
    return OpenCloudQuota(rt, stack)


# ---- executors ----------------------------------------------------------------------------------------------------------------------
def _node(stack: Stack):
    nid = stack.cfg.get("gromox_node_id")
    if not nid:
        raise IdentityError("no mail server node is configured for this stack")
    return nid


def _known(stack: Stack) -> list[str]:
    return [stack.ldap_pw, stack.kc_secret, *([stack.mas_secret] if stack.mas_secret else []), *([stack.oc_pw] if stack.oc_pw else [])]


def _audit(rt, action, resource_id, **d):
    with rt.session() as s:
        audit.append(s, action, actor_name="worker", resource="idm_user", resource_id=str(resource_id) if resource_id else None, details=d)
        s.commit()


def exec_set_aliases(rt: Runtime, db, m: SetAliases, plan, known: list[str]) -> dict:
    stack = load_stack(rt, m.stack)
    known.extend(_known(stack))
    u = _users_row(rt, stack.id, m.uid)
    if u is None or u.state != "active":
        raise IdentityError("user is not active")
    with rt.session() as s:
        have = set(current_aliases(s, stack.id, m.uid))
    want = sorted((have | set(m.add)) - set(m.remove))
    t = time.monotonic()
    r = identity.agent_call(rt, _node(stack), "gromox.set_aliases", {"user": m.uid, "aliases": want}, known)
    if sorted(r.get("aliases", [])) != want:
        raise IdentityError("the mail server did not store the aliases as requested")
    with rt.session() as s:
        for a in sorted(set(m.remove) & have):
            s.execute(text("DELETE FROM idm_aliases WHERE stack_id = :s AND alias = :a"), {"s": stack.id, "a": a})
        for a in sorted(set(want) - have):
            s.execute(text("INSERT INTO idm_aliases (stack_id, uid, alias) VALUES (:s, :u, :a)"), {"s": stack.id, "u": m.uid, "a": a})
        audit.append(s, "identity.aliases_changed", actor_name="worker", resource="idm_user", resource_id=str(u.id),
                     details={"uid": m.uid, "add": m.add, "remove": m.remove, "aliases": want})
        s.commit()
    steps: list = []
    _step(steps, "gromox.set_aliases", t, aliases=want)
    return {"uid": m.uid, "aliases": want, "steps": steps}


def exec_shared_create(rt: Runtime, db, m: SharedCreate, plan, known: list[str]) -> dict:
    stack = load_stack(rt, m.stack)
    known.extend(_known(stack))
    t = time.monotonic()
    r = identity.agent_call(rt, _node(stack), "gromox.shared_create", {"name": m.name, "display_name": m.display_name}, known)
    mail = f"{m.name}@{stack.mail_domain}"
    if r.get("mail") != mail or r.get("address_status") != 4:
        raise IdentityError("the mail server did not create the shared mailbox as requested")
    with rt.session() as s:
        sid = s.execute(text("INSERT INTO idm_shared_mailboxes (stack_id, name, mail, display_name, created_by) VALUES (:s, :n, :m, :d, :c) RETURNING id"),
                        {"s": stack.id, "n": m.name, "m": mail, "d": m.display_name, "c": str(plan.requested_by)}).scalar()
        audit.append(s, "identity.shared_mailbox_created", actor_name="worker", resource="idm_shared_mailbox", resource_id=str(sid),
                     details={"stack": stack.name, "name": m.name, "mail": mail})
        s.commit()
    steps: list = []
    _step(steps, "gromox.shared_create", t, mail=mail)
    return {"name": m.name, "mail": mail, "steps": steps}


def exec_shared_delete(rt: Runtime, db, m: SharedDelete, plan, known: list[str]) -> dict:
    stack = load_stack(rt, m.stack)
    known.extend(_known(stack))
    with rt.session() as s:
        sm = _shared_row(s, stack.id, m.name)
    t = time.monotonic()
    r = identity.agent_call(rt, _node(stack), "gromox.shared_delete", {"name": m.name}, known)
    if not r.get("suspended"):
        raise IdentityError("the mail server did not suspend the shared mailbox")
    with rt.session() as s:
        s.execute(text("DELETE FROM idm_shared_grants WHERE shared_id = :i"), {"i": str(sm.id)})
        s.execute(text("UPDATE idm_shared_mailboxes SET state = 'deleted', deleted_at = now() WHERE id = :i"), {"i": str(sm.id)})
        audit.append(s, "identity.shared_mailbox_deleted", actor_name="worker", resource="idm_shared_mailbox", resource_id=str(sm.id),
                     details={"stack": stack.name, "name": m.name, "reason": m.reason, "data_retained": True})
        s.commit()
    steps: list = []
    _step(steps, "gromox.shared_delete", t, data_retained=True)
    return {"name": m.name, "state": "deleted", "data_retained": True, "steps": steps}


def _exec_access(rt: Runtime, m: SharedAccess, known: list[str], grant: bool) -> dict:
    stack = load_stack(rt, m.stack)
    known.extend(_known(stack))
    with rt.session() as s:
        sm = _shared_row(s, stack.id, m.name)
    t = time.monotonic()
    r = identity.agent_call(rt, _node(stack), "gromox.shared_access", {"name": m.name, "user": m.uid, "kind": m.kind, "grant": grant}, known)
    addr = f"{m.uid}@{stack.mail_domain}"
    listed = addr in [x.lower() for x in (r.get("members") or {}).get(m.kind, [])]
    if listed != grant:
        raise IdentityError("the mail server did not apply the change")
    with rt.session() as s:
        if grant:
            s.execute(text("INSERT INTO idm_shared_grants (shared_id, uid, kind) VALUES (:i, :u, :k) ON CONFLICT DO NOTHING"), {"i": str(sm.id), "u": m.uid, "k": m.kind})
        else:
            s.execute(text("DELETE FROM idm_shared_grants WHERE shared_id = :i AND uid = :u AND kind = :k"), {"i": str(sm.id), "u": m.uid, "k": m.kind})
        audit.append(s, "identity.shared_mailbox_granted" if grant else "identity.shared_mailbox_revoked", actor_name="worker", resource="idm_shared_mailbox",
                     resource_id=str(sm.id), details={"stack": stack.name, "name": m.name, "uid": m.uid, "kind": m.kind})
        s.commit()
    steps: list = []
    _step(steps, "gromox.shared_access", t, kind=m.kind, granted=grant)
    return {"name": m.name, "uid": m.uid, "kind": m.kind, "granted": grant, "steps": steps}


def exec_shared_grant(rt, db, m, plan, known):
    return _exec_access(rt, m, known, True)


def exec_shared_revoke(rt, db, m, plan, known):
    return _exec_access(rt, m, known, False)


def exec_set_mail_quota(rt: Runtime, db, m: SetMailQuota, plan, known: list[str]) -> dict:
    stack = load_stack(rt, m.stack)
    known.extend(_known(stack))
    u = _users_row(rt, stack.id, m.uid)
    if u is None or u.state != "active":
        raise IdentityError("user is not active")
    want = m.effective()
    t = time.monotonic()
    r = identity.agent_call(rt, _node(stack), "gromox.set_quota", {"user": m.uid, **want}, known)
    if any(r.get(k) != v for k, v in want.items()):
        raise IdentityError("the mail server did not store the quota as requested")
    with rt.session() as s:
        s.execute(text("INSERT INTO idm_quotas (stack_id, uid, mail_send_kb, mail_receive_kb, mail_storage_kb) VALUES (:s, :u, :a, :b, :c) "
                       "ON CONFLICT (stack_id, uid) DO UPDATE SET mail_send_kb = :a, mail_receive_kb = :b, mail_storage_kb = :c, updated_at = now()"),
                  {"s": stack.id, "u": m.uid, "a": want["send_kb"], "b": want["receive_kb"], "c": want["storage_kb"]})
        audit.append(s, "identity.mail_quota_set", actor_name="worker", resource="idm_user", resource_id=str(u.id), details={"uid": m.uid, **want})
        s.commit()
    steps: list = []
    _step(steps, "gromox.set_quota", t, **want)
    return {"uid": m.uid, **want, "steps": steps}


def exec_set_storage_quota(rt: Runtime, db, m: SetStorageQuota, plan, known: list[str]) -> dict:
    stack = load_stack(rt, m.stack)
    known.extend(_known(stack))
    u = _users_row(rt, stack.id, m.uid)
    if u is None or u.state != "active":
        raise IdentityError("user is not active")
    total = (m.quota_mb or 0) * 1024 * 1024
    steps: list = []
    oc = _oc(rt, stack)
    try:
        t = time.monotonic()
        d = oc.personal_drives().get(u.entry_uuid)
        if d is None:
            raise IdentityError("the person has no personal drive yet (it is created at their first sign-in to the files service)")
        oc.set_total(d["drive_id"], total)
        after = oc.personal_drives().get(u.entry_uuid) or {}
        if after.get("total") != total:
            raise IdentityError("the files service did not store the quota as requested")
        _step(steps, "opencloud.set_quota", t, total_bytes=total)
    finally:
        oc.close()
    with rt.session() as s:
        s.execute(text("INSERT INTO idm_quotas (stack_id, uid, files_quota_bytes) VALUES (:s, :u, :q) "
                       "ON CONFLICT (stack_id, uid) DO UPDATE SET files_quota_bytes = :q, updated_at = now()"), {"s": stack.id, "u": m.uid, "q": total})
        audit.append(s, "identity.storage_quota_set", actor_name="worker", resource="idm_user", resource_id=str(u.id), details={"uid": m.uid, "total_bytes": total})
        s.commit()
    return {"uid": m.uid, "total_bytes": total, "steps": steps}


EXECUTORS = {"idm.user.set_aliases": exec_set_aliases, "idm.shared_mailbox.create": exec_shared_create, "idm.shared_mailbox.delete": exec_shared_delete,
             "idm.shared_mailbox.grant": exec_shared_grant, "idm.shared_mailbox.revoke": exec_shared_revoke,
             "idm.user.set_mail_quota": exec_set_mail_quota, "idm.user.set_storage_quota": exec_set_storage_quota}


# ---- read side (portal): usage ----------------------------------------------------------------------------------------------------
def usage(rt: Runtime, stack_name: str, users: list[tuple[str, str]]) -> dict:
    """users = [(uid, entry_uuid)]. Returns {uid: {"mail": {...}|None, "files": {...}|None}} and per-source availability. Never raises: a source that
    cannot be read is reported as unavailable so the page still renders."""
    stack = load_stack(rt, stack_name)
    out = {uid: {"mail": None, "files": None} for uid, _ in users}
    avail = {"mail": False, "files": False}
    nid = stack.cfg.get("gromox_node_id")
    if nid and users:
        try:
            for i in range(0, len(users), 100):
                r = identity.agent_call(rt, nid, "gromox.mail_usage", {"users": [u for u, _ in users[i:i + 100]]}, [])
                for uid, v in (r.get("usage") or {}).items():
                    if uid in out:
                        out[uid]["mail"] = v
            avail["mail"] = True
        except (IdentityError, identity.AgentError):
            pass
    if stack.cfg.get("oc_quota_user") and stack.oc_pw and users:
        oc = None
        try:
            oc = _oc(rt, stack)
            drives = oc.personal_drives()
            for uid, eid in users:
                if eid in drives:
                    out[uid]["files"] = {"total_bytes": drives[eid]["total"], "used_bytes": drives[eid]["used"]}
            avail["files"] = True
        except IdentityError:
            pass
        finally:
            if oc:
                oc.close()
    return {"users": out, "available": avail}
