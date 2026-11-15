"""User lifecycle for one customer stack: OpenLDAP (source of truth) -> Keycloak (SSO) -> Gromox (mailbox) -> OpenCloud (files).

Everything is a typed action (see CATALOG in actions.py): idm.stack.register, idm.user.create / update_groups / disable / enable / delete, idm.reconcile.
Credentials: the stack's LDAP bind password and Keycloak client secret live in the vault (AAD bound to stack id + config hash); they are the
narrowly scoped service identities `cn=svc-ics` (write only under ou=people / `member` of ou=groups, cannot read userPassword) and the Keycloak
client `ou-ics` (service account with realm-management manage-users/view-users/query-clients only). Gromox and OpenCloud are driven through the
signed node agent with fixed, allowlisted runbooks (gromox.sync_user / kick_user / user_state, opencloud.check_user): no shell, no free-form argv.
Audit/job results never contain a credential. Initial passwords do not exist: the creator receives a one-time enrollment token (see `reveal`).
"""
import hashlib
import hmac
import json
import logging
import re
import secrets
import ssl
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal, Self
from uuid import UUID

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from sqlalchemy import text

from . import agentclient, audit, idprobe
from .agentclient import AgentError
from .proxmox import ProxmoxError, check_destination
from .runtime import Runtime
from .vault import VaultError

log = logging.getLogger("ics.identity")

UID_RE = r"^[a-z][a-z0-9._-]{1,31}$"
GROUP_RE = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
NAME_RE = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$"
HOST_RE = r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$"
MAIL_RE = r"^[a-z0-9][a-z0-9._-]{0,63}@[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$"
DN_RE = r"^[A-Za-z0-9=,._ -]{3,200}$"
TARGET_SECONDS = 60          # acceptance target: every credential path refused within this many seconds after the lock
LOCK_VALUE = "000001010000Z"  # ppolicy permanent lock (same value the lab's ldap-user.sh uses)
STATES = ("active", "disabled", "deleted")


class IdentityError(Exception):
    """Message is safe to store and show (no credentials, no transport text)."""


ACTIONS = ("idm.stack.register", "idm.user.create", "idm.user.update_groups", "idm.user.disable", "idm.user.enable", "idm.user.delete",
           "idm.reconcile", "idm.user.devices", "idm.user.set_extension", "idm.user.issue_sip_credential")
EXT_RE = r"^[1-9][0-9]{3}$"            # 4-digit internal extension = LDAP telephoneNumber (same rule as the PBX provisioner)
SIP_DEVICES = ("web", "native", "desk")
SIP_CRED_TTL = 900                     # seconds an unrevealed SIP credential stays decryptable at the ICS


# ---- typed parameters --------------------------------------------------------------------------------------------------------------------
def _pem(v: str | None) -> str | None:
    if v is None:
        return v
    from cryptography import x509
    try:
        if not x509.load_pem_x509_certificates(v.encode()):
            raise ValueError
    except Exception:  # noqa: BLE001
        raise ValueError("must contain valid PEM certificate(s)") from None
    return v


def _secret(v):
    raw = v.get_secret_value() if isinstance(v, SecretStr) else v
    if not isinstance(raw, str) or not re.fullmatch(r"[\x21-\x7e]{8,200}", raw.strip()):
        raise ValueError("secret must be 8-200 printable ASCII characters without whitespace")
    return raw.strip()


class StackRegister(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=NAME_RE, description="customer stack name")
    ldap_url: str = Field(description="ldaps://host[:port] (TLS verified against ca_pem)")
    ldap_bind_dn: str = Field(pattern=DN_RE, description="the narrow ICS service account, e.g. cn=svc-ics,ou=system,dc=...")
    ldap_bind_password: SecretStr
    ldap_people_dn: str = Field(pattern=DN_RE)
    ldap_groups_dn: str = Field(pattern=DN_RE)
    mail_domain: str = Field(pattern=HOST_RE)
    entitlement_group: str = Field(default="mail-users", pattern=GROUP_RE, description="group that entitles a user to a mailbox")
    allowed_groups: list[str] = Field(min_length=1, max_length=50, description="groups the ICS may add/remove users to")
    privileged_groups: list[str] = Field(default_factory=list, max_length=50, description="subset of allowed_groups: changing membership is HIGH risk (2 approvers)")
    kc_url: str = Field(description="https://keycloak host")
    kc_realm: str = Field(pattern=NAME_RE)
    kc_client_id: str = Field(pattern=NAME_RE)
    kc_client_secret: SecretStr
    kc_offline_clients: list[str] = Field(default_factory=list, max_length=20, description="clientIds that may hold offline tokens for users")
    identity_ca_pem: str = Field(max_length=100_000, description="CA for LDAP, Keycloak and the files host")
    files_url: str | None = Field(default=None, description="https://opencloud host (WebDAV/Graph probes)")
    files_node_id: UUID | None = Field(default=None, description="enrolled node whose agent offers opencloud.check_user")
    gromox_node_id: UUID | None = Field(default=None, description="enrolled node whose agent offers gromox.* runbooks")
    mail_host: str | None = Field(default=None, pattern=HOST_RE)
    mail_ca_pem: str | None = Field(default=None, max_length=100_000)
    probe_client_id: str | None = Field(default=None, pattern=NAME_RE, description="public Keycloak client with direct grants used ONLY by the VERIFY probes")
    mas_url: str | None = Field(default=None, description="https://matrix-authentication-service host (admin API); enables the Matrix downstream")
    mas_client_id: str | None = Field(default=None, pattern=NAME_RE, description="MAS OAuth2 client (client credentials, scope urn:mas:admin) dedicated to the ICS")
    mas_client_secret: SecretStr | None = None
    pbx_node_id: UUID | None = Field(default=None, description="enrolled node (the PBX) whose agent offers the pbx.* runbooks; enables the telephony downstream")
    pbx_domain: str | None = Field(default=None, pattern=HOST_RE, description="SIP domain shown to users with their one-time credential")
    reconcile_interval_seconds: int = Field(default=900, ge=0, le=86400, description="0 disables the periodic reconcile")

    _s1 = field_validator("ldap_bind_password", "kc_client_secret", mode="before")(lambda cls, v: _secret(v))
    _s2 = field_validator("mas_client_secret", mode="before")(lambda cls, v: None if v is None else _secret(v))
    _p1 = field_validator("identity_ca_pem", "mail_ca_pem")(lambda cls, v: _pem(v))

    @field_validator("ldap_url")
    @classmethod
    def _ldaps(cls, v: str) -> str:
        m = re.fullmatch(r"ldaps://([A-Za-z0-9.-]{1,253})(:(\d{1,5}))?", v)
        if not m or (m.group(3) and not 1 <= int(m.group(3)) <= 65535):
            raise ValueError("ldap_url must be ldaps://host[:port]")
        return v

    @field_validator("kc_url", "files_url", "mas_url")
    @classmethod
    def _https(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not re.fullmatch(r"https://[A-Za-z0-9.-]{1,253}(:\d{1,5})?", v):
            raise ValueError("must be https://host[:port] (no path, no credentials)")
        return v

    @field_validator("allowed_groups", "privileged_groups", "kc_offline_clients")
    @classmethod
    def _groups(cls, v: list[str]) -> list[str]:
        for g in v:
            if not re.fullmatch(GROUP_RE, g):
                raise ValueError("invalid group/client name")
        return sorted(set(v))

    @model_validator(mode="after")
    def _chk(self) -> Self:
        if not set(self.privileged_groups) <= set(self.allowed_groups):
            raise ValueError("privileged_groups must be a subset of allowed_groups")
        if self.entitlement_group not in self.allowed_groups:
            raise ValueError("entitlement_group must be in allowed_groups")
        if self.gromox_node_id and not (self.mail_host and self.mail_ca_pem):
            raise ValueError("gromox_node_id needs mail_host and mail_ca_pem")
        if bool(self.mas_url) != bool(self.mas_client_id) or bool(self.mas_url) != bool(self.mas_client_secret):
            raise ValueError("mas_url, mas_client_id and mas_client_secret must be given together")
        if bool(self.pbx_node_id) != bool(self.pbx_domain):
            raise ValueError("pbx_node_id and pbx_domain must be given together")
        if self.probe_client_id and not (self.mail_host or self.files_url):
            raise ValueError("probe_client_id needs mail_host and/or files_url")
        return self


class _UserRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stack: str = Field(pattern=NAME_RE)
    uid: str = Field(pattern=UID_RE)


def _groups(v: list[str]) -> list[str]:
    for g in v:
        if not re.fullmatch(GROUP_RE, g):
            raise ValueError("invalid group name")
    return sorted(set(v))


class UserCreate(_UserRef):
    display_name: str = Field(min_length=1, max_length=100)
    mail: str = Field(pattern=MAIL_RE, max_length=254)
    groups: list[str] = Field(default_factory=list, max_length=20)
    mailbox: bool = Field(default=True, description="entitle to a Gromox mailbox (adds the stack's entitlement group)")
    extension: str | None = Field(default=None, pattern=EXT_RE, description="4-digit PBX extension (LDAP telephoneNumber); needs a stack with a PBX node")

    _g = field_validator("groups")(lambda cls, v: _groups(v))

    @field_validator("display_name")
    @classmethod
    def _dn(cls, v: str) -> str:
        if not v.strip() or re.search(r"[\x00-\x1f\x7f]", v) or v != v.strip():
            raise ValueError("display_name must be non-empty printable text without leading/trailing spaces")
        return v

    @model_validator(mode="after")
    def _local(self) -> Self:
        if self.mail.split("@", 1)[0] != self.uid:
            raise ValueError("policy: the mail local part must equal the uid (the Gromox runbooks map uid -> uid@domain)")
        return self


class UserUpdateGroups(_UserRef):
    add: list[str] = Field(default_factory=list, max_length=20)
    remove: list[str] = Field(default_factory=list, max_length=20)

    _g = field_validator("add", "remove")(lambda cls, v: _groups(v))

    @model_validator(mode="after")
    def _chk(self) -> Self:
        if not self.add and not self.remove:
            raise ValueError("nothing to change")
        if set(self.add) & set(self.remove):
            raise ValueError("add and remove overlap")
        return self


class UserSetExtension(_UserRef):
    extension: str | None = Field(pattern=EXT_RE, description="new 4-digit extension, or null to remove it (the PBX purges the user's devices and credentials)")


class IssueSipCredential(_UserRef):
    device: Literal["web", "native", "desk"] = Field(description="device class; re-issuing rotates that device's credential (the old one stops working)")


class UserDisable(_UserRef):
    rotate_credentials: bool = Field(default=True, description="replace the password with a random one known only to the VERIFY step (enables active probes with a baseline)")
    verify_timeout_seconds: int = Field(default=45, ge=5, le=75)
    reason: str = Field(default="", max_length=200)
    wipe_devices: bool = Field(default=False, description="request an ActiveSync remote wipe for ALL of the user's devices BEFORE the account is suspended "
                               "(destructive: plan risk is high, two approvers). A device can only receive it while it can still authenticate")
    wipe_wait_seconds: int = Field(default=0, ge=0, le=300, description="how long to wait (before the lock) for devices to pick the wipe up; 0 = request only")

    @model_validator(mode="after")
    def _wipe(self) -> Self:
        if self.wipe_wait_seconds and not self.wipe_devices:
            raise ValueError("wipe_wait_seconds needs wipe_devices")
        return self


class UserDevices(_UserRef):
    """Read only: the user's ActiveSync devices with wipe status and acknowledgement history."""


class UserEnable(_UserRef):
    reason: str = Field(default="", max_length=200)


class UserDelete(_UserRef):
    reason: str = Field(min_length=3, max_length=200, description="mandatory: why; mailbox data is RETAINED (no purge action exists)")


class Reconcile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stack: str = Field(pattern=NAME_RE)


# ---- stack loading -----------------------------------------------------------------------------------------------------------------
def _cfg_hash(cfg: dict) -> str:
    return hashlib.sha256(audit.canon(cfg).encode()).hexdigest()


def stack_aad(stack_id, cfg: dict) -> str:
    return f"idm-stack:{stack_id}:{_cfg_hash(cfg)}"


class Stack:
    def __init__(self, row, secrets_: dict):
        self.id, self.name, self.cfg = str(row.id), row.name, dict(row.config)
        self.ldap_pw, self.kc_secret = secrets_["ldap_bind_password"], secrets_["kc_client_secret"]
        self.mas_secret = secrets_.get("mas_client_secret")

    @property
    def mail_domain(self) -> str:
        return self.cfg["mail_domain"]


def load_stack(rt: Runtime, name: str) -> Stack:
    with rt.session() as db:
        row = db.execute(text("SELECT * FROM idm_stacks WHERE name = :n"), {"n": name}).first()
    if row is None:
        raise IdentityError("stack not found")
    try:
        sec = json.loads(rt.vault.decrypt(row.secret_enc, stack_aad(row.id, row.config)))
    except (VaultError, ValueError):
        raise IdentityError("stack credentials cannot be decrypted (configuration changed or wrong vault key)") from None
    return Stack(row, sec)


def _guard(rt: Runtime, host: str) -> None:
    try:
        check_destination(host, rt.settings.allow_loopback_endpoints)
    except ProxmoxError as e:
        raise IdentityError(str(e)) from None


# ---- LDAP --------------------------------------------------------------------------------------------------------------------------
LOCKED_OK = "0"


class Directory:
    """The only code that talks LDAP. ldaps:// with certificate AND hostname verification against the stack CA, bound as the narrow service account."""

    def __init__(self, rt: Runtime, stack: Stack):
        import ldap3
        from urllib.parse import urlparse
        u = urlparse(stack.cfg["ldap_url"])
        self.host, self.port = u.hostname, u.port or 636
        _guard(rt, self.host)
        self._ldap3 = ldap3
        self.people, self.groups_dn = stack.cfg["ldap_people_dn"], stack.cfg["ldap_groups_dn"]
        self.bind_dn, self._pw, self._ca = stack.cfg["ldap_bind_dn"], stack.ldap_pw, stack.cfg["identity_ca_pem"]
        self.conn = self._connect(self.bind_dn, self._pw)

    def _server(self):
        l3 = self._ldap3
        tls = l3.Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLS_CLIENT, ca_certs_data=self._ca, valid_names=[self.host])
        return l3.Server(self.host, port=self.port, use_ssl=True, tls=tls, connect_timeout=8, get_info=l3.NONE)

    def _connect(self, dn: str, pw: str):
        try:
            return self._ldap3.Connection(self._server(), user=dn, password=pw, auto_bind=True, receive_timeout=15, raise_exceptions=True)
        except self._ldap3.core.exceptions.LDAPBindError:
            raise IdentityError("LDAP bind refused (service account credentials)") from None
        except Exception as e:  # noqa: BLE001
            raise IdentityError(f"LDAP unreachable or untrusted: {type(e).__name__}") from None

    def close(self) -> None:
        try:
            self.conn.unbind()
        except Exception:  # noqa: BLE001
            pass

    def dn(self, uid: str) -> str:
        if not re.fullmatch(UID_RE, uid):
            raise IdentityError("invalid uid")
        return f"uid={uid},{self.people}"

    @staticmethod
    def _s(entry, attr: str) -> list[str]:
        return [v.decode("utf-8", "replace") for v in entry.get("raw_attributes", {}).get(attr, [])]

    def _entry(self, e) -> dict:
        a = {k: self._s(e, k) for k in ("uid", "mail", "displayName", "cn", "entryUUID", "pwdAccountLockedTime", "telephoneNumber")}
        return {"dn": e["dn"], "uid": (a["uid"] or [""])[0], "mail": (a["mail"] or [""])[0].lower(), "extension": (a["telephoneNumber"] or [None])[0],
                "display_name": (a["displayName"] or a["cn"] or [""])[0], "entry_uuid": (a["entryUUID"] or [""])[0],
                "locked": bool(a["pwdAccountLockedTime"])}

    _ATTRS = ["uid", "mail", "displayName", "cn", "entryUUID", "pwdAccountLockedTime", "telephoneNumber"]

    def _search(self, base, flt, attrs, scope=None):
        l3 = self._ldap3
        try:
            self.conn.search(base, flt, search_scope=scope or l3.SUBTREE, attributes=attrs)
        except l3.core.exceptions.LDAPNoSuchObjectResult:
            return []
        except Exception as e:  # noqa: BLE001
            raise IdentityError(f"LDAP search failed: {type(e).__name__}") from None
        return [r for r in self.conn.response if r.get("type") == "searchResEntry"]

    def groups_of(self, dn: str) -> list[str]:
        from ldap3.utils.conv import escape_filter_chars
        rows = self._search(self.groups_dn, f"(&(objectClass=groupOfNames)(member={escape_filter_chars(dn)}))", ["cn"], self._ldap3.LEVEL)
        return sorted(self._s(r, "cn")[0] for r in rows if self._s(r, "cn"))

    def get(self, uid: str) -> dict | None:
        from ldap3.utils.conv import escape_filter_chars
        rows = self._search(self.people, f"(&(objectClass=inetOrgPerson)(uid={escape_filter_chars(uid)}))", self._ATTRS, self._ldap3.LEVEL)
        if not rows:
            return None
        if len(rows) > 1:
            raise IdentityError("uid is not unique in the directory")
        d = self._entry(rows[0])
        d["groups"] = self.groups_of(d["dn"])
        return d

    def list_people(self) -> list[dict]:
        out = []
        for r in self._search(self.people, "(objectClass=inetOrgPerson)", self._ATTRS, self._ldap3.LEVEL):
            d = self._entry(r)
            d["groups"] = self.groups_of(d["dn"])
            out.append(d)
        return out

    def _do(self, what: str, fn):
        try:
            ok = fn()
        except Exception as e:  # noqa: BLE001
            raise IdentityError(f"LDAP {what} failed: {type(e).__name__}") from None
        if not ok:
            raise IdentityError(f"LDAP {what} refused: {self.conn.result.get('description', 'error')}")

    def add(self, uid: str, display_name: str, mail: str, extension: str | None = None) -> None:
        parts = display_name.split()
        attrs = {"uid": uid, "cn": display_name, "displayName": display_name, "sn": parts[-1] if len(parts) > 1 else display_name,
                 "givenName": parts[0], "mail": mail}
        if extension:
            if not re.fullmatch(EXT_RE, extension):
                raise IdentityError("invalid extension")
            attrs["telephoneNumber"] = extension
        self._do("add", lambda: self.conn.add(self.dn(uid), ["inetOrgPerson", "organizationalPerson", "person", "top"], attrs))

    def set_extension(self, uid: str, extension: str | None) -> None:
        """telephoneNumber is the ONLY telephony attribute the ICS writes (the svc-ics ACL covers ou=people); None clears it."""
        if extension is not None and not re.fullmatch(EXT_RE, extension):
            raise IdentityError("invalid extension")
        self._do("set extension", lambda: self.conn.modify(self.dn(uid), {"telephoneNumber": [(self._ldap3.MODIFY_REPLACE, [extension] if extension else [])]}))

    def extension_owner(self, extension: str) -> str | None:
        rows = self._search(self.people, f"(&(objectClass=inetOrgPerson)(telephoneNumber={extension}))", ["uid"], self._ldap3.LEVEL)
        return (self._s(rows[0], "uid") or [None])[0] if rows else None

    def set_password(self, uid: str, password: str) -> None:
        self._do("set password", lambda: self.conn.modify(self.dn(uid), {"userPassword": [(self._ldap3.MODIFY_REPLACE, [password])]}))

    def lock(self, uid: str) -> None:
        self._do("lock", lambda: self.conn.modify(self.dn(uid), {"pwdAccountLockedTime": [(self._ldap3.MODIFY_REPLACE, [LOCK_VALUE])]}))

    def unlock(self, uid: str) -> None:
        try:  # a password change already clears a ppolicy lock: "no such attribute" then means "already unlocked"
            self.conn.modify(self.dn(uid), {"pwdAccountLockedTime": [(self._ldap3.MODIFY_DELETE, [])]})
        except self._ldap3.core.exceptions.LDAPNoSuchAttributeResult:
            return
        except Exception as e:  # noqa: BLE001
            raise IdentityError(f"LDAP unlock failed: {type(e).__name__}") from None

    def member(self, group: str, uid: str, add: bool) -> None:
        if not re.fullmatch(GROUP_RE, group):
            raise IdentityError("invalid group")
        gdn = f"cn={group},{self.groups_dn}"
        mode = self._ldap3.MODIFY_ADD if add else self._ldap3.MODIFY_DELETE
        ex = self._ldap3.core.exceptions
        try:
            self.conn.modify(gdn, {"member": [(mode, [self.dn(uid)])]})
        except (ex.LDAPAttributeOrValueExistsResult, ex.LDAPNoSuchAttributeResult):
            return  # already (not) a member: idempotent
        except Exception as e:  # noqa: BLE001
            raise IdentityError(f"LDAP group change failed: {type(e).__name__}") from None

    def delete(self, uid: str) -> None:
        self._do("delete", lambda: self.conn.delete(self.dn(uid)))

    def can_bind(self, uid: str, password: str) -> bool | None:
        """True = the directory accepts this credential, False = refused (bad credentials / locked), None = inconclusive."""
        try:
            c = self._ldap3.Connection(self._server(), user=self.dn(uid), password=password, auto_bind=True, receive_timeout=10, raise_exceptions=True)
            c.unbind()
            return True
        except (self._ldap3.core.exceptions.LDAPBindError, self._ldap3.core.exceptions.LDAPInvalidCredentialsResult):
            return False
        except Exception:  # noqa: BLE001
            return None


# ---- Keycloak ----------------------------------------------------------------------------------------------------------------------
class Keycloak:
    """Service-account client (client credentials). Needs only realm-management manage-users, view-users, query-clients."""

    def __init__(self, rt: Runtime, stack: Stack):
        c = stack.cfg
        from urllib.parse import urlparse
        _guard(rt, urlparse(c["kc_url"]).hostname)
        self.base, self.realm = c["kc_url"].rstrip("/"), c["kc_realm"]
        self.client_id, self._secret = c["kc_client_id"], stack.kc_secret
        self.offline_clients = c.get("kc_offline_clients", [])
        ctx = ssl.create_default_context(cadata=c["identity_ca_pem"])
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.http = httpx.Client(verify=ctx, timeout=httpx.Timeout(10.0), follow_redirects=False, trust_env=False)
        self._tok, self._exp = None, 0.0

    def close(self) -> None:
        self.http.close()

    def _token(self) -> str:
        if self._tok and time.monotonic() < self._exp:
            return self._tok
        try:
            r = self.http.post(f"{self.base}/realms/{self.realm}/protocol/openid-connect/token",
                               data={"grant_type": "client_credentials", "client_id": self.client_id, "client_secret": self._secret})
        except (httpx.HTTPError, ssl.SSLError, OSError) as e:
            raise IdentityError(f"Keycloak unreachable or untrusted: {type(e).__name__}") from None
        if r.status_code != 200:
            raise IdentityError(f"Keycloak service-account login refused (HTTP {r.status_code})")
        j = r.json()
        self._tok, self._exp = j["access_token"], time.monotonic() + max(10, int(j.get("expires_in", 60)) - 15)
        return self._tok

    def req(self, method: str, path: str, ok=(200, 204), **kw):
        try:
            r = self.http.request(method, f"{self.base}/admin/realms/{self.realm}{path}", headers={"Authorization": f"Bearer {self._token()}"}, **kw)
        except (httpx.HTTPError, ssl.SSLError, OSError) as e:
            raise IdentityError(f"Keycloak request failed: {type(e).__name__}") from None
        if r.status_code not in ok:
            raise IdentityError(f"Keycloak {method} {path.split('?')[0].rsplit('/', 1)[-1] if '/' in path else path} refused: HTTP {r.status_code}")
        return r

    def find(self, uid: str) -> dict | None:
        r = self.req("GET", "/users", params={"username": uid, "exact": "true"})
        return r.json()[0] if r.json() else None

    # attributes that carry the mailbox identity: gromox maps a session to a mailbox ONLY by the token's email claim (security review 4, M4)
    PROFILE_LOCKED = ("email", "username")

    def profile_check(self) -> list[dict]:
        """Reconcile finding(s) if the realm user profile lets users edit email/username (read-only call; the existing ICS role set manage-users+view-users+query-clients is enough, verified live)."""
        try:
            attrs = {a.get("name"): a for a in self.req("GET", "/users/profile").json().get("attributes", [])}
        except IdentityError as e:
            return [{"uid": "(realm)", "kind": "kc_profile_check_failed", "system": "keycloak", "severity": "warning", "detail": str(e)[:200]}]
        out = []
        for name in self.PROFILE_LOCKED:
            a = attrs.get(name)
            if a is None:
                out.append({"uid": "(realm)", "kind": "kc_profile_attribute_missing", "system": "keycloak", "severity": "warning",
                            "detail": f"user profile has no '{name}' attribute (cannot verify it is admin-edit-only)"})
                continue
            editors = sorted(set((a.get("permissions") or {}).get("edit") or []) - {"admin"})
            if editors:
                out.append({"uid": "(realm)", "kind": "kc_profile_user_editable", "system": "keycloak", "severity": "critical",
                            "detail": f"'{name}' is editable by {','.join(editors)}: a user could take over another mailbox (fix: kc-profile-harden.py apply)"})
        return out

    def set_enabled(self, user: dict, enabled: bool) -> None:
        full = self.req("GET", f"/users/{user['id']}").json()
        full["enabled"] = enabled
        self.req("PUT", f"/users/{user['id']}", json=full)

    def logout(self, kid: str) -> None:
        self.req("POST", f"/users/{kid}/logout")

    def sessions(self, kid: str) -> int:
        return len(self.req("GET", f"/users/{kid}/sessions").json())

    def consent_clients(self, kid: str) -> list[str]:
        return [c["clientId"] for c in self.req("GET", f"/users/{kid}/consents").json()]

    def revoke_consent(self, kid: str, client_id: str) -> None:
        self.req("DELETE", f"/users/{kid}/consents/{client_id}", ok=(200, 204, 404))

    def offline_sessions(self, kid: str, extra_clients=()) -> int:
        n = 0
        for cid in sorted(set(self.offline_clients) | set(extra_clients)):
            cl = self.req("GET", "/clients", params={"clientId": cid}).json()
            if cl:
                n += len(self.req("GET", f"/users/{kid}/offline-sessions/{cl[0]['id']}", ok=(200, 404)).json() or [])
        return n

    def delete(self, kid: str) -> None:
        self.req("DELETE", f"/users/{kid}")

class Mas:
    """Matrix Authentication Service admin API (downstream of Keycloak). Client-credentials client dedicated to the ICS.
    MAS has a single admin scope (`urn:mas:admin`), so the scope itself cannot be narrowed; the narrowing is: its own client id + vault-held secret, the
    admin API reachable only from the ICS (network), and this class only ever calls the user lookup, lock/unlock/deactivate and session finish endpoints."""

    def __init__(self, rt: Runtime, stack: Stack):
        c = stack.cfg
        from urllib.parse import urlparse
        _guard(rt, urlparse(c["mas_url"]).hostname)
        self.base, self.client_id, self._secret = c["mas_url"].rstrip("/"), c["mas_client_id"], stack.mas_secret
        ctx = ssl.create_default_context(cadata=c["identity_ca_pem"])
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.http = httpx.Client(verify=ctx, timeout=httpx.Timeout(10.0), follow_redirects=False, trust_env=False)
        self._tok, self._exp = None, 0.0

    def close(self) -> None:
        self.http.close()

    def _token(self) -> str:
        if self._tok and time.monotonic() < self._exp:
            return self._tok
        try:
            r = self.http.post(f"{self.base}/oauth2/token", auth=(self.client_id, self._secret or ""),
                               data={"grant_type": "client_credentials", "scope": "urn:mas:admin"})
        except (httpx.HTTPError, ssl.SSLError, OSError) as e:
            raise IdentityError(f"MAS unreachable or untrusted: {type(e).__name__}") from None
        if r.status_code != 200:
            raise IdentityError(f"MAS admin client login refused (HTTP {r.status_code})")
        j = r.json()
        self._tok, self._exp = j["access_token"], time.monotonic() + max(10, int(j.get("expires_in", 60)) - 15)
        return self._tok

    def req(self, method: str, path: str, ok=(200, 204), **kw):
        try:
            r = self.http.request(method, f"{self.base}/api/admin/v1{path}", headers={"Authorization": f"Bearer {self._token()}"}, **kw)
        except (httpx.HTTPError, ssl.SSLError, OSError) as e:
            raise IdentityError(f"MAS request failed: {type(e).__name__}") from None
        if r.status_code not in ok:
            raise IdentityError(f"MAS {method} {path.split('?')[0].rsplit('/', 1)[-1]} refused: HTTP {r.status_code}")
        return r

    def probe(self) -> None:
        self.req("GET", "/users", params={"page[first]": 1})

    def find(self, uid: str) -> dict | None:
        """-> {"id", "locked", "deactivated"} or None when MAS never saw the user."""
        r = self.req("GET", f"/users/by-username/{uid}", ok=(200, 404))
        if r.status_code == 404:
            return None
        d = r.json()["data"]
        a = d.get("attributes", {})
        return {"id": d["id"], "locked": bool(a.get("locked_at")), "deactivated": bool(a.get("deactivated_at"))}

    def lock(self, mid: str) -> None:
        self.req("POST", f"/users/{mid}/lock")

    def unlock(self, mid: str) -> None:
        self.req("POST", f"/users/{mid}/unlock")

    def deactivate(self, mid: str) -> None:
        self.req("POST", f"/users/{mid}/deactivate")

    KINDS = ("oauth2-sessions", "compat-sessions")

    def active_sessions(self, mid: str) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for kind in self.KINDS:                       # cursor pagination: a user with > 100 sessions must not leave any behind (review 4, L5)
            after, seen = None, set()
            for _ in range(50):
                params = {"filter[user]": mid, "filter[status]": "active", "page[first]": 100}
                if after:
                    params["page[after]"] = after
                data = self.req("GET", f"/{kind}", params=params).json().get("data", [])
                new = [x["id"] for x in data if x["id"] not in seen]
                out += [(kind, i) for i in new]
                seen.update(new)
                if len(data) < 100 or not new:
                    break
                after = data[-1]["id"]
        return out

    def end_sessions(self, mid: str) -> int:
        n = 0
        for kind, sid in self.active_sessions(mid):
            self.req("POST", f"/{kind}/{sid}/finish", ok=(200, 204, 404))
            n += 1
        return n

    def state(self, uid: str) -> dict:
        u = self.find(uid)
        if u is None:
            return {"user_present": False}
        return {"user_present": True, "locked": u["locked"], "deactivated": u["deactivated"], "active_sessions": len(self.active_sessions(u["id"]))}


# ---- node agent (gromox / opencloud runbooks) ----------------------------------------------------------------------------------------
def _audit(rt: Runtime, action: str, plan=None, resource="idm_user", resource_id=None, **details) -> None:
    """Own short transaction: never hold the audit chain lock while talking to remote systems (see actions._exec_runbook)."""
    with rt.session() as d:
        audit.append(d, action, actor_name="worker", resource=resource, resource_id=resource_id, details=details)
        d.commit()


def agent_user(rt: Runtime, node_id, action: str, uid: str, known: list[str], device: str | None = None, raw: bool = False) -> dict:
    """One signed agent request (fixed runbook, params exactly {user}; {user, device} for pbx.issue_credential). Returns the helper's JSON result
    (sanitised; raw=True only for the SIP credential issue, whose result carries the one-time secret and is never audited); raises IdentityError otherwise."""
    with rt.session() as d:
        node = d.execute(text("SELECT * FROM nodes WHERE id = :i"), {"i": str(node_id)}).first()
    if node is None:
        raise IdentityError("node not found (enroll the node first)")
    priv = agentclient.load_signing_key(rt.settings.signing_key_file)
    jid = str(uuid.uuid4())
    params = {"user": uid, **({"device": device} if device else {})}
    body = agentclient.build_request(priv, action=action, params=params, node_id=str(node.id), job_id=jid, ttl=rt.settings.agent_request_ttl_seconds)
    req = body["req"]
    with rt.session() as d:
        d.execute(text("INSERT INTO agent_requests (node_id, job_id, nonce, action, issued_at, expires_at) "
                       "VALUES (:n, :j, :nc, :a, to_timestamp(:i), to_timestamp(:e))"),
                  {"n": str(node.id), "j": jid, "nc": req["nonce"], "a": action, "i": req["issued_at"], "e": req["expires_at"]})
        d.commit()
    code, resp = "error", {}
    try:
        _, resp = agentclient.call(node, priv, action=action, params=params, job_id=jid, deadline=rt.settings.agent_deadline_seconds,
                                   allow_loopback=rt.settings.allow_loopback_endpoints, req_override=body)
        code = str(resp.get("code"))[:60]
    except AgentError:
        code = "transport_or_signature_error"
        raise
    finally:
        with rt.session() as d:
            d.execute(text("UPDATE agent_requests SET status = :s, response_code = :c, finished_at = now() WHERE job_id = :j"),
                      {"s": "done" if code == "ok" else "failed", "c": code, "j": jid})
            audit.append(d, "runbook.executed", actor_name="worker", resource="node", resource_id=str(node.id),
                         details={"runbook": action, "params": params, "agent_status": resp.get("status", "error"), "agent_code": code,
                                  "job_id": jid, "nonce": req["nonce"]})
            d.commit()
    if resp.get("status") != "ok":
        raise IdentityError(f"{action}: agent {resp.get('status')}: {code}")
    r = resp.get("result") or {}
    if r.get("returncode") not in (0,) or not isinstance(r.get("result"), dict):
        raise IdentityError(f"{action}: helper failed (rc={r.get('returncode')})")
    return r["result"] if raw else audit.sanitize(r["result"])


# ---- SIP credentials (one-time reveal) -----------------------------------------------------------------------------------------------
def _store_sip_credential(rt: Runtime, user_id: str, plan_id, requested_by, device: str, cred: dict) -> dict:
    cid = uuid.uuid4()
    exp = datetime.now(timezone.utc) + timedelta(seconds=SIP_CRED_TTL)
    with rt.session() as d:
        d.execute(text("UPDATE idm_sip_credentials SET secret_enc = NULL WHERE user_id = :u AND device = :v AND revealed_at IS NULL"), {"u": user_id, "v": device})
        d.execute(text("INSERT INTO idm_sip_credentials (id, user_id, plan_id, requested_by, device, secret_enc, expires_at) VALUES (:i, :u, :p, :r, :v, :e, :x)"),
                  {"i": str(cid), "u": user_id, "p": str(plan_id), "r": str(requested_by), "v": device,
                   "e": rt.vault.encrypt(json.dumps(cred).encode(), f"idm-sip:{cid}"), "x": exp})
        d.commit()
    return {"issued": True, "device": device, "expires_at": exp.isoformat(), "reveal": f"POST /api/v1/identity/sip-credentials/{plan_id}/reveal (requester only, once)"}


def reveal_sip_credential(db, rt: Runtime, user, plan_id) -> dict:
    """The SIP password is shown ONCE to the requester; the ciphertext is wiped in the same transaction. The PBX only ever stores its MD5 digest."""
    row = db.execute(text(
        "SELECT c.*, u.uid, s.name AS stack FROM idm_sip_credentials c JOIN idm_users u ON u.id = c.user_id JOIN idm_stacks s ON s.id = u.stack_id "
        "WHERE c.plan_id = :p AND c.requested_by = :r AND c.secret_enc IS NOT NULL AND c.revealed_at IS NULL AND c.expires_at > now() "
        "ORDER BY c.created_at DESC LIMIT 1 FOR UPDATE OF c"), {"p": str(plan_id), "r": str(user.id)}).first()
    if row is None:
        return {}
    cred = json.loads(rt.vault.decrypt(row.secret_enc, f"idm-sip:{row.id}").decode())
    db.execute(text("UPDATE idm_sip_credentials SET secret_enc = NULL, revealed_at = now() WHERE id = :i"), {"i": str(row.id)})
    audit.append(db, "identity.sip_credential_revealed", actor_id=user.id, actor_name=user.username, resource="idm_user",
                 resource_id=str(row.user_id), details={"uid": row.uid, "stack": row.stack, "device": row.device, "plan_id": str(plan_id)})
    db.commit()
    return {**cred, "uid": row.uid, "stack": row.stack, "device": row.device, "expires_at": row.expires_at.isoformat(),
            "note": "shown once; the PBX stores only a digest. Enter it in the softphone/device now."}


# ---- enrollment tokens ---------------------------------------------------------------------------------------------------------------
def _issue_enrollment(rt: Runtime, user_id: str, plan_id, requested_by) -> dict:
    eid = uuid.uuid4()
    secret = secrets.token_urlsafe(32)
    token = f"{eid}.{secret}"
    exp = datetime.now(timezone.utc) + timedelta(seconds=rt.settings.enrollment_ttl_seconds)
    with rt.session() as d:
        d.execute(text("UPDATE idm_enrollments SET token_enc = NULL, expires_at = LEAST(expires_at, now()) "
                       "WHERE user_id = :u AND used_at IS NULL"), {"u": user_id})  # a newer token supersedes older ones
        d.execute(text("INSERT INTO idm_enrollments (id, user_id, plan_id, requested_by, token_sha256, token_enc, expires_at) "
                       "VALUES (:i, :u, :p, :r, :h, :e, :x)"),
                  {"i": str(eid), "u": user_id, "p": str(plan_id), "r": str(requested_by), "h": hashlib.sha256(secret.encode()).hexdigest(),
                   "e": rt.vault.encrypt(token.encode(), f"idm-enroll:{eid}"), "x": exp})
        d.commit()
    return {"issued": True, "expires_at": exp.isoformat(), "reveal": f"POST /api/v1/identity/enrollments/{plan_id}/reveal (requester only, once)"}


def reveal_enrollment(db, rt: Runtime, user, plan_id) -> dict:
    """Shown ONLY to the requester of the plan, exactly once; the ciphertext is wiped in the same transaction."""
    row = db.execute(text(
        "SELECT e.*, u.uid, s.name AS stack FROM idm_enrollments e JOIN idm_users u ON u.id = e.user_id JOIN idm_stacks s ON s.id = u.stack_id "
        "WHERE e.plan_id = :p AND e.requested_by = :r AND e.token_enc IS NOT NULL AND e.used_at IS NULL AND e.expires_at > now() "
        "ORDER BY e.created_at DESC LIMIT 1 FOR UPDATE OF e"), {"p": str(plan_id), "r": str(user.id)}).first()
    if row is None:
        return {}
    token = rt.vault.decrypt(row.token_enc, f"idm-enroll:{row.id}").decode()
    db.execute(text("UPDATE idm_enrollments SET token_enc = NULL, revealed_at = now() WHERE id = :i"), {"i": str(row.id)})
    audit.append(db, "identity.enrollment_revealed", actor_id=user.id, actor_name=user.username, resource="idm_user",
                 resource_id=str(row.user_id), details={"uid": row.uid, "stack": row.stack, "plan_id": str(plan_id)})
    db.commit()
    return {"token": token, "uid": row.uid, "stack": row.stack, "expires_at": row.expires_at.isoformat(),
            "redeem": "POST /api/v1/identity/enroll {stack, uid, token, password}"}


def _password_ok(uid: str, pw: str) -> str | None:
    if not 12 <= len(pw) <= 256:
        return "password must be 12-256 characters"
    if uid in pw.lower() or len(set(pw)) < 5:
        return "password is too guessable"
    return None


class EnrollRefused(Exception):
    pass


def redeem_enrollment(db, rt: Runtime, stack_name: str, uid: str, token: str, password: str, ip: str | None) -> None:
    """Unauthenticated endpoint. One generic error for every refusal (no oracle); 5 failures burn the token."""
    bad = _password_ok(uid, password)
    m = re.fullmatch(r"([0-9a-f-]{36})\.([A-Za-z0-9_-]{20,80})", token or "")
    row = None
    try:
        eid = str(uuid.UUID(m.group(1))) if m else None
    except ValueError:
        eid = None
    if eid:
        row = db.execute(text(
            "SELECT e.*, u.uid, u.state, u.stack_id, s.name AS stack FROM idm_enrollments e JOIN idm_users u ON u.id = e.user_id "
            "JOIN idm_stacks s ON s.id = u.stack_id WHERE e.id = :i FOR UPDATE OF e"), {"i": eid}).first()
    if row is None or row.uid != uid or row.stack != stack_name or row.used_at is not None or row.failures >= 5 \
            or row.expires_at < datetime.now(timezone.utc) or row.state != "active":
        audit.append(db, "identity.enroll_refused", actor_name="anonymous", ip=ip, resource="idm_user", details={"uid": uid[:40], "stack": stack_name[:63]})
        db.commit()
        raise EnrollRefused("invalid or expired enrollment token")
    if not hmac.compare_digest(hashlib.sha256(m.group(2).encode()).hexdigest(), row.token_sha256):
        db.execute(text("UPDATE idm_enrollments SET failures = failures + 1 WHERE id = :i"), {"i": str(row.id)})
        audit.append(db, "identity.enroll_refused", actor_name="anonymous", ip=ip, resource="idm_user", resource_id=str(row.user_id), details={"uid": uid})
        db.commit()
        raise EnrollRefused("invalid or expired enrollment token")
    if bad:
        raise ValueError(bad)
    stack = load_stack(rt, stack_name)
    d = Directory(rt, stack)
    try:
        d.set_password(uid, password)
    finally:
        d.close()
    db.execute(text("UPDATE idm_enrollments SET used_at = now(), token_enc = NULL WHERE id = :i"), {"i": str(row.id)})
    audit.append(db, "identity.enrolled", actor_name="anonymous", ip=ip, resource="idm_user", resource_id=str(row.user_id),
                 details={"uid": uid, "stack": stack_name})
    db.commit()


# ---- plan-time policy ----------------------------------------------------------------------------------------------------------------
def _stack_row(db, name: str):
    row = db.execute(text("SELECT * FROM idm_stacks WHERE name = :n"), {"n": name}).first()
    if row is None:
        raise KeyError("stack not found")
    return row


def _user_row(db, stack_id, uid: str, states: tuple[str, ...]):
    row = db.execute(text("SELECT * FROM idm_users WHERE stack_id = :s AND uid = :u AND state <> 'deleted'"), {"s": str(stack_id), "u": uid}).first()
    if row is None:
        raise KeyError("user not found in this stack (not managed by the ICS or already deleted)")
    if row.state not in states:
        raise ValueError(f"user is {row.state}; this action needs state {' or '.join(states)}")
    return row


def _ext_free(db, stack_row, ext: str, own_user_id) -> None:
    if not stack_row.config.get("pbx_node_id"):
        raise ValueError("this stack has no PBX node (register it with pbx_node_id/pbx_domain)")
    r = db.execute(text("SELECT id FROM idm_users WHERE stack_id = :s AND extension = :e AND state <> 'deleted'"), {"s": str(stack_row.id), "e": ext}).first()
    if r and (own_user_id is None or str(r.id) != str(own_user_id)):
        raise LookupError("extension already assigned to another user")


def risk_for(db, action: str, p) -> str:
    """normal = one approver other than the requester; high = two. Privileged groups raise create/update to high."""
    if action in ("idm.stack.register", "idm.user.delete"):
        return "high"
    if action in ("idm.reconcile", "idm.user.devices"):
        return "low"
    if action == "idm.user.disable" and getattr(p, "wipe_devices", False):
        return "high"
    if action in ("idm.user.create", "idm.user.update_groups"):
        priv = set(_stack_row(db, p.stack).config.get("privileged_groups", []))
        touched = set(p.groups) if action == "idm.user.create" else set(p.add) | set(p.remove)
        if touched & priv:
            return "high"
    return "normal"


def precheck(db, rt: Runtime, action: str, p) -> dict:
    """Raises ValueError (-> HTTP 422/409 via PlanError in actions.py). Returns extra info shown to the approver."""
    if action == "idm.stack.register":
        if db.execute(text("SELECT 1 FROM idm_stacks WHERE name = :n"), {"n": p.name}).first():
            raise LookupError("stack name already exists")
        for h in (p.ldap_url.split("//")[1].split(":")[0], p.kc_url.split("//")[1].split(":")[0], *( [p.files_url.split("//")[1].split(":")[0]] if p.files_url else []),
                  *([p.mail_host] if p.mail_host else [])):
            _guard(rt, h)
        for nid in (p.files_node_id, p.gromox_node_id, p.pbx_node_id):
            if nid and db.execute(text("SELECT 1 FROM nodes WHERE id = :i"), {"i": str(nid)}).first() is None:
                raise ValueError("node not found (enroll it first)")
        return {}
    row = _stack_row(db, p.stack)
    cfg = row.config
    allowed = set(cfg["allowed_groups"])
    if action == "idm.reconcile":
        return {}
    if action == "idm.user.create":
        if p.mail.split("@", 1)[1] != cfg["mail_domain"]:
            raise ValueError(f"mail domain must be {cfg['mail_domain']}")
        if not set(p.groups) <= allowed:
            raise ValueError("group not allowed for this stack: " + ",".join(sorted(set(p.groups) - allowed)))
        if p.extension:
            _ext_free(db, row, p.extension, None)
        if db.execute(text("SELECT 1 FROM idm_users WHERE stack_id = :s AND uid = :u AND state <> 'deleted'"), {"s": str(row.id), "u": p.uid}).first():
            raise LookupError("uid already exists in this stack")
        if db.execute(text("SELECT 1 FROM idm_users WHERE stack_id = :s AND mail = :m AND state <> 'deleted'"), {"s": str(row.id), "m": p.mail}).first():
            raise LookupError("mail already in use")
        if db.execute(text("SELECT 1 FROM idm_users WHERE stack_id = :s AND (uid = :u OR mail = :m) AND state = 'deleted'"),
                      {"s": str(row.id), "u": p.uid, "m": p.mail}).first():
            raise LookupError("this uid/mail belonged to a deleted user whose mailbox is RETAINED; there is no purge action, so it cannot be reused")
        return {"mailbox": p.mailbox, "privileged": sorted((set(p.groups)) & set(cfg.get("privileged_groups", [])))}
    if action == "idm.user.set_extension":
        u = _user_row(db, row.id, p.uid, ("active",))
        if p.extension:
            _ext_free(db, row, p.extension, u.id)
        elif not cfg.get("pbx_node_id"):
            raise ValueError("this stack has no PBX node")
        return {"extension": p.extension}
    if action == "idm.user.issue_sip_credential":
        u = _user_row(db, row.id, p.uid, ("active",))
        if not cfg.get("pbx_node_id"):
            raise ValueError("this stack has no PBX node")
        if not u.extension:
            raise ValueError("the user has no extension (assign one with idm.user.set_extension first)")
        return {"extension": u.extension, "device": p.device}
    if action == "idm.user.update_groups":
        _user_row(db, row.id, p.uid, ("active",))
        bad = (set(p.add) | set(p.remove)) - allowed
        if bad:
            raise ValueError("group not allowed for this stack: " + ",".join(sorted(bad)))
        return {"privileged": sorted((set(p.add) | set(p.remove)) & set(cfg.get("privileged_groups", [])))}
    if action == "idm.user.devices":
        if not cfg.get("gromox_node_id"):
            raise ValueError("this stack has no Gromox node")
        _user_row(db, row.id, p.uid, ("active", "disabled"))
    if action == "idm.user.disable":
        _user_row(db, row.id, p.uid, ("active",))
        if p.wipe_devices and not cfg.get("gromox_node_id"):
            raise ValueError("wipe_devices needs a Gromox node in the stack")
    elif action == "idm.user.enable":
        _user_row(db, row.id, p.uid, ("disabled",))
    elif action == "idm.user.delete":
        _user_row(db, row.id, p.uid, ("disabled",))  # delete only after a verified disable
    return {}


# ---- executors ---------------------------------------------------------------------------------------------------------------------
def _step(steps: list, name: str, t0: float, **kw) -> None:
    steps.append({"step": name, "ms": int((time.monotonic() - t0) * 1000), **kw})


def _users_row(rt: Runtime, stack_id: str, uid: str):
    with rt.session() as d:
        return d.execute(text("SELECT * FROM idm_users WHERE stack_id = :s AND uid = :u AND state <> 'deleted'"), {"s": stack_id, "u": uid}).first()


def _set_state(rt: Runtime, user_id: str, state: str, **extra) -> None:
    sets = "".join(f", {k} = :{k}" for k in extra)
    with rt.session() as d:
        d.execute(text(f"UPDATE idm_users SET state = :s, updated_at = now(){sets} WHERE id = :i"), {"s": state, "i": user_id, **extra})
        d.commit()


def _oc_check(rt, stack, uid, known, retries=1) -> dict | None:
    nid = stack.cfg.get("files_node_id")
    if not nid:
        return None
    r = {}
    for i in range(retries):
        r = agent_user(rt, nid, "opencloud.check_user", uid, known)
        if r.get("resolved"):
            break
        time.sleep(3)
    return r


def _gromox(rt, stack, action, uid, known) -> dict | None:
    nid = stack.cfg.get("gromox_node_id")
    return agent_user(rt, nid, action, uid, known) if nid else None


def _pbx(rt, stack, action, uid, known) -> dict | None:
    nid = stack.cfg.get("pbx_node_id")
    return agent_user(rt, nid, action, uid, known) if nid else None


def exec_register(rt: Runtime, db, m: StackRegister, plan, known: list[str]) -> dict:
    sid = uuid.uuid4()
    cfg = m.model_dump(mode="json", exclude={"ldap_bind_password", "kc_client_secret", "mas_client_secret"})
    sec = {"ldap_bind_password": m.ldap_bind_password.get_secret_value(), "kc_client_secret": m.kc_client_secret.get_secret_value()}
    if m.mas_client_secret:
        sec["mas_client_secret"] = m.mas_client_secret.get_secret_value()
    known.extend(sec.values())
    stack = Stack(type("R", (), {"id": sid, "name": m.name, "config": cfg}), sec)
    d = Directory(rt, stack)  # proves TLS trust + service-account bind before anything is stored
    try:
        if d._search(cfg["ldap_people_dn"], "(objectClass=*)", ["1.1"], d._ldap3.BASE) == []:
            raise IdentityError("people base DN is not readable with the service account")
    finally:
        d.close()
    kc = Keycloak(rt, stack)
    try:
        kc.req("GET", "/users/count")  # service account can read users
    finally:
        kc.close()
    if cfg.get("mas_url"):
        mas = Mas(rt, stack)
        try:
            mas.probe()  # client credentials accepted and the admin API answers
        finally:
            mas.close()
    enc = rt.vault.encrypt(json.dumps(sec).encode(), stack_aad(sid, cfg))
    db.execute(text("INSERT INTO idm_stacks (id, name, config, secret_enc, created_by) VALUES (:i, :n, CAST(:c AS jsonb), :s, :u)"),
               {"i": str(sid), "n": m.name, "c": audit.canon(cfg), "s": enc, "u": str(plan.requested_by)})
    audit.append(db, "identity.stack_registered", actor_name="worker", resource="idm_stack", resource_id=str(sid),
                 details={"name": m.name, "ldap_bind_dn": m.ldap_bind_dn, "kc_client_id": m.kc_client_id, "nodes": {"gromox": str(m.gromox_node_id), "files": str(m.files_node_id)}})
    return {"stack_id": str(sid)}


def exec_create(rt: Runtime, db, m: UserCreate, plan, known: list[str]) -> dict:
    stack = load_stack(rt, m.stack)
    known.extend([stack.ldap_pw, stack.kc_secret, *([stack.mas_secret] if stack.mas_secret else [])])
    steps: list = []
    t = time.monotonic()
    d = Directory(rt, stack)
    try:
        if d.get(m.uid) is not None:
            raise IdentityError("uid already exists in the directory (unmanaged entry?): refusing to adopt it")
        if m.extension and d.extension_owner(m.extension):
            raise IdentityError("extension is already in use in the directory")
        d.add(m.uid, m.display_name, m.mail, extension=m.extension)
        e = d.get(m.uid)
        if not e or not e["entry_uuid"]:
            raise IdentityError("created entry cannot be read back")
        _step(steps, "ldap.add", t, entry_uuid=e["entry_uuid"])
        t = time.monotonic()
        groups = sorted(set(m.groups) | ({stack.cfg["entitlement_group"]} if m.mailbox else set()))
        uid_ = str(uuid.uuid4())
        with rt.session() as s:  # the stable id is recorded immediately: a later failure must not orphan the directory entry
            s.execute(text("INSERT INTO idm_users (id, stack_id, uid, entry_uuid, mail, display_name, groups, created_by, extension) "
                           "VALUES (:i, :s, :u, :e, :m, :d, CAST(:g AS jsonb), :c, :x)"),
                      {"i": uid_, "s": stack.id, "u": m.uid, "e": e["entry_uuid"], "m": m.mail, "d": m.display_name, "g": json.dumps(groups),
                       "c": str(plan.requested_by), "x": m.extension})
            audit.append(s, "identity.user_created", actor_name="worker", resource="idm_user", resource_id=uid_,
                         details={"stack": stack.name, "uid": m.uid, "entry_uuid": e["entry_uuid"], "groups": groups, "mail": m.mail})
            s.commit()
        for g in groups:
            d.member(g, m.uid, True)
        _step(steps, "ldap.groups", t, groups=groups)
    finally:
        d.close()
    t = time.monotonic()
    enrol = _issue_enrollment(rt, uid_, plan.id, plan.requested_by)
    _step(steps, "enrollment.issued", t)
    out = {"user_id": uid_, "entry_uuid": e["entry_uuid"], "uid": m.uid, "mail": m.mail, "groups": groups, "enrollment": enrol, "steps": steps}
    if m.mailbox:
        t = time.monotonic()
        g = _gromox(rt, stack, "gromox.sync_user", m.uid, known)
        if g is None:
            _step(steps, "gromox.sync", t, skipped="no gromox node configured")
        else:
            act = [x["action"] for x in g.get("sync", [])]
            if g.get("sync_errors") or g["state"].get("address_status") != 0 or g["state"].get("externid") != e["entry_uuid"]:
                raise IdentityError(f"gromox mailbox not provisioned correctly (sync: {act})")
            _step(steps, "gromox.sync", t, sync=act, externid_matches_entry_uuid=True)
    if m.extension:
        t = time.monotonic()
        pb = _pbx(rt, stack, "pbx.sync_extensions", m.uid, known)
        out["extension"] = m.extension
        if pb is None:
            _step(steps, "pbx.sync", t, skipped="no PBX node configured")
        else:
            if pb.get("extension") != m.extension or not pb.get("known_to_pbx"):
                raise IdentityError("PBX does not see the extension in the directory after sync")
            _step(steps, "pbx.sync", t, extension=m.extension, known_to_pbx=True, devices=pb.get("devices", []))
    t = time.monotonic()
    oc = _oc_check(rt, stack, m.uid, known, retries=4)
    if oc is None:
        _step(steps, "opencloud.visible", t, skipped="no files node configured")
    else:
        out["opencloud_visible"] = bool(oc.get("resolved"))
        _step(steps, "opencloud.visible", t, resolved=bool(oc.get("resolved")))
        if not oc.get("resolved"):
            raise IdentityError("user was created but OpenCloud cannot resolve it (check directory filters/groups)")
    return out


def exec_set_extension(rt: Runtime, db, m: UserSetExtension, plan, known: list[str]) -> dict:
    stack = load_stack(rt, m.stack)
    known.extend([stack.ldap_pw, stack.kc_secret])
    u = _users_row(rt, stack.id, m.uid)
    if u is None or u.state != "active":
        raise IdentityError("user is not active")
    steps: list = []
    d = Directory(rt, stack)
    try:
        t = time.monotonic()
        if m.extension:
            owner = d.extension_owner(m.extension)
            if owner and owner != m.uid:
                raise IdentityError("extension is already in use in the directory")
        d.set_extension(m.uid, m.extension)
        now = d.get(m.uid)
        if (now or {}).get("extension") != m.extension:
            raise IdentityError("extension cannot be read back from the directory")
        _step(steps, "ldap.telephoneNumber", t, extension=m.extension)
    finally:
        d.close()
    with rt.session() as s:
        s.execute(text("UPDATE idm_users SET extension = :x, updated_at = now() WHERE id = :i"), {"x": m.extension, "i": str(u.id)})
        audit.append(s, "identity.extension_changed", actor_name="worker", resource="idm_user", resource_id=str(u.id),
                     details={"uid": m.uid, "stack": stack.name, "from": u.extension, "to": m.extension})
        s.commit()
    t = time.monotonic()
    # removing/changing an extension ends the old registrations and purges the credentials (the PBX derives everything from the directory)
    pb = _pbx(rt, stack, "pbx.kick_user" if (u.extension and u.extension != m.extension) else "pbx.sync_extensions", m.uid, known)
    if pb is not None:
        if m.extension and (pb.get("extension") != m.extension or not pb.get("known_to_pbx")):
            raise IdentityError("PBX does not see the new extension after sync")
        _step(steps, "pbx.sync", t, extension=m.extension, registrations_removed=pb.get("contacts_removed"), channels_hung_up=pb.get("channels_hung_up"))
    else:
        _step(steps, "pbx.sync", t, skipped="no PBX node configured")
    return {"uid": m.uid, "extension": m.extension, "steps": steps}


def exec_issue_sip(rt: Runtime, db, m: IssueSipCredential, plan, known: list[str]) -> dict:
    stack = load_stack(rt, m.stack)
    u = _users_row(rt, stack.id, m.uid)
    if u is None or u.state != "active":
        raise IdentityError("user is not active")
    if not u.extension or not stack.cfg.get("pbx_node_id"):
        raise IdentityError("user has no extension or the stack has no PBX node")
    t = time.monotonic()
    r = agent_user(rt, stack.cfg["pbx_node_id"], "pbx.issue_credential", m.uid, known, device=m.device, raw=True)
    pw = r.pop("password", None)
    if not isinstance(pw, str) or len(pw) < 16 or r.get("extension") != u.extension:
        raise IdentityError("PBX did not return a usable credential for the user's extension")
    known.append(pw)
    cred = {"username": r["username"], "password": pw, "realm": r.get("realm"), "domain": stack.cfg.get("pbx_domain") or r.get("domain"),
            "extension": u.extension, "display_name": r.get("display_name"), "wss": r.get("wss"), "tls_port": r.get("tls_port")}
    rev = _store_sip_credential(rt, str(u.id), plan.id, plan.requested_by, m.device, cred)
    _audit(rt, "identity.sip_credential_issued", resource_id=str(u.id), uid=m.uid, stack=stack.name, device=m.device, extension=u.extension)
    return {"uid": m.uid, "device": m.device, "username": cred["username"], "extension": u.extension, "reveal": rev,
            "steps": [{"step": "pbx.issue_credential", "ms": int((time.monotonic() - t) * 1000), "stored_on_pbx": "md5 digest only"}]}


def exec_update_groups(rt: Runtime, db, m: UserUpdateGroups, plan, known: list[str]) -> dict:
    stack = load_stack(rt, m.stack)
    known.extend([stack.ldap_pw, stack.kc_secret, *([stack.mas_secret] if stack.mas_secret else [])])
    u = _users_row(rt, stack.id, m.uid)
    if u is None or u.state != "active":
        raise IdentityError("user is not active")
    steps: list = []
    d = Directory(rt, stack)
    try:
        t = time.monotonic()
        for g in m.remove:
            d.member(g, m.uid, False)
        for g in m.add:
            d.member(g, m.uid, True)
        now = d.get(m.uid)
        _step(steps, "ldap.groups", t, groups=now["groups"] if now else None)
    finally:
        d.close()
    groups = now["groups"] if now else []
    with rt.session() as s:
        s.execute(text("UPDATE idm_users SET groups = CAST(:g AS jsonb), updated_at = now() WHERE id = :i"), {"g": json.dumps(groups), "i": str(u.id)})
        audit.append(s, "identity.groups_changed", actor_name="worker", resource="idm_user", resource_id=str(u.id),
                     details={"uid": m.uid, "add": m.add, "remove": m.remove, "groups": groups})
        s.commit()
    ent = stack.cfg["entitlement_group"]
    if ent in m.add or ent in m.remove:
        t = time.monotonic()
        g = _gromox(rt, stack, "gromox.sync_user", m.uid, known)
        _step(steps, "gromox.sync", t, sync=[x["action"] for x in (g or {}).get("sync", [])] if g else "skipped")
    if m.remove:  # token claims (roles) are only re-evaluated on a new login: end SSO sessions so removed rights do not linger in tokens
        kc = Keycloak(rt, stack)
        try:
            t = time.monotonic()
            ku = kc.find(m.uid)
            if ku:
                kc.logout(ku["id"])
            _step(steps, "keycloak.logout", t, user_known=bool(ku))
        finally:
            kc.close()
    return {"uid": m.uid, "groups": groups, "steps": steps}


def _kc_revoke(kc: Keycloak, uid: str, steps: list, t_lock: float) -> dict:
    """disable user -> logout all sessions -> revoke consents (kills offline tokens). Returns the Keycloak ids/state for VERIFY."""
    t = time.monotonic()
    ku = kc.find(uid)
    if ku is None:
        _step(steps, "keycloak.revoke", t, user_known=False, at=round(time.monotonic() - t_lock, 1))
        return {"id": None}
    kc.set_enabled(ku, False)
    kc.logout(ku["id"])
    revoked = []
    for cid in sorted(set(kc.consent_clients(ku["id"])) | set(kc.offline_clients)):
        kc.revoke_consent(ku["id"], cid)
        revoked.append(cid)
    _step(steps, "keycloak.revoke", t, user_known=True, disabled=True, logout=True, consents_revoked=revoked, at=round(time.monotonic() - t_lock, 1))
    return {"id": ku["id"]}


def _probe_cfg(rt: Runtime, stack: Stack) -> idprobe.ProbeConfig | None:
    c = stack.cfg
    if not c.get("probe_client_id"):
        return None
    return idprobe.ProbeConfig(kc_url=c["kc_url"], realm=c["kc_realm"], client_id=c["probe_client_id"], files_url=c.get("files_url"),
                               mail_host=c.get("mail_host"), kc_ca_pem=c["identity_ca_pem"], files_ca_pem=c["identity_ca_pem"],
                               mail_ca_pem=c.get("mail_ca_pem"), allow_loopback=rt.settings.allow_loopback_endpoints)


WIPE_POLL_SECONDS = 5.0
WIPE_DELIVERED = 4          # user_devices.status: >= 4 means the device fetched the wipe instruction (REQUESTED 4, WIPED 8, account-only 32/64)


def _devices_brief(r: dict) -> list[dict]:
    return [{"device": d["device"], "status": d["status_name"], "last_sync": d.get("last_sync")} for d in r.get("devices", [])]


def _wipe_devices(rt, stack, uid: str, wait_s: int, known, steps: list) -> dict:
    """Request the wipe for every device and (optionally) wait until the devices picked it up. Runs BEFORE the lock: a suspended account cannot authenticate."""
    t = time.monotonic()
    nid = stack.cfg.get("gromox_node_id")
    r = agent_user(rt, nid, "gromox.wipe_devices", uid, known)
    devs = r.get("devices", [])
    deadline = t + wait_s
    while devs and any(d["status"] < WIPE_DELIVERED for d in devs) and time.monotonic() < deadline:
        time.sleep(min(WIPE_POLL_SECONDS, max(0.0, deadline - time.monotonic())))
        devs = agent_user(rt, nid, "gromox.devices", uid, known).get("devices", [])
    pending = [d["device"] for d in devs if d["status"] < WIPE_DELIVERED]
    out = {"requested": len(devs), "delivered": len(devs) - len(pending), "undelivered_devices": pending, "waited_s": round(time.monotonic() - t, 1),
           "devices": _devices_brief({"devices": devs})}
    _step(steps, "gromox.wipe_devices", t, **{k: v for k, v in out.items() if k != "devices"}, devices=out["devices"])
    return out


def exec_devices(rt: Runtime, db, m: UserDevices, plan, known: list[str]) -> dict:
    stack = load_stack(rt, m.stack)
    known.extend([stack.ldap_pw, stack.kc_secret])
    r = agent_user(rt, stack.cfg["gromox_node_id"], "gromox.devices", m.uid, known)
    return {"uid": m.uid, "devices": r.get("devices", [])}


def exec_disable(rt: Runtime, db, m: UserDisable, plan, known: list[str]) -> dict:
    t_job = time.monotonic()
    stack = load_stack(rt, m.stack)
    known.extend([stack.ldap_pw, stack.kc_secret, *([stack.mas_secret] if stack.mas_secret else [])])
    u = _users_row(rt, stack.id, m.uid)
    if u is None or u.state != "active":
        raise IdentityError("user is not active")
    steps: list = []
    pc = _probe_cfg(rt, stack)
    d = Directory(rt, stack)
    kc = Keycloak(rt, stack)
    mas = Mas(rt, stack) if stack.cfg.get("mas_url") else None
    baseline: dict = {}
    canary = None
    sessions: dict = {}
    try:
        mail, uid = u.mail, m.uid
        # 0. device wipe FIRST: devices must still authenticate with the user's real credential (the canary below replaces it) and the account must not be locked
        wipe = _wipe_devices(rt, stack, uid, m.wipe_wait_seconds, known, steps) if m.wipe_devices else None
        # 1. optional canary credential: lets VERIFY present a VALID credential before and after the revocation (a refusal is then a real signal)
        if m.rotate_credentials and pc is not None:
            t = time.monotonic()
            canary = secrets.token_urlsafe(24)
            known.append(canary)
            d.set_password(uid, canary)
            v1, tok = idprobe.kc_password_grant(pc, uid, canary)
            v2, tok_off = idprobe.kc_password_grant(pc, uid, canary, offline=True)
            baseline["kc_login"] = v1
            baseline["kc_sso_refresh"] = bool(v1 and tok.get("refresh_token"))
            baseline["kc_offline_refresh"] = bool(v2 and tok_off.get("refresh_token"))
            baseline["ldap_bind"] = d.can_bind(uid, canary)
            if pc.files_url and tok.get("access_token"):
                baseline["oc_bearer_graph"] = idprobe.files_bearer(pc, tok["access_token"], uid)
                baseline["oc_bearer_webdav"] = idprobe.files_webdav_bearer(pc, tok["access_token"], uid)
            if pc.mail_host:
                baseline["imap_login"] = idprobe.imap_login(pc, mail, canary)
                baseline["ews_getfolder"] = idprobe.ews_getfolder(pc, mail, canary)
                baseline["activesync_options"] = idprobe.activesync_options(pc, mail, canary)
                sessions["imap"] = idprobe.imap_open(pc, mail, canary)
                baseline["imap_open_session"] = bool(sessions["imap"] and idprobe.imap_session_alive(sessions["imap"]))
            _step(steps, "verify.baseline", t, accepted_before_revocation={k: v for k, v in baseline.items()})
        # 1b. OpenCloud app-token revocation (OpenCloud cannot resolve a locked user)
        oc_tokens = None
        if stack.cfg.get("files_node_id"):
            t = time.monotonic()
            oc_tokens = agent_user(rt, stack.cfg["files_node_id"], "opencloud.revoke_app_tokens", uid, known)
            _step(steps, "opencloud.revoke_app_tokens", t, resolved=oc_tokens.get("resolved"), listed=oc_tokens.get("listed"), revoked=oc_tokens.get("revoked"),
                  remaining=oc_tokens.get("remaining"), ok=oc_tokens.get("ok"), error=oc_tokens.get("error"))
        # 2. revocation, timed from the moment the account is locked
        t = time.monotonic()
        t_lock = time.monotonic()
        lock_epoch = round(time.time(), 3)
        d.lock(uid)
        _step(steps, "ldap.lock", t, at=0.0)
        kcs = _kc_revoke(kc, uid, steps, t_lock)
        if mas is not None:
            t = time.monotonic()
            mu = mas.find(uid)  # None: the user never signed in to Matrix
            if mu:
                mas.lock(mu["id"])  # refuses refresh tokens and new logins at once; Synapse stops honouring the access token within ~2 s (lab)
                ended = mas.end_sessions(mu["id"])
            _step(steps, "matrix.lock", t, user_known=bool(mu), locked=bool(mu), sessions_ended=ended if mu else 0, at=round(time.monotonic() - t_lock, 1))
        pbk = None
        if stack.cfg.get("pbx_node_id"):
            t = time.monotonic()
            pbk = _pbx(rt, stack, "pbx.kick_user", uid, known)  # sync from the (now locked) directory: endpoint+credentials purged, contacts deleted, calls hung up
            _step(steps, "pbx.kick", t, registrations_removed=pbk.get("contacts_removed"), channels_hung_up=pbk.get("channels_hung_up"),
                  endpoint_removed=pbk.get("endpoint_removed"), at=round(time.monotonic() - t_lock, 1))
        t = time.monotonic()
        g = _gromox(rt, stack, "gromox.sync_user", uid, known)
        gq = None
        if g is not None:
            _step(steps, "gromox.suspend", t, sync=[x["action"] for x in g.get("sync", [])], at=round(time.monotonic() - t_lock, 1))
            t = time.monotonic()
            gk = _gromox(rt, stack, "gromox.kill_sessions", uid, known)  # USER-KICK: the (patched) gromox-imap closes the user's open sessions
            _step(steps, "gromox.kill_sessions", t, kick_sent=gk.get("kick_sent"), at=round(time.monotonic() - t_lock, 1))
            t = time.monotonic()
            gq = _gromox(rt, stack, "gromox.kick_user", uid, known)  # freeze store + unload midb + chmod 000: ends access of open IMAP sessions
            _step(steps, "gromox.quarantine_mailbox", t, frozen=gq.get("frozen"), midb_unloaded=gq.get("midb_unloaded"),
                  maildir_mode=gq.get("maildir_mode"), at=round(time.monotonic() - t_lock, 1))
        _set_state(rt, str(u.id), "disabled", disabled_at=datetime.now(timezone.utc))
        _audit(rt, "identity.user_disabled", resource_id=str(u.id), uid=uid, stack=stack.name, reason=m.reason, rotated_credentials=bool(canary))
        # 3. VERIFY: actively probe every credential path and record when each is refused (target TARGET_SECONDS)
        timeout = min(float(m.verify_timeout_seconds), max(5.0, rt.settings.job_timeout_seconds - 15 - (time.monotonic() - t_job)))
        checks: dict = {"ldap_bind": lambda: d.can_bind(uid, canary or secrets.token_urlsafe(12)) if canary else None}
        if canary:
            checks["kc_login"] = lambda: idprobe.kc_password_grant(pc, uid, canary)[0]
            if baseline.get("kc_sso_refresh"):
                checks["kc_sso_refresh"] = lambda: idprobe.kc_refresh(pc, tok["refresh_token"])
            if baseline.get("kc_offline_refresh"):
                checks["kc_offline_refresh"] = lambda: idprobe.kc_refresh(pc, tok_off["refresh_token"])
            if baseline.get("oc_bearer_graph"):
                checks["oc_bearer_graph"] = lambda: idprobe.files_bearer(pc, tok["access_token"], uid)
            if baseline.get("oc_bearer_webdav"):
                checks["oc_bearer_webdav"] = lambda: idprobe.files_webdav_bearer(pc, tok["access_token"], uid)
            for name, fn in (("imap_login", lambda: idprobe.imap_login(pc, mail, canary)),
                             ("ews_getfolder", lambda: idprobe.ews_getfolder(pc, mail, canary)),
                             ("activesync_options", lambda: idprobe.activesync_options(pc, mail, canary))):
                if baseline.get(name):
                    checks[name] = fn
            if baseline.get("imap_open_session"):
                checks["imap_open_session"] = lambda: idprobe.imap_session_alive(sessions["imap"])
        else:
            checks.pop("ldap_bind")
        if mas is not None:
            def _matrix_access() -> bool:
                u2 = mas.find(uid)
                return bool(u2 and (not u2["locked"] or mas.active_sessions(u2["id"])))  # False = refused (locked and no live session)
            checks["matrix_access"] = _matrix_access
        if stack.cfg.get("pbx_node_id"):
            def _pbx_access() -> bool:
                r = agent_user(rt, stack.cfg["pbx_node_id"], "pbx.user_state", uid, known)
                return bool(r.get("endpoint_present") or r.get("contacts") or r.get("channels"))  # True = the user can still register or talk
            checks["pbx_access"] = _pbx_access
        if stack.cfg.get("files_node_id"):
            checks["oc_user_resolution"] = lambda: bool(agent_user(rt, stack.cfg["files_node_id"], "opencloud.check_user", uid, known).get("resolved"))
        measured = idprobe.measure(checks, t_lock, timeout)
        not_probed = sorted(k for k, v in baseline.items() if not v)
        # state checks (read-only truth from each system)
        st: dict = {"ldap": {"locked": bool((d.get(uid) or {}).get("locked"))}}
        if kcs["id"]:
            st["keycloak"] = {"enabled": False, "online_sessions": kc.sessions(kcs["id"]), "offline_sessions": kc.offline_sessions(kcs["id"])}
        else:
            st["keycloak"] = {"user_present": False}
        if stack.cfg.get("gromox_node_id"):
            gs = _gromox(rt, stack, "gromox.user_state", uid, known)
            st["gromox"] = {"address_status": gs["state"].get("address_status"), "maildir_mode": gs.get("maildir_mode")}
        if stack.cfg.get("pbx_node_id"):
            ps = agent_user(rt, stack.cfg["pbx_node_id"], "pbx.user_state", uid, known)
            st["pbx"] = {"endpoint_present": bool(ps.get("endpoint_present")), "contacts": ps.get("contacts"), "channels": ps.get("channels")}
        if mas is not None:
            st["matrix"] = mas.state(uid)
        mx_ok = mas is None or not st["matrix"]["user_present"] or (st["matrix"]["locked"] and st["matrix"]["active_sessions"] == 0)
        pbx_ok = not st.get("pbx") or (not st["pbx"]["endpoint_present"] and not st["pbx"]["contacts"] and not st["pbx"]["channels"])
        ok_states = (mx_ok and pbx_ok and st["ldap"]["locked"] and (not kcs["id"] or (st["keycloak"]["online_sessions"] == 0 and st["keycloak"]["offline_sessions"] == 0))
                     and (not st.get("gromox") or (st["gromox"]["address_status"] == 1)))
        not_revoked = sorted(n for n, o in measured.items() if o["status"] != "refused" or (o["seconds"] or 0) > TARGET_SECONDS)
        if oc_tokens is not None and oc_tokens.get("resolved") and not oc_tokens.get("ok"):
            not_revoked.append("oc_app_tokens")       # the user was resolvable but the revoke did not finish cleanly
        verdict = {"mode": "canary_probe" if canary else "state_only", "target_seconds": TARGET_SECONDS, "measured_from": "LDAP lock applied", "lock_applied_epoch": lock_epoch,
                   "revocation_steps_complete_after_s": round(time.monotonic() - t_lock - 0, 1), "paths": measured,
                   "no_baseline_not_probed": not_probed, "state": st, "not_revoked": not_revoked,
                   "oc_app_tokens": None if oc_tokens is None else {k: oc_tokens.get(k) for k in ("resolved", "listed", "revoked", "remaining", "temp_token_dead", "ok")},
                   "device_wipe": wipe,
                   "overall": "PASS" if (ok_states and not not_revoked) else "FAIL"}
        with rt.session() as s:
            s.execute(text("UPDATE idm_users SET last_verification = CAST(:v AS jsonb) WHERE id = :i"), {"v": audit.canon(audit.sanitize(verdict)), "i": str(u.id)})
            audit.append(s, "identity.verify", actor_name="worker", resource="idm_user", resource_id=str(u.id),
                         details={"uid": uid, "overall": verdict["overall"], "mode": verdict["mode"], "not_revoked": not_revoked,
                                  "seconds": {k: o["seconds"] for k, o in measured.items()}})
            s.commit()
        if verdict["overall"] != "PASS":
            raise IdentityError("VERIFY FAILED: user is disabled but credential paths remain valid: " + ", ".join(not_revoked or ["state check"]))
        return {"uid": uid, "state": "disabled", "verification": verdict, "steps": steps}
    finally:
        if sessions.get("imap") is not None:
            try:
                sessions["imap"].shutdown()
            except Exception:  # noqa: BLE001
                pass
        d.close()
        kc.close()
        if mas is not None:
            mas.close()


def exec_enable(rt: Runtime, db, m: UserEnable, plan, known: list[str]) -> dict:
    stack = load_stack(rt, m.stack)
    known.extend([stack.ldap_pw, stack.kc_secret, *([stack.mas_secret] if stack.mas_secret else [])])
    u = _users_row(rt, stack.id, m.uid)
    if u is None or u.state != "disabled":
        raise IdentityError("user is not disabled")
    steps: list = []
    d = Directory(rt, stack)
    kc = Keycloak(rt, stack)
    mas = Mas(rt, stack) if stack.cfg.get("mas_url") else None
    try:
        t = time.monotonic()
        d.set_password(m.uid, secrets.token_urlsafe(32))  # the old credential never comes back: the user re-enrolls through a new one-time token
        d.unlock(m.uid)
        _step(steps, "ldap.unlock+credential_reset", t)
        t = time.monotonic()
        ku = kc.find(m.uid)
        if ku:
            kc.set_enabled(ku, True)
        _step(steps, "keycloak.enable", t, user_known=bool(ku))
        if mas is not None:
            t = time.monotonic()
            mu = mas.find(m.uid)
            if mu and mu["deactivated"]:
                raise IdentityError("Matrix account is deactivated (irreversible); cannot re-enable it")
            if mu and mu["locked"]:
                mas.unlock(mu["id"])
            _step(steps, "matrix.unlock", t, user_known=bool(mu))
    finally:
        d.close()
        kc.close()
        if mas is not None:
            mas.close()
    t = time.monotonic()
    g = _gromox(rt, stack, "gromox.sync_user", m.uid, known)
    if g:
        if g["state"].get("address_status") != 0:
            raise IdentityError("gromox mailbox is still suspended after sync")
        _step(steps, "gromox.reactivate", t, sync=[x["action"] for x in g.get("sync", [])], released=g.get("released"), maildir_mode=g.get("maildir_mode"))
    if u.extension:
        t = time.monotonic()
        pb = _pbx(rt, stack, "pbx.sync_extensions", m.uid, known)
        if pb is not None:   # the extension is back, but the old SIP credentials stay purged: the user needs a new one-time credential
            _step(steps, "pbx.sync", t, extension=u.extension, known_to_pbx=pb.get("known_to_pbx"), devices=pb.get("devices", []))
    t = time.monotonic()
    oc = _oc_check(rt, stack, m.uid, known, retries=4)
    if oc is not None:
        _step(steps, "opencloud.visible", t, resolved=bool(oc.get("resolved")))
    _set_state(rt, str(u.id), "active", disabled_at=None)
    enrol = _issue_enrollment(rt, str(u.id), plan.id, plan.requested_by)
    _audit(rt, "identity.user_enabled", resource_id=str(u.id), uid=m.uid, stack=stack.name, reason=m.reason)
    return {"uid": m.uid, "state": "active", "enrollment": enrol, "steps": steps,
            "note": "app tokens issued before the disable become valid again in OpenCloud (no revoke API): see docs"}


def exec_delete(rt: Runtime, db, m: UserDelete, plan, known: list[str]) -> dict:
    stack = load_stack(rt, m.stack)
    known.extend([stack.ldap_pw, stack.kc_secret, *([stack.mas_secret] if stack.mas_secret else [])])
    u = _users_row(rt, stack.id, m.uid)
    if u is None or u.state != "disabled":
        raise IdentityError("user must be disabled (and verified) before deletion")
    steps: list = []
    d = Directory(rt, stack)
    kc = Keycloak(rt, stack)
    mas = Mas(rt, stack) if stack.cfg.get("mas_url") else None
    try:
        cur = d.get(m.uid)
        if cur is not None and cur["entry_uuid"] != u.entry_uuid:
            raise IdentityError("directory entry has a different entryUUID than the recorded stable id: refusing to delete")
        t = time.monotonic()  # Keycloak first (its federation link is still valid); a failure here leaves the locked directory entry in place
        ku = kc.find(m.uid)
        if ku:
            try:
                kc.logout(ku["id"])  # best effort: the sessions were already ended by the disable
            except IdentityError:
                pass
            kc.delete(ku["id"])
        _step(steps, "keycloak.delete", t, user_known=bool(ku))
        if mas is not None:
            t = time.monotonic()
            mu = mas.find(m.uid)
            if mu:
                mas.end_sessions(mu["id"])
                if not mu["deactivated"]:
                    mas.deactivate(mu["id"])  # irreversible: the Matrix account is closed (rooms/history stay on the homeserver)
            _step(steps, "matrix.deactivate", t, user_known=bool(mu))
        t = time.monotonic()
        if cur is not None:
            d.delete(m.uid)
        _step(steps, "ldap.delete", t, existed=cur is not None)
    finally:
        d.close()
        kc.close()
        if mas is not None:
            mas.close()
    t = time.monotonic()
    g = _gromox(rt, stack, "gromox.sync_user", m.uid, known)
    if g:
        _step(steps, "gromox.suspend", t, sync=[x["action"] for x in g.get("sync", [])], address_status=g["state"].get("address_status"))
    if stack.cfg.get("pbx_node_id") and u.extension:
        t = time.monotonic()
        pb = _pbx(rt, stack, "pbx.kick_user", m.uid, known)
        _step(steps, "pbx.kick", t, registrations_removed=pb.get("contacts_removed"), channels_hung_up=pb.get("channels_hung_up"))
    _set_state(rt, str(u.id), "deleted")
    _audit(rt, "identity.user_deleted", resource_id=str(u.id), uid=m.uid, stack=stack.name, reason=m.reason, entry_uuid=u.entry_uuid,
           mailbox_retained=True)
    return {"uid": m.uid, "state": "deleted", "entry_uuid": u.entry_uuid, "mailbox_retained": True, "steps": steps,
            "note": "mailbox data is retained on the groupware node (suspended, locked); there is no purge action"}


# ---- reconcile (report only) ---------------------------------------------------------------------------------------------------------
DESTRUCTIVE = {"ldap_exists_deleted", "ldap_missing", "ldap_entryuuid_mismatch", "ldap_not_locked", "kc_enabled", "kc_sessions_remain", "kc_orphan", "gromox_active",
               "gromox_mailbox_open", "opencloud_resolves", "matrix_not_locked", "matrix_sessions_remain", "matrix_active"}


def classify(u: dict, ldap: dict | None, kc: dict | None, gx: dict | None, oc: dict | None, cfg: dict, mx: dict | None = None) -> list[dict]:
    """Pure comparison of one managed user across the four systems. `kind` in DESTRUCTIVE = access that should be gone is still there
    (or identity swapped); everything else is informational. Never repaired automatically."""
    f: list[dict] = []
    want = u["state"]  # active | disabled | deleted

    def add(kind, system, detail):
        f.append({"kind": kind, "system": system, "severity": "critical" if kind in DESTRUCTIVE else "warning", "detail": detail})

    if want == "deleted":
        if ldap:
            add("ldap_exists_deleted", "ldap", "entry still exists although the user is deleted")
        if kc:
            add("kc_orphan", "keycloak", "Keycloak user still present for a deleted user")
        if gx and gx.get("address_status") == 0:
            add("gromox_active", "gromox", "mailbox still active for a deleted user")
        if mx and mx.get("user_present") and not mx.get("deactivated"):
            add("matrix_active", "matrix", "Matrix account not deactivated for a deleted user")
        return f
    if ldap is None:
        add("ldap_missing", "ldap", "directory entry is gone but the ICS has it as " + want)
        return f
    if ldap["entry_uuid"] != u["entry_uuid"]:
        add("ldap_entryuuid_mismatch", "ldap", "entryUUID differs from the recorded stable id (entry replaced?)")
    if want == "disabled":
        if not ldap["locked"]:
            add("ldap_not_locked", "ldap", "disabled in the ICS but not locked in the directory")
        if kc and (kc.get("enabled") or kc.get("online_sessions", 0) or kc.get("offline_sessions", 0)):
            add("kc_enabled" if kc.get("enabled") else "kc_sessions_remain", "keycloak", f"enabled={kc.get('enabled')} online={kc.get('online_sessions')} offline={kc.get('offline_sessions')}")
        if gx and gx.get("address_status") == 0:
            add("gromox_active", "gromox", "mailbox active for a disabled user")
        if gx and gx.get("address_status") == 1 and gx.get("maildir_mode") not in ("0000", None):
            add("gromox_mailbox_open", "gromox", f"suspended but maildir mode {gx.get('maildir_mode')} (open IMAP sessions could still read it)")
        if mx and mx.get("user_present"):
            if not mx.get("locked") and not mx.get("deactivated"):
                add("matrix_not_locked", "matrix", "Matrix (MAS) account not locked for a disabled user")
            if mx.get("active_sessions", 0):
                add("matrix_sessions_remain", "matrix", f"{mx.get('active_sessions')} active Matrix session(s) for a disabled user")
        if oc and oc.get("resolved"):
            add("opencloud_resolves", "opencloud", "OpenCloud still resolves a disabled user")
        return f
    if ldap["locked"]:
        add("ldap_locked", "ldap", "active in the ICS but locked in the directory")
    if kc is not None and kc.get("enabled") is False:
        add("kc_disabled", "keycloak", "active in the ICS but disabled in Keycloak")
    mailbox = cfg.get("entitlement_group") in u["groups"]
    if gx is not None:
        if mailbox and gx.get("address_status") != 0:
            add("gromox_suspended", "gromox", "entitled user has a suspended/missing mailbox")
        if not gx.get("exists", True) and mailbox:
            add("gromox_missing", "gromox", "no Gromox user row")
        if gx.get("maildir_mode") == "0000" and mailbox:
            add("gromox_mailbox_locked", "gromox", "mailbox is quarantined (mode 0000) for an active user")
    if mx and mx.get("user_present") and mx.get("locked"):
        add("matrix_locked", "matrix", "active in the ICS but locked in Matrix (MAS)")
    if oc is not None and not oc.get("resolved"):
        add("opencloud_invisible", "opencloud", "OpenCloud cannot resolve an active user")
    if sorted(ldap["groups"]) != sorted(u["groups"]):
        add("group_drift", "ldap", f"groups recorded {sorted(u['groups'])} vs directory {sorted(ldap['groups'])}")
    return f


def reconcile(rt: Runtime, stack_name: str, trigger: str = "periodic", max_users: int = 200) -> dict:
    stack = load_stack(rt, stack_name)
    known: list[str] = [stack.ldap_pw, stack.kc_secret, *([stack.mas_secret] if stack.mas_secret else [])]
    with rt.session() as d:
        users = [dict(r._mapping) for r in d.execute(text("SELECT * FROM idm_users WHERE stack_id = :s AND state <> 'deleted' ORDER BY uid LIMIT :n"),
                                                     {"s": stack.id, "n": max_users}).all()]
        deleted = [dict(r._mapping) for r in d.execute(text("SELECT * FROM idm_users WHERE stack_id = :s AND state = 'deleted' "
                                                            "AND updated_at > now() - interval '30 days'"), {"s": stack.id}).all()]
    d = Directory(rt, stack)
    kc = Keycloak(rt, stack)
    mas = Mas(rt, stack) if stack.cfg.get("mas_url") else None
    findings: list[dict] = []
    try:
        findings.extend(kc.profile_check())
        people = {p["uid"]: p for p in d.list_people()}
        managed = {u["uid"] for u in users}
        for u in users + deleted:
            row = {"uid": u["uid"], "state": u["state"], "entry_uuid": u["entry_uuid"], "groups": list(u["groups"])}
            kc_state = None
            try:
                ku = kc.find(u["uid"])
                if ku:
                    kc_state = {"enabled": bool(ku.get("enabled")), "online_sessions": kc.sessions(ku["id"]),
                                "offline_sessions": kc.offline_sessions(ku["id"])}
                gx = oc = None
                if stack.cfg.get("gromox_node_id"):
                    r = agent_user(rt, stack.cfg["gromox_node_id"], "gromox.user_state", u["uid"], known)
                    gx = {**r["state"], "maildir_mode": r.get("maildir_mode")}
                if stack.cfg.get("files_node_id") and u["state"] != "deleted":
                    oc = agent_user(rt, stack.cfg["files_node_id"], "opencloud.check_user", u["uid"], known)
                mx = mas.state(u["uid"]) if mas is not None else None
                for x in classify(row, people.get(u["uid"]), kc_state, gx, oc, stack.cfg, mx):
                    findings.append({"uid": u["uid"], **x})
            except (IdentityError, AgentError) as e:
                findings.append({"uid": u["uid"], "kind": "check_failed", "system": "reconcile", "severity": "warning", "detail": str(e)[:200]})
        unmanaged = sorted(set(people) - managed - {u["uid"] for u in deleted})
        for uid_ in unmanaged:
            findings.append({"uid": uid_, "kind": "unmanaged_directory_user", "system": "ldap", "severity": "info",
                             "detail": "directory user not created by the ICS (not touched)"})
    finally:
        d.close()
        kc.close()
        if mas is not None:
            mas.close()
    crit = sum(1 for f in findings if f["severity"] == "critical")
    res = {"stack": stack.name, "users_checked": len(users) + len(deleted), "findings": findings, "critical": crit,
           "ok": not any(f["severity"] in ("critical", "warning") for f in findings), "trigger": trigger}
    with rt.session() as s:
        s.execute(text("INSERT INTO idm_reconcile_runs (stack_id, trigger, ok, findings) VALUES (:s, :t, :o, CAST(:f AS jsonb))"),
                  {"s": stack.id, "t": trigger, "o": res["ok"], "f": audit.canon(audit.sanitize(findings))})
        s.execute(text("UPDATE idm_stacks SET last_reconcile_at = now() WHERE id = :i"), {"i": stack.id})
        audit.append(s, "identity.reconcile", actor_name="worker", resource="idm_stack", resource_id=stack.id,
                     details={"trigger": trigger, "users": res["users_checked"], "critical": crit, "findings": len(findings),
                              "kinds": sorted({f["kind"] for f in findings})})
        s.commit()
    return res


def exec_reconcile(rt: Runtime, db, m: Reconcile, plan, known: list[str]) -> dict:
    r = reconcile(rt, m.stack, trigger="on_demand")
    return {k: r[k] for k in ("stack", "users_checked", "critical", "ok")} | {"findings": r["findings"][:100]}


def reconcile_due(rt: Runtime) -> int:
    """Called from the worker loop: runs the periodic reconcile for stacks whose interval has elapsed. Report only: nothing is repaired."""
    n = 0
    with rt.session() as d:
        due = d.execute(text("SELECT name FROM idm_stacks WHERE (config->>'reconcile_interval_seconds')::int > 0 AND "
                             "(last_reconcile_at IS NULL OR last_reconcile_at < now() - make_interval(secs => (config->>'reconcile_interval_seconds')::int))")).all()
        d.execute(text("UPDATE idm_stacks SET last_reconcile_at = now() WHERE name = ANY(:n)"), {"n": [r.name for r in due]})  # claim before running
        d.commit()
    for r in due:
        try:
            reconcile(rt, r.name)
            n += 1
        except Exception as e:  # noqa: BLE001
            log.error("reconcile of %s failed: %s", r.name, type(e).__name__)
    return n


MODELS = {"idm.user.devices": UserDevices, "idm.stack.register": StackRegister, "idm.user.create": UserCreate, "idm.user.update_groups": UserUpdateGroups,
          "idm.user.disable": UserDisable, "idm.user.enable": UserEnable, "idm.user.delete": UserDelete, "idm.reconcile": Reconcile,
          "idm.user.set_extension": UserSetExtension, "idm.user.issue_sip_credential": IssueSipCredential}
EXECUTORS = {"idm.user.devices": exec_devices, "idm.stack.register": exec_register, "idm.user.create": exec_create, "idm.user.update_groups": exec_update_groups,
             "idm.user.disable": exec_disable, "idm.user.enable": exec_enable, "idm.user.delete": exec_delete, "idm.reconcile": exec_reconcile,
             "idm.user.set_extension": exec_set_extension, "idm.user.issue_sip_credential": exec_issue_sip}
SECRETS = {"idm.stack.register": ("ldap_bind_password", "kc_client_secret", "mas_client_secret")}
