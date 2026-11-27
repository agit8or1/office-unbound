"""Client-protocol access to the demo deployment's applications, always signed in as one seeded person (never an admin API):

    Imap        IMAPS (imaplib): APPEND into the person's own folders, flags, find/delete by X-OU-Demo-Id
    Dav         CalDAV (grommunio-dav, HTTP Basic as the person): discovery, PUT (create-only), MKCALENDAR, query by UID prefix, DELETE
    sign_in     the person's real sign-in: the Keycloak login form reached through the application's own OIDC/SSO flow
    Files       OpenCloud: Graph (/graph) for the personal drive, users and sharing; WebDAV on the drive for folders and files
    Matrix      Matrix client-server API with a token from MAS's compatibility SSO login

Every HTTP request passes guard.HostGuard (https on the demo domain only) before a connection is made; TLS is always verified (system
trust or the --ca-file bundle). The IMAP host is checked the same way. No SMTP anywhere."""
from __future__ import annotations

import base64
import hashlib
import imaplib
import json
import re
import secrets
import ssl
import time
from html.parser import HTMLParser
from urllib.parse import parse_qs, quote, urlencode, urljoin, urlsplit
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape as _xesc

import httpx

from . import guard, org

UA = "OfficeUnbound-DemoSeed/1"
LOOPBACK = "http://127.0.0.1"          # OIDC redirect of the public PKCE client OpenCloudDesktop (realm template); never requested


class SeedError(Exception):
    pass


class LoginFailed(SeedError):
    pass


def tls_context(ca_file: str | None = None) -> ssl.SSLContext:
    """System trust, plus the deployment CA bundle when given (--ca-file). Verification is never turned off."""
    ctx = ssl.create_default_context()
    if ca_file:
        ctx.load_verify_locations(cafile=ca_file)
    return ctx


def http_client(domain: str, ca_file: str | None = None, transport: httpx.BaseTransport | None = None) -> httpx.Client:
    hook = guard.HostGuard(domain)
    kw = {"transport": transport} if transport is not None else {"verify": tls_context(ca_file)}
    return httpx.Client(event_hooks={"request": [hook]}, follow_redirects=False, timeout=60, headers={"User-Agent": UA}, **kw)


# ================================================================ IMAP
class Imap:
    def __init__(self, host: str, domain: str, user: str, password: str, *, port: int = 993, ca_file: str | None = None, factory=None):
        if not guard.host_allowed(host, domain):
            raise guard.DemoRefused(f"refusing IMAP outside the demo deployment: {host}")
        if factory is None:
            ctx = tls_context(ca_file)
            factory = lambda h, p: imaplib.IMAP4_SSL(h, p, ssl_context=ctx)  # noqa: E731
        self.c = factory(host, port)
        typ, _ = self.c.login(user, password)
        if typ != "OK":
            raise LoginFailed(f"IMAP sign-in refused for {user}")
        self._sent: str | None = None

    def close(self) -> None:
        try:
            self.c.logout()
        except Exception:  # noqa: BLE001
            pass

    def sent_folder(self) -> str:
        if self._sent:
            return self._sent
        typ, data = self.c.list()
        names = []
        for raw in data or []:
            line = raw.decode() if isinstance(raw, bytes) else str(raw)
            m = re.match(r'\((?P<flags>[^)]*)\) (?:"[^"]*"|NIL) (?P<name>.+)$', line)
            if not m:
                continue
            name = m.group("name").strip().strip('"')
            if "\\sent" in m.group("flags").lower():
                self._sent = name
                return name
            names.append(name)
        for cand in ("Sent Items", "Sent"):
            if cand in names:
                self._sent = cand
                return cand
        raise SeedError("no Sent folder found")

    def folder(self, name: str) -> str:
        return self.sent_folder() if name == "SENT" else name

    @staticmethod
    def _q(name: str) -> str:
        return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'

    def demo_ids(self, folder: str) -> dict[str, bytes]:
        """X-OU-Demo-Id -> IMAP UID of the demo messages in the folder."""
        typ, data = self.c.select(self._q(self.folder(folder)))
        if typ != "OK":
            raise SeedError(f"cannot open folder {folder}")
        if int((data or [b"0"])[0] or 0) == 0:
            return {}
        typ, data = self.c.uid("FETCH", "1:*", "(UID BODY.PEEK[HEADER.FIELDS (X-OU-DEMO-ID)])")
        out = {}
        for part in data or []:
            if not isinstance(part, tuple):
                continue
            meta, hdr = part
            m = re.search(rb"UID (\d+)", meta)
            h = re.search(rb"X-OU-Demo-Id:\s*(\S+)", hdr or b"", re.I)
            if m and h:
                out[h.group(1).decode()] = m.group(1)
        return out

    def append(self, folder: str, flags: tuple[str, ...], when, raw: bytes) -> None:
        typ, _ = self.c.append(self._q(self.folder(folder)), "(" + " ".join(flags) + ")", imaplib.Time2Internaldate(when.timestamp()), raw)
        if typ != "OK":
            raise SeedError(f"IMAP APPEND refused in {folder}")

    def set_flags(self, uid: bytes, flags: tuple[str, ...]) -> None:
        self.c.uid("STORE", uid, "FLAGS", "(" + " ".join(flags) + ")")

    def delete_demo(self, folder: str) -> int:
        """Removes the messages this tool placed (X-OU-Demo-Id) and, in INBOX, the meeting requests and cancellations the server
        generated for demo meetings (their iCalendar UID starts with ou-demo-)."""
        ids = list(self.demo_ids(folder).values())
        if folder == "INBOX":
            typ, data = self.c.uid("SEARCH", None, "BODY", org.UID_PREFIX)
            if typ == "OK" and data and data[0]:
                ids += [x for x in data[0].split() if x not in ids]
        for uid in ids:
            self.c.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
        if ids:
            self.c.expunge()
        return len(ids)


# ================================================================ CalDAV
NS = {"d": "DAV:", "c": "urn:ietf:params:xml:ns:caldav"}
_PROPFIND = '<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop>{}</d:prop></d:propfind>'


class Dav:
    def __init__(self, client: httpx.Client, base: str, user: str, password: str):
        self.h, self.base = client, base.rstrip("/") + "/"
        self.auth = httpx.BasicAuth(user, password)
        self.events: str | None = None
        self.tasks: str | None = None
        self.home: str | None = None

    def _req(self, method: str, url: str, **kw) -> httpx.Response:
        r = self.h.request(method, urljoin(self.base, url), auth=self.auth, **kw)
        if r.status_code == 401:
            raise LoginFailed("CalDAV sign-in refused")
        return r

    def _propfind(self, url: str, props: str, depth: str = "0") -> ET.Element:
        r = self._req("PROPFIND", url, headers={"Depth": depth, "Content-Type": "application/xml"}, content=_PROPFIND.format(props))
        if r.status_code != 207:
            raise SeedError(f"CalDAV PROPFIND {urlsplit(url).path} answered {r.status_code}")
        return ET.fromstring(r.content)

    def discover(self) -> None:
        x = self._propfind(self.base, "<d:current-user-principal/>")
        principal = x.findtext(".//d:current-user-principal/d:href", namespaces=NS)
        x = self._propfind(principal, "<c:calendar-home-set/>")
        self.home = x.findtext(".//c:calendar-home-set/d:href", namespaces=NS)
        x = self._propfind(self.home, "<d:resourcetype/><d:displayname/><c:supported-calendar-component-set/>", "1")
        for resp in x.findall("d:response", NS):
            href = resp.findtext("d:href", namespaces=NS)
            if resp.find(".//d:resourcetype/c:calendar", NS) is None:
                continue
            comps = {e.get("name") for e in resp.findall(".//c:supported-calendar-component-set/c:comp", NS)}
            name = (resp.findtext(".//d:displayname", namespaces=NS) or "").lower()
            if "VTODO" in comps and self.tasks is None:
                self.tasks = href
            elif ("VEVENT" in comps or not comps) and self.events is None and name in ("calendar", "kalender", ""):
                self.events = href
            elif "VEVENT" in comps and self.events is None:
                self.events = href
        if not self.events:
            raise SeedError("no event calendar found")

    def collection(self, name: str) -> str:
        if name == "events":
            return self.events
        if name == "tasks":
            if not self.tasks:
                raise SeedError("no task list found")
            return self.tasks
        return self.home.rstrip("/") + "/" + name + "/"

    def exists(self, url: str) -> bool:
        r = self._req("PROPFIND", url, headers={"Depth": "0", "Content-Type": "application/xml"}, content=_PROPFIND.format("<d:resourcetype/>"))
        return r.status_code == 207

    def mkcalendar(self, url: str, name: str) -> bool:
        if self.exists(url):
            return False
        body = ('<?xml version="1.0"?><c:mkcalendar xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:set><d:prop>'
                f'<d:displayname>{_xesc(name)}</d:displayname><c:supported-calendar-component-set><c:comp name="VEVENT"/>'
                '</c:supported-calendar-component-set></d:prop></d:set></c:mkcalendar>')
        r = self._req("MKCALENDAR", url, content=body, headers={"Content-Type": "application/xml"})
        if r.status_code not in (201, 405):
            raise SeedError(f"MKCALENDAR answered {r.status_code}")
        return r.status_code == 201

    def put_once(self, url: str, ics: str) -> bool:
        """PUT with If-None-Match: *. Callers check uids() first: grommunio-dav stores an object under a name derived from its UID,
        not the requested one, so this header alone never sees an existing object there (first real run 2026-11-27). True = created."""
        r = self._req("PUT", url, content=ics.encode(), headers={"Content-Type": "text/calendar; charset=utf-8", "If-None-Match": "*"})
        if r.status_code in (201, 204):
            return True
        if r.status_code == 412:
            return False
        raise SeedError(f"CalDAV PUT answered {r.status_code}")

    def uids(self, collection: str) -> dict[str, str]:
        """UID -> href of every event and task in the collection, read from the objects themselves (a plain calendar-query with
        calendar-data: grommunio-dav does not answer UID text-match filters)."""
        body = ('<?xml version="1.0"?><c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/>'
                '<c:calendar-data/></d:prop><c:filter><c:comp-filter name="VCALENDAR"><c:comp-filter name="{}"/></c:comp-filter></c:filter>'
                '</c:calendar-query>')
        out: dict[str, str] = {}
        for comp in ("VEVENT", "VTODO"):
            r = self._req("REPORT", collection, content=body.format(comp), headers={"Depth": "1", "Content-Type": "application/xml"})
            if r.status_code != 207:
                continue
            for resp in ET.fromstring(r.content).findall("d:response", NS):
                href, data = resp.findtext("d:href", namespaces=NS), resp.findtext(".//c:calendar-data", namespaces=NS) or ""
                m = re.search(r"^UID:(.+?)\r?$", data.replace("\r\n ", "").replace("\n ", ""), re.M)
                if href and m and not href.endswith("/"):
                    out.setdefault(m.group(1).strip(), href)
        return out

    def demo_hrefs(self, collection: str) -> list[str]:
        """Objects in the collection whose UID starts with ou-demo- (this tool's own and the server's scheduling copies)."""
        return sorted({h for u, h in self.uids(collection).items() if u.startswith(org.UID_PREFIX)})

    def delete(self, url: str) -> bool:
        return self._req("DELETE", url).status_code in (200, 204)

    def calendars(self) -> list[str]:
        x = self._propfind(self.home, "<d:resourcetype/>", "1")
        return [r.findtext("d:href", namespaces=NS) for r in x.findall("d:response", NS) if r.find(".//d:resourcetype/c:calendar", NS) is not None]


# ================================================================ sign-in (OIDC / SSO, as the person)
class _Forms(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []
        self.links: list[str] = []
        self._cur = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._cur = {"action": a.get("action") or "", "method": (a.get("method") or "get").lower(), "id": a.get("id") or "", "inputs": {}}
            self.forms.append(self._cur)
        elif tag in ("input", "button") and self._cur is not None and a.get("name"):
            if tag == "input" and (a.get("type") or "text").lower() in ("hidden", "text", "email", "password", "submit"):
                self._cur["inputs"].setdefault(a["name"], a.get("value") or "")
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur = None


def sign_in(h: httpx.Client, start: str, username: str, password: str, stop: str, max_steps: int = 20) -> str:
    """Walks the application's sign-in like a browser (cookies kept by the client): redirects, MAS's 'continue with' link and consent
    form, and the Keycloak login form (filled with the person's own credentials). Returns the first redirect to `stop`, which is never
    requested. Refuses any host outside the demo domain (the client's HostGuard). Cookies are cleared first, so every person signs
    in on their own (never riding on the previous person's Keycloak or MAS session)."""
    h.cookies.clear()
    r = h.get(start)
    sent_password = False
    for _ in range(max_steps):
        if r.status_code in (301, 302, 303, 307, 308):
            loc = urljoin(str(r.url), r.headers.get("location", ""))
            if loc.startswith(stop):
                return loc
            r = h.get(loc)
            continue
        if r.status_code != 200:
            raise SeedError(f"sign-in stopped at {urlsplit(str(r.url)).path} (HTTP {r.status_code})")
        p = _Forms()
        p.feed(r.text)
        login = next((f for f in p.forms if "password" in f["inputs"] or f["id"] == "kc-form-login"), None)
        if login is not None:
            if sent_password:
                raise LoginFailed(f"the sign-in for {username} was refused")
            data = {**login["inputs"], "username": username, "password": password}
            data.pop("login", None)
            sent_password = True
            r = h.post(urljoin(str(r.url), login["action"]), data=data)
            continue
        upstream = next((x for x in p.links if "/upstream/authorize/" in x), None)
        if upstream:
            r = h.get(urljoin(str(r.url), upstream))
            continue
        post = [f for f in p.forms if f["method"] == "post"]
        if len(post) >= 1:
            f = next((x for x in post if "csrf" in x["inputs"]), post[0])   # MAS consent / continue page
            r = h.post(urljoin(str(r.url), f["action"] or str(r.url)), data=f["inputs"])
            continue
        raise SeedError(f"sign-in stopped at {urlsplit(str(r.url)).path}: no form to continue")
    raise SeedError("sign-in did not finish")


def oidc_token(h: httpx.Client, issuer: str, client_id: str, username: str, password: str, scope: str = "openid profile email") -> str:
    """Authorization code + PKCE as the public client (no client secret); the redirect target is the loopback address the realm
    registers for that client and is never contacted."""
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(16)
    q = {"client_id": client_id, "response_type": "code", "redirect_uri": LOOPBACK, "scope": scope, "state": state,
         "code_challenge": challenge, "code_challenge_method": "S256"}
    loc = sign_in(h, f"{issuer}/protocol/openid-connect/auth?{urlencode(q)}", username, password, LOOPBACK)
    got = parse_qs(urlsplit(loc).query)
    if got.get("state", [""])[0] != state or "code" not in got:
        raise SeedError("the sign-in returned no authorization code")
    r = h.post(f"{issuer}/protocol/openid-connect/token", data={"grant_type": "authorization_code", "code": got["code"][0],
                                                                "redirect_uri": LOOPBACK, "client_id": client_id, "code_verifier": verifier})
    if r.status_code != 200:
        raise SeedError(f"token exchange answered {r.status_code}")
    return r.json()["access_token"]


# ================================================================ OpenCloud
_WD = '<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:fileid/></d:prop></d:propfind>'


class Files:
    def __init__(self, h: httpx.Client, base: str, token: str):
        self.h, self.base = h, base.rstrip("/")
        self.hd = {"Authorization": f"Bearer {token}"}
        self.drive_id: str | None = None
        self.dav: str | None = None

    def _r(self, method: str, url: str, **kw) -> httpx.Response:
        r = self.h.request(method, url if url.startswith("https://") else self.base + url, headers={**self.hd, **kw.pop("headers", {})}, **kw)
        if r.status_code == 401:
            raise LoginFailed("OpenCloud refused the token")
        return r

    def open_drive(self) -> None:
        r = self._r("GET", "/graph/v1.0/me/drives")
        if r.status_code != 200:
            raise SeedError(f"OpenCloud drives answered {r.status_code}")
        d = next((x for x in r.json().get("value", []) if x.get("driveType") == "personal"), None)
        if d is None:
            raise SeedError("no personal space")
        self.drive_id, self.dav = d["id"], d["root"]["webDavUrl"].rstrip("/")

    def _u(self, path: str) -> str:
        return self.dav + "/" + "/".join(quote(p) for p in path.strip("/").split("/"))

    def item_id(self, path: str) -> str | None:
        r = self._r("PROPFIND", self._u(path), content=_WD, headers={"Depth": "0", "Content-Type": "application/xml"})
        if r.status_code != 207:
            return None
        return ET.fromstring(r.content).findtext(".//{http://owncloud.org/ns}fileid")

    def mkdirs(self, path: str) -> int:
        made, cur = 0, ""
        for part in path.strip("/").split("/"):
            cur = f"{cur}/{part}" if cur else part
            r = self._r("MKCOL", self._u(cur))
            if r.status_code == 201:
                made += 1
            elif r.status_code not in (405, 409):
                raise SeedError(f"MKCOL answered {r.status_code}")
        return made

    def put_if_absent(self, path: str, data: bytes, mime: str) -> bool:
        if self.item_id(path):
            return False
        r = self._r("PUT", self._u(path), content=data, headers={"Content-Type": mime})
        if r.status_code not in (201, 204):
            raise SeedError(f"PUT answered {r.status_code}")
        return True

    def delete(self, path: str) -> bool:
        return self._r("DELETE", self._u(path)).status_code in (204, 200)

    def user_id(self, uid: str, email: str) -> str:
        r = self._r("GET", "/graph/v1.0/users", params={"$search": f'"{uid}"'})
        for u in (r.json().get("value", []) if r.status_code == 200 else []):
            if (u.get("mail") or "").lower() == email.lower() or u.get("onPremisesSamAccountName") == uid:
                return u["id"]
        raise SeedError(f"OpenCloud does not know {uid}")

    def share(self, item: str, recipient_id: str, role: str) -> bool:
        """Invites one person to a folder with the edit or view role; an existing grant is kept. True = invited now."""
        base = f"/graph/v1beta1/drives/{quote(self.drive_id, safe='')}/items/{quote(item, safe='')}"
        r = self._r("GET", base + "/permissions")
        if r.status_code != 200:
            raise SeedError(f"permissions answered {r.status_code}")
        body = r.json()
        for p in body.get("value", []):
            if ((p.get("grantedToV2") or {}).get("user") or {}).get("id") == recipient_id:
                return False
        role_id = pick_role(body.get("@libre.graph.permissions.roles.allowedValues", []), role)
        r = self._r("POST", base + "/invite", json={"roles": [role_id], "recipients": [{"objectId": recipient_id,
                                                                                    "@libre.graph.recipient.type": "user"}]})
        if r.status_code not in (200, 201):
            raise SeedError(f"invite answered {r.status_code}")
        return True


def pick_role(allowed: list[dict], role: str) -> str:
    """The role offered by OpenCloud for this item: 'edit' -> the highest-weighted role that can upload/edit, 'view' -> the
    lowest-weighted (viewer). Chosen from the server's own list, never a hard-coded id."""
    if not allowed:
        raise SeedError("OpenCloud offered no sharing roles")
    ranked = sorted(allowed, key=lambda r: r.get("@libre.graph.weight", 0))
    if role == "view":
        return next((r["id"] for r in ranked if "view" in (r.get("displayName") or "").lower()), ranked[0]["id"])
    return next((r["id"] for r in reversed(ranked) if "edit" in (r.get("displayName") or "").lower()), ranked[-1]["id"])


# ================================================================ Matrix
def _mx_err(r: httpx.Response) -> str:
    """Matrix error code and text (never request content): makes a refusal diagnosable from the seed's output."""
    try:
        j = r.json()
    except ValueError:
        return ""
    return f"{j.get('errcode', '')}: {str(j.get('error', ''))[:160]}" if isinstance(j, dict) else ""


class Matrix:
    def __init__(self, h: httpx.Client, base: str, token: str):
        self.h, self.base = h, base.rstrip("/")
        self.hd = {"Authorization": f"Bearer {token}"}
        self.user_id: str | None = None

    @classmethod
    def login(cls, h: httpx.Client, base: str, username: str, password: str) -> "Matrix":
        """MAS compatibility SSO: /login/sso/redirect -> MAS -> the deployment's Keycloak -> loginToken -> m.login.token."""
        stop = LOOPBACK + "/ou-demo-sso"
        loc = sign_in(h, f"{base.rstrip('/')}/_matrix/client/v3/login/sso/redirect?{urlencode({'redirectUrl': stop})}", username, password, stop)
        tok = parse_qs(urlsplit(loc).query).get("loginToken", [None])[0]
        if not tok:
            raise SeedError("the chat sign-in returned no login token")
        r = h.post(f"{base.rstrip('/')}/_matrix/client/v3/login", json={"type": "m.login.token", "token": tok,
                                                                        "initial_device_display_name": "Office Unbound demo seed"})
        if r.status_code != 200:
            raise SeedError(f"chat login answered {r.status_code}")
        m = cls(h, base, r.json()["access_token"])
        m.user_id = r.json().get("user_id")
        return m

    def _r(self, method: str, path: str, **kw) -> httpx.Response:
        for _ in range(5):
            r = self.h.request(method, self.base + "/_matrix/client/v3" + path, headers=self.hd, **kw)
            if r.status_code == 429:
                time.sleep(min(10, (r.json().get("retry_after_ms") or 1000) / 1000))
                continue
            return r
        return r

    def alias_room(self, alias: str) -> str | None:
        r = self._r("GET", "/directory/room/" + quote(alias, safe=""))
        return r.json()["room_id"] if r.status_code == 200 else None

    def create_room(self, local_alias: str, name: str, topic: str, invite: list[str], direct: bool) -> str:
        body = {"room_alias_name": local_alias, "visibility": "private", "preset": "trusted_private_chat" if direct else "private_chat",
                "invite": invite, "is_direct": direct, "creation_content": {"ou.demo.seed": org.SEED_TAG}}
        if name:
            body["name"] = name
        if topic:
            body["topic"] = topic
        r = self._r("POST", "/createRoom", json=body)
        if r.status_code != 200:
            raise SeedError(f"createRoom answered {r.status_code} {_mx_err(r)}")
        return r.json()["room_id"]

    def members(self, room: str) -> dict[str, str]:
        r = self._r("GET", f"/rooms/{quote(room)}/members")
        if r.status_code != 200:
            return {}
        return {e["state_key"]: e["content"].get("membership") for e in r.json().get("chunk", [])}

    def invite(self, room: str, user: str) -> None:
        self._r("POST", f"/rooms/{quote(room)}/invite", json={"user_id": user})

    def join(self, room: str) -> bool:
        return self._r("POST", f"/join/{quote(room)}", json={}).status_code == 200

    def demo_ids(self, room: str) -> set[str]:
        r = self._r("GET", f"/rooms/{quote(room)}/messages", params={"dir": "b", "limit": "500",
                                                                     "filter": json.dumps({"types": ["m.room.message"]})})
        if r.status_code != 200:
            return set()
        return {e["content"]["ou.demo.id"] for e in r.json().get("chunk", []) if isinstance(e.get("content"), dict) and e["content"].get("ou.demo.id")}

    def send(self, room: str, demo_id: str, text: str) -> None:
        r = self._r("PUT", f"/rooms/{quote(room)}/send/m.room.message/{quote(org.UID_PREFIX + demo_id)}",
                    json={"msgtype": "m.text", "body": text, "ou.demo.id": demo_id})
        if r.status_code != 200:
            raise SeedError(f"send answered {r.status_code}")

    def mark_direct(self, other: str, room: str) -> None:
        r = self._r("GET", f"/user/{quote(self.user_id)}/account_data/m.direct")
        cur = r.json() if r.status_code == 200 else {}
        if room in cur.get(other, []):
            return
        cur.setdefault(other, []).append(room)
        self._r("PUT", f"/user/{quote(self.user_id)}/account_data/m.direct", json=cur)

    def leave(self, room: str) -> None:
        self._r("POST", f"/rooms/{quote(room)}/leave", json={})
        self._r("POST", f"/rooms/{quote(room)}/forget", json={})

    def delete_alias(self, alias: str) -> None:
        self._r("DELETE", "/directory/room/" + quote(alias, safe=""))

    def logout(self) -> None:
        self._r("POST", "/logout", json={})
