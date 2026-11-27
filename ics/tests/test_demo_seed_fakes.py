"""In-memory stand-ins for the demo deployment's applications (no test here): an IMAP server, and one httpx MockTransport serving
grommunio-dav (CalDAV), Keycloak (login form + token endpoint), OpenCloud (Graph + WebDAV), MAS (compat SSO) and Synapse (client API).
They implement only what ics/demo/clients.py uses, with the real protocols' status codes, and record every request host so the tests
can prove nothing outside the demo domain was contacted."""
from __future__ import annotations

import json
import re
from email import message_from_bytes
from urllib.parse import parse_qs, quote, unquote, urlencode

import httpx

DOMAIN = "demo.example.org"
REALM = "ou"


# ================================================================ IMAP
class ImapServer:
    def __init__(self, passwords: dict[str, str]):
        self.passwords = passwords                          # email -> password
        self.boxes: dict[str, dict[str, list]] = {}         # email -> folder -> [[uid, flags(set), raw]]
        self.next_uid = 1
        self.logins: list[tuple[str, int]] = []

    def factory(self, host, port):
        self.logins.append((host, port))
        return _ImapConn(self)


class _ImapConn:
    def __init__(self, srv: ImapServer):
        self.s, self.user, self.sel = srv, None, None

    def login(self, user, pw):
        if self.s.passwords.get(user) != pw:
            return "NO", [b"auth failed"]
        self.user = user
        self.s.boxes.setdefault(user, {"INBOX": [], "Sent Items": []})
        return "OK", [b"ok"]

    def logout(self):
        return "BYE", []

    def list(self):
        return "OK", [b'(\\HasNoChildren) "/" "INBOX"', b'(\\HasNoChildren \\Sent) "/" "Sent Items"']

    def _box(self):
        return self.s.boxes[self.user][self.sel]

    def select(self, name):
        self.sel = name.strip('"')
        if self.sel not in self.s.boxes[self.user]:
            return "NO", [b"no such folder"]
        return "OK", [str(len(self._box())).encode()]

    def append(self, folder, flags, date, raw):
        f = folder.strip('"')
        self.s.boxes[self.user][f].append([self.s.next_uid, set(flags.strip("()").split()), raw])
        self.s.next_uid += 1
        return "OK", [b"appended"]

    def uid(self, cmd, *args):
        box = self._box()
        if cmd == "FETCH":
            out = []
            for uid, _fl, raw in box:
                m = message_from_bytes(raw)
                hdr = f"X-OU-Demo-Id: {m['X-OU-Demo-Id']}\r\n\r\n".encode() if m["X-OU-Demo-Id"] else b"\r\n"
                out.append((f"1 (UID {uid} BODY[HEADER.FIELDS (X-OU-DEMO-ID)] {{{len(hdr)}}}".encode(), hdr))
                out.append(b")")
            return "OK", out
        if cmd == "SEARCH":
            needle = args[-1].encode()
            return "OK", [b" ".join(str(u).encode() for u, _f, raw in box if needle in raw and not message_from_bytes(raw)["X-OU-Demo-Id"])]
        if cmd == "STORE":
            uid, op, flags = args
            for row in box:
                if str(row[0]).encode() == uid or str(row[0]) == str(uid):
                    fl = set(flags.strip("()").split())
                    row[1] = row[1] | fl if op.startswith("+") else fl
            return "OK", []
        raise AssertionError(cmd)

    def expunge(self):
        self.s.boxes[self.user][self.sel] = [r for r in self._box() if "\\Deleted" not in r[1]]
        return "OK", []


# ================================================================ HTTP: one transport for every application of the demo deployment
class Apps:
    def __init__(self, passwords: dict[str, str], domain: str = DOMAIN):
        self.d = domain
        self.pw = passwords                     # uid -> password
        self.hosts: list[str] = []
        self.cal: dict[str, dict[str, dict[str, str]]] = {}     # email -> collection -> href -> ics
        self.dav: dict[str, dict[str, bytes | None]] = {}       # uid -> path -> bytes (None = folder)
        self.perms: dict[tuple[str, str], list[dict]] = {}      # (owner uid, path) -> permissions
        self.codes: dict[str, str] = {}                          # code -> uid
        self.rooms: dict[str, dict] = {}
        self.aliases: dict[str, str] = {}
        self.acct: dict[str, dict] = {}
        self.tokens: dict[str, str] = {}                         # matrix token -> user id
        self.logged_out = 0
        self.kc_logins: list[str] = []

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    # ------------------------------------------------------------ dispatch
    def handle(self, req: httpx.Request) -> httpx.Response:
        host = req.url.host
        self.hosts.append(host)
        assert host == self.d or host.endswith("." + self.d), f"request outside the demo domain: {host}"
        assert req.url.scheme == "https"
        sub = host[: -len(self.d) - 1]
        return {"mail": self._dav_h, "auth": self._kc, "cloud": self._oc, "matrix": self._mx, "mas": self._mas}[sub](req)

    # ------------------------------------------------------------ CalDAV
    def _basic(self, req) -> str | None:
        import base64
        a = req.headers.get("authorization", "")
        if not a.startswith("Basic "):
            return None
        user, _, pw = base64.b64decode(a[6:]).decode().partition(":")
        uid = user.split("@")[0]
        return user if self.pw.get(uid) == pw else None

    def _ms(self, items: list[tuple[str, str]]) -> httpx.Response:
        body = '<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">' + "".join(
            f"<d:response><d:href>{h}</d:href><d:propstat><d:prop>{p}</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
            for h, p in items) + "</d:multistatus>"
        return httpx.Response(207, content=body.encode())

    def _dav_h(self, req) -> httpx.Response:
        user = self._basic(req)
        if user is None:
            return httpx.Response(401)
        cals = self.cal.setdefault(user, {"Calendar": {}, "Tasks": {}})
        path = unquote(req.url.path)
        home = f"/dav/calendars/{user}/"
        if req.method == "PROPFIND":
            body = req.content.decode()
            if path == "/dav/":
                return self._ms([("/dav/", f"<d:current-user-principal><d:href>/dav/principals/{user}/</d:href></d:current-user-principal>")])
            if path.startswith("/dav/principals/"):
                return self._ms([(path, f"<c:calendar-home-set><d:href>{home}</d:href></c:calendar-home-set>")])
            if path == home:
                items = [(home, "<d:resourcetype><d:collection/></d:resourcetype>")]
                for name in cals:
                    comp = "VTODO" if name == "Tasks" else "VEVENT"
                    items.append((home + name + "/", f"<d:resourcetype><d:collection/><c:calendar/></d:resourcetype><d:displayname>{name}</d:displayname>"
                                  f'<c:supported-calendar-component-set><c:comp name="{comp}"/></c:supported-calendar-component-set>'))
                return self._ms(items)
            name = path[len(home):].strip("/")
            if name in cals and "resourcetype" in body:
                return self._ms([(path, "<d:resourcetype><d:collection/><c:calendar/></d:resourcetype>")])
            return httpx.Response(404)
        col, _, obj = path[len(home):].partition("/")
        if req.method == "MKCALENDAR":
            if col in cals:
                return httpx.Response(405)
            cals[col] = {}
            return httpx.Response(201)
        if req.method == "PUT":
            if col not in cals:
                return httpx.Response(409)
            if obj in cals[col] and req.headers.get("if-none-match") == "*":
                return httpx.Response(412)
            cals[col][obj] = req.content.decode()
            self._schedule(user, req.content.decode())
            return httpx.Response(201)
        if req.method == "REPORT":
            m = re.search(r'comp-filter name="(VEVENT|VTODO)"><c:prop-filter name="UID"><c:text-match[^>]*>([^<]+)<', req.content.decode())
            comp, needle = m.group(1), m.group(2)
            return self._ms([(f"{home}{col}/{h}", "<d:getetag>\"1\"</d:getetag>") for h, ics in cals.get(col, {}).items()
                             if f"BEGIN:{comp}" in ics and re.search(r"^UID:" + re.escape(needle), ics, re.M)])
        if req.method == "DELETE":
            if obj:
                return httpx.Response(204) if cals.get(col, {}).pop(obj, None) is not None else httpx.Response(404)
            return httpx.Response(204) if cals.pop(col, None) is not None else httpx.Response(404)
        raise AssertionError(req.method)

    def _schedule(self, organizer: str, ics: str) -> None:
        """What grommunio-dav's scheduling does for local attendees: a copy in each attendee's calendar."""
        if "ORGANIZER" not in ics:
            return
        for a in re.findall(r"^ATTENDEE[^\n]*mailto:([^\r\n]+)", ics.replace("\r\n ", ""), re.M):
            uid = re.search(r"^UID:(\S+)", ics, re.M).group(1)
            self.cal.setdefault(a, {"Calendar": {}, "Tasks": {}})["Calendar"][f"sched-{uid}.ics"] = ics

    # ------------------------------------------------------------ Keycloak
    LOGIN_FORM = ('<html><body><form id="kc-form-login" action="/realms/ou/login-actions/authenticate?session_code=s1" method="post">'
                  '<input name="username" type="text"/><input name="password" type="password"/><input type="hidden" name="credentialId" value=""/>'
                  '<input name="login" type="submit" value="Sign In"/></form></body></html>')

    def _kc(self, req) -> httpx.Response:
        p = req.url.path
        if p == f"/realms/{REALM}/protocol/openid-connect/auth":
            q = dict(req.url.params)
            return httpx.Response(200, html=self.LOGIN_FORM, headers={"set-cookie": "AUTH_SESSION_ID=" + quote(json.dumps(q), safe="") + "; Path=/realms/ou/"})
        if p == f"/realms/{REALM}/login-actions/authenticate":
            form = parse_qs(req.content.decode(), keep_blank_values=True)
            uid, pw = form["username"][0], form["password"][0]
            q = json.loads(unquote(req.headers.get("cookie", "").split("AUTH_SESSION_ID=")[1].split(";")[0]))
            if self.pw.get(uid) != pw or "credentialId" not in form:
                return httpx.Response(200, html=self.LOGIN_FORM)
            self.kc_logins.append(uid)
            code = f"code-{uid}-{len(self.codes)}"
            self.codes[code] = uid
            return httpx.Response(302, headers={"location": q["redirect_uri"] + "?" + urlencode({"code": code, "state": q["state"]})})
        if p == f"/realms/{REALM}/protocol/openid-connect/token":
            form = parse_qs(req.content.decode())
            assert form["client_id"] == ["OpenCloudDesktop"] and form["code_verifier"] and form["redirect_uri"] == ["http://127.0.0.1"]
            uid = self.codes.pop(form["code"][0])
            return httpx.Response(200, json={"access_token": f"oc-{uid}", "token_type": "Bearer"})
        raise AssertionError(p)

    # ------------------------------------------------------------ OpenCloud
    def _oc(self, req) -> httpx.Response:
        a = req.headers.get("authorization", "")
        if not a.startswith("Bearer oc-"):
            return httpx.Response(401)
        uid = a[len("Bearer oc-"):]
        files = self.dav.setdefault(uid, {})
        p = unquote(req.url.path)
        if p == "/graph/v1.0/me/drives":
            return httpx.Response(200, json={"value": [{"id": f"drive-{uid}", "driveType": "personal",
                                                        "root": {"webDavUrl": f"https://cloud.{self.d}/dav/spaces/drive-{uid}"}}]})
        if p == "/graph/v1.0/users":
            s = req.url.params["$search"].strip('"')
            return httpx.Response(200, json={"value": [{"id": f"id-{s}", "mail": f"{s}@{self.d}", "onPremisesSamAccountName": s}]})
        m = re.match(r"/graph/v1beta1/drives/drive-([^/]+)/items/([^/]+)/(permissions|invite)$", req.url.raw_path.decode().split("?")[0])
        if m:
            owner, item, what = unquote(m.group(1)), unquote(m.group(2)), m.group(3)
            key = (owner, item)
            perms = self.perms.setdefault(key, [])
            if what == "permissions":
                return httpx.Response(200, json={"value": perms, "@libre.graph.permissions.roles.allowedValues": [
                    {"id": "role-viewer", "displayName": "Can view", "@libre.graph.weight": 1},
                    {"id": "role-upload", "displayName": "Can upload", "@libre.graph.weight": 2},
                    {"id": "role-editor", "displayName": "Can edit", "@libre.graph.weight": 3}]})
            b = json.loads(req.content)
            perms.append({"id": f"perm-{len(perms)}", "roles": b["roles"], "grantedToV2": {"user": {"id": b["recipients"][0]["objectId"]}}})
            return httpx.Response(200, json={"value": [perms[-1]]})
        prefix = f"/dav/spaces/drive-{uid}/"
        assert p.startswith(prefix), p
        path = p[len(prefix):]
        parent = path.rsplit("/", 1)[0] if "/" in path else ""
        if req.method == "MKCOL":
            if path in files:
                return httpx.Response(405)
            if parent and parent not in files:
                return httpx.Response(409)
            files[path] = None
            return httpx.Response(201)
        if req.method == "PUT":
            if parent and files.get(parent, 0) is not None:
                return httpx.Response(409)
            files[path] = req.content
            return httpx.Response(201)
        if req.method == "PROPFIND":
            if path not in files:
                return httpx.Response(404)
            return httpx.Response(207, content=(f'<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>{quote(p)}</d:href>'
                                                f"<d:propstat><d:prop><oc:fileid>{quote(path, safe='')}</oc:fileid></d:prop></d:propstat></d:response></d:multistatus>").encode())
        if req.method == "DELETE":
            gone = [k for k in files if k == path or k.startswith(path + "/")]
            for k in gone:
                files.pop(k)
            return httpx.Response(204 if gone else 404)
        raise AssertionError(req.method)

    # ------------------------------------------------------------ MAS (compat SSO) and Synapse
    def _mas(self, req) -> httpx.Response:
        p = req.url.path
        if p == "/complete-compat-sso/abc":
            if req.method == "GET":
                if "mas_session" in req.headers.get("cookie", ""):
                    return httpx.Response(200, html='<form method="post" action="/complete-compat-sso/abc"><input type="hidden" name="csrf" value="c1"/>'
                                                    '<button type="submit">Continue</button></form>')
                return httpx.Response(200, html='<a href="/upstream/authorize/P1">Continue with Office Unbound</a>')
            assert parse_qs(req.content.decode()).get("csrf") == ["c1"]
            uid = req.headers["cookie"].split("mas_session=")[1].split(";")[0]
            redirect = req.headers["cookie"].split("mas_redirect=")[1].split(";")[0]
            return httpx.Response(302, headers={"location": unquote(redirect) + "?loginToken=lt-" + uid})
        if p == "/upstream/authorize/P1":
            q = {"client_id": "mas", "redirect_uri": f"https://mas.{self.d}/upstream/callback/P1", "state": "st"}
            return httpx.Response(302, headers={"location": f"https://auth.{self.d}/realms/{REALM}/protocol/openid-connect/auth?" + urlencode(q)})
        if p == "/upstream/callback/P1":
            uid = self.codes.pop(req.url.params["code"])
            return httpx.Response(302, headers={"location": f"https://mas.{self.d}/complete-compat-sso/abc", "set-cookie": f"mas_session={uid}; Path=/"})
        raise AssertionError(p)

    def _mx(self, req) -> httpx.Response:
        p = unquote(req.url.raw_path.decode().split("?")[0])
        base = "/_matrix/client/v3"
        assert p.startswith(base), p
        p = p[len(base):]
        if p == "/login/sso/redirect":
            r = req.url.params["redirectUrl"]
            return httpx.Response(302, headers={"location": f"https://mas.{self.d}/complete-compat-sso/abc",
                                                "set-cookie": f"mas_redirect={quote(r, safe='')}; Domain={self.d}; Path=/"})
        if p == "/login":
            b = json.loads(req.content)
            uid = b["token"][len("lt-"):]
            tok = f"mx-{uid}-{len(self.tokens)}"
            self.tokens[tok] = f"@{uid}:matrix.{self.d}"
            return httpx.Response(200, json={"access_token": tok, "user_id": self.tokens[tok]})
        me = self.tokens.get(req.headers.get("authorization", "")[len("Bearer "):])
        if me is None:
            return httpx.Response(401)
        if p == "/logout":
            self.tokens = {k: v for k, v in self.tokens.items() if k != req.headers["authorization"][7:]}
            self.logged_out += 1
            return httpx.Response(200, json={})
        if p.startswith("/directory/room/"):
            alias = p[len("/directory/room/"):]
            if req.method == "DELETE":
                self.aliases.pop(alias, None)
                return httpx.Response(200, json={})
            return httpx.Response(200, json={"room_id": self.aliases[alias]}) if alias in self.aliases else httpx.Response(404, json={"errcode": "M_NOT_FOUND"})
        if p == "/createRoom":
            b = json.loads(req.content)
            alias = f"#{b['room_alias_name']}:matrix.{self.d}"
            if alias in self.aliases:
                return httpx.Response(400, json={"errcode": "M_ROOM_IN_USE"})
            rid = f"!r{len(self.rooms)}:matrix.{self.d}"
            self.rooms[rid] = {"members": {me: "join", **{u: "invite" for u in b["invite"]}}, "events": [], "body": b}
            self.aliases[alias] = rid
            return httpx.Response(200, json={"room_id": rid})
        m = re.match(r"/rooms/([^/]+)/(members|invite|messages|send/m\.room\.message/.+|leave|forget)$", p)
        if m:
            room = self.rooms[m.group(1)]
            what = m.group(2)
            if what == "members":
                return httpx.Response(200, json={"chunk": [{"state_key": u, "content": {"membership": s}} for u, s in room["members"].items()]})
            if what == "invite":
                u = json.loads(req.content)["user_id"]
                if room["members"].get(u) == "join":
                    return httpx.Response(403, json={"errcode": "M_FORBIDDEN"})
                room["members"][u] = "invite"
                return httpx.Response(200, json={})
            if what == "messages":
                return httpx.Response(200, json={"chunk": [{"content": e} for e in reversed(room["events"])]})
            if what.startswith("send/"):
                assert room["members"].get(me) == "join", "sender is not in the room"
                room["events"].append({**json.loads(req.content), "sender": me})
                return httpx.Response(200, json={"event_id": f"$e{len(room['events'])}"})
            if what == "leave":
                room["members"][me] = "leave"
            return httpx.Response(200, json={})
        m = re.match(r"/join/(.+)$", p)
        if m:
            room = self.rooms[m.group(1)]
            if room["members"].get(me) not in ("invite", "join"):
                return httpx.Response(403, json={"errcode": "M_FORBIDDEN"})
            room["members"][me] = "join"
            return httpx.Response(200, json={"room_id": m.group(1)})
        m = re.match(r"/user/([^/]+)/account_data/m\.direct$", p)
        if m:
            if req.method == "GET":
                return httpx.Response(200, json=self.acct[me]) if me in self.acct else httpx.Response(404, json={"errcode": "M_NOT_FOUND"})
            self.acct[me] = json.loads(req.content)
            return httpx.Response(200, json={})
        raise AssertionError(p)
