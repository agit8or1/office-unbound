"""Loopback fake HTTP server standing in for Microsoft Graph, Entra token endpoint, Google Admin SDK/Reports/Gmail/Drive
and OAuth token endpoint. Serves recorded-shape fixtures (tests/fixtures). No traffic leaves the machine."""
from __future__ import annotations

import base64
import json
import os
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def fixture(rel: str, base: str = "") -> bytes:
    with open(os.path.join(FIX, rel), "rb") as f:
        return f.read().replace(b"{base}", base.encode())


class Req:
    def __init__(self, method, path, query, headers, body):
        self.method, self.path, self.query, self.headers, self.body = method, path, query, headers, body

    @property
    def auth(self):
        return self.headers.get("Authorization")


class FakeServer:
    def __init__(self):
        self.requests: list[Req] = []
        self.routes: dict[tuple[str, str], object] = {}
        self.queues: dict[tuple[str, str], list] = {}   # scripted one-shot responses, consumed first
        self.lock = threading.Lock()
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _do(self, method):
                u = urllib.parse.urlsplit(self.path)
                n = int(self.headers.get("Content-Length") or 0)
                req = Req(method, urllib.parse.unquote(u.path), urllib.parse.parse_qs(u.query), self.headers, self.rfile.read(n) if n else b"")
                with outer.lock:
                    outer.requests.append(req)
                    q = outer.queues.get((method, req.path))
                    resp = q.pop(0) if q else None
                if resp is None:
                    h = outer.routes.get((method, req.path))
                    if h is None:
                        for (m, prefix), hh in outer.routes.items():
                            if m == method and prefix.endswith("*") and req.path.startswith(prefix[:-1]):
                                h = hh
                                break
                    resp = h(req) if callable(h) else h
                if resp is None:
                    resp = (404, {}, b'{"error":{"code":"NotFound","message":"no route"}}')
                status, headers, body = resp
                if isinstance(body, (dict, list)):
                    body = json.dumps(body).encode()
                    headers = {"Content-Type": "application/json", **headers}
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self._do("GET")

            def do_POST(self):
                self._do("POST")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=lambda: self.httpd.serve_forever(poll_interval=0.01), daemon=True)

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def script(self, method, path, responses):
        self.queues.setdefault((method, path), []).extend(responses)

    def seen(self, path_prefix):
        return [r for r in self.requests if r.path.startswith(path_prefix)]


def json_ok(rel, base):
    return (200, {"Content-Type": "application/json"}, fixture(rel, base))


# ---------------------------------------------------------------------------------------------------------------
GRAPH_TOKEN = "FAKE-GRAPH-TOKEN-0123456789"
GRAPH_SECRET = "s3cr3t-client-secret-VALUE"
TENANT = "84841066-274d-4ec0-a5c1-276be684bdd3"


def install_graph(s: FakeServer):
    b = s.base

    def token(req):
        form = urllib.parse.parse_qs(req.body.decode())
        if form.get("client_secret") != [GRAPH_SECRET] or form.get("grant_type") != ["client_credentials"] \
                or form.get("scope") != ["https://graph.microsoft.com/.default"]:
            return (401, {}, {"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret"})
        return (200, {}, {"token_type": "Bearer", "expires_in": 3599, "access_token": GRAPH_TOKEN})

    def authed(fn):
        def w(req):
            if req.auth != f"Bearer {GRAPH_TOKEN}":
                return (401, {}, {"error": {"code": "InvalidAuthenticationToken", "message": "bad token"}})
            return fn(req)
        return w

    s.routes[("POST", f"/login/{TENANT}/oauth2/v2.0/token")] = token
    s.routes[("GET", "/graph/v1.0/organization")] = authed(lambda r: json_ok("graph/organization.json", b))
    s.routes[("GET", "/graph/v1.0/domains")] = authed(lambda r: json_ok("graph/domains.json", b))
    s.routes[("GET", "/graph/v1.0/users")] = authed(
        lambda r: json_ok("graph/users_p2.json" if "PAGE2" in r.query.get("$skiptoken", [""])[0] else "graph/users_p1.json", b))
    s.routes[("GET", "/graph/v1.0/groups")] = authed(lambda r: json_ok("graph/groups.json", b))
    s.routes[("GET", "/graph/v1.0/groups/*")] = authed(lambda r: (200, {"Content-Type": "text/plain"}, b"3"))
    for rep, f in (("getMailboxUsageDetail", "mailbox_usage"), ("getOneDriveUsageAccountDetail", "onedrive_usage"),
                   ("getSharePointSiteUsageDetail", "sharepoint_usage")):
        s.routes[("GET", f"/graph/v1.0/reports/{rep}(period='D30')")] = authed(
            lambda r, f=f: (302, {"Location": f"{b}/download/{f}.csv"}, b""))
        # pre-authenticated download host: must be called WITHOUT Authorization
        s.routes[("GET", f"/download/{f}.csv")] = (lambda r, f=f: (200, {"Content-Type": "application/octet-stream"},
                                                                   b"\xef\xbb\xbf" + fixture(f"graph/{f}.csv")))
    s.routes[("GET", "/graph/v1.0/users/*")] = authed(lambda r: (200, {"Content-Type": "text/plain"}, b"7"))


# ---------------------------------------------------------------------------------------------------------------
def install_google(s: FakeServer, public_key, today_minus_data_day=3, today=None):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    import datetime as dt
    b = s.base
    s.issued = []

    def b64d(x):
        return base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))

    def token(req):
        form = urllib.parse.parse_qs(req.body.decode())
        if form.get("grant_type") != ["urn:ietf:params:oauth:grant-type:jwt-bearer"]:
            return (400, {}, {"error": "unsupported_grant_type"})
        h, c, sig = form["assertion"][0].split(".")
        try:
            public_key.verify(b64d(sig), f"{h}.{c}".encode(), padding.PKCS1v15(), hashes.SHA256())
        except Exception:
            return (400, {}, {"error": "invalid_grant", "error_description": "Invalid JWT Signature."})
        claims = json.loads(b64d(c))
        allowed = s.dwd_allowed
        for sc in claims["scope"].split():
            if sc not in allowed:
                return (401, {}, {"error": "unauthorized_client", "error_description": "Client is unauthorized to retrieve access tokens using this method, or client not authorized for any of the scopes requested."})
        s.issued.append(claims)
        return (200, {}, {"access_token": f"FAKE-G|{claims['sub']}|{claims['scope']}", "expires_in": 3599, "token_type": "Bearer"})

    s.dwd_allowed = set()
    s.routes[("POST", "/gtoken")] = token

    def authed(fn, need):
        def w(req):
            a = req.auth or ""
            if not a.startswith("Bearer FAKE-G|"):
                return (401, {}, {"error": {"code": 401, "message": "Invalid Credentials"}})
            if need not in a.split("|", 2)[2].split():
                return (403, {}, {"error": {"code": 403, "message": "Request had insufficient authentication scopes."}})
            return fn(req)
        return w

    A = "https://www.googleapis.com/auth/"
    s.routes[("GET", "/dir/customers/my_customer")] = authed(lambda r: json_ok("google/customer.json", b), A + "admin.directory.customer.readonly")
    s.routes[("GET", "/dir/customer/my_customer/domains")] = authed(lambda r: json_ok("google/domains.json", b), A + "admin.directory.domain.readonly")
    s.routes[("GET", "/dir/users")] = authed(lambda r: json_ok(
        "google/users_p2.json" if r.query.get("pageToken") == ["TOKEN2"] else "google/users_p1.json", b), A + "admin.directory.user.readonly")
    s.routes[("GET", "/dir/groups")] = authed(lambda r: json_ok("google/groups.json", b), A + "admin.directory.group.readonly")
    s.routes[("GET", "/dir/customer/my_customer/resources/calendars")] = authed(
        lambda r: (200, {}, {"kind": "admin#directory#resources#calendars#CalendarResources", "items": [{"resourceId": "r1"}, {"resourceId": "r2"}]}),
        A + "admin.directory.resource.calendar.readonly")
    data_date = ((today or dt.date.today()) - dt.timedelta(days=today_minus_data_day)).isoformat()

    def usage(req):
        if not req.path.endswith(data_date):
            return (400, {}, {"error": {"code": 400, "message": "Data for date is not available yet.", "errors": [{"reason": "invalid"}]}})
        return json_ok("google/usage.json", b)

    s.routes[("GET", "/reports/usage/users/all/dates/*")] = authed(usage, A + "admin.reports.usage.readonly")
    s.routes[("GET", "/gmail/users/me/profile")] = authed(
        lambda r: (200, {}, {"emailAddress": r.auth.split("|")[1], "messagesTotal": 4321, "threadsTotal": 1000, "historyId": "1"}), A + "gmail.metadata")
    s.routes[("GET", "/drive/files")] = authed(lambda r: json_ok("google/drive_files.json", b), A + "drive.metadata.readonly")
    return data_date
