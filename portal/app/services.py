"""Calls to the user's own services with the user's own access token (Keycloak token accepted directly by OpenCloud:
no token exchange needed — verified in the lab, see docs/status/portal-results.md)."""
from __future__ import annotations

import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import quote
from xml.sax.saxutils import escape as xml_escape

import httpx

from .config import Settings

DAV = "{DAV:}"
OC = "{http://owncloud.org/ns}"
MAX_XML = 2_000_000

_SEARCH = """<?xml version="1.0"?>
<oc:search-files xmlns:a="DAV:" xmlns:oc="http://owncloud.org/ns"><a:prop><a:displayname/><a:getlastmodified/><a:getcontentlength/><a:getcontenttype/><a:resourcetype/><oc:fileid/><oc:name/><oc:privatelink/></a:prop><oc:search><oc:pattern>{pattern}</oc:pattern><oc:limit>{limit}</oc:limit></oc:search></oc:search-files>"""


class ServiceError(Exception):
    pass


def _h(token: str) -> dict:
    return {"Authorization": "Bearer " + token}


async def my_drive(cfg: Settings, http: httpx.AsyncClient, token: str) -> dict:
    r = await http.get(cfg.files_url + "/graph/v1.0/me/drive", headers=_h(token))
    if r.status_code != 200:
        raise ServiceError(f"files: drive lookup answered {r.status_code}")
    d = r.json()
    return {"id": d["id"], "alias": d["driveAlias"], "root": d["root"]["id"], "used": d.get("quota", {}).get("used")}


def parse_recent(xml_bytes: bytes, cfg: Settings, limit: int = 8, dirs: bool = False, newest_first: bool = True) -> list[dict]:
    if len(xml_bytes) > MAX_XML:
        raise ServiceError("files: search response too large")
    root = ET.fromstring(xml_bytes)
    items = []
    for resp in root.iter(DAV + "response"):
        prop = resp.find(f"{DAV}propstat/{DAV}prop")
        is_dir = prop is not None and prop.find(f"{DAV}resourcetype/{DAV}collection") is not None
        if prop is None or (is_dir and not dirs):
            continue                                    # files only, unless folders were asked for (search)
        name = (prop.findtext(OC + "name") or "").strip()
        fid = (prop.findtext(OC + "fileid") or "").strip()
        lm = prop.findtext(DAV + "getlastmodified")
        if not name or not fid or not lm:
            continue
        try:
            mtime = parsedate_to_datetime(lm)
        except (TypeError, ValueError):
            continue
        size = prop.findtext(DAV + "getcontentlength")
        items.append({
            "name": name, "id": fid, "mtime": mtime, "size": int(size) if size and size.isdigit() else None,
            "mime": prop.findtext(DAV + "getcontenttype") or "", "dir": is_dir, "kind": file_kind(name, is_dir),
            # OpenCloud's own resolver URL (opens the file in the right app); rebuilt on OUR configured files host
            "url": f"{cfg.files_url}/f/{quote(fid, safe='')}",
        })
    if newest_first:
        items.sort(key=lambda i: i["mtime"], reverse=True)
    return items[:limit]


KIND_EXT = {"document": {"odt", "docx", "doc", "rtf", "txt", "md"}, "spreadsheet": {"ods", "xlsx", "xls", "csv"},
            "presentation": {"odp", "pptx", "ppt"}, "pdf": {"pdf"}, "image": {"png", "jpg", "jpeg", "gif", "webp", "svg", "heic"}}


def file_kind(name: str, is_dir: bool = False) -> str:
    """The icon family of a file (by extension; never by content)."""
    if is_dir:
        return "folder"
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return next((k for k, v in KIND_EXT.items() if ext in v), "file")


SEARCH_MAX = 80
_KQL_UNSAFE = re.compile(r'["\\<>&()*:]')


def search_term(q: str | None) -> str:
    """The user's search words as ONE quoted KQL phrase: quotes, operators and markup removed, length capped (no query injection)."""
    return " ".join(_KQL_UNSAFE.sub(" ", (q or "")[:SEARCH_MAX]).split())


async def search_files(cfg: Settings, http: httpx.AsyncClient, token: str, username: str, q: str, limit: int = 50) -> list[dict]:
    """Files and folders whose name matches `q`, across the user's spaces (OpenCloud search, the same REPORT as recent files)."""
    term = search_term(q)
    if not term:
        return []
    body = _SEARCH.format(pattern=xml_escape(f'"{term}"'), limit=limit)
    r = await http.request("REPORT", f"{cfg.files_url}/remote.php/dav/files/{quote(username, safe='')}",
                           headers={**_h(token), "Content-Type": "application/xml"}, content=body)
    if r.status_code != 207:
        raise ServiceError(f"files: search answered {r.status_code}")
    try:
        return parse_recent(r.content, cfg, limit, dirs=True, newest_first=False)
    except ET.ParseError as e:
        raise ServiceError("files: unreadable search response") from e


async def shared_with_me(cfg: Settings, http: httpx.AsyncClient, token: str, limit: int = 6) -> list[dict]:
    """Files and folders other people shared with the user (OpenCloud Graph sharedWithMe), newest first. Hidden shares are left out."""
    r = await http.get(cfg.files_url + "/graph/v1beta1/me/drive/sharedWithMe", headers=_h(token))
    if r.status_code != 200:
        raise ServiceError(f"files: shared-with-me answered {r.status_code}")
    out = []
    for it in (r.json().get("value") or [])[:200]:
        if not isinstance(it, dict) or it.get("@UI.Hidden"):
            continue
        name, rid = str(it.get("name") or ""), str((it.get("remoteItem") or {}).get("id") or it.get("id") or "")
        if not name or not rid:
            continue
        try:
            mtime = datetime.fromisoformat(str(it.get("lastModifiedDateTime")).replace("Z", "+00:00"))
        except ValueError:
            continue
        by = ((it.get("remoteItem") or {}).get("shared") or {}).get("sharedBy") or {}
        is_dir = "folder" in (it.get("remoteItem") or it)
        out.append({"name": name, "id": rid, "mtime": mtime, "dir": is_dir, "kind": file_kind(name, is_dir),
                    "by": str((by.get("user") or {}).get("displayName") or ""), "url": f"{cfg.files_url}/f/{quote(rid, safe='')}"})
    out.sort(key=lambda i: i["mtime"], reverse=True)
    return out[:limit]


async def recent_files(cfg: Settings, http: httpx.AsyncClient, token: str, username: str, days: int = 90, limit: int = 8) -> list[dict]:
    """Most recently modified files across the user's spaces (OpenCloud search, KQL mtime filter), newest first."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    body = _SEARCH.format(pattern=f"mtime&gt;={since}", limit=100)
    r = await http.request("REPORT", f"{cfg.files_url}/remote.php/dav/files/{quote(username, safe='')}",
                           headers={**_h(token), "Content-Type": "application/xml"}, content=body)
    if r.status_code != 207:
        raise ServiceError(f"files: search answered {r.status_code}")
    try:
        return parse_recent(r.content, cfg, limit)
    except ET.ParseError as e:
        raise ServiceError("files: unreadable search response") from e


def stamp_name(kind: str, ext: str) -> str:
    label = {"document": "Document", "spreadsheet": "Spreadsheet", "presentation": "Presentation"}[kind]
    return f"New {label.lower()} {datetime.now().strftime('%Y-%m-%d %H%M%S')}.{ext}"


APP_NAME_RE = re.compile(r"^[A-Za-z0-9]{1,64}$")     # OpenCloud: one word, no whitespace (collaboration COLLABORATION_APP_NAME)
_EDITOR_TTL = 300.0
_editor_cache: dict[tuple[str, str], tuple[float, str]] = {}


async def editor_route(cfg: Settings, http: httpx.AsyncClient, ext: str) -> str:
    """OpenCloud Web's route of the office app that opens `.ext` files: `external-<app name, lower case>` (web-app-external), the app name
    being what OpenCloud's app registry lists (/app/list, public) as the default application for that extension. The deployment names the
    app (ICS opencloud.env COLLABORATION_APP_NAME, "Documents" -> /external-documents/); asking OpenCloud keeps the portal right for a
    deployment configured before or after a rename. Falls back to the configured route when the registry cannot be read."""
    key = (cfg.files_url, ext)
    hit = _editor_cache.get(key)
    if hit and time.monotonic() - hit[0] < _EDITOR_TTL:
        return hit[1]
    route = cfg.editor_app
    try:
        r = await http.get(cfg.files_url + "/app/list")
        if r.status_code == 200:
            for mt in r.json().get("mime-types") or []:
                if not isinstance(mt, dict) or mt.get("ext") != ext:
                    continue
                names = [p.get("name") for p in mt.get("app_providers") or [] if isinstance(p, dict)]
                name = mt.get("default_application") if mt.get("default_application") in names else (names[0] if names else None)
                if isinstance(name, str) and APP_NAME_RE.fullmatch(name):
                    route = f"external-{name.lower()}"
                    _editor_cache[key] = (time.monotonic(), route)
                break
    except (httpx.HTTPError, ValueError, AttributeError):
        pass
    return route


async def create_document(cfg: Settings, http: httpx.AsyncClient, token: str, drive: dict, kind: str) -> str:
    """Create an empty office file in the user's home via OpenCloud's app-provider (/app/new) and return the URL that opens it
    in the editor inside OpenCloud web (same URL the OpenCloud UI navigates to after its own New > Document)."""
    name = stamp_name(kind, cfg.doc_ext[kind])
    r = await http.post(cfg.files_url + "/app/new", headers=_h(token), params={"parent_container_id": drive["root"], "filename": name})
    if r.status_code != 200:
        raise ServiceError(f"files: create answered {r.status_code}")
    file_id = r.json()["file_id"]
    alias = drive["alias"]                                   # e.g. personal/bob
    q = (f"fileId={quote(file_id, safe='')}&contextRouteName=files-spaces-generic"
         f"&contextRouteParams.driveAliasAndItem={quote(alias, safe='/')}&contextRouteQuery.fileId={quote(drive['root'], safe='')}")
    route = await editor_route(cfg, http, cfg.doc_ext[kind])
    return f"{cfg.files_url}/{route}/{quote(alias, safe='/')}/{quote(name)}?{q}"


async def account_sessions(cfg: Settings, http: httpx.AsyncClient, token: str) -> list[dict]:
    r = await http.get(cfg.account_url + "/sessions", headers={**_h(token), "Accept": "application/json"})
    if r.status_code != 200:
        raise ServiceError(f"account: sessions answered {r.status_code}")
    out = []
    for s in r.json():
        out.append({
            "id": s.get("id"), "ip": s.get("ipAddress"), "browser": s.get("browser") or "unknown",
            "started": datetime.fromtimestamp(s.get("started", 0), timezone.utc),
            "last": datetime.fromtimestamp(s.get("lastAccess", 0), timezone.utc),
            "clients": sorted({c.get("clientName") or c.get("clientId") for c in s.get("clients", []) if c.get("clientId")}),
        })
    out.sort(key=lambda s: s["last"], reverse=True)
    return out


async def end_other_sessions(cfg: Settings, http: httpx.AsyncClient, token: str) -> None:
    r = await http.delete(cfg.account_url + "/sessions", params={"current": "false"}, headers={**_h(token), "Accept": "application/json"})
    if r.status_code not in (200, 204):
        raise ServiceError(f"account: end sessions answered {r.status_code}")


async def credential_summary(cfg: Settings, http: httpx.AsyncClient, token: str) -> dict:
    """Is a second factor enrolled? (Keycloak account API: credential types with configured credentials.)"""
    r = await http.get(cfg.account_url + "/credentials", headers={**_h(token), "Accept": "application/json"})
    if r.status_code != 200:
        raise ServiceError(f"account: credentials answered {r.status_code}")
    second = [c for c in r.json() if c.get("category") == "two-factor"]
    enrolled = any(c.get("userCredentialMetadatas") for c in second)
    return {"second_factor": enrolled}


def ago(dt: datetime, now: float | None = None) -> str:
    secs = int((now or time.time()) - dt.timestamp())
    if secs < 90:
        return "just now"
    if secs < 3600:
        return f"{secs // 60} minutes ago"
    if secs < 86400:
        h = secs // 3600
        return f"{h} hour{'s' if h != 1 else ''} ago"
    if secs < 7 * 86400:
        d = secs // 86400
        return f"{d} day{'s' if d != 1 else ''} ago"
    return dt.strftime("%-d %b %Y")


def human_size(n: int | None) -> str:
    if n is None:
        return ""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


_CHAT = {"at": 0.0, "ok": False}
CHAT_RECHECK = 300.0


async def chat_available(cfg, http) -> bool:
    """Whether the deployment's chat (Element Web behind the chat name) answers its health page; checked at most every 5 minutes, so a
    deployment without chat shows no bubble and one that gains chat shows it without a portal restart."""
    if not cfg.chat_url:
        return False
    now = time.monotonic()
    if now - _CHAT["at"] < CHAT_RECHECK:
        return _CHAT["ok"]
    _CHAT["at"] = now
    try:
        r = await http.get(cfg.chat_url + "/healthz", timeout=3.0)
        _CHAT["ok"] = r.status_code == 200 and r.text.strip() == "ok"
    except httpx.HTTPError:
        _CHAT["ok"] = False
    return _CHAT["ok"]


# ---- profile (Keycloak account API; what may be edited comes from the realm's declared user profile, never from the portal) -------------
PROFILE_FIELDS = ("firstName", "lastName", "displayName", "phone", "mobile")      # the order of the form; others are shown, never sent
TOP_LEVEL = ("username", "email", "firstName", "lastName")


async def get_profile(cfg: Settings, http: httpx.AsyncClient, token: str) -> dict:
    """{rep, fields}: the account representation and the attributes of the declared profile with label, value and whether the user may edit it.
    A deployment whose directory is read-only to the sign-in service reports every attribute read-only."""
    r = await http.get(cfg.account_url + "/", params={"userProfileMetadata": "true"}, headers={**_h(token), "Accept": "application/json"})
    if r.status_code != 200:
        raise ServiceError(f"account: profile answered {r.status_code}")
    rep = r.json()
    meta = {a.get("name"): a for a in (rep.get("userProfileMetadata") or {}).get("attributes", []) if isinstance(a, dict)}
    attrs = rep.get("attributes") or {}

    def value(n):
        v = rep.get(n) if n in TOP_LEVEL else (attrs.get(n) or [""])
        return (v[0] if isinstance(v, list) and v else v) or ""
    labels = {"username": "User name", "email": "E-mail", "firstName": "First name", "lastName": "Last name", "displayName": "Display name",
              "phone": "Phone", "mobile": "Mobile"}
    fields = []
    for n in ("username", "email", *PROFILE_FIELDS):
        if n not in meta and n not in TOP_LEVEL:
            continue
        m = meta.get(n, {})
        fields.append({"name": n, "label": labels.get(n, n), "value": str(value(n)), "editable": n in PROFILE_FIELDS and n in meta and not m.get("readOnly", True),
                       "required": bool(m.get("required"))})
    return {"rep": rep, "fields": fields}


class ProfileRejected(ServiceError):
    def __init__(self, errors: list[dict]):
        super().__init__("profile rejected")
        self.errors = errors


async def update_profile(cfg: Settings, http: httpx.AsyncClient, token: str, form: dict) -> None:
    """Send the editable fields (only those the realm marks editable for this user) on top of the current representation."""
    cur = await get_profile(cfg, http, token)
    rep = {k: cur["rep"].get(k) for k in ("id", *TOP_LEVEL) if k in cur["rep"]}
    attrs = {k: v for k, v in (cur["rep"].get("attributes") or {}).items()}
    changed = False
    for f in cur["fields"]:
        if not f["editable"] or f["name"] not in form:
            continue
        v = str(form[f["name"]]).strip()[:128]
        if v == f["value"]:
            continue
        changed = True
        if f["name"] in TOP_LEVEL:
            rep[f["name"]] = v
        else:
            attrs[f["name"]] = [v] if v else []
    if not changed:
        return
    rep["attributes"] = attrs
    r = await http.post(cfg.account_url + "/", json=rep, headers={**_h(token), "Accept": "application/json"})
    if r.status_code in (200, 204):
        return
    if r.status_code == 400:
        try:
            body = r.json()
        except ValueError:
            body = {}
        errs = body.get("errors") if isinstance(body, dict) and isinstance(body.get("errors"), list) else [body] if isinstance(body, dict) else []
        raise ProfileRejected([{"field": str(e.get("field") or ""), "message": str(e.get("errorMessage") or "invalid")} for e in errs if isinstance(e, dict)])
    raise ServiceError(f"account: profile update answered {r.status_code}")
