"""Calls to the user's own services with the user's own access token (Keycloak token accepted directly by OpenCloud:
no token exchange needed — verified in the lab, see docs/status/portal-results.md)."""
from __future__ import annotations

import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import quote

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


def parse_recent(xml_bytes: bytes, cfg: Settings, limit: int = 8) -> list[dict]:
    if len(xml_bytes) > MAX_XML:
        raise ServiceError("files: search response too large")
    root = ET.fromstring(xml_bytes)
    items = []
    for resp in root.iter(DAV + "response"):
        prop = resp.find(f"{DAV}propstat/{DAV}prop")
        if prop is None or prop.find(f"{DAV}resourcetype/{DAV}collection") is not None:
            continue                                    # files only
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
            "mime": prop.findtext(DAV + "getcontenttype") or "",
            # OpenCloud's own resolver URL (opens the file in the right app); rebuilt on OUR configured files host
            "url": f"{cfg.files_url}/f/{quote(fid, safe='')}",
        })
    items.sort(key=lambda i: i["mtime"], reverse=True)
    return items[:limit]


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
