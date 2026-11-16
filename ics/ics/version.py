"""Product/build version. Never calls git or any subprocess (ADR-0011).

Source order: BUILD_INFO.json written at install time next to the package (production), else the repo-root VERSION and
VERSIONS.json (source checkout, tests), else an explicit "unknown" marker. Result is cached for the process lifetime.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

PRODUCT = "Office Unbound"
API_VERSION = "v1"
_PKG_PARENT = Path(__file__).resolve().parent.parent          # <install>/ics  (BUILD_INFO.json lives here)
_REPO_ROOT = _PKG_PARENT.parent                               # checkout root (VERSION, VERSIONS.json, docs/)
UNKNOWN = "0.0.0+unknown"


def _load(path: Path) -> dict | None:
    try:
        d = json.loads(path.read_text())
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def _compute(pkg_parent: Path, repo_root: Path) -> dict:
    d = _load(pkg_parent / "BUILD_INFO.json")
    if d and isinstance(d.get("version"), str):
        return {"product": PRODUCT, "commit": None, "built_at": None, "dirty": None, "schema_head": None, "components": {},
                "interfaces": {}, "releases": [], "source": "build-info", **d}
    try:
        v = (repo_root / "VERSION").read_text().strip() or UNKNOWN
    except OSError:
        v = UNKNOWN
    vs = _load(repo_root / "VERSIONS.json") or {}
    prog = _load(repo_root / "docs" / "progress.json") or {}
    return {"product": PRODUCT, "version": v, "commit": None, "built_at": None, "dirty": None, "schema_head": None,
            "components": vs.get("components", {}), "interfaces": vs.get("interfaces", {}),
            "releases": prog.get("releases", []), "release_names": vs.get("release_names", {}), "source": "source-tree"}


@lru_cache(maxsize=1)
def build_info() -> dict:
    return _compute(_PKG_PARENT, _REPO_ROOT)


def read_version() -> str:
    return build_info()["version"]


def codename(info: dict | None = None) -> str | None:
    """Release name of the version's MAJOR.MINOR line (ADR-0011 §1), e.g. 0.2.0-dev -> "Beacon"; None if not named."""
    info = info or build_info()
    names = info.get("release_names") or {}
    m = re.match(r"^(\d+)\.(\d+)\.", str(info.get("version", "")))
    n = names.get(f"{m[1]}.{m[2]}") if m else None
    return n if isinstance(n, str) and n else None


def short_commit(info: dict | None = None) -> str | None:
    c = (info or build_info()).get("commit")
    return c[:7] if isinstance(c, str) and c else None


def _key(v: str) -> tuple:
    """SemVer precedence for MAJOR.MINOR.PATCH[-pre]; unparsable -> (-1,)."""
    core, _, pre = v.partition("+")[0].partition("-")
    try:
        nums = tuple(int(x) for x in core.split("."))
    except ValueError:
        return (-1,)
    return nums + ((0, pre) if pre else (1, ""))


def update_status(info: dict | None = None) -> dict:
    """Deployed vs latest *known* release. Local data only: the release list bundled at build time. No network access."""
    info = info or build_info()
    cur = info["version"]
    rel = [r for r in info.get("releases", []) if isinstance(r, dict) and isinstance(r.get("version"), str)]
    latest = max(rel, key=lambda r: _key(r["version"]), default=None)
    return {"current": cur, "latest_known": latest["version"] if latest else None,
            "latest_date": latest.get("date") if latest else None, "notes_url": latest.get("notes_url") if latest else None,
            "update_available": bool(latest) and _key(latest["version"]) > _key(cur),
            "checked": "local release list bundled at install time; no network check is performed"}


__version__ = read_version()
