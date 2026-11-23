"""Portal version (ADR-0011). Kept in step with VERSIONS.json by a test; commit/build date come from an optional
BUILD_INFO.json beside the app directory (written when the deployment tarball is built), never from a live git call."""
import json
from pathlib import Path

PORTAL_VERSION = "0.3.3"


def build_info() -> dict:
    try:
        d = json.loads((Path(__file__).resolve().parent.parent / "BUILD_INFO.json").read_text())
    except (OSError, ValueError):
        d = {}
    return {"product": "Office Unbound", "version": PORTAL_VERSION, "product_version": d.get("version"), "commit": d.get("commit"),
            "built_at": d.get("built_at")}
