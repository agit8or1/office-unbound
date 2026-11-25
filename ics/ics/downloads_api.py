"""Downloads in the console: Office Unbound Desktop for Windows from the ICS itself (owner 2026-11-25: "the app needs to be able to be
directly downloaded from the ui"; not from GitHub). Viewer and up, any customer scope: the installer is the same signed-off file for every
tenant and carries no tenant data. Only the file the manifest names, and only when its bytes hash to the manifest's sha256
(desktop_download.open_verified); a mismatch is logged and refused without sending any bytes."""
from __future__ import annotations

import logging

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse

from . import desktop_download
from .auth import User, require

API = "/api/v1"
log = logging.getLogger("ics.downloads")


def _dir(request: Request) -> str:
    return request.app.state.rt.settings.desktop_windows_dir


def mount(app: FastAPI) -> None:
    @app.get(f"{API}/downloads/desktop")
    def desktop_info(request: Request, user: User = Depends(require("viewer"))):
        m = desktop_download.manifest(_dir(request))
        if m is None:
            return {"windows": None}
        return {"windows": {k: m[k] for k in ("product", "platform", "version", "file", "sha256", "size", "unsigned", "stage")} |
                {"url": f"{API}/downloads/desktop/windows"}}

    @app.get(f"{API}/downloads/desktop/windows")
    def desktop_windows(request: Request, user: User = Depends(require("viewer"))):
        try:
            m, fd = desktop_download.open_verified(_dir(request))
        except desktop_download.Unavailable:
            raise HTTPException(404, "Office Unbound Desktop for Windows is not available on this server") from None
        except desktop_download.Mismatch as e:
            log.error("desktop installer refused: %s", e)
            raise HTTPException(500, "the installer on this server failed its integrity check and is not offered") from None
        return StreamingResponse(desktop_download.chunks(fd, m["size"]), media_type=m["content_type"], headers={
            "Content-Disposition": f'attachment; filename="{m["file"]}"', "Content-Length": str(m["size"]),
            "X-Content-Type-Options": "nosniff", "Cache-Control": "private, no-cache", "ETag": f'"{m["sha256"]}"',
            "Content-Security-Policy": "default-src 'none'; sandbox"})
