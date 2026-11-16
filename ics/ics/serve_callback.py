"""python -m ics.serve_callback : the dedicated guest-callback listener (review 5 L4). Serves ONLY POST /api/v1/guest-bootstrap/report and /healthz.
Bind address/port: ICS_GUEST_CALLBACK_LISTEN (default 127.0.0.1:8089); put it behind a reverse proxy that terminates TLS with the pinned certificate and
exposes only that path on the guest-facing address (docs/admin/security.md). It has its own in-process limiter, separate from the console's."""
import os

import uvicorn

from .config import load_settings


def main() -> None:
    listen = os.environ.get("ICS_GUEST_CALLBACK_LISTEN", "127.0.0.1:8089")
    host, _, port = listen.rpartition(":")
    tp = load_settings().trusted_proxy
    uvicorn.Server(uvicorn.Config("ics.guest.callback:create_callback_app", factory=True, host=host or "127.0.0.1", port=int(port), proxy_headers=bool(tp),
                                  forwarded_allow_ips=tp or "", server_header=False, date_header=True)).run()


if __name__ == "__main__":
    main()
