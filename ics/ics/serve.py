"""python -m ics.serve : run uvicorn on 127.0.0.1 (the console backend behind nginx).
X-Forwarded-For is ignored (L1) unless ICS_TRUSTED_PROXY names the local reverse proxy's loopback IP;
that proxy must OVERWRITE X-Forwarded-For with $remote_addr (see deploy/bootstrap.sh).
ICS_WORKERS=N (default 1) runs N uvicorn worker processes. Safe because: sessions, login throttling and every rate limit live in PostgreSQL
(ics/ratelimit.py, login_attempts), and the background worker runs in exactly one process (advisory-lock leader, ics.main lifespan)."""
import os

import uvicorn

from .config import load_settings


def make_config(host: str = "127.0.0.1", port: int = 8088, trusted_proxy: str | None = None, workers: int = 1) -> uvicorn.Config:
    return uvicorn.Config("ics.main:create_app", factory=True, host=host, port=port, workers=workers,
                          proxy_headers=bool(trusted_proxy), forwarded_allow_ips=trusted_proxy or "",
                          server_header=False, date_header=True)


def main() -> None:
    n = max(1, min(int(os.environ.get("ICS_WORKERS", "1")), 16))
    cfg = make_config(trusted_proxy=load_settings().trusted_proxy, workers=n)
    server = uvicorn.Server(cfg)
    if n > 1:
        from uvicorn.supervisors import Multiprocess
        sock = cfg.bind_socket()
        try:
            Multiprocess(cfg, sockets=[sock]).run()   # uvicorn >= 0.30 signature (the supervisor builds its own Server per worker)
        finally:
            sock.close()
    else:
        server.run()


if __name__ == "__main__":
    main()
