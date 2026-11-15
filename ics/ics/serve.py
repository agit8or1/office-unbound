"""python -m ics.serve : run uvicorn on 127.0.0.1.
X-Forwarded-For is ignored (L1) unless ICS_TRUSTED_PROXY names the local reverse proxy's loopback IP;
that proxy must OVERWRITE X-Forwarded-For with $remote_addr (see deploy/nginx-ics.conf)."""
import uvicorn

from .config import load_settings


def make_config(host: str = "127.0.0.1", port: int = 8088, trusted_proxy: str | None = None) -> uvicorn.Config:
    return uvicorn.Config("ics.main:create_app", factory=True, host=host, port=port,
                          proxy_headers=bool(trusted_proxy), forwarded_allow_ips=trusted_proxy or "",
                          server_header=False, date_header=True)


if __name__ == "__main__":
    uvicorn.Server(make_config(trusted_proxy=load_settings().trusted_proxy)).run()
