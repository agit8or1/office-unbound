"""python -m ics.serve_callback : the dedicated guest-bootstrap listener (unit ics-bootstrap.service).

It is its own process with its own socket and its own TLS certificate (the one the guests pin, delivered through SMBIOS), serving ONLY
`POST /api/v1/guest-bootstrap/report` and `GET /healthz` (everything else: 404). It has no session middleware, no cookies, no console routes, no static
files and no OpenAPI. Limits applied here, before any application code runs (RequestLimits, pure ASGI):
  * request body: hard cap (MAX_BODY) by Content-Length and by counting streamed bytes (chunked bodies), 413;
  * request line / headers: uvicorn's h11 buffer cap (h11_max_incomplete_event_size, 16 KiB);
  * whole request (headers received -> response): REQUEST_TIMEOUT seconds, then 408;
  * connections: limit_concurrency (503 beyond), timeout_keep_alive 5 s, backlog 128, no HTTP/2, no websockets.
Per-source connection limits belong to the firewall (deploy/bootstrap.sh installs `ct count` rules; docs/admin/security.md).

Environment (EnvironmentFile /etc/office-unbound/callback.env + ics.env):
  ICS_GUEST_CALLBACK_LISTEN    ip:port to bind (default 127.0.0.1:8089)
  ICS_GUEST_CALLBACK_TLS_CERT  PEM certificate (chain) file    } required unless the bind address is loopback; the key may be given as a
  ICS_GUEST_CALLBACK_TLS_KEY   PEM private key file            } systemd credential path (LoadCredential=)
The rate limits are shared with every other process through PostgreSQL (ics/ratelimit.py)."""
import asyncio
import os

import uvicorn

from .config import load_settings

MAX_BODY = 4096
REQUEST_TIMEOUT = 10.0
MAX_CONCURRENCY = 64


class RequestLimits:
    """Pure ASGI middleware: enforces the body cap and the request deadline before the application sees the request."""

    def __init__(self, app, max_body: int = MAX_BODY, timeout: float = REQUEST_TIMEOUT):
        self.app, self.max_body, self.timeout = app, max_body, timeout

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            if scope["type"] == "lifespan":
                return await self.app(scope, receive, send)
            return   # websockets etc.: no such thing here
        for k, v in scope["headers"]:
            if k == b"content-length":
                try:
                    if int(v) > self.max_body:
                        return await self._reply(send, 413, b"body too large")
                except ValueError:
                    return await self._reply(send, 400, b"bad content-length")
        seen = 0
        answered = False   # True once WE answered (413/408): everything the application sends afterwards is dropped

        async def limited_receive():
            nonlocal seen, answered
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > self.max_body and not answered:
                    answered = True
                    await self._reply(send, 413, b"body too large")
                    return {"type": "http.disconnect"}
            return msg

        async def guarded_send(msg):
            if not answered:
                await send(msg)

        started = False

        async def tracking_send(msg):
            nonlocal started
            started = True
            await guarded_send(msg)

        try:
            await asyncio.wait_for(self.app(scope, limited_receive, tracking_send), self.timeout)
        except asyncio.TimeoutError:
            if not started and not answered:
                answered = True
                await self._reply(send, 408, b"request timeout")
        except Exception:   # noqa: BLE001  the app failed after we already answered (disconnect we signalled): nothing more to say
            if not answered:
                raise

    @staticmethod
    async def _reply(send, status: int, body: bytes):
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"text/plain"), (b"content-length", str(len(body)).encode()), (b"connection", b"close")]})
        await send({"type": "http.response.body", "body": body})


def create_limited_app():
    from .guest.callback import create_callback_app
    return RequestLimits(create_callback_app())


def make_config(env=None) -> uvicorn.Config:
    env = os.environ if env is None else env
    host, _, port = env.get("ICS_GUEST_CALLBACK_LISTEN", "127.0.0.1:8089").rpartition(":")
    host = host or "127.0.0.1"
    cert, key = env.get("ICS_GUEST_CALLBACK_TLS_CERT"), env.get("ICS_GUEST_CALLBACK_TLS_KEY")
    loopback = host in ("127.0.0.1", "::1", "localhost")
    if not loopback and not (cert and key):
        raise SystemExit("ics.serve_callback: a non-loopback listener requires ICS_GUEST_CALLBACK_TLS_CERT and ICS_GUEST_CALLBACK_TLS_KEY (guests pin this certificate)")
    # X-Forwarded-For is only honoured behind a local proxy, never on a directly exposed socket
    tp = load_settings().trusted_proxy if loopback else None
    return uvicorn.Config("ics.serve_callback:create_limited_app", factory=True, host=host, port=int(port), http="h11", ws="none", lifespan="off",
                          ssl_certfile=cert or None, ssl_keyfile=key or None,
                          proxy_headers=bool(tp), forwarded_allow_ips=tp or "", server_header=False, date_header=True,
                          limit_concurrency=MAX_CONCURRENCY, timeout_keep_alive=5, backlog=128, h11_max_incomplete_event_size=16384,
                          access_log=False)


def main() -> None:
    uvicorn.Server(make_config()).run()


if __name__ == "__main__":
    main()
