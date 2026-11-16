"""Office Unbound MSP API reference client (Python 3.10+, standard library only).

Signs every request (HMAC-SHA256 over method, request target, timestamp, nonce and body hash), sends an Idempotency-Key on every mutation
and retries network errors / 5xx / 429 / `idempotency_in_progress` with the SAME key (so a retry can never create a second plan).
"""
import hashlib
import hmac
import json
import secrets
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

API_PREFIX = "/api/msp/v1"
MUTATING = ("POST", "PUT", "PATCH", "DELETE")


class MspApiError(Exception):
    def __init__(self, status: int, code: str, message: str, details=None, request_id: str | None = None):
        super().__init__(f"{status} {code}: {message}")
        self.status, self.code, self.message, self.details, self.request_id = status, code, message, details, request_id


def string_to_sign(method: str, target: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    return "\n".join(["OU-MSP1", method.upper(), target, timestamp, nonce, hashlib.sha256(body).hexdigest()]).encode()


def sign(secret: str, method: str, target: str, timestamp: str, nonce: str, body: bytes) -> str:
    return "v1=" + hmac.new(secret.encode(), string_to_sign(method, target, timestamp, nonce, body), hashlib.sha256).hexdigest()


def _urllib_transport(ctx: ssl.SSLContext | None, timeout: float):
    def send(method: str, url: str, headers: dict, body: bytes):
        req = urllib.request.Request(url, data=body if body else None, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:  # TLS verification stays ON (default context)
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()
    return send


class MspClient:
    def __init__(self, base_url: str, client_id: str, secret: str, *, transport=None, timeout: float = 30.0,
                 ssl_context: ssl.SSLContext | None = None, max_retries: int = 3, backoff: float = 0.5, sleep=time.sleep):
        """`transport(method, url, headers, body) -> (status, headers, body_bytes)` is injectable for tests; `ssl_context` carries a client
        certificate for clients bound to mTLS (ssl.create_default_context(); ctx.load_cert_chain(cert, key))."""
        self.base, self.client_id, self._secret = base_url.rstrip("/"), client_id, secret
        self._send = transport or _urllib_transport(ssl_context, timeout)
        self.max_retries, self.backoff, self._sleep = max_retries, backoff, sleep

    # ---- core ------------------------------------------------------------------------------------------------------------------
    def request(self, method: str, path: str, *, query: dict | None = None, body=None, idempotency_key: str | None = None):
        method = method.upper()
        target = API_PREFIX + path + (("?" + urllib.parse.urlencode(query)) if query else "")
        raw = b"" if body is None else json.dumps(body, separators=(",", ":")).encode()
        key = idempotency_key or (str(uuid.uuid4()) if method in MUTATING else None)
        last: Exception | None = None
        for attempt in range(self.max_retries + 1):
            ts, nonce = str(int(time.time())), secrets.token_urlsafe(18)  # fresh timestamp + nonce on EVERY attempt
            headers = {"X-MSP-Client": self.client_id, "X-MSP-Timestamp": ts, "X-MSP-Nonce": nonce,
                       "X-MSP-Signature": sign(self._secret, method, target, ts, nonce, raw), "Accept": "application/json"}
            if raw:
                headers["Content-Type"] = "application/json"
            if key:
                headers["Idempotency-Key"] = key
            try:
                status, rh, data = self._send(method, self.base + target, headers, raw)
            except OSError as e:  # connection reset / timeout: the request may or may not have arrived; the same key makes a retry safe
                last = e
                self._sleep(self.backoff * 2 ** attempt)
                continue
            payload = json.loads(data) if data else None
            if status < 400:
                return payload
            err = (payload or {}).get("error", {})
            retryable = status >= 500 or status == 429 or err.get("code") == "idempotency_in_progress"
            if retryable and attempt < self.max_retries:
                wait = float({k.lower(): v for k, v in rh.items()}.get("retry-after", self.backoff * 2 ** attempt))
                self._sleep(min(wait, 30))
                continue
            raise MspApiError(status, err.get("code", "http_error"), err.get("message", ""), err.get("details"), err.get("request_id"))
        raise last or MspApiError(0, "unavailable", "no response")

    # ---- resources -------------------------------------------------------------------------------------------------------------
    def me(self): return self.request("GET", "/me")

    def list_customers(self, **q): return self.request("GET", "/customers", query=q or None)
    def create_customer(self, **body): return self.request("POST", "/customers", body=body)
    def get_customer(self, customer_id): return self.request("GET", f"/customers/{customer_id}")
    def update_customer(self, customer_id, **body): return self.request("PATCH", f"/customers/{customer_id}", body=body)
    def usage(self, customer_id): return self.request("GET", f"/customers/{customer_id}/usage")

    def preview_deployment(self, customer_id, spec): return self.request("POST", f"/customers/{customer_id}/deployments/preview", body=spec)
    def create_deployment(self, customer_id, spec, plan_hash): return self.request("POST", f"/customers/{customer_id}/deployments", body={"spec": spec, "plan_hash": plan_hash})
    def list_deployments(self, **q): return self.request("GET", "/deployments", query=q or None)
    def deployment(self, slug): return self.request("GET", f"/deployments/{slug}")
    def health(self, slug): return self.request("GET", f"/deployments/{slug}/health")
    def preview_change(self, slug, changes): return self.request("POST", f"/deployments/{slug}/changes/preview", body={"changes": changes})
    def create_change(self, slug, changes, plan_hash, **kw): return self.request("POST", f"/deployments/{slug}/changes", body={"changes": changes, "plan_hash": plan_hash, **kw})
    def preview_destroy(self, slug): return self.request("POST", f"/deployments/{slug}/destroy/preview")
    def create_destroy(self, slug, plan_hash): return self.request("POST", f"/deployments/{slug}/destroy", body={"confirm": slug, "plan_hash": plan_hash})

    def list_users(self, customer_id, **q): return self.request("GET", f"/customers/{customer_id}/users", query=q or None)
    def create_user(self, customer_id, **body): return self.request("POST", f"/customers/{customer_id}/users", body=body)
    def update_user_groups(self, customer_id, uid, add=(), remove=(), **kw): return self.request("PATCH", f"/customers/{customer_id}/users/{uid}", body={"add": list(add), "remove": list(remove), **kw})
    def disable_user(self, customer_id, uid, **kw): return self.request("POST", f"/customers/{customer_id}/users/{uid}/disable", body=kw)
    def enable_user(self, customer_id, uid, **kw): return self.request("POST", f"/customers/{customer_id}/users/{uid}/enable", body=kw)
    def delete_user(self, customer_id, uid, reason, **kw): return self.request("DELETE", f"/customers/{customer_id}/users/{uid}", body={"reason": reason, **kw})
    def reconcile_identity(self, customer_id, **kw): return self.request("POST", f"/customers/{customer_id}/identity/reconcile", body=kw)

    def plan(self, plan_id): return self.request("GET", f"/plans/{plan_id}")
    def plans(self, **q): return self.request("GET", "/plans", query=q or None)
    def approve_plan(self, plan_id): return self.request("POST", f"/plans/{plan_id}/approve")
    def reveal_enrollment(self, plan_id): return self.request("POST", f"/plans/{plan_id}/enrollment")
    def job(self, job_id): return self.request("GET", f"/jobs/{job_id}")

    def create_webhook(self, url, events, description=None):
        return self.request("POST", "/webhooks", body={"url": url, "events": list(events), **({"description": description} if description else {})})
    def webhooks(self): return self.request("GET", "/webhooks")
    def delete_webhook(self, webhook_id): return self.request("DELETE", f"/webhooks/{webhook_id}")
    def rotate_webhook_secret(self, webhook_id): return self.request("POST", f"/webhooks/{webhook_id}/rotate-secret")
    def webhook_deliveries(self, webhook_id): return self.request("GET", f"/webhooks/{webhook_id}/deliveries")
    def events(self, after_seq=0, limit=100): return self.request("GET", "/events", query={"after_seq": after_seq, "limit": limit})

    def wait_for_plan(self, plan_id, *, timeout: float = 3600, interval: float = 5.0, clock=time.monotonic):
        """Polls until the plan is rejected or its job finished; returns the final plan view. Prefer webhooks in production."""
        end = clock() + timeout
        while True:
            p = self.plan(plan_id)
            if p["status"] == "rejected" or (p["execution"] and p["execution"]["status"] in ("succeeded", "failed")):
                return p
            if clock() > end:
                raise TimeoutError(f"plan {plan_id} still {p['status']}")
            self._sleep(interval)
