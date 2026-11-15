"""In-memory server-side sessions. The browser only holds an opaque random id (httpOnly __Host- cookie).

Restart = everyone is sent through SSO again (silent while the Keycloak session lives). Acceptable for a single-process portal;
a shared store (Redis/Postgres) is the upgrade path if the portal is ever scaled out.
"""
from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass, field

COOKIE = "__Host-ou_portal"
FLOW_COOKIE = "__Host-ou_portal_flow"


@dataclass
class Session:
    sid: str
    claims: dict
    id_token: str
    access_token: str
    refresh_token: str | None
    access_exp: float
    created: float
    csrf: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    drive: dict | None = None


@dataclass
class Flow:
    verifier: str
    nonce: str
    created: float
    next: str
    ip: str = ""


class Store:
    def __init__(self, ttl: int, max_sessions: int = 5000):
        self.ttl, self.max = ttl, max_sessions
        self.sessions: dict[str, Session] = {}
        self.flows: dict[str, Flow] = {}

    def _gc(self) -> None:
        now = time.time()
        for k in [k for k, s in self.sessions.items() if now - s.created > self.ttl]:
            del self.sessions[k]
        for k in [k for k, f in self.flows.items() if now - f.created > 600]:
            del self.flows[k]

    FLOWS_PER_IP = 20      # in-flight sign-ins one source address may hold; its own oldest are evicted first
    FLOWS_MAX = 2000

    def new_flow(self, verifier: str, nonce: str, next_path: str, ip: str = "") -> str:
        """Review 3 L6: pending-auth state is bounded PER source address, so a /login flood evicts only the flooder's own flows.
        At the global cap the address holding the most flows loses its oldest one (never an arbitrary victim)."""
        self._gc()
        mine = [k for k, f in self.flows.items() if f.ip == ip]       # insertion order = oldest first
        while len(mine) >= self.FLOWS_PER_IP:
            self.flows.pop(mine.pop(0), None)
        if len(self.flows) >= self.FLOWS_MAX:
            counts: dict[str, int] = {}
            for f in reversed(list(self.flows.values())):   # ties: the most recent address pays, older sign-ins survive
                counts[f.ip] = counts.get(f.ip, 0) + 1
            worst = max(counts, key=counts.get)
            self.flows.pop(next(k for k, f in self.flows.items() if f.ip == worst))
        state = secrets.token_urlsafe(24)
        self.flows[state] = Flow(verifier, nonce, time.time(), next_path, ip)
        return state

    def pop_flow(self, state: str) -> Flow | None:
        f = self.flows.pop(state, None)
        return f if f and time.time() - f.created <= 600 else None

    def create(self, **kw) -> Session:
        self._gc()
        if len(self.sessions) >= self.max:
            self.sessions.pop(min(self.sessions, key=lambda k: self.sessions[k].created))
        s = Session(sid=secrets.token_urlsafe(32), created=time.time(), **kw)
        self.sessions[s.sid] = s
        return s

    def get(self, sid: str | None) -> Session | None:
        if not sid:
            return None
        s = self.sessions.get(sid)
        if s and time.time() - s.created > self.ttl:
            del self.sessions[sid]
            return None
        return s

    def drop(self, sid: str | None) -> None:
        if sid:
            self.sessions.pop(sid, None)
