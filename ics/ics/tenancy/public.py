"""PUBLIC customer approval endpoints (no ICS account, no cookies, no session). Deliberately minimal:
 - POST only, JSON only; the token travels in the request body (the link keeps it in the URL *fragment*, which browsers never send
   to servers, proxies or logs), so there is no ambient credential for CSRF to ride on;
 - uniform 404 for unknown/expired/tampered/used links; per-IP rate limit + failure backoff via the shared login_attempts table;
 - nothing else of ICS is reachable with a link: it addresses exactly one approval row.
"""
import base64
import hashlib
import threading
import time
from collections import defaultdict, deque

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text

from .. import auth
from . import approvals

API = "/api/v1/public/approvals"
RATE_PER_MINUTE = 30
_hits: dict = defaultdict(deque)
_lock = threading.Lock()


class TokenIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(max_length=200)


class DecideIn(TokenIn):
    decision: str = Field(max_length=20)
    name: str = Field(max_length=100)
    email: str = Field(max_length=254)
    statement: str = Field(default="", max_length=1000)
    note: str = Field(default="", max_length=1000)
    proposal_hash: str = Field(default="", max_length=64)


class CompleteIn(TokenIn):
    name: str = Field(max_length=100)
    email: str = Field(max_length=254)
    note: str = Field(default="", max_length=1000)


def _rate(ip: str | None) -> bool:
    now = time.monotonic()
    with _lock:
        q = _hits[ip or "?"]
        while q and q[0] < now - 60:
            q.popleft()
        if len(q) >= RATE_PER_MINUTE:
            return False
        q.append(now)
        if len(_hits) > 10000:
            _hits.clear()
    return True


def reset_rate_limits() -> None:  # tests
    with _lock:
        _hits.clear()


def _run(request: Request, fn):
    rt = request.app.state.rt
    ip = auth.client_ip(request)
    if "application/json" not in request.headers.get("content-type", ""):
        raise HTTPException(415, "application/json required")
    if not _rate(ip):
        raise HTTPException(429, "too many requests", headers={"Retry-After": "60"})
    with rt.session() as db:
        if auth.throttle_remaining(db, rt, "approval-link", ip) > 0:
            raise HTTPException(429, "too many attempts", headers={"Retry-After": "60"})
        try:
            out = fn(db, rt)
            db.commit()
            return out
        except approvals.ApprovalError as e:
            db.rollback()
            if e.status == 404:  # bad/expired/used token: counts toward the backoff
                db.execute(text("INSERT INTO login_attempts (username, ip, success) VALUES ('approval-link', :i, false)"), {"i": ip})
                db.commit()
            raise HTTPException(e.status, e.msg) from None


_PAGE_STYLE = ("body{font:15px/1.5 system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem;color:#1a1a1a}"
               "textarea,input{width:100%;box-sizing:border-box;margin:.2rem 0 .8rem;padding:.4rem}button{margin-right:.5rem;padding:.5rem 1rem}"
               "pre{white-space:pre-wrap;background:#f4f4f4;padding:.6rem}.err{color:#a00}")
_PAGE_SCRIPT = r"""
(function(){
var h=new URLSearchParams(location.hash.slice(1)),kind=h.get('c')?'c':'a',token=h.get('c')||h.get('t');
history.replaceState(null,'',location.pathname);
var root=document.getElementById('app');
function el(t,txt,p){var e=document.createElement(t);if(txt!==undefined)e.textContent=txt;(p||root).appendChild(e);return e}
function api(path,body){return fetch('/api/v1/public/approvals/'+path,{method:'POST',headers:{'Content-Type':'application/json'},credentials:'omit',body:JSON.stringify(body)}).then(function(r){return r.json().catch(function(){return{}}).then(function(j){if(!r.ok)throw new Error(j.detail||('error '+r.status));return j})})}
function fail(m){root.textContent='';el('p',m,root).className='err'}
if(!token){fail('This link is incomplete.');return}
api('view',{token:token}).then(function(v){
 el('h1','Provisioning request: '+v.title);el('p','Customer: '+v.customer+' | link expires '+v.expires_at);el('p',v.summary||'');
 if(v.stub_plan)el('p','Note: this is a placeholder permission plan.').className='err';
 el('h2','Requested permissions');var ul=el('ul');
 v.permissions.forEach(function(p){el('li',p.privilege+' on '+p.path+' - '+p.reason,ul)});
 var dl=el('button','Download instructions');dl.onclick=function(){api('instructions',{token:token}).then(function(j){var a=document.createElement('a');a.href=URL.createObjectURL(new Blob([j.instructions],{type:'text/markdown'}));a.download='provisioning-instructions.md';a.click()}).catch(function(e){fail(e.message)})};
 if(kind==='c'){el('h2','Confirm provisioning is complete');
  var n=el('input');n.placeholder='Your name';var m=el('input');m.placeholder='Your email';var no=el('textarea');no.placeholder='Note (optional)';
  var b=el('button','Confirm completed');b.onclick=function(){api('complete',{token:token,name:n.value,email:m.value,note:no.value}).then(function(){root.textContent='';el('p','Thank you. Completion recorded.')}).catch(function(e){fail(e.message)})};return}
 el('h2','Your decision');
 var n2=el('input');n2.placeholder='Your full name';var m2=el('input');m2.placeholder='Your email address';
 var st=el('textarea');st.placeholder='Approval statement (required to approve), e.g. "I am authorised to approve these permissions for '+v.customer+'"';
 var nt=el('textarea');nt.placeholder='Note or requested changes (optional)';
 function go(d){api('decide',{token:token,decision:d,name:n2.value,email:m2.value,statement:st.value,note:nt.value,proposal_hash:v.proposal_hash}).then(function(j){
  root.textContent='';el('p','Recorded: '+j.status.replace('_',' ')+'.');
  if(j.completion_link_path){el('p','When provisioning is finished, open this one-time link to confirm completion. Save it now; it is shown only once:');el('pre',location.origin+j.completion_link_path)}
 }).catch(function(e){fail(e.message)})}
 [['Approve','approve'],['Reject','reject'],['Request changes','request_changes']].forEach(function(x){el('button',x[0]).onclick=function(){go(x[1])}});
}).catch(function(e){fail(e.message)});
})();
"""


def _sha(s: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(s.encode()).digest()).decode() + "'"


_HTML = ("<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
         "<meta name=robots content=noindex><title>Provisioning approval</title><style>" + _PAGE_STYLE + "</style></head>"
         "<body><div id=app>Loading...</div><script>" + _PAGE_SCRIPT + "</script></body></html>")
_CSP = (f"default-src 'none'; script-src {_sha(_PAGE_SCRIPT)}; style-src {_sha(_PAGE_STYLE)}; connect-src 'self'; img-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'none'")


def mount(app: FastAPI) -> None:
    @app.get("/approve", include_in_schema=False)
    def page():
        return HTMLResponse(_HTML, headers={"Content-Security-Policy": _CSP, "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"})

    @app.post(f"{API}/view")
    def view(body: TokenIn, request: Request):
        return _run(request, lambda db, rt: approvals.view(db, rt, body.token, _kind(body.token)))

    @app.post(f"{API}/instructions")
    def instr(body: TokenIn, request: Request):
        return _run(request, lambda db, rt: {"instructions": approvals.instructions(db, rt, body.token, _kind(body.token))})

    @app.post(f"{API}/decide")
    def decide(body: DecideIn, request: Request):
        ip, ua = auth.client_ip(request), request.headers.get("user-agent")
        return _run(request, lambda db, rt: approvals.decide(db, rt, body.token, decision=body.decision, name=body.name, email=body.email,
                                                             statement=body.statement, note=body.note, shown_hash=body.proposal_hash, ip=ip, user_agent=ua))

    @app.post(f"{API}/complete")
    def complete(body: CompleteIn, request: Request):
        ip, ua = auth.client_ip(request), request.headers.get("user-agent")
        return _run(request, lambda db, rt: approvals.complete(db, rt, body.token, name=body.name, email=body.email, note=body.note, ip=ip, user_agent=ua))


def _kind(token: str) -> str:
    return "c" if token.startswith("c.") else "a"
