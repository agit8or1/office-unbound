"""PUBLIC customer approval endpoints (no ICS account, no cookies, no session). Deliberately minimal:
 - POST only, JSON only; the token travels in the request body (the link keeps it in the URL *fragment*, which browsers never send
   to servers, proxies or logs), so there is no ambient credential for CSRF to ride on;
 - uniform 404 for unknown/expired/tampered/used links; per-IP rate limit + failure backoff via the shared login_attempts table;
 - nothing else of ICS is reachable with a link: it addresses exactly one approval row.
"""
import base64
import hashlib

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text

from .. import auth, ratelimit
from . import approvals

API = "/api/v1/public/approvals"
RATE_PER_MINUTE = 30


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


def _rate(rt, ip: str | None) -> bool:
    return ratelimit.allow(rt, "approval-ip:" + (ip or "?"), RATE_PER_MINUTE, 60.0)


def reset_rate_limits() -> None:  # tests
    ratelimit.reset()


def _run(request: Request, fn):
    rt = request.app.state.rt
    ip = auth.client_ip(request)
    if "application/json" not in request.headers.get("content-type", ""):
        raise HTTPException(415, "application/json required")
    if not _rate(rt, ip):
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


_PAGE_STYLE = (
    ":root{color-scheme:light dark;--bg:#F3F1EA;--card:#fff;--text:#17202C;--muted:#5B6572;--line:#E1DCCF;--accent:#B04A20;--accent-t:#fff;--ok:#1B7444;--okbg:#E1F0E7;--bad:#B02B2B;--badbg:#F9E1DF;--sunk:#ECE8DE}"
    "@media(prefers-color-scheme:dark){:root{--bg:#0A1422;--card:#112038;--text:#E8ECF2;--muted:#9DA9BA;--line:#213755;--accent:#EE9066;--accent-t:#1A0F08;--ok:#5FC88D;--okbg:#153A27;--bad:#F4908B;--badbg:#4A2022;--sunk:#0D192C}}"
    "*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}"
    "main{max-width:44rem;margin:0 auto;padding:2rem 1.1rem 3rem}"
    ".brand{font-size:.8rem;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin:0 0 1.2rem}"
    "h1{font-size:1.55rem;line-height:1.25;margin:.2rem 0 .4rem;letter-spacing:-.01em}h2{font-size:1.05rem;margin:0 0 .6rem}"
    ".lead{color:var(--muted);margin:0 0 1.4rem}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:1.1rem 1.25rem;margin:0 0 1rem}"
    ".meta{display:grid;grid-template-columns:max-content 1fr;gap:.25rem 1rem;margin:0;font-size:.92rem}.meta dt{color:var(--muted)}.meta dd{margin:0;overflow-wrap:anywhere}"
    "table{border-collapse:collapse;width:100%;font-size:.88rem}th,td{text-align:left;padding:.45rem .5rem;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600;font-size:.76rem;text-transform:uppercase;letter-spacing:.04em}"
    "code,.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.84rem}.scroll{overflow-x:auto}"
    "label{display:block;font-weight:600;font-size:.9rem;margin:.8rem 0 .25rem}input,textarea{width:100%;font:inherit;color:inherit;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:.55rem .65rem}textarea{min-height:5.5rem}"
    "input:focus,textarea:focus,button:focus-visible{outline:2px solid var(--accent);outline-offset:2px}"
    ".row{display:flex;gap:.6rem;flex-wrap:wrap;margin-top:1.1rem}button{font:inherit;font-weight:600;border-radius:9px;border:1px solid var(--line);background:var(--card);color:var(--text);padding:.65rem 1.1rem;cursor:pointer}"
    "button.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-t)}button:disabled{opacity:.55;cursor:wait}"
    ".note{border-radius:10px;padding:.7rem .9rem;margin:0 0 1rem;font-size:.92rem}.note.ok{background:var(--okbg);color:var(--ok)}.note.bad{background:var(--badbg);color:var(--bad)}.note.info{background:var(--sunk);color:var(--muted)}"
    ".fine{color:var(--muted);font-size:.85rem;margin-top:1.5rem}.why{margin-top:.1rem}pre{white-space:pre-wrap;background:var(--sunk);padding:.7rem;border-radius:8px;overflow-wrap:anywhere}"
)
_PAGE_SCRIPT = r"""
(function(){
var h=new URLSearchParams(location.hash.slice(1)),kind=h.get('c')?'c':'a',token=h.get('c')||h.get('t');
history.replaceState(null,'',location.pathname);
var root=document.getElementById('app');
function el(t,txt,p,cls){var e=document.createElement(t);if(txt!==undefined&&txt!==null)e.textContent=txt;if(cls)e.className=cls;(p||root).appendChild(e);return e}
function api(path,body){return fetch('/api/v1/public/approvals/'+path,{method:'POST',headers:{'Content-Type':'application/json'},credentials:'omit',body:JSON.stringify(body)}).then(function(r){return r.json().catch(function(){return{}}).then(function(j){if(!r.ok)throw new Error(j.detail||('error '+r.status));return j})})}
function page(){root.textContent='';el('p','Office Unbound · secure request',root,'brand')}
function fail(m){page();el('div',m,root,'note bad');el('p','If you were expecting a request, ask the person who sent it for a new link. Links work once and expire.',root,'fine')}
function field(p,label,tag,ph){el('label',label,p);var f=el(tag||'input');f.placeholder=ph||'';p.appendChild(f);return f}
if(!token){fail('This link is incomplete.');return}
api('view',{token:token}).then(function(v){
 page();el('h1',kind==='c'?'Confirm that setup is finished':'Please review this access request');
 el('p',v.summary||'',root,'lead');
 var c=el('div',null,root,'card');var dl=el('dl',null,c,'meta');
 [['Customer',v.customer],['Request',v.title],['Link expires',new Date(v.expires_at).toLocaleString()],['Reference',(v.proposal_hash||'').slice(0,12)]].forEach(function(x){el('dt',x[0],dl);el('dd',x[1],dl)});
 if(v.stub_plan)el('div','This request contains a placeholder permission list. Do not approve it.',root,'note bad');
 var pc=el('div',null,root,'card');el('h2','Permissions requested',pc);el('p','Each line lets Office Unbound do one specific thing in your Proxmox cluster. Nothing else is granted.',pc,'lead');
 var sc=el('div',null,pc,'scroll'),tb=el('table',null,sc),hd=el('tr',null,el('thead',null,tb));['Where','Permission and reason'].forEach(function(x){el('th',x,hd)});
 var bd=el('tbody',null,tb);v.permissions.forEach(function(p){var r=el('tr',null,bd);el('td',p.path,r,'mono');var t=el('td',null,r);el('div',p.privilege,t,'mono');el('div',p.reason,t,'fine why')});
 var dl2=el('button','Download full instructions',pc);dl2.onclick=function(){api('instructions',{token:token}).then(function(j){var a=document.createElement('a');a.href=URL.createObjectURL(new Blob([j.instructions],{type:'text/markdown'}));a.download='provisioning-instructions.md';a.click()}).catch(function(e){fail(e.message)})};
 if(v.package_available){var pk=el('button','Download package (scripts + report)',pc);pk.onclick=function(){fetch('/api/v1/public/approvals/package',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'omit',body:JSON.stringify({token:token})}).then(function(r){if(!r.ok)throw new Error('error '+r.status);return r.blob()}).then(function(b){var a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='provisioning-package.zip';a.click()}).catch(function(e){fail(e.message)})}}
 var dc=el('div',null,root,'card');
 if(kind==='c'){el('h2','Your confirmation',dc);var n=field(dc,'Your name'),m=field(dc,'Your email address'),no=field(dc,'Note (optional)','textarea');
  var b=el('button','Confirm completed',el('div',null,dc,'row'),'primary');b.onclick=function(){b.disabled=true;api('complete',{token:token,name:n.value,email:m.value,note:no.value}).then(function(){page();el('h1','Thank you');el('div','Completion recorded.',root,'note ok')}).catch(function(e){b.disabled=false;fail(e.message)})};return}
 el('h2','Your decision',dc);
 var n2=field(dc,'Your full name'),m2=field(dc,'Your email address');
 var st=field(dc,'Approval statement (required to approve)','textarea','For example: I am authorised to approve these permissions for '+v.customer+'.');
 var nt=field(dc,'Note or requested changes (optional)','textarea');
 var rw=el('div',null,dc,'row');
 function go(d,btn){btn.disabled=true;api('decide',{token:token,decision:d,name:n2.value,email:m2.value,statement:st.value,note:nt.value,proposal_hash:v.proposal_hash}).then(function(j){
  page();el('h1','Your decision is recorded');el('div',j.status.replace('_',' '),root,'note ok');
  if(j.completion_link_path){el('p','When the setup is finished, open this one-time link to confirm completion. Save it now; it is shown only once.',root,'lead');el('pre',location.origin+j.completion_link_path,root)}
 }).catch(function(e){btn.disabled=false;fail(e.message)})}
 [['Approve','approve','primary'],['Request changes','request_changes',''],['Reject','reject','']].forEach(function(x){var bt=el('button',x[0],rw,x[2]);bt.onclick=function(){go(x[1],bt)}});
 el('p','Your name, email, statement and network address are recorded with this decision. You do not need an account.',root,'fine');
}).catch(function(e){fail(e.message)});
})();
"""


def _sha(s: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(s.encode()).digest()).decode() + "'"


_HTML = ("<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
         "<meta name=robots content=noindex><title>Provisioning approval</title><style>" + _PAGE_STYLE + "</style></head>"
         "<body><main id=app>Loading...</main><script>" + _PAGE_SCRIPT + "</script></body></html>")
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

    @app.post(f"{API}/package")
    def package(body: TokenIn, request: Request):
        import io
        import zipfile
        from fastapi.responses import Response
        files = _run(request, lambda db, rt: approvals.package(db, rt, body.token, _kind(body.token)))
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for n, c in sorted(files.items()):
                z.writestr(n, c)
        return Response(buf.getvalue(), media_type="application/zip", headers={"Content-Disposition": 'attachment; filename="provisioning-package.zip"'})

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
