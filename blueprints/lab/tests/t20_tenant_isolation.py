#!/usr/bin/env python3
"""T20 - tenant isolation between two INDEPENDENT customer deployments (acceptance A20).

Two separate stacks built by blueprints/lab/tenant/build-customer.sh (own lab CA, OpenLDAP, Postgres, Keycloak realm,
OpenCloud, secrets; machines ou-ca-{id,files} = custa.ou-lab.internal, ou-cb-{id,files} = custb.ou-lab.internal).
Every negative test is paired with a CONTROL (the same request in the legitimate direction succeeds), so a PASS is
never "the endpoint was simply down".

Sections: identity | files | network | ics | backup      (select with OU_T20_SECTIONS=identity,files,...; default all)
backup = per-customer backup boundaries with the real backup product (restic + rest-server + ICS policies), needs ou-bkp1, dev ICS on 127.0.0.1:8123 (database ics_test_aa),
         ICS_TEST_ENV_FILE=/etc/office-unbound/ics-test-aa.env; OU_T20_BKP_RESTORE=0 skips the restore verification (needs scratch machines ou-ca-idr / ou-cb-idr).
Run with the ICS virtualenv python (requests, cryptography, sqlalchemy, pyotp). Needs sudo for `systemd-run -M`,
`nft` (network section) and the ICS dev instance (127.0.0.1:8122, database ics_test_g, never the production service).
Secrets are read from the customer machines at run time and kept in memory only (never printed).
"""
import base64
import json
import os
import re
import subprocess
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import requests  # noqa: E402
from ou_lab import Report  # noqa: E402

SECTIONS = set((os.environ.get("OU_T20_SECTIONS") or "identity,files,network,ics,backup").split(","))
RUN = uuid.uuid4().hex[:8]
LINKPW = "Lnk-%s-Pw!9x" % uuid.uuid4().hex[:10]   # OpenCloud enforces password-protected public links
WORK = os.environ.get("OU_T20_WORK", "/tmp/ou-t20-" + RUN)
os.makedirs(WORK, mode=0o700, exist_ok=True)
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
rep = Report("T20 tenant isolation (two independent customer deployments)")


def sh(machine, script, timeout=60):
    p = subprocess.run(["sudo", "systemd-run", "-M", machine, "--quiet", "--pipe", "--wait", "/bin/bash", "-c", script],
                       capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Cust:
    def __init__(self, key):
        self.key = key
        self.dom = "cust%s.ou-lab.internal" % key
        self.realm = "cust" + key
        self.idm, self.fm = "ou-c%s-id" % key, "ou-c%s-files" % key
        self.kc = "https://auth.%s" % self.dom
        self.oc = "https://cloud.%s" % self.dom
        self.idip = {"a": "192.168.186.61", "b": "192.168.186.71"}[key]
        self.fip = {"a": "192.168.186.62", "b": "192.168.186.72"}[key]
        rc, out, _ = sh(self.idm, "cat /root/ou-lab-ca/ca.crt")
        self.ca = os.path.join(WORK, "ca-%s.crt" % key)
        open(self.ca, "w").write(out)
        rc, out, _ = sh(self.idm, "cat /root/ou-lab-secrets/test-users.env")
        self.pw = {k[len("OU_PASSWORD_"):].lower(): v for k, v in (l.split("=", 1) for l in out.split())}
        self.tok = {}

    def get(self, url, **kw):
        return requests.get(url, verify=self.ca, timeout=30, **kw)

    def req(self, method, url, **kw):
        return requests.request(method, url, verify=self.ca, timeout=30, **kw)

    def token(self, user, scope="openid profile email", client="ou-lab-test"):
        r = self.req("POST", "%s/realms/%s/protocol/openid-connect/token" % (self.kc, self.realm),
                     data={"grant_type": "password", "client_id": client, "username": user, "password": self.pw[user], "scope": scope})
        r.raise_for_status()
        return r.json()

    def jwks(self):
        return self.get("%s/realms/%s/protocol/openid-connect/certs" % (self.kc, self.realm)).json()


A, B = Cust("a"), Cust("b")
DENY = (400, 401, 403, 404)


def H(t):
    return {"Authorization": "Bearer " + t}


def claims(tok):
    return json.loads(b64d(tok.split(".")[1]))


# =========================================================================================== identity
def identity():
    ta, tb = A.token("alice", "openid profile email offline_access"), B.token("alice", "openid profile email offline_access")
    A.tok, B.tok = ta, tb
    ca, cb = claims(ta["access_token"]), claims(tb["access_token"])
    rep.check("I00 setup: two distinct issuers, two distinct CAs, same username alice in both",
              ca["iss"] != cb["iss"] and ca["preferred_username"] == cb["preferred_username"] == "alice" and open(A.ca).read() != open(B.ca).read(),
              "iss A=%s B=%s; uuid A=%s B=%s; CA sha256 differ" % (ca["iss"], cb["iss"], ca.get("uuid"), cb.get("uuid")), "isolation precondition broken")
    rep.check("I00b signing keys disjoint (JWKS kids)", not ({k["kid"] for k in A.jwks()["keys"]} & {k["kid"] for k in B.jwks()["keys"]}),
              "no common kid / key material", "a signing key is shared")
    for src, dst in ((A, B), (B, A)):
        try:
            requests.get(dst.kc + "/", verify=src.ca, timeout=15); ok = False
        except requests.exceptions.SSLError:
            ok = True
        rep.check("I00c TLS trust boundary: %s's CA does not validate %s's server certificates" % (src.key.upper(), dst.key.upper()), ok, "certificate verify failed (distinct CA)", "cross-trust")
    # controls
    for c, t in ((A, ta), (B, tb)):
        r = c.get(c.oc + "/graph/v1.0/me", headers=H(t["access_token"]))
        rep.check("I01 control: %s token accepted by its own OpenCloud /me" % c.key.upper(), r.status_code == 200, "HTTP 200", "HTTP %s %s" % (r.status_code, r.text[:80]))
        r = c.get(c.kc + "/realms/%s/protocol/openid-connect/userinfo" % c.realm, headers=H(t["access_token"]))
        rep.check("I01 control: %s token accepted by its own Keycloak userinfo" % c.key.upper(), r.status_code == 200, "HTTP 200", "HTTP %s" % r.status_code)
    # cross use of access tokens
    for src, dst in ((A, B), (B, A)):
        t = src.tok["access_token"]
        r = dst.get(dst.oc + "/graph/v1.0/me", headers=H(t))
        rep.check("I02 %s access token -> %s OpenCloud Graph /me" % (src.key.upper(), dst.key.upper()), r.status_code == 401, "HTTP 401", "HTTP %s %s" % (r.status_code, r.text[:80]))
        r = dst.get(dst.oc + "/remote.php/dav/files/alice/", headers=H(t))
        rep.check("I02 %s access token -> %s WebDAV (same username alice)" % (src.key.upper(), dst.key.upper()), r.status_code == 401, "HTTP 401", "HTTP %s" % r.status_code)
        r = dst.req("PROPFIND", dst.oc + "/dav/spaces/", headers={**H(t), "Depth": "0"})
        rep.check("I02 %s access token -> %s /dav/spaces" % (src.key.upper(), dst.key.upper()), r.status_code == 401, "HTTP 401", "HTTP %s" % r.status_code)
        r = dst.get(dst.kc + "/realms/%s/protocol/openid-connect/userinfo" % dst.realm, headers=H(t))
        rep.check("I03 %s access token -> %s Keycloak userinfo (realm %s)" % (src.key.upper(), dst.key.upper(), dst.realm), r.status_code == 401, "HTTP 401", "HTTP %s" % r.status_code)
        r = dst.get(dst.kc + "/realms/%s/protocol/openid-connect/userinfo" % src.realm, headers=H(t))
        rep.check("I03b %s token -> %s Keycloak but naming the %s realm path" % (src.key.upper(), dst.key.upper(), src.realm), r.status_code in DENY + (404,),
                  "HTTP %s (no such realm there)" % r.status_code, "HTTP %s" % r.status_code)
        # id token as bearer
        r = dst.get(dst.oc + "/graph/v1.0/me", headers=H(src.tok["id_token"]))
        rep.check("I04 %s ID token -> %s OpenCloud" % (src.key.upper(), dst.key.upper()), r.status_code == 401, "HTTP 401", "HTTP %s" % r.status_code)
    # refresh + offline tokens at the other realm's token endpoint
    for src, dst in ((A, B), (B, A)):
        for name, scope in (("refresh", "openid profile email"), ("offline", "openid profile email offline_access")):
            tk = src.token("alice", scope)
            rt = tk["refresh_token"]
            typ = claims(rt).get("typ")
            r = dst.req("POST", "%s/realms/%s/protocol/openid-connect/token" % (dst.kc, dst.realm),
                        data={"grant_type": "refresh_token", "client_id": "ou-lab-test", "refresh_token": rt})
            ok = r.status_code in (400, 401) and "access_token" not in r.text
            rep.check("I05 %s %s token (typ=%s) -> %s token endpoint" % (src.key.upper(), name, typ, dst.key.upper()), ok,
                      "HTTP %s %s" % (r.status_code, r.json().get("error")), "HTTP %s %s" % (r.status_code, r.text[:100]))
            r = src.req("POST", "%s/realms/%s/protocol/openid-connect/token" % (src.kc, src.realm),
                        data={"grant_type": "refresh_token", "client_id": "ou-lab-test", "refresh_token": rt})
            rep.check("I05 control: %s %s token works at its own realm" % (src.key.upper(), name), r.status_code == 200, "HTTP 200", "HTTP %s" % r.status_code)
    # same-username collision on credentials
    for src, dst in ((A, B), (B, A)):
        r = dst.req("POST", "%s/realms/%s/protocol/openid-connect/token" % (dst.kc, dst.realm),
                    data={"grant_type": "password", "client_id": "ou-lab-test", "username": "alice", "password": src.pw["alice"]})
        rep.check("I06 same-username collision: %s alice's password at %s Keycloak" % (src.key.upper(), dst.key.upper()), r.status_code in (400, 401),
                  "HTTP %s %s" % (r.status_code, r.json().get("error")), "HTTP %s" % r.status_code)
    # forged / tampered tokens
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    atk = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def rs256(hdr, pl, key=atk):
        si = (b64u(json.dumps(hdr).encode()) + "." + b64u(json.dumps(pl).encode())).encode()
        return si.decode() + "." + b64u(key.sign(si, padding.PKCS1v15(), hashes.SHA256()))
    hb = json.loads(b64d(tb["access_token"].split(".")[0]))
    ha = json.loads(b64d(ta["access_token"].split(".")[0]))
    forged = {}
    # (1) A's real claims for B's issuer/uuid, attacker key, B's kid
    pl = dict(ca, iss=cb["iss"], uuid=cb["uuid"], sub=cb["sub"], azp=cb.get("azp"))
    forged["attacker-key RS256, claims=B alice (iss/uuid/sub), B's kid"] = (B, rs256(hb, pl))
    forged["attacker-key RS256, claims=A alice, A's kid"] = (A, rs256(ha, dict(ca)))
    # (2) alg none
    forged["alg=none, claims=B alice"] = (B, b64u(json.dumps({"alg": "none", "typ": "JWT"}).encode()) + "." + b64u(json.dumps(dict(cb)).encode()) + ".")
    # (3) HS256 with B's public key as secret (key confusion)
    import hmac
    import hashlib
    pubpem = "-----BEGIN PUBLIC KEY-----"  # use the JWKS RSA modulus as the HMAC secret material (best effort confusion attempt)
    k = next(x for x in B.jwks()["keys"] if x["kid"] == hb["kid"])
    si = (b64u(json.dumps({"alg": "HS256", "typ": "JWT", "kid": hb["kid"]}).encode()) + "." + b64u(json.dumps(dict(cb)).encode())).encode()
    forged["HS256 with B's public modulus as secret"] = (B, si.decode() + "." + b64u(hmac.new(b64d(k["n"]), si, hashlib.sha256).digest()))
    # (4) A's genuine signature, payload edited to B's iss + uuid (claims tampering)
    h_, p_, s_ = ta["access_token"].split(".")
    forged["A signature kept, payload edited -> iss/uuid of B alice"] = (B, h_ + "." + b64u(json.dumps(dict(ca, iss=cb["iss"], uuid=cb["uuid"], sub=cb["sub"])).encode()) + "." + s_)
    forged["A signature kept, payload edited -> uuid of A bob (privilege/identity swap at HOME)"] = (A, h_ + "." + b64u(json.dumps(dict(ca, uuid=claims(A.token('bob')['access_token'])['uuid'], preferred_username="bob")).encode()) + "." + s_)
    # (5) B's genuine token, payload edited to A's uuid at A? (B signature, target A) and the 'same issuer string' trick
    h2, p2, s2 = tb["access_token"].split(".")
    forged["B signature kept, payload edited -> iss/uuid of A alice, sent to A"] = (A, h2 + "." + b64u(json.dumps(dict(cb, iss=ca["iss"], uuid=ca["uuid"], sub=ca["sub"])).encode()) + "." + s2)
    for name, (dst, tok) in forged.items():
        r = dst.get(dst.oc + "/graph/v1.0/me", headers=H(tok))
        r2 = dst.get(dst.oc + "/remote.php/dav/files/alice/", headers=H(tok))
        rep.check("I07 forged token [%s] -> %s OpenCloud" % (name, dst.key.upper()), r.status_code == 401 and r2.status_code == 401,
                  "me HTTP 401, WebDAV HTTP 401", "me HTTP %s, dav HTTP %s" % (r.status_code, r2.status_code))
        r = dst.get(dst.kc + "/realms/%s/protocol/openid-connect/userinfo" % dst.realm, headers=H(tok))
        rep.check("I07 forged token [%s] -> %s Keycloak userinfo" % (name, dst.key.upper()), r.status_code == 401, "HTTP 401", "HTTP %s" % r.status_code)
    # service-account (client credentials) token of ICS client: customer A's ou-ics cannot administer B
    sec = {}
    for c in (A, B):
        rc, out, _ = sh(c.idm, "cat /root/ou-lab-secrets/kc-ics-client-secret")
        sec[c.key] = out.strip()
    for src, dst in ((A, B), (B, A)):
        r = src.req("POST", "%s/realms/%s/protocol/openid-connect/token" % (src.kc, src.realm),
                    data={"grant_type": "client_credentials", "client_id": "ou-ics", "client_secret": sec[src.key]})
        if r.status_code != 200:
            rep.skipped("I08 service-account token", "ou-ics client_credentials failed at %s: HTTP %s" % (src.key, r.status_code)); continue
        st = r.json()["access_token"]
        r_ok = src.get("%s/admin/realms/%s/users?username=alice" % (src.kc, src.realm), headers=H(st))
        rep.check("I08 control: %s ou-ics service token manages %s users" % (src.key.upper(), src.key.upper()), r_ok.status_code == 200 and len(r_ok.json()) == 1, "HTTP 200, 1 user", "HTTP %s" % r_ok.status_code)
        r = dst.get("%s/admin/realms/%s/users?username=alice" % (dst.kc, dst.realm), headers=H(st))
        rep.check("I08 %s ou-ics service token -> %s admin API" % (src.key.upper(), dst.key.upper()), r.status_code in (401, 403), "HTTP %s" % r.status_code, "HTTP %s %s" % (r.status_code, r.text[:80]))
        r = dst.req("POST", "%s/realms/%s/protocol/openid-connect/token" % (dst.kc, dst.realm),
                    data={"grant_type": "client_credentials", "client_id": "ou-ics", "client_secret": sec[src.key]})
        rep.check("I08 %s ou-ics client secret used at %s's Keycloak" % (src.key.upper(), dst.key.upper()), r.status_code in (400, 401), "HTTP %s" % r.status_code, "HTTP %s" % r.status_code)
    # OpenCloud app tokens (basic auth)
    for src, dst in ((A, B), (B, A)):
        r = src.req("POST", src.oc + "/auth-app/tokens?expiry=1h", headers=H(src.tok["access_token"]))
        if r.status_code != 200:
            rep.skipped("I09 app token", "auth-app/tokens HTTP %s on %s" % (r.status_code, src.key)); continue
        tok = r.json()["token"]
        r_ok = src.get(src.oc + "/remote.php/dav/files/alice/", auth=("alice", tok))
        rep.check("I09 control: %s app token works at %s WebDAV" % (src.key.upper(), src.key.upper()), r_ok.status_code in (200, 207), "HTTP %s" % r_ok.status_code, "HTTP %s (app-auth not enabled? basic auth off)" % r_ok.status_code)
        r = dst.get(dst.oc + "/remote.php/dav/files/alice/", auth=("alice", tok))
        rep.check("I09 %s app token (user alice) -> %s WebDAV" % (src.key.upper(), dst.key.upper()), r.status_code in (401, 403), "HTTP %s" % r.status_code, "HTTP %s" % r.status_code)
    # LDAP: A's bind account cannot bind to B's directory
    rc, out, _ = sh(A.fm, "LDAPTLS_CACERT=/etc/ou-lab/tls/ca.crt ldapwhoami -x -H ldaps://ldap.%s -D cn=svc-bind,ou=system,dc=%s,dc=ou-lab,dc=internal -w \"$(cat /root/ou-lab-secrets/ldap-bind-password)\" 2>&1" % (A.dom, A.realm))
    rep.check("I10 control: A's read-only bind works against A's LDAP", "dn:" in out, out.strip()[:60], out.strip()[:100])
    _, bpw, _ = sh(A.idm, "cat /root/ou-lab-secrets/ldap-bind-password")
    rc, out, _ = sh(A.idm, "echo | grep -q . ; LDAPTLS_CACERT=/etc/ou-lab/tls/ca.crt LDAPTLS_REQCERT=allow ldapwhoami -x -H ldaps://%s -D cn=svc-bind,ou=system,dc=custb,dc=ou-lab,dc=internal -w \"$(cat /root/ou-lab-secrets/ldap-bind-password)\" 2>&1" % B.idip)
    rep.check("I10 A's bind secret against B's LDAP (even skipping cert verification)", "dn:" not in out and ("Invalid credentials" in out or "49" in out or "Can't contact" in out), out.strip()[:100], out.strip()[:100])


# =========================================================================================== files
def files():
    ids = {}
    for c in (A, B):
        t = c.token("alice")["access_token"]
        c.at = t
        r = c.req("PUT", c.oc + "/remote.php/dav/files/alice/secret-%s-%s.txt" % (c.key, RUN), headers=H(t), data=("MARKER-%s-%s" % (c.key, RUN)).encode())
        rep.check("F00 seed: %s alice writes her file" % c.key.upper(), r.status_code in (201, 204), "HTTP %s" % r.status_code, "HTTP %s" % r.status_code)
        pf = c.req("PROPFIND", c.oc + "/remote.php/dav/files/alice/secret-%s-%s.txt" % (c.key, RUN), headers={**H(t), "Depth": "0"},
                   data='<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:fileid/></d:prop></d:propfind>')
        fid = re.search(r"<oc:fileid>([^<]+)</oc:fileid>", pf.text).group(1)
        drives = c.get(c.oc + "/graph/v1.0/me/drives", headers=H(t)).json()["value"]
        personal = next(d for d in drives if d["driveType"] == "personal")
        sp = c.req("POST", c.oc + "/graph/v1.0/drives", headers=H(t), json={"name": "Finance-%s-%s" % (c.key.upper(), RUN)})
        space = sp.json() if sp.status_code in (200, 201) else None
        if space:
            c.req("PUT", c.oc + "/dav/spaces/%s/budget-%s.txt" % (space["id"], c.key), headers=H(t), data=b"SPACE-MARKER-" + c.key.encode())
        lk = c.req("POST", c.oc + "/graph/v1beta1/drives/%s/items/%s/createLink" % (personal["id"], fid), headers=H(t), json={"type": "view", "password": LINKPW})
        link = lk.json().get("link", {}).get("webUrl") if lk.status_code in (200, 201) else None
        c.f = dict(fid=fid, drive=personal["id"], space=space["id"] if space else None, link=link, linktok=link.rsplit("/", 1)[-1] if link else None,
                   drives={d["id"] for d in drives})
        rep.check("F00 seed: %s project space + public link created" % c.key.upper(), bool(space and link), "space %s link ...%s" % (c.f["space"][:8] if space else None, c.f["linktok"][-6:] if link else None),
                  "space HTTP %s link HTTP %s" % (sp.status_code, lk.status_code))
    for me, other in ((A, B), (B, A)):
        # listings disjoint
        drives = {d["id"] for d in me.get(me.oc + "/graph/v1.0/me/drives", headers=H(me.at)).json()["value"]}
        alld = me.get(me.oc + "/graph/v1.0/drives", headers=H(me.at))
        alli = {d["id"] for d in alld.json().get("value", [])} if alld.status_code == 200 else set()
        rep.check("F01 %s alice (admin) sees none of %s's drive ids (/me/drives + /drives)" % (me.key.upper(), other.key.upper()),
                  not ((drives | alli) & ({other.f["drive"], other.f["space"]})), "%d drives visible, 0 foreign" % len(drives | alli), "foreign drive visible")
        r = me.req("PROPFIND", me.oc + "/remote.php/dav/files/alice/", headers={**H(me.at), "Depth": "1"})
        rep.check("F01 %s alice's home listing contains only her own marker file" % me.key.upper(), ("secret-%s-%s" % (me.key, RUN)) in r.text and ("secret-%s-" % other.key) not in r.text, "own file only", "foreign file visible")
        # guessed ids at the *other* deployment with a LEGIT local admin token (strongest case) and at own
        for what, val in (("personal drive id", other.f["drive"]), ("project space id", other.f["space"]), ("file id", other.f["fid"])):
            for label, url in (("dav/spaces", "/dav/spaces/%s" % val), ("graph drive", "/graph/v1.0/drives/%s" % (val.split("!")[0] if what != "file id" else other.f["drive"]))):
                r = me.req("PROPFIND" if "dav" in label else "GET", me.oc + url, headers={**H(me.at), "Depth": "0"})
                body = r.text
                leaked = ("MARKER-%s" % other.key) in body or other.f["fid"] in body and what == "file id" and r.status_code in (200, 207)
                rep.check("F02 %s admin token at %s's OpenCloud asks for %s's %s via %s" % (me.key.upper(), me.key.upper(), other.key.upper(), what, label),
                          r.status_code in (403, 404, 400) and not leaked, "HTTP %s, nothing returned" % r.status_code, "HTTP %s %s" % (r.status_code, body[:80]))
        r = me.req("GET", me.oc + "/dav/spaces/%s/budget-%s.txt" % (other.f["space"], other.key), headers=H(me.at))
        rep.check("F02 GET foreign space file with guessed path (%s -> %s space)" % (me.key.upper(), other.key.upper()), r.status_code in (403, 404) and "SPACE-MARKER" not in r.text, "HTTP %s" % r.status_code, "HTTP %s %s" % (r.status_code, r.text[:60]))
        # my token at the other deployment with the other's real ids
        r = other.req("GET", other.oc + "/dav/spaces/%s/budget-%s.txt" % (other.f["space"], other.key), headers=H(me.at))
        rep.check("F03 %s token + %s's REAL space path at %s's OpenCloud" % (me.key.upper(), other.key.upper(), other.key.upper()), r.status_code == 401 and "SPACE-MARKER" not in r.text, "HTTP 401", "HTTP %s" % r.status_code)
        r = other.req("GET", other.oc + "/remote.php/dav/files/alice/secret-%s-%s.txt" % (other.key, RUN), headers=H(me.at))
        rep.check("F03 %s token + %s alice's REAL file path (same username) at %s" % (me.key.upper(), other.key.upper(), other.key.upper()), r.status_code == 401, "HTTP 401", "HTTP %s" % r.status_code)
    # controls for the guess tests
    for c in (A, B):
        r = c.req("GET", c.oc + "/dav/spaces/%s/budget-%s.txt" % (c.f["space"], c.key), headers=H(c.at))
        rep.check("F04 control: %s alice reads her own project space file by id" % c.key.upper(), r.status_code == 200 and "SPACE-MARKER-" + c.key in r.text, "HTTP 200", "HTTP %s" % r.status_code)
    # public links
    for me, other in ((A, B), (B, A)):
        r_ok = me.req("PROPFIND", me.oc + "/dav/public-files/%s" % me.f["linktok"], headers={"Depth": "0"}, auth=("public", LINKPW))
        g_ok = me.get(me.oc + "/dav/public-files/%s/secret-%s-%s.txt" % (me.f["linktok"], me.key, RUN), auth=("public", LINKPW))
        if g_ok.status_code != 200:
            g_ok = me.get(me.oc + "/dav/public-files/%s" % me.f["linktok"], auth=("public", LINKPW))
        rep.check("F05 control: %s public link resolves on %s" % (me.key.upper(), me.key.upper()), (g_ok.status_code == 200 and ("MARKER-%s" % me.key) in g_ok.text) or r_ok.status_code == 207, "PROPFIND %s / GET %s (content served)" % (r_ok.status_code, g_ok.status_code), "PROPFIND %s GET %s" % (r_ok.status_code, g_ok.status_code))
        r = other.get(other.oc + "/dav/public-files/%s/secret-%s-%s.txt" % (me.f["linktok"], me.key, RUN), auth=("public", LINKPW))
        r2 = other.req("PROPFIND", other.oc + "/dav/public-files/%s" % me.f["linktok"], headers={"Depth": "0"}, auth=("public", LINKPW))
        rep.check("F05 %s's public-link token on %s's OpenCloud" % (me.key.upper(), other.key.upper()), r.status_code in (401, 403, 404) and r2.status_code in (401, 403, 404) and ("MARKER-%s" % me.key) not in r.text,
                  "GET %s PROPFIND %s" % (r.status_code, r2.status_code), "GET %s PROPFIND %s" % (r.status_code, r2.status_code))
        r = other.get(other.oc + "/graph/v1beta1/drives/%s/items/%s/permissions" % (me.f["drive"], me.f["fid"]), headers=H(other.at))
        rep.check("F05 %s admin lists permissions/links of %s's item by id" % (other.key.upper(), me.key.upper()), r.status_code in (403, 404) and (me.f["linktok"] or "~") not in r.text, "HTTP %s" % r.status_code, "HTTP %s %s" % (r.status_code, r.text[:80]))
    # sharing into the other deployment
    VIEWER = "b1e2218d-eef8-4d4c-b82d-0f1a1b48f3b5"
    for me, other in ((A, B), (B, A)):
        bob = me.req("GET", me.oc + "/graph/v1.0/users?$search=bob", headers=H(me.at)).json().get("value", [])
        obob = other.req("GET", other.oc + "/graph/v1.0/users?$search=bob", headers=H(other.at)).json().get("value", [])
        if not bob or not obob:
            rep.skipped("F06 share invite", "cannot resolve bob in both deployments"); continue
        body = lambda uid: {"recipients": [{"@libre.graph.recipient.type": "user", "objectId": uid}], "roles": [VIEWER]}
        r = me.req("POST", me.oc + "/graph/v1beta1/drives/%s/items/%s/invite" % (me.f["drive"], me.f["fid"]), headers=H(me.at), json=body(bob[0]["id"]))
        rep.check("F06 control: %s alice invites %s bob into her own file" % (me.key.upper(), me.key.upper()), r.status_code in (200, 201), "HTTP %s" % r.status_code, "HTTP %s %s" % (r.status_code, r.text[:80]))
        r = me.req("POST", me.oc + "/graph/v1beta1/drives/%s/items/%s/invite" % (me.f["drive"], me.f["fid"]), headers=H(me.at), json=body(obob[0]["id"]))
        rep.check("F06 %s alice shares into %s: invite %s's bob (user id from the other directory)" % (me.key.upper(), other.key.upper(), other.key.upper()), r.status_code in (400, 404, 403, 422), "HTTP %s refused" % r.status_code, "HTTP %s %s" % (r.status_code, r.text[:80]))
        r = other.req("POST", other.oc + "/graph/v1beta1/drives/%s/items/%s/invite" % (me.f["drive"], me.f["fid"]), headers=H(other.at), json=body(obob[0]["id"]))
        rep.check("F06 %s admin invites someone onto %s's item id at %s" % (other.key.upper(), me.key.upper(), other.key.upper()), r.status_code in (400, 403, 404), "HTTP %s" % r.status_code, "HTTP %s %s" % (r.status_code, r.text[:80]))
        r = other.req("POST", other.oc + "/graph/v1beta1/drives/%s/items/%s/invite" % (me.f["drive"], me.f["fid"]), headers=H(me.at), json=body(obob[0]["id"]))
        rep.check("F06 %s token drives the share API of %s" % (me.key.upper(), other.key.upper()), r.status_code == 401, "HTTP 401", "HTTP %s" % r.status_code)


# =========================================================================================== network
NFT = """table bridge ou_tenant_t20 {
  chain forward {
    type filter hook forward priority -1; policy accept;
    iifname "vb-ou-ca-*" oifname "vb-ou-cb-*" counter drop
    iifname "vb-ou-cb-*" oifname "vb-ou-ca-*" counter drop
  }
}
"""
PORTS = [(443, "Keycloak/https"), (636, "LDAPS")]


def reach(machine, ip, port, v6=False):
    cmd = "timeout 4 bash -c 'echo > /dev/tcp/%s/%d' && echo OPEN || echo CLOSED" % (ip, port)
    rc, out, _ = sh(machine, cmd, 15)
    return "OPEN" in out


def network():
    probes = [(A.fm, B.idip, 443), (A.fm, B.idip, 636), (A.fm, B.fip, 443), (A.idm, B.idip, 443), (A.idm, B.idip, 636), (A.idm, B.fip, 443),
              (B.fm, A.idip, 443), (B.fm, A.idip, 636), (B.fm, A.fip, 443), (B.idm, A.idip, 636), (B.idm, A.fip, 443)]
    ctrl = [(A.fm, A.idip, 443), (A.fm, A.idip, 636), (B.fm, B.idip, 443), (B.fm, B.idip, 636), (A.idm, A.fip, 443), (B.idm, B.fip, 443)]
    subprocess.run(["sudo", "nft", "delete", "table", "bridge", "ou_tenant_t20"], capture_output=True)
    before = {p: reach(*p) for p in probes}
    n_open = sum(before.values())
    print("INFO N00 baseline with NO per-customer rule (shared nspawn zone / one L2 bridge): %d of %d cross-customer probes OPEN" % (n_open, len(probes)))
    for p, v in before.items():
        print("INFO   %s -> %s:%d %s" % (p[0], p[1], p[2], "OPEN" if v else "closed"))
    rep.check("N00 lab limitation confirmed: without extra rules the shared zone does NOT isolate customers", n_open > 0,
              "%d/%d cross-customer connections succeed (expected in this lab zone; this is exactly what production VLAN/SDN separation must remove)" % (n_open, len(probes)),
              "no cross traffic even without rules (unexpected)")
    rc, out, _ = sh(B.idm, "ip -6 -o a show host0 scope link | awk '{print $4}' | cut -d/ -f1")
    ll = out.strip()
    v6_before = False
    if ll:
        rc, o, _ = sh(A.fm, "timeout 4 bash -c 'echo > /dev/tcp/%s%%host0/636' && echo OPEN || echo CLOSED" % ll, 15)
        v6_before = "OPEN" in o
    print("INFO N00 IPv6 link-local A files -> B id :636 before the rule: %s" % ("OPEN" if v6_before else "closed"))
    open(os.path.join(WORK, "ou_tenant_t20.nft"), "w").write(NFT)
    p = subprocess.run(["sudo", "nft", "-f", os.path.join(WORK, "ou_tenant_t20.nft")], capture_output=True, text=True)
    if p.returncode:
        rep.failed("N01 install bridge-family nft rule", p.stderr[:200]); return
    try:
        after = {p: reach(*p) for p in probes}
        rep.check("N01 per-customer host rule (bridge family, port-based) blocks A<->B on all %d probes" % len(probes), not any(after.values()),
                  "0/%d cross-customer connections open" % len(probes), "still open: %s" % [p for p, v in after.items() if v])
        okc = {p: reach(*p) for p in ctrl}
        rep.check("N02 control: intra-customer traffic (A files->A id, B files->B id) unaffected", all(okc.values()), "%d/%d intra-customer probes open" % (sum(okc.values()), len(ctrl)), "closed: %s" % [p for p, v in okc.items() if not v])
        # IPv6 link-local path
        if ll and v6_before:
            rc, o, _ = sh(A.fm, "timeout 4 bash -c 'echo > /dev/tcp/%s%%host0/636' && echo OPEN || echo CLOSED" % ll, 15)
            rep.check("N03 IPv6 link-local path A files -> B id :636 (fe80) blocked by the port-based rule", "OPEN" not in o, "closed", "OPEN over IPv6")
        rc, o, _ = sh(A.fm, "ping -c1 -W2 %s >/dev/null 2>&1 && echo UP || echo DOWN" % B.fip, 10)
        rep.check("N04 ICMP A -> B blocked", "DOWN" in o, "no echo reply", "ping works")
        hostok = subprocess.run("curl -s -m 8 -o /dev/null -w %%{http_code} --cacert %s %s/" % (A.ca, A.oc), shell=True, capture_output=True, text=True).stdout
        hostok2 = subprocess.run("curl -s -m 8 -o /dev/null -w %%{http_code} --cacert %s %s/" % (B.ca, B.oc), shell=True, capture_output=True, text=True).stdout
        rep.check("N05 control: operator host (ICS) still reaches both customers' services", hostok == "200" and hostok2 == "200", "A HTTP %s, B HTTP %s" % (hostok, hostok2), "A %s B %s" % (hostok, hostok2))
        if os.environ.get("OU_T20_KEEP_NFT") != "1":
            pass
    finally:
        if os.environ.get("OU_T20_KEEP_NFT") != "1":
            subprocess.run(["sudo", "nft", "delete", "table", "bridge", "ou_tenant_t20"], capture_output=True)
    again = reach(A.fm, B.idip, 636)
    if os.environ.get("OU_T20_KEEP_NFT") != "1":
        print("INFO N06 rule removed again; A->B:636 %s (rule file kept at blueprints/lab/tenant/nft-per-customer.nft)" % ("OPEN again" if again else "closed"))
    rep.skipped("N07 in-guest firewall (defence in depth)", "NOT TESTED: no nftables inside the customer containers in this lab (package not installed; not attempted). Production guests carry an nftables policy (guest-bootstrap) which was not exercised for tenant separation")


# =========================================================================================== ics (secrets/operators)
def ics():
    sys.path.insert(0, os.path.join(REPO, "ics", "scripts"))
    sys.path.insert(0, os.path.join(REPO, "ics"))
    os.environ.setdefault("OU_INST_SUFFIX", "g")
    os.environ.setdefault("OU_INST_PORT", "8122")
    os.environ.setdefault("OU_INST_DIR", os.path.join(WORK, "icsg"))
    import lab_ics_instance as li
    li.init()                       # drops/recreates ics_test_g schema, throw-away keys, 3 accounts (never the production DB)
    from sqlalchemy import create_engine, text
    from ics import auth
    from ics.runtime import Runtime
    import pyotp
    rt = Runtime()
    accts = {}
    for name, role in (("t-adm", "admin"), ("t-ap1", "approver"), ("t-ap2", "approver"), ("t-opall", "operator"), ("t-opa", "operator"), ("t-opb", "operator")):
        pw = uuid.uuid4().hex + "Aa1!"
        with rt.session() as db:
            tok = auth.create_account_cli(db, rt, name, role)
            uri = auth.enroll_begin(db, rt, name, tok, pw, "127.0.0.1")
            secret = re.search(r"secret=([A-Z2-7]+)", uri).group(1)
            auth.enroll_confirm(db, rt, name, tok, pyotp.TOTP(secret).now(), "127.0.0.1")
        accts[name] = (pw, secret)
        time.sleep(1.1)
    srv = subprocess.Popen([sys.executable, os.path.join(REPO, "ics", "scripts", "lab_ics_instance.py"), "serve"],
                           env=dict(os.environ), stdout=open(os.path.join(WORK, "ics-serve.log"), "w"), stderr=subprocess.STDOUT)
    base = "http://127.0.0.1:%s" % os.environ["OU_INST_PORT"]
    try:
        for _ in range(60):
            try:
                if requests.get(base + "/readyz", timeout=2).status_code < 500:
                    break
            except Exception:
                time.sleep(1)
        API = base + "/api/v1"

        class Cl:
            def __init__(self, name):
                pw, secret = accts[name]
                self.s = requests.Session()
                step = int(time.time() // 30) + 1
                r = self.s.post(API + "/auth/login", json={"username": name, "password": pw, "totp_code": pyotp.TOTP(secret).at(step * 30)})
                assert r.status_code == 200, (name, r.status_code, r.text[:100])
                self.h = {"X-CSRF-Token": r.json()["csrf_token"]}
                self.ck = "; ".join("%s=%s" % (c.name, c.value) for c in self.s.cookies)   # Secure cookie over plain http: send manually

            def r(self, m, p, **kw):
                return requests.request(m, API + p, headers={**self.h, "Cookie": self.ck}, timeout=60, **kw)
        adm, ap1, ap2 = Cl("t-adm"), Cl("t-ap1"), Cl("t-ap2")
        time.sleep(1)

        def run(req, action, params, approvers=(ap1, ap2)):
            p = req.r("POST", "/plans", json={"action": action, "params": params})
            if p.status_code != 201:
                return p.status_code, p.text
            pj = p.json()
            jid = pj.get("job_id")
            for a in approvers[: pj["approvals_required"]]:
                if pj["status"] != "approved":
                    jid = a.r("POST", "/plans/%s/approve" % pj["plan_id"]).json().get("job_id") or jid
            for _ in range(60):
                j = req.r("GET", "/jobs/%s" % jid).json() if jid else {}
                if j.get("status") in ("succeeded", "failed", "cancelled"):
                    return 200, j
                time.sleep(1)
            return 0, "timeout"
        cid = {}
        for k, c in (("a", A), ("b", B)):
            st, j = run(adm, "customer.create", {"name": "Customer %s (t20 %s)" % (k.upper(), RUN), "msp_owned": False})
            cid[k] = j["result"]["customer_id"] if st == 200 and j["status"] == "succeeded" else None
            if not cid[k]:
                print("INFO customer.create %s -> %s %s" % (k, st, str(j)[:300]))
        rep.check("S00 customers A and B registered through the real API (plan -> 2 approvals -> job)", all(cid.values()), "A=%s B=%s" % (cid["a"][:8], cid["b"][:8]) if all(cid.values()) else "", "customer.create failed: %s" % cid)
        if not all(cid.values()):
            return
        # scoped operators
        for name, k in (("t-opa", "a"), ("t-opb", "b")):
            st, j = run(adm, "operator.set_scope", {"username": name, "all_customers": False, "customer_ids": [cid[k]]})
            rep.check("S00 operator %s scoped to customer %s" % (name, k.upper()), st == 200 and j["status"] == "succeeded", "scope set", "%s %s" % (st, j))
        opall, opa, opb = Cl("t-opall"), Cl("t-opa"), Cl("t-opb")
        # identity stack per customer (the 'identity endpoint' of each stack), real API with the REAL stack credentials
        stack, stack_secrets = {}, []
        for k, c in (("a", A), ("b", B)):
            _, lpw, _ = sh(c.idm, "cat /root/ou-lab-secrets/ldap-ics-password")
            _, ksec, _ = sh(c.idm, "cat /root/ou-lab-secrets/kc-ics-client-secret")
            _, ca_pem, _ = sh(c.idm, "cat /root/ou-lab-ca/ca.crt")
            stack_secrets.extend([lpw.strip(), ksec.strip()])
            base_dn = "dc=%s,dc=ou-lab,dc=internal" % c.realm
            params = {"name": "stack-%s" % c.key, "ldap_url": "ldaps://ldap.%s" % c.dom, "ldap_bind_dn": "cn=svc-ics,ou=system," + base_dn, "ldap_bind_password": lpw.strip(),
                      "ldap_people_dn": "ou=people," + base_dn, "ldap_groups_dn": "ou=groups," + base_dn, "mail_domain": c.dom,
                      "allowed_groups": ["mail-users", "opencloudUser", "opencloudAdmin"], "privileged_groups": ["opencloudAdmin"], "kc_url": c.kc, "kc_realm": c.realm,
                      "kc_client_id": "ou-ics", "kc_client_secret": ksec.strip(), "identity_ca_pem": ca_pem, "files_url": c.oc, "reconcile_interval_seconds": 0, "customer_id": cid[k]}
            st, j = run(adm, "idm.stack.register", params)
            if st == 422 and "customer_id" in str(j):
                params.pop("customer_id")
                st, j = run(adm, "idm.stack.register", params)
                stack[k] = ("registered WITHOUT customer binding (model has no customer_id)", st == 200 and j["status"] == "succeeded", j)
            else:
                stack[k] = ("registered with customer_id", st == 200 and j["status"] == "succeeded", j)
        for k in "ab":
            rep.check("S01 identity stack of customer %s registered through the real API: %s" % (k.upper(), stack[k][0]), stack[k][1], "stack-%s registered" % k, "failed: %s" % str(stack[k][2])[:200])
        # credentials, endpoints, approvals, deployments per customer
        cred = {}
        for k in "ab":
            st, j = run(adm, "credential.create", {"provider": "fakeprov", "customer_id": cid[k], "label": "t20 %s" % k, "credential_type": "api_token", "purpose": "inventory",
                                                   "identity": "svc-%s@pve!ics" % k, "secret": "T20Secret-%s-%s" % (k, RUN) + "x" * 8})
            cred[k] = j["result"]["credential_id"] if st == 200 and j["status"] == "succeeded" else None
        rep.check("S02 credentials created per customer through typed action (vault)", all(cred.values()), "both created", str(cred))
        eng = create_engine(li.urls()[1])
        ep, dep, appr = {}, {}, {}
        with eng.begin() as db:
            for k in "ab":
                ep[k] = str(db.execute(text("INSERT INTO endpoints (name, type, base_url, token_id, token_secret_enc, fingerprint_sha256, customer_id) VALUES (:n,'proxmox',:u,'tid','\\x'::bytea,:f,:c) RETURNING id"),
                                       {"n": "pve-%s-%s" % (k, RUN), "u": "https://pve-%s.invalid:8006" % k, "f": "ab" * 32, "c": cid[k]}).scalar())
                db.execute(text("INSERT INTO deployments (slug, customer_id, profile, profile_version, endpoint_id, status, desired_spec) VALUES (:s,:c,'p',1,:e,'active','{}'::jsonb)"),
                           {"s": "dep-%s-%s" % (k, RUN), "c": cid[k], "e": ep[k]})
        for k in "ab":
            r = opall.r("POST", "/customer-approvals", json={"customer_id": cid[k], "title": "link %s" % k})
            appr[k] = r.json()["id"]
            appr[k + "_link"] = opall.r("POST", "/customer-approvals/%s/submit" % appr[k], json={}).json().get("link_path", "")
        # --- scoped operator A vs customer B
        for me, other, ob in ((opa, "b", "t-opa"), (opb, "a", "t-opb")):
            mine = "a" if other == "b" else "b"
            lc = [c["id"] for c in me.r("GET", "/credentials").json()]
            rep.check("S10 %s lists credentials: only its own customer's" % ob, lc == [cred[mine]], "own only", str(lc))
            rep.check("S10 %s GET credential of the other customer" % ob, me.r("GET", "/credentials/%s" % cred[other]).status_code == 404, "404", "readable")
            le = [e["id"] for e in me.r("GET", "/endpoints").json()]
            rep.check("S11 %s lists endpoints: only own" % ob, le == [ep[mine]], "own only", str(le))
            rep.check("S11 %s GET/inventory of the other customer's endpoint" % ob, me.r("GET", "/endpoints/%s" % ep[other]).status_code == 404 and me.r("GET", "/endpoints/%s/inventory" % ep[other]).status_code == 404, "404/404", "readable")
            rep.check("S12 %s GET other customer record" % ob, me.r("GET", "/customers/%s" % cid[other]).status_code == 404, "404", "readable")
            for action, params in (("credential.test", {"credential_id": cred[other]}), ("credential.revoke", {"credential_id": cred[other], "reason": "attempted cross use"}),
                                   ("inventory.refresh", {"endpoint_id": ep[other]})):
                rep.check("S13 %s plan %s against the other customer's object (use)" % (ob, action), me.r("POST", "/plans", json={"action": action, "params": params}).status_code == 404, "404", "plan accepted")
            ra = me.r("GET", "/customer-approvals").json()
            rep.check("S14 %s lists approval links: only own customer's" % ob, [x["id"] for x in ra] == [appr[mine]], "own only", str([x["id"][:6] for x in ra]))
            rep.check("S14 %s GET/submit/cancel the other customer's approval" % ob, all(me.r(m, "/customer-approvals/%s%s" % (appr[other], s), json={} if m == "POST" else None).status_code == 404 for m, s in (("GET", ""), ("POST", "/submit"), ("POST", "/cancel"))), "404 x3", "accessible")
            lp = {p["id"] for p in me.r("GET", "/plans").json()}
            rep.check("S15 %s plan list holds no plan touching the other customer" % ob, True if not lp else all(me.r("GET", "/plans").json()[i].get("customer_id") in (None, cid[mine]) for i in range(len(lp))), "own/none", "foreign plans listed")
            ld = [d["slug"] for d in me.r("GET", "/deployments").json()]
            rep.check("S16 %s lists deployments: only own customer's" % ob, ld == ["dep-%s-%s" % (mine, RUN)], "own only", "foreign deployments listed: %s" % ld)
            rep.check("S16 %s GET the other customer's deployment (+resources)" % ob, me.r("GET", "/deployments/dep-%s-%s" % (other, RUN)).status_code == 404 and me.r("GET", "/deployments/dep-%s-%s/resources" % (other, RUN)).status_code == 404, "404/404", "readable")
            ls = [s["name"] for s in me.r("GET", "/identity/stacks").json()]
            rep.check("S17 %s lists identity stacks (customers' identity endpoints): only own" % ob, ls == ["stack-%s" % mine], "own only", "foreign identity stack listed: %s" % ls)
            lu = me.r("GET", "/identity/users?stack=stack-%s" % other)
            rep.check("S17 %s reads users of the other customer's stack" % ob, lu.status_code in (403, 404) or lu.json() == [], "refused/empty", "HTTP %s %s" % (lu.status_code, str(lu.json())[:60]))
            rep.check("S18 %s cannot read the global audit log / register stacks / set scopes" % ob, me.r("GET", "/audit").status_code == 403 and me.r("POST", "/plans", json={"action": "operator.set_scope", "params": {"username": ob, "all_customers": True}}).status_code in (403, 404), "403", "allowed")
        # the approval link of A cannot be used to read/decide B's proposal (token is bound to its approval)
        tokA = appr["a_link"].split("#t=")[-1]
        v = requests.post(base + "/api/v1/public/approvals/view", json={"token": tokA}, timeout=20)
        if v.status_code == 200:
            vj = json.dumps(v.json())
            rep.check("S19 approval link A shows only customer A's proposal", ("Customer B" not in vj) and (cid["b"] not in vj), "no B data in A's link view", "B data present")
            bad = requests.post(base + "/api/v1/public/approvals/view", json={"token": tokA[:-3] + "xyz"}, timeout=20)
            rep.check("S19 altered link token", bad.status_code == 404, "uniform 404", "HTTP %s" % bad.status_code)
        else:
            rep.skipped("S19 approval link view", "public view HTTP %s (path differs?)" % v.status_code)
        # vault AAD binding: ciphertext bound to credential id/provider/CUSTOMER
        from ics.credentials import service
        ok_a = service.get_secret(rt, cred["a"]) == "T20Secret-a-%s" % RUN + "x" * 8
        rep.check("S20 control: ICS decrypts A's credential through the service", ok_a, "decrypts", "does not decrypt")
        with eng.begin() as db:
            db.execute(text("UPDATE credentials SET customer_id = :b WHERE id = :a"), {"b": cid["b"], "a": cred["a"]})
        try:
            service.get_secret(rt, cred["a"]); moved = "DECRYPTS (AAD does not bind customer)"
        except Exception as e:
            moved = None
            err = type(e).__name__
        finally:
            with eng.begin() as db:
                db.execute(text("UPDATE credentials SET customer_id = :a WHERE id = :i"), {"a": cid["a"], "i": cred["a"]})
        rep.check("S20 re-labelling A's credential row to customer B (DB tamper) makes it undecryptable (AAD binds customer)", moved is None, "refused (%s)" % (err if moved is None else ""), moved)
        with eng.begin() as db:
            blob = db.execute(text("SELECT secret_enc FROM credentials WHERE id = :i"), {"i": cred["a"]}).scalar()
            db.execute(text("UPDATE credentials SET secret_enc = :b WHERE id = :i"), {"b": bytes(blob), "i": cred["b"]})
        try:
            service.get_secret(rt, cred["b"]); sw = "DECRYPTS"
        except Exception:
            sw = None
        rep.check("S21 copying A's ciphertext onto B's credential row (swap) is refused", sw is None, "refused", sw)
        # a plan param for B's credential from A's operator already covered (S13); mass check of secret leakage in the API responses
        dump = json.dumps([opa.r("GET", "/credentials").json(), opa.r("GET", "/identity/stacks").json(), opa.r("GET", "/plans").json(), opa.r("GET", "/jobs").json()])
        leak = [s for s in ["T20Secret-a-%s" % RUN, "T20Secret-b-%s" % RUN, "PRIVATE KEY"] + stack_secrets if s in dump]
        rep.check("S22 scoped operator A: no credential / stack (LDAP bind, Keycloak client) secret or private key in list responses (public CA certificates in plan params are not secrets)", not leak, "no secrets", "leaked %s" % leak)
    finally:
        srv.terminate()
        try:
            srv.wait(10)
        except Exception:
            srv.kill()


# =========================================================================================== backup
# Per-customer backup boundaries with the REAL backup product (ADR-0010: restic + rest-server, ICS policies/actions), agent AU.
# Customer A and B each get: their own ICS customer record and scoped operator, their own backup policy, their own restic repository (own repository
# PASSWORD generated by the ICS vault and bound to the customer), their own rest-server user and path (--private-repos, append-only listener + separate
# maintenance listener, separate passwords), their own runner profile (/etc/ou-backup/c-<id>/) and their own scratch machine for restore verification.
# Needs (lab host, sudo): ou-bkp1 + ou-ca-id + ou-cb-id running (the section starts them when stopped); scratch machines ou-ca-idr / ou-cb-idr (cloned from
# ou-id-r1 when missing, powered on only during the restore verification); dev ICS 127.0.0.1:8123 on database ics_test_aa (ICS_TEST_ENV_FILE=...ics-test-aa.env).
BKP = "ou-bkp1"
BK_SECRETS = "/etc/office-unbound/backup-lab"
LABBK = os.path.join(REPO, "blueprints", "lab", "backup")
BK_RESTORE = os.environ.get("OU_T20_BKP_RESTORE", "1") == "1"
SCRATCH = {"a": "ou-ca-idr", "b": "ou-cb-idr"}
RESTIC = "/usr/local/bin/restic"


def host(*argv, inp=None, timeout=900, check=True, env=None):
    p = subprocess.run(["sudo", "-n"] + (["env"] + ["%s=%s" % kv for kv in env.items()] if env else []) + list(argv), input=inp, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError("%s failed: %s" % (argv[0], (p.stderr or p.stdout)[-400:]))
    return p


def mem_available_mb():
    return int([l for l in open("/proc/meminfo") if l.startswith("MemAvailable")][0].split()[1]) // 1024


def ics_instance(suffix, port, tag, names):
    """A throw-away dev ICS (never the production service/database): own keys under WORK/<tag>, database ics_test_<suffix>, 127.0.0.1:<port>."""
    sys.path.insert(0, os.path.join(REPO, "ics", "scripts"))
    sys.path.insert(0, os.path.join(REPO, "ics"))
    import lab_ics_instance as li
    li.D, li.SUF, li.PORT = os.path.join(WORK, tag), suffix, port
    li.ENVF = os.environ.get("ICS_TEST_ENV_FILE", li.ENVF)
    os.environ.update(OU_INST_SUFFIX=suffix, OU_INST_PORT=str(port), OU_INST_DIR=li.D, ICS_BACKUP_SCHEDULER_ENABLED="false")
    li.init()
    from ics import auth
    from ics.runtime import Runtime
    import pyotp
    rt = Runtime()
    accts = {}
    for name, role in names:
        pw = uuid.uuid4().hex + "Aa1!"
        with rt.session() as db:
            tok = auth.create_account_cli(db, rt, name, role)
            uri = auth.enroll_begin(db, rt, name, tok, pw, "127.0.0.1")
            secret = re.search(r"secret=([A-Z2-7]+)", uri).group(1)
            auth.enroll_confirm(db, rt, name, tok, pyotp.TOTP(secret).now(), "127.0.0.1")
        accts[name] = (pw, secret)
        time.sleep(1.1)
    srv = subprocess.Popen([sys.executable, os.path.join(REPO, "ics", "scripts", "lab_ics_instance.py"), "serve"], env=dict(os.environ),
                           stdout=open(os.path.join(WORK, tag + "-serve.log"), "w"), stderr=subprocess.STDOUT)
    base = "http://127.0.0.1:%d" % port
    for _ in range(90):
        try:
            if requests.get(base + "/readyz", timeout=2).status_code < 500:
                break
        except Exception:
            time.sleep(1)
    API = base + "/api/v1"

    class Cl:
        def __init__(self, name):
            pw, secret = accts[name]
            self.s = requests.Session()
            step = int(time.time() // 30) + 1
            r = self.s.post(API + "/auth/login", json={"username": name, "password": pw, "totp_code": pyotp.TOTP(secret).at(step * 30)})
            assert r.status_code == 200, (name, r.status_code, r.text[:100])
            self.h = {"X-CSRF-Token": r.json()["csrf_token"]}
            self.ck = "; ".join("%s=%s" % (c.name, c.value) for c in self.s.cookies)

        def r(self, m, p, **kw):
            return requests.request(m, API + p, headers={**self.h, "Cookie": self.ck}, timeout=60, **kw)
    time.sleep(1)
    return types_ns(rt=rt, srv=srv, Cl=Cl, accts=accts, li=li)


def types_ns(**kw):
    import types
    return types.SimpleNamespace(**kw)


def backup():
    free = mem_available_mb()
    if free < 2048:
        rep.failed("B00 host memory", "only %d MiB available (<2 GiB): aborting before starting any machine" % free)
        return
    started = []
    for m in (BKP, A.idm, B.idm):
        if host("machinectl", "show", m, "-p", "State", "--value", check=False).stdout.strip() != "running":
            host("machinectl", "start", m)
            started.append(m)
    for _ in range(60):
        if all(sh(m, "true")[0] == 0 for m in (BKP, A.idm, B.idm)):
            break
        time.sleep(2)
    inst = ics_instance("aa", 8123, "icsbk", [("t-adm", "admin"), ("t-ap1", "approver"), ("t-ap2", "approver"), ("t-opa", "operator"), ("t-opb", "operator")])
    rt, srv = inst.rt, inst.srv
    try:
        _backup_body(inst, rt)
    finally:
        srv.terminate()
        try:
            srv.wait(15)
        except Exception:
            srv.kill()
        for m in SCRATCH.values():
            host("machinectl", "poweroff", m, check=False)
        for m in started:
            host("machinectl", "poweroff", m, check=False)


def _backup_body(inst, rt):
    sys.path.insert(0, os.path.join(REPO, "ics"))
    from ics.backups import ops, policy as pol
    Cl = inst.Cl
    adm, ap1, ap2, opa, opb = Cl("t-adm"), Cl("t-ap1"), Cl("t-ap2"), Cl("t-opa"), Cl("t-opb")

    def run(req, action, params, approvers=(ap1, ap2), wait=900):
        p = req.r("POST", "/plans", json={"action": action, "params": params})
        if p.status_code != 201:
            return p.status_code, p.text
        pj = p.json()
        jid = pj.get("job_id")
        for a in approvers[: pj["approvals_required"]]:
            if pj["status"] != "approved":
                jid = a.r("POST", "/plans/%s/approve" % pj["plan_id"]).json().get("job_id") or jid
        for _ in range(wait):
            j = req.r("GET", "/jobs/%s" % jid).json() if jid else {}
            if j.get("status") in ("succeeded", "failed", "cancelled"):
                return 200, j
            time.sleep(1)
        return 0, "timeout"

    def ok(st, j):
        return st == 200 and j["status"] == "succeeded"

    cid = {}
    for k, c in (("a", A), ("b", B)):
        st, j = run(adm, "customer.create", {"name": "Backup customer %s (t20 %s)" % (k.upper(), RUN), "msp_owned": True})
        cid[k] = j["result"]["customer_id"] if ok(st, j) else None
    rep.check("B00 customers A and B registered through the real API", all(cid.values()), "A=%s B=%s" % (cid["a"][:8], cid["b"][:8]) if all(cid.values()) else "", "customer.create failed %s" % cid)
    if not all(cid.values()):
        return
    for name, k in (("t-opa", "a"), ("t-opb", "b")):
        st, j = run(adm, "operator.set_scope", {"username": name, "all_customers": False, "customer_ids": [cid[k]]})
        rep.check("B00 operator %s scoped to customer %s" % (name, k.upper()), ok(st, j), "scope set", "%s %s" % (st, j))
    prof = {k: pol.customer_profile(cid[k]) for k in cid}
    # profiles of earlier runs would (correctly) collide with this run's machines in the helper's isolation check: start from a clean lab runner/target
    host("bash", "-c", "rm -rf /etc/ou-backup/c-* /var/lib/ou-backup/stage/c-* %s/cust" % BK_SECRETS)
    sh(BKP, "rm -rf /srv/restic-cust/c-*")
    # ---- lab infrastructure: per-customer rest-server users, runner agent allowlist, canaries, scratch machines
    host("bash", os.path.join(LABBK, "bkp-customer-setup.sh"), prof["a"], prof["b"], timeout=300)
    ip = sh(BKP, "ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1")[1].strip()
    bridge = host("bash", "-c", "ip -4 -o addr show vz-oulab | awk '{print $4}' | cut -d/ -f1 | grep -v '^169.254' | head -1").stdout.strip()
    ca_fp = host("openssl", "x509", "-in", BK_SECRETS + "/bkp.crt", "-noout", "-fingerprint", "-sha256").stdout.split("=")[1].strip().replace(":", "").lower()
    hs = os.path.join(WORK, "handshake.json")
    host("bash", os.path.join(LABBK, "lab-agent-setup.sh"), REPO, bridge, "18443", hs, env={"OU_BKP_CUSTOMERS": "%s,%s" % (prof["a"], prof["b"]), "OU_BKP_TIERS": "identity"})
    hsj = json.load(open(hs))
    for k, c in (("a", A), ("b", B)):
        sh(c.idm, "bash /root/lab/spike-identity-files/kc/ldap-user.sh add drillcanary - >/dev/null 2>&1; true")   # canary directory entry (idempotent)
        sh(c.idm, "cd /root/lab/spike-groupware && KC_URL=%s KC_REALM=%s KC_CA=/root/ou-lab-ca/ca.crt python3 -c \"import kc_lib as k; t=k.admin_token(); "
           "k.call('POST','/admin/realms/%s/roles',t,{'name':'drill-canary-t20-%s'},ok_codes=(409,))\"" % (c.kc, c.realm, c.realm, k))        # DB-only canary role
        host("bash", os.path.join(LABBK, "lab-customer-runner-setup.sh"), REPO, prof[k], "identity", c.idm, SCRATCH[k] if BK_RESTORE else "-",
             '{"ldap_uid":"drillcanary","role_prefix":"drill-canary-"}', json.dumps({"OU_REALM": c.realm, "OU_DOMAIN": c.dom}), timeout=300)
        if BK_RESTORE and host("machinectl", "show-image", SCRATCH[k], check=False).returncode != 0:
            host("machinectl", "clone", "ou-id-r1", SCRATCH[k])
            host("bash", "-c", "printf '[Exec]\\nBoot=yes\\nPrivateUsers=pick\\n[Network]\\nZone=oulab\\n' > /etc/systemd/nspawn/%s.nspawn; "
                 "systemctl set-property --runtime systemd-nspawn@%s MemoryMax=2G" % (SCRATCH[k], SCRATCH[k]))
    # ---- enrol the runner, create the two policies (each by its own scoped operator), provision + init repositories
    st, j = run(adm, "node.enroll", {"name": "bkp-runner-t20", "address": hsj["address"], "port": hsj["port"], "tls_fingerprint_sha256": hsj["tls_fingerprint_sha256"],
                                      "agent_key_fingerprint_sha256": hsj["agent_key_fingerprint_sha256"], "enrollment_token": hsj["token"]})
    rep.check("B00 backup runner enrolled (real node.enroll, agent allowlist = identity tier + exactly the two customer profiles)", ok(st, j), "enrolled", "%s %s" % (st, str(j)[:200]))
    node = [n for n in adm.r("GET", "/nodes").json() if n["name"] == "bkp-runner-t20"][0]
    caps = node.get("capabilities") or {}
    rep.check("B00 the node's advertised capability lists both customer profiles", set((caps.get("backup.run") or {}).get("customers", [])) == {prof["a"], prof["b"]}, "customers=%d" % len(caps["backup.run"]["customers"]), "capabilities %s" % caps)
    pnames = {"a": "t20-bk-a", "b": "t20-bk-b"}
    for k, op in (("a", opa), ("b", opb)):
        st, j = run(op, "backup.policy.create", {"name": pnames[k], "tier": "identity", "deployment": "customer %s identity" % k.upper(), "customer_id": cid[k], "runner_node_id": node["id"],
                                                  "schedule": {"every_hours": 12}, "rpo_seconds": 86400, "rto_seconds": 900, "repo": {"url": "https://%s:8010/%s/identity" % (ip, prof[k]), "ca_sha256": ca_fp},
                                                  "verify": {"check_every_seconds": 3600, "check_read_data_percent": 100, "restore_every_seconds": 86400}})
        rep.check("B01 operator %s (scoped to %s) creates the backup policy of its own customer through the real API" % (k.upper(), k.upper()), ok(st, j), "policy %s" % pnames[k], "%s %s" % (st, str(j)[:300]))
    repopw = {}
    for k in ("a", "b"):
        with rt.session() as db:
            repopw[k] = ops.node_secret(rt, db, pnames[k])["repo_password"]       # break-glass export: audited, value never printed
        host("/usr/local/sbin/ou-backup", "--direct", "--customer", prof[k], "provision", "identity", inp=json.dumps({"repo_password": repopw[k]}))
        sh(BKP, "rm -rf /srv/restic-cust/%s" % prof[k])      # fresh repository per run
        out = json.loads(host("/usr/local/sbin/ou-backup", "--direct", "--customer", prof[k], "init", "identity").stdout)
        rk = "/var/lib/ou-backup/recovery-%s.txt" % k
        host("rm", "-f", rk)
        rec = json.loads(host("/usr/local/sbin/ou-backup", "--direct", "--customer", prof[k], "recovery-key", "identity", rk).stdout)
        host("shred", "-u", rk)
        with rt.session() as db:
            ops.recovery_ack(db, pnames[k], rec["recovery_fp"])
    rep.check("B01 repository passwords differ per customer and neither equals the other's (vault-generated, never printed)", repopw["a"] != repopw["b"] and len(repopw["a"]) >= 40, "distinct 256-bit secrets", "same or short password")
    # ---- real backups through the typed actions (plan -> job -> signed agent request -> ou-backup -> restic -> ou-bkp1)
    for k, op in (("a", opa), ("b", opb)):
        st, j = run(op, "backup.run", {"policy": pnames[k]})
        rep.check("B02 %s's operator runs backup.run on its own policy (control: the legitimate path works)" % k.upper(), ok(st, j) and j["result"].get("repo_confirmed") is True,
                  "snapshot %s, %s bytes added" % (str(j["result"].get("snapshot"))[:8], j["result"].get("bytes_added")) if ok(st, j) else "", "%s %s" % (st, str(j)[:400]))
    for k, op in (("a", opa), ("b", opb)):
        st, j = run(op, "backup.verify", {"policy": pnames[k], "level": "check"})
        rep.check("B02 %s: repository check through the policy (reads 100%% of the data)" % k.upper(), ok(st, j), "passed", "%s %s" % (st, str(j)[:300]))
    # ---- storage-level isolation: credentials, keys, paths (direct restic / HTTP against the per-customer rest-server)
    rest = {}
    for k in ("a", "b"):
        rest[k] = {l: host("cat", "%s/cust/%s/rest-%s.pw" % (BK_SECRETS, prof[k], l)).stdout.strip() for l in ("backup", "maint")}
    cacert = "/etc/ou-backup/bkp-ca.crt"

    def restic(repo_user, rest_pw, repo_profile, repo_pw, *args, port=8010):
        env = {"RESTIC_REPOSITORY": "rest:https://%s:%d/%s/identity/" % (ip, port, repo_profile), "RESTIC_PASSWORD": repo_pw, "RESTIC_CACERT": cacert,
               "RESTIC_REST_USERNAME": repo_user, "RESTIC_REST_PASSWORD": rest_pw, "RESTIC_CACHE_DIR": "/tmp/ou-t20-restic-cache-%s" % RUN, "HOME": "/root"}
        return subprocess.run([RESTIC, *args], env=dict(os.environ, **env), capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL)   # no sudo: secrets stay out of argv

    def snaps(p):
        try:
            return json.loads(p.stdout)
        except Exception:
            return None
    own = {}
    for k in ("a", "b"):
        r = restic(prof[k], rest[k]["backup"], prof[k], repopw[k], "snapshots", "--json")
        own[k] = snaps(r)
        rep.check("B10 control: %s's REST credential + %s's repository key open %s's own repository and list its snapshot" % (k.upper(), k.upper(), k.upper()), r.returncode == 0 and own[k] and len(own[k]) >= 1,
                  "%d snapshot(s)" % len(own[k] or []), "rc=%s %s" % (r.returncode, r.stderr[-200:]))
    for me, other in (("a", "b"), ("b", "a")):
        M, O = me.upper(), other.upper()
        # (1) another customer's REST user against my repository path: the rest-server refuses (--private-repos)
        r = restic(prof[other], rest[other]["backup"], prof[me], repopw[me], "snapshots", "--json")
        rep.check("B11 %s's REST credential (and even %s's valid repository key) cannot list %s's repository" % (O, M, M), r.returncode != 0 and not snaps(r), "refused: %s" % r.stderr.strip().splitlines()[-1][:120] if r.stderr.strip() else "refused", "LISTED: %s" % r.stdout[:200])
        # (2) raw HTTP with the other's credentials: read, list, write
        base = "https://%s:8010/%s/identity" % (ip, prof[me])
        import requests as rq
        au = (prof[other], rest[other]["backup"])
        codes = {}
        for label, method, path, kw in (("read config", "GET", "/config", {}), ("list snapshots", "GET", "/snapshots/", {"headers": {"Accept": "application/vnd.x.restic.rest.v2"}}),
                                        ("list data", "GET", "/data/", {"headers": {"Accept": "application/vnd.x.restic.rest.v2"}}), ("write a data blob", "POST", "/data/" + "ab" * 32, {"data": b"x"}),
                                        ("write a key", "POST", "/keys/" + "cd" * 32, {"data": b"x"}), ("create repository", "POST", "/?create=true", {}),
                                        ("delete a snapshot", "DELETE", "/snapshots/" + "ef" * 32, {})):
            codes[label] = rq.request(method, base + path, auth=au, verify=cacert, timeout=30, **kw).status_code
        rep.check("B11 raw HTTP with %s's credentials on %s's path: read/list/write/create/delete all refused" % (O, M), all(c in (401, 403, 404) for c in codes.values()), str(codes), "NOT refused: %s" % codes)
        # (3) the key boundary alone: right REST access (misconfigured ACL case) but another customer's repository password
        r = restic(prof[me], rest[me]["backup"], prof[me], repopw[other], "snapshots", "--json")
        rep.check("B12 %s's repository key cannot open %s's repository even with %s's own REST credential (encryption boundary alone)" % (O, M, M), r.returncode != 0 and "wrong password" in (r.stderr + r.stdout).lower(), "wrong password or no key found", "rc=%s %s" % (r.returncode, (r.stderr + r.stdout)[-200:]))
        r = restic(prof[me], rest[me]["backup"], prof[me], repopw[other], "backup", "--host", "evil", "/etc/hostname")
        rep.check("B12 %s's key cannot write a snapshot into %s's repository" % (O, M), r.returncode != 0, "refused", "WRITE SUCCEEDED")
        r = restic(prof[me], rest[me]["backup"], prof[me], repopw[other], "key", "list")
        rep.check("B12 %s's key cannot list %s's repository keys" % (O, M), r.returncode != 0, "refused", "LISTED")
        # (4) credentials are per listener: the append-only credential does not work on the maintenance listener and vice versa
        r = restic(prof[me], rest[me]["backup"], prof[me], repopw[me], "snapshots", port=8011)
        rep.check("B13 %s's append-only credential is rejected by the maintenance listener (separate credentials)" % M, r.returncode != 0, "rejected", "ACCEPTED")
        r = restic(prof[me], rest[me]["maint"], prof[me], repopw[me], "snapshots", port=8010)
        rep.check("B13 %s's maintenance credential is rejected by the append-only listener" % M, r.returncode != 0, "rejected", "ACCEPTED")
        r = restic(prof[me], rest[me]["maint"], prof[me], repopw[me], "snapshots", "--json", port=8011)
        rep.check("B13 control: %s's maintenance credential works on the maintenance listener" % M, r.returncode == 0 and snaps(r), "ok", "rc=%s %s" % (r.returncode, r.stderr[-150:]))
        r = restic(prof[other], rest[other]["maint"], prof[me], repopw[me], "snapshots", port=8011)
        rep.check("B13 %s's maintenance credential cannot reach %s's repository on the maintenance listener" % (O, M), r.returncode != 0, "refused", "REACHED")
        # (5) append-only per customer: the runner credential cannot delete history
        before = own[me]
        r = restic(prof[me], rest[me]["backup"], prof[me], repopw[me], "forget", before[0]["id"])
        after = snaps(restic(prof[me], rest[me]["backup"], prof[me], repopw[me], "snapshots", "--json"))
        rep.check("B14 %s's runner credential cannot delete its own history (append-only listener): snapshot still present" % M, any(s["id"] == before[0]["id"] for s in (after or [])), "history intact (%d snapshots)" % len(after or []), "snapshot deleted")
    # (6) the repository at rest holds no cleartext of either customer, with a control that the content is really in there
    hits = sh(BKP, "grep -rIl --binary-files=text -e 'dc=custa' -e 'dc=custb' -e custa.ou-lab.internal -e custb.ou-lab.internal -e 'PRIVATE KEY' /srv/restic-cust 2>/dev/null | head -3")[1].strip()
    rep.check("B15 the per-customer repositories on the backup host contain no cleartext domain, realm secret or private key (encrypted at rest)", hits == "", "no occurrence in /srv/restic-cust", "cleartext found in: %s" % hits)
    for k, c in (("a", A), ("b", B)):
        env = {"RESTIC_REPOSITORY": "rest:https://%s:8010/%s/identity/" % (ip, prof[k]), "RESTIC_PASSWORD": repopw[k], "RESTIC_CACERT": cacert, "RESTIC_REST_USERNAME": prof[k],
               "RESTIC_REST_PASSWORD": rest[k]["backup"], "RESTIC_CACHE_DIR": "/tmp/ou-t20-restic-cache-%s" % RUN}
        r = subprocess.run([RESTIC, "dump", "latest", "/var/lib/ou-backup/stage/%s/identity/current/identity.tar" % prof[k], "--host", c.idm], env=dict(os.environ, **env), capture_output=True, timeout=300)
        own_dom, other_dom = b"dc=cust%s," % k.encode(), b"dc=cust%s," % ("b" if k == "a" else "a").encode()
        rep.check("B15 control: %s's own key decrypts its repository: the %d-byte archive holds %s's directory (dc=cust%s) and nothing of the other customer" % (k.upper(), len(r.stdout), k.upper(), k),
                  r.returncode == 0 and own_dom in r.stdout and other_dom not in r.stdout, "decrypted, own domain found, other domain absent", "rc=%s own=%s other=%s %s" % (r.returncode, own_dom in r.stdout, other_dom in r.stdout, r.stderr[-120:]))
    # ---- ICS operator scoping on the real API
    for me, other, op in (("a", "b", opa), ("b", "a", opb)):
        M, O = me.upper(), other.upper()
        res = {}
        for label, action, params in (("run", "backup.run", {"policy": pnames[other]}), ("verify check", "backup.verify", {"policy": pnames[other], "level": "check"}),
                                      ("verify restore", "backup.verify", {"policy": pnames[other], "level": "restore"}), ("prune", "backup.prune", {"policy": pnames[other]}),
                                      ("update", "backup.policy.update", {"policy": pnames[other], "enabled": False})):
            p = op.r("POST", "/plans", json={"action": action, "params": params})
            res[label] = p.status_code
        miss = op.r("POST", "/plans", json={"action": "backup.run", "params": {"policy": "no-such-policy"}})
        rep.check("B20 operator scoped to %s cannot plan run / verify (check, restore) / prune / update on %s's policy: 404, same as a missing policy" % (M, O),
                  all(c == 404 for c in res.values()) and miss.status_code == 404, str(res), "NOT refused: %s (missing -> %s)" % (res, miss.status_code))
        p = op.r("POST", "/plans", json={"action": "backup.policy.create", "params": {"name": "sneak-%s" % me, "tier": "identity", "deployment": "x", "customer_id": cid[other], "runner_node_id": node["id"],
                                                                                    "schedule": {"every_hours": 12}, "rpo_seconds": 86400, "rto_seconds": 900,
                                                                                    "repo": {"url": "https://%s:8010/%s/sneak" % (ip, prof[other]), "ca_sha256": ca_fp}}})
        rep.check("B20 operator %s cannot create a backup policy (a repository) in %s's namespace: 404" % (M, O), p.status_code == 404, "404", "got %s" % p.status_code)
        pols = [x["name"] for x in op.r("GET", "/backups/policies").json()]
        runs = {x["policy"] for x in op.r("GET", "/backups/runs").json()}
        vers = {x["policy"] for x in op.r("GET", "/backups/verifications").json()}
        rep.check("B20 %s's operator sees only %s's policies, runs and verifications in the read API" % (M, M), pols == [pnames[me]] and runs == {pnames[me]} and vers == {pnames[me]}, "only %s" % pnames[me], "policies=%s runs=%s verifications=%s" % (pols, runs, vers))
        snap_before = len(snaps(restic(prof[other], rest[other]["backup"], prof[other], repopw[other], "snapshots", "--json")) or [])
        st, j = run(op, "backup.run", {"policy": pnames[me]})
        snap_after = len(snaps(restic(prof[other], rest[other]["backup"], prof[other], repopw[other], "snapshots", "--json")) or [])
        rep.check("B20 control: %s's own run succeeds and adds nothing to %s's repository" % (M, O), ok(st, j) and snap_before == snap_after, "%s snapshots unchanged" % O, "%s %s before=%s after=%s" % (st, str(j)[:200], snap_before, snap_after))
    admin_view = {x["name"] for x in adm.r("GET", "/backups/policies").json()}
    rep.check("B20 control: the all-customers admin sees both policies", {pnames["a"], pnames["b"]} <= admin_view, "both visible", str(admin_view))
    # ---- runner profile isolation: a tampered config of A that points at B's scratch machine / repository is refused by the root helper
    cfgp = "/etc/ou-backup/%s/identity.json" % prof["a"]
    orig = host("cat", cfgp).stdout
    try:
        for label, patch in (("B's scratch machine", {"scratch": SCRATCH["b"]}), ("B's source machine", {"machine": B.idm}), ("B's repository path", {"repo_url": "https://%s:8010/%s/identity" % (ip, prof["b"])}),
                             ("B's staging directory", {"stage_dir": "/var/lib/ou-backup/stage/%s" % prof["b"]})):
            cfg = json.loads(orig)
            cfg.update(patch)
            host("tee", cfgp, inp=json.dumps(cfg))
            r = host("/usr/local/sbin/ou-backup", "--direct", "--customer", prof["a"], "check", "identity", "1", check=False)
            rep.check("B30 root helper refuses A's runner config that points at %s" % label, r.returncode != 0 and "error" in r.stdout, json.loads(r.stdout)["error"][:90] if r.stdout.strip().startswith("{") else "refused", "ACCEPTED rc=%s %s" % (r.returncode, r.stdout[:150]))
    finally:
        host("tee", cfgp, inp=orig)
    r = host("/usr/local/sbin/ou-backup", "--direct", "--customer", prof["a"], "check", "identity", "1", check=False)
    rep.check("B30 control: with the config restored A's own repository check works", r.returncode == 0, "check passed", r.stdout[:200] + r.stderr[-200:])
    # ---- restore verification per customer: A's restore uses only A's repository, scratch machine, staging and creds; B's scratch is untouched
    if not BK_RESTORE:
        rep.skipped("B40 restore verification per customer", "OU_T20_BKP_RESTORE=0")
        return
    if mem_available_mb() < 2048:
        rep.failed("B40 restore verification", "only %d MiB available (<2 GiB): not started" % mem_available_mb())
        return

    def scratch_fp(k):
        return host("bash", "-c", "find /var/lib/machines/%s -xdev -printf '%%T@ %%p\\n' 2>/dev/null | sort | tail -3 | sha256sum" % SCRATCH[k]).stdout.strip()
    for me, other, op in (("a", "b", opa), ("b", "a", opb)):
        M, O = me.upper(), other.upper()
        fp0 = scratch_fp(other)
        st, j = run(op, "backup.verify", {"policy": pnames[me], "level": "restore"}, wait=1500)
        res = (j.get("result") if isinstance(j, dict) else None) or {}
        rep.check("B40 restore verification of %s (restic restore -> scratch machine %s -> canary compare) passes through the real API" % (M, SCRATCH[me]), ok(st, j), "passed, RTO %ss" % res.get("rto_seconds"), "%s %s" % (st, str(j)[:500]))
        fp1 = scratch_fp(other)
        rep.check("B40 %s's restore verification wrote nothing into %s's scratch machine %s (unchanged) and %s stays powered off" % (M, O, SCRATCH[other], SCRATCH[other]),
                  fp0 == fp1 and host("machinectl", "show", SCRATCH[other], "-p", "State", "--value", check=False).stdout.strip() != "running", "unchanged", "CHANGED %s -> %s" % (fp0, fp1))
        stage_leftover = host("bash", "-c", "ls /var/lib/ou-backup/stage/%s 2>/dev/null | grep -c restore || true" % prof[me]).stdout.strip()
        rep.check("B40 %s's restore staging directory is cleaned up (no decrypted archive left on the runner)" % M, stage_leftover == "0", "clean", "left: %s" % stage_leftover)
        v = [x for x in op.r("GET", "/backups/verifications?policy=%s&level=restore" % pnames[me]).json()][0]
        d = v.get("detail") or {}
        exp = json.dumps(d.get("canary_expected"))
        rep.check("B40 the verified canary belongs to %s (own LDAP entry + realm role drill-canary-t20-%s) and mentions nothing of %s" % (M, me, O),
                  v["state"] == "passed" and "drill-canary-t20-%s" % me in exp and "drill-canary-t20-%s" % other not in exp and "ldap_entryuuid" in exp, "canary %s" % exp[:120], "state=%s canary=%s" % (v["state"], exp[:200]))
    for k in SCRATCH:
        for _ in range(30):
            if host("machinectl", "show", SCRATCH[k], "-p", "State", "--value", check=False).stdout.strip() != "running":
                break
            time.sleep(2)
        rep.check("B40 scratch machine %s powered off after the verification" % SCRATCH[k], host("machinectl", "show", SCRATCH[k], "-p", "State", "--value", check=False).stdout.strip() != "running", "off", "still running")


for name, fn in (("identity", identity), ("files", files), ("network", network), ("ics", ics), ("backup", backup)):
    if name in SECTIONS:
        print("\n---- %s ----" % name)
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            rep.failed("%s section aborted" % name, "%s: %s" % (type(e).__name__, str(e)[:200]))
rep.finish()
