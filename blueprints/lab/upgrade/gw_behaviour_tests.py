#!/usr/bin/env python3
"""A21 drill: behaviours of the PATCHED gromox (0001 bearer claims, 0002 USER-KICK) measured against a live node. Run on the ICS host.
  gw_behaviour_tests.py [--expect patched|unpatched]     default patched; `unpatched` asserts the OLD behaviour (used after a rollback to ou1)
Uses: gw1-users.env (IMAP passwords, never printed), ou-id1 test-users.env (bob's Keycloak password, never printed), sudo systemd-run -M <node>.
Bearer: real bob token (client ou-lab-test, aud=account) + forged alg variants go to zcore mapi_logon_token on the node, under four settings of
bearer_issuer/bearer_audience (set temporarily in /etc/gromox/gromox.cfg, then the production values are restored).
Kick: bob (victim, two sessions) and alice (bystander) hold IMAP sessions, `ou-gw-user kill bob` is run on the node, bob's sessions get BYE, alice's
does not, bob can log in again.
"""
import base64, imaplib, json, os, re, ssl, subprocess, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests"))
import gw_lab as L  # noqa

NODE = os.environ.get("GW_MACHINE", "ou-gw1")
ISS = "https://auth.ou-lab.internal/realms/ou-lab"
PROD_ISS, PROD_AUD = ISS, os.environ.get("PROD_AUDIENCE", "ou-webmail")
EXPECT = "unpatched" if "--expect" in sys.argv and sys.argv[sys.argv.index("--expect") + 1] == "unpatched" else "patched"
rep = L.Rep("gromox patched behaviours on %s (expect %s)" % (NODE, EXPECT))


def node(cmd, inp=None, timeout=120):
    r = subprocess.run(["sudo", "systemd-run", "-M", NODE, "--quiet", "--pipe", "--wait", "/bin/bash", "-c", cmd], input=inp, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout + r.stderr


def bob_token():
    r = subprocess.run(["sudo", "systemd-run", "-M", "ou-id1", "--quiet", "--pipe", "--wait", "/bin/cat", "/root/ou-lab-secrets/test-users.env"], capture_output=True, text=True)
    pw = re.search(r"^OU_PASSWORD_BOB=(.*)$", r.stdout, re.M).group(1)
    cmd = ["curl", "-sS", "--cacert", L.CA, "--resolve", "auth.ou-lab.internal:443:192.168.186.241", "https://auth.ou-lab.internal/realms/ou-lab/protocol/openid-connect/token",
           "-d", "grant_type=password", "-d", "client_id=ou-lab-test", "-d", "username=bob", "--data-urlencode", "password=" + pw, "-d", "scope=openid"]
    return json.loads(subprocess.run(cmd, capture_output=True, text=True).stdout)["access_token"]


def forged(tok):
    h, p, s = tok.split(".")
    e = lambda o: base64.urlsafe_b64encode(json.dumps(o, separators=(",", ":")).encode()).rstrip(b"=").decode()
    return {"real": tok, "alg_none": e({"alg": "none", "typ": "JWT"}) + "." + p + ".", "alg_hs256_header": e({"alg": "HS256", "typ": "JWT"}) + "." + p + "." + s,
            "alg_rs512_header": e({"alg": "RS512", "typ": "JWT"}) + "." + p + "." + s}


PHP = r"""php -r '$t=json_decode(file_get_contents("/run/ou-toks.json"),true); foreach($t as $k=>$v){ try { $s=mapi_logon_token($v); echo $k,"=",($s?"ACCEPTED":"rejected"),"\n"; } catch(Throwable $e){ echo $k,"=rejected\n"; } }'"""


def setcfg(lines):
    node("sed -i '/^bearer_issuer\\|^bearer_audience/d' /etc/gromox/gromox.cfg; printf '%b' '" + lines + "' >> /etc/gromox/gromox.cfg; systemctl restart gromox-zcore; sleep 3")


def bearer():
    toks = forged(bob_token())
    node("umask 077; cat > /run/ou-toks.json", json.dumps(toks))
    rows = {}
    try:
        for label, cfg in (("legacy", ""), ("aud=ou-webmail", "bearer_audience=ou-webmail\\n"), ("aud=account+iss", "bearer_audience=account\\nbearer_issuer=%s\\n" % ISS),
                           ("aud=account+wrong iss", "bearer_audience=account\\nbearer_issuer=https://evil.example/realms/x\\n")):
            setcfg(cfg)
            _, out = node(PHP)
            rows[label] = dict(l.split("=") for l in out.split() if "=" in l)
            print("   %-22s %s" % (label, rows[label]))
    finally:
        setcfg("bearer_issuer=%s\\nbearer_audience=%s\\n" % (PROD_ISS, PROD_AUD))
        node("rm -f /run/ou-toks.json")
    acc = lambda lab, k: rows[lab].get(k) == "ACCEPTED"
    rep.check("legacy (no policy): real token accepted", acc("legacy", "real"), "ACCEPTED", "rejected")
    if EXPECT == "patched":
        rep.check("alg none/HS256/RS512 rejected", not any(acc("legacy", k) for k in ("alg_none", "alg_hs256_header", "alg_rs512_header")), "all 3 rejected", "a forged alg was ACCEPTED")
        rep.check("audience=ou-webmail refuses a token issued to another client (aud=account)", not acc("aud=ou-webmail", "real"), "rejected", "ACCEPTED")
        rep.check("audience=account + correct issuer accepts", acc("aud=account+iss", "real"), "ACCEPTED", "rejected")
        rep.check("audience=account + wrong issuer refuses", not acc("aud=account+wrong iss", "real"), "rejected", "ACCEPTED")
    else:
        rep.check("UNPATCHED: audience/issuer directives ignored (token for another client still accepted)", acc("aud=ou-webmail", "real") and acc("aud=account+wrong iss", "real"),
                  "ACCEPTED as expected for ou1", "rejected (patched behaviour?)")


def imap(u):
    ctx = ssl.create_default_context(cafile=L.CA)
    im = imaplib.IMAP4_SSL(L.HOST, 993, ssl_context=ctx, timeout=30)
    im.login(L.addr(u), L.PW[u]); im.select("INBOX")
    return im


def wait_bye(im, secs=10):
    t0 = time.time()
    while time.time() - t0 < secs:
        try:
            im.noop(); time.sleep(0.2)
        except (imaplib.IMAP4.abort, ssl.SSLError, OSError, imaplib.IMAP4.error) as e:
            return time.time() - t0, str(e)[:60]
    return None, ""


def kick():
    v, b, v2 = imap("bob"), imap("alice"), imap("bob")
    t0 = time.time()
    rc, out = node("ou-gw-user kill bob; echo rc=$?")
    print("   ou-gw-user kill bob ->", out.strip().replace("\n", " ")[:120], "(%.1fs)" % (time.time() - t0))
    dt, why = wait_bye(v, 10)
    dt2, _ = wait_bye(v2, 5)
    if EXPECT == "patched":
        rep.check("victim IMAP sessions ended by USER-KICK", dt is not None and dt2 is not None, "closed after %.1fs / %.1fs (%s)" % (dt or -1, dt2 or -1, why), "session still open")
        try:
            b.noop(); rep.ok("bystander session (alice) unaffected")
        except Exception as e:
            rep.fail("bystander session (alice) unaffected", str(e)[:80])
        try:
            n = imap("bob"); n.noop(); n.logout(); rep.ok("kicked user can log in again (no ban list)")
        except Exception as e:
            rep.fail("kicked user can log in again", str(e)[:80])
    else:
        rep.check("UNPATCHED: session NOT terminated by the kick event", dt is None, "still open (verb unknown to ou1)", "closed (patched?)")
    for s in (v, v2, b):
        try:
            s.logout()
        except Exception:
            pass


bearer()
kick()
rep.done()
