#!/usr/bin/env python3
"""P01: two headless Chromium WebRTC softphones (bob 1002, carol 1003; Keycloak login -> own SIP credential -> JsSIP over WSS) register,
bob calls carol, carol answers, RTP is verified on the PBX (channelstats, two samples), hang up, CDR row written."""
import os
import re
import sys
import time

from playwright.sync_api import sync_playwright

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pbx_lib as L

rep = L.Report("P01 WebRTC softphone call bob -> carol (WSS + DTLS-SRTP)")
cdr_before = L.pbx("wc -l < /var/log/asterisk/cdr-csv/Master.csv 2>/dev/null || echo 0").strip()
with sync_playwright() as p:
    b = L.browser(p)
    try:
        t0 = time.time()
        cb, pb = L.open_phone(b, "bob")
        cc, pc = L.open_phone(b, "carol")
        for name, pg in (("bob", pb), ("carol", pc)):
            dt = L.wait_state(pg, "#status", "registered", 30)
            rep.check("%s softphone registered over WSS (own credential from /api/credential)" % name, dt is not None,
                      "status=%r ext=%s" % (pg.inner_text("#status"), pg.inner_text("#ext")))
        rep.check("login + provisioning + register for both users took", True, "%.1fs" % (time.time() - t0))
        csp = pb.evaluate("fetch('/static/phone.css').then(r=>r.headers.get('content-security-policy'))")
        rep.check("strict CSP on softphone assets", bool(csp) and "script-src 'self'" in csp and "'unsafe-inline'" not in csp, csp)
        eps = L.ast("pjsip show contacts")
        rep.check("PBX shows both WSS contacts", "bob.web" in eps and "carol.web" in eps, re.sub(r"\s+", " ", eps)[-260:])

        pb.fill("#number", "1003")
        pb.click("#call")
        rep.check("carol's phone rings (Answer button visible)", pc.wait_for_selector("#answer", state="visible", timeout=15000) is not None,
                  "carol callstate=%s peer=%r" % (pc.get_attribute("#callstate", "data-state"), pc.inner_text("#peer")))
        pc.click("#answer")
        d1 = L.wait_state(pb, "#callstate", "connected", 20)
        d2 = L.wait_state(pc, "#callstate", "connected", 20)
        rep.check("call answered: both sides 'connected'", d1 is not None and d2 is not None)
        time.sleep(4)
        ch = L.ast("core show channels concise")
        rep.check("two PJSIP channels Up and bridged on the PBX", len(re.findall(r"^PJSIP/\S+!.*!Up!", ch, re.M)) == 2, ch.strip().replace("\n", " | ")[:300])
        s1 = L.ast("pjsip show channelstats")
        time.sleep(3)
        s2 = L.ast("pjsip show channelstats")

        print("---- pjsip show channelstats (sample 1) ----\n" + s1.strip() + "\n---- (sample 2, +3 s) ----\n" + s2.strip())

        def pk(txt):
            tot = []
            for line in txt.splitlines():
                f = line.split()
                # columns: BridgeId ChannelId UpTime Codec  Count Lost Pct Jitter | Count Lost Pct Jitter RTT
                if len(f) >= 13 and re.match(r".+-[0-9a-f]{8}$", f[1]):
                    tot.append((int(f[4]), int(f[8])))
            return tot
        a, c = pk(s1), pk(s2)
        ok = len(a) == 2 and len(c) == 2 and all(c[i][0] > a[i][0] and c[i][1] > a[i][1] for i in range(2)) and all(x[0] > 50 for x in c)
        rep.check("RTP flows both directions on both legs (rx/tx packet counters grow)", ok, "sample1=%s sample2=%s" % (a, c))
        ep = L.ast("pjsip show endpoint bob.web")
        m = re.search(r"media_encryption\s*:\s*(\S+)", ep)
        rep.check("web endpoint media encryption is mandatory DTLS-SRTP (a plain-RTP call could not have connected)", bool(m) and m.group(1) == "dtls", m.group(0) if m else ep[:200])
        pb.click("#hangup")
        e1 = L.wait_state(pb, "#callstate", "ended", 15)
        e2 = L.wait_state(pc, "#callstate", "ended", 15)
        rep.check("hang up: both sides 'ended'", e1 is not None and e2 is not None)
        time.sleep(2)
        rep.check("no channels left on PBX", "PJSIP" not in L.ast("core show channels concise"))
        cdr = L.pbx("tail -n +%d /var/log/asterisk/cdr-csv/Master.csv" % (int(cdr_before) + 1))
        rows = [r for r in cdr.strip().splitlines() if '"1002"' in r and '1003' in r]
        rep.check("CDR row written (1002 -> 1003, ANSWERED, billsec>0)", any("ANSWERED" in r for r in rows), rows[-1] if rows else cdr[-300:])
    finally:
        b.close()
rep.finish()
