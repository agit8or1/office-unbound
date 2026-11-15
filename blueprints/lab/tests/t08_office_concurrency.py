#!/usr/bin/env python3
"""T08 Collabora concurrency through OpenCloud: N simultaneous editing sessions on N DISTINCT documents, all via
POST /app/open (OpenCloud WOPI) -> wss office /cool/.../ws, all held open at the same time, then each types a marker
and saves (PutFile into OpenCloud) and the stored DOCX is read back. Shows there is no 20-connection / 10-document cap
(vendor CODE caps) end-to-end. N from OU_CONC_N (default 30). Needs requests, python-docx, websocket-client.
DOES NOT PROVE: browser rendering, co-editing of ONE doc by many users (not exercised), behaviour above N, RAM sizing.
"""
import io
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ou_lab as L

N = int(os.environ.get("OU_CONC_N", "30"))
rep = L.Report("T08 Collabora %d concurrent sessions via OpenCloud" % N)
if not L.need_requests(rep):
    rep.finish()
import requests
try:
    import docx
    import websocket
except ImportError:
    rep.skipped("dependencies", "python-docx / websocket-client missing"); rep.finish()
pw = L.password_for("bob")
if not (L.CA_FILE and pw):
    rep.skipped("config", "need OU_CA_FILE and OU_PASSWORD_BOB"); rep.finish()
tok = L.get_token(requests, "bob", pw)["access_token"]
dav = L.OcDav(requests, "bob", tok)
if not dav.discover():
    rep.failed("webdav", "no base path"); rep.finish()
L.wait_app_ready(requests)
names = ["conc-%s-%02d.docx" % (L.RUN_ID, i) for i in range(N)]
ids = []
for i, n in enumerate(names):
    d = docx.Document(); d.add_paragraph("CONC %s doc %d" % (L.RUN_ID, i))
    b = io.BytesIO(); d.save(b)
    if dav.put(n, b.getvalue()).status_code not in (201, 204):
        rep.failed("upload", n); rep.finish()
for n in names:
    ids.append(dav.fileid(n))
rep.check("uploaded %d docs" % N, all(ids), "all have fileids", "missing fileids")

res = [None] * N
loaded_evt = threading.Barrier(N, timeout=180)


def work(i):
    r = {"open": False, "loaded": False, "saved": False}
    res[i] = r
    S = None
    try:
        for _ in range(8):             # 425 TOO_EARLY = OpenCloud postprocessing not finished: retry
            S = L.CollaboraSession(requests, websocket, tok, ids[i])
            if S.ok_open or S.open_status != 425:
                break
            time.sleep(2)
        r["open"] = S.ok_open
        if not S.ok_open:
            r["err"] = "app/open %s" % S.open_status
            return
        r["loaded"] = S.connect_and_load(timeout=90) and "perm: edit" in S.messages
        try:
            loaded_evt.wait()          # hold until all sessions are open simultaneously
        except threading.BrokenBarrierError:
            pass
        time.sleep(10)                 # keep all N open concurrently for a while
        if r["loaded"]:
            r["saved"] = S.insert_text_and_save("CONCMARK%02d" % i, timeout=90)
    except Exception as e:  # noqa: BLE001
        r["err"] = str(e)[:150]
    finally:
        if S:
            S.close()


t0 = time.time()
th = [threading.Thread(target=work, args=(i,)) for i in range(N)]
for t in th:
    t.start()
for t in th:
    t.join()
nopen, nload, nsave = (sum(r[k] for r in res) for k in ("open", "loaded", "saved"))
errs = [r.get("err") for r in res if r.get("err")][:3]
rep.check("all %d sessions opened via /app/open" % N, nopen == N, "%d/%d" % (nopen, N), "%d/%d errs=%s" % (nopen, N, errs))
rep.check("all %d sessions loaded concurrently (perm: edit)" % N, nload == N, "%d/%d in %.0fs" % (nload, N, time.time() - t0),
          "%d/%d" % (nload, N))
rep.check("all %d saved (PutFile)" % N, nsave == N, "%d/%d" % (nsave, N), "%d/%d" % (nsave, N))
time.sleep(3)
ok = 0
for i, n in enumerate(names):
    try:
        p = [x.text for x in docx.Document(io.BytesIO(dav.get(n).content)).paragraphs]
        ok += any("CONCMARK%02d" % i in x for x in p)
    except Exception:  # noqa: BLE001
        pass
rep.check("stored DOCX of every session contains its own marker", ok == N, "%d/%d" % (ok, N), "%d/%d" % (ok, N))
for n in names:
    dav.delete(n)
rep.finish()
