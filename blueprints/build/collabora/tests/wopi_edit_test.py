#!/usr/bin/env python3
"""Office Unbound Docs functional test: tiny WOPI host + websocket client.
 usage: wopi_edit_test.py edit  <docx>            -> insert text, save, verify PutFile body
        wopi_edit_test.py many  <docx> N          -> N concurrent documents (distinct file ids), 1 session each
        wopi_edit_test.py conns <docx> N          -> N concurrent sessions on ONE document
Runs in the runtime machine; coolwsd at 127.0.0.1:9980 (no TLS), WOPI host at 127.0.0.1:9990."""
import asyncio, sys, io, json, urllib.parse, time, shutil, hashlib
import aiohttp
from aiohttp import web

COOL = "127.0.0.1:9980"
WOPI = "127.0.0.1:9990"
MARK = "OU-EDIT-MARKER-7f3a9c"
SRC = sys.argv[2]
state = {"puts": {}, "gets": 0, "checks": 0}

def file_bytes(): return open(SRC, "rb").read()

async def check_file_info(req):
    fid = req.match_info["fid"]; state["checks"] += 1
    data = file_bytes()
    return web.json_response({"BaseFileName": f"doc{fid}.docx", "Size": len(data), "OwnerId": "ou",
        "UserId": f"u{req.query.get('uidx','1')}", "UserFriendlyName": "OU Tester", "Version": "1",
        "UserCanWrite": True, "SupportsUpdate": True, "SupportsLocks": False,
        "UserCanNotWriteRelative": True, "LastModifiedTime": "2026-11-15T00:00:00Z"})
async def get_file(req):
    state["gets"] += 1
    return web.Response(body=file_bytes(), content_type="application/octet-stream")
async def put_file(req):
    body = await req.read(); fid = req.match_info["fid"]
    state["puts"].setdefault(fid, []).append(body)
    return web.json_response({"LastModifiedTime": time.strftime("%Y-%m-%dT%H:%M:%S.0000000Z", time.gmtime())})
async def lock_or_other(req): return web.Response(status=200)

async def start_wopi():
    app = web.Application(client_max_size=1<<28)
    app.router.add_get("/wopi/files/{fid}", check_file_info)
    app.router.add_get("/wopi/files/{fid}/contents", get_file)
    app.router.add_post("/wopi/files/{fid}/contents", put_file)
    app.router.add_post("/wopi/files/{fid}", lock_or_other)
    r = web.AppRunner(app); await r.setup()
    await web.TCPSite(r, "127.0.0.1", 9990).start(); return r

async def session(http, fid, uidx=1, do_edit=False, hold=0.0, log=None):
    src = f"http://{WOPI}/wopi/files/{fid}"
    url = f"ws://{COOL}/cool/{urllib.parse.quote(src+'?access_token=t&uidx='+str(uidx), safe='')}/ws?WOPISrc={urllib.parse.quote(src, safe='')}&access_token=t"
    ws = await http.ws_connect(url, headers={"Origin": f"http://{COOL}"}, max_msg_size=0)
    await ws.send_str("coolclient 0.1")
    await ws.send_str(f"load url={src}?access_token=t&uidx={uidx} access_token=t timestamp= deviceFormFactor=desktop")
    status = False; got_err = None; loaded = False; modified = False
    t0 = time.time(); typed = False; saved = False
    while time.time() - t0 < 90:
        try: msg = await ws.receive(timeout=30)
        except asyncio.TimeoutError: break
        if msg.type == aiohttp.WSMsgType.TEXT:
            s = msg.data
            if log is not None and not s.startswith(("tile", "invalidate", "cursor", "textselection")): log.append(s[:160])
            if s.startswith("error:"): got_err = s; break
            if s.startswith("status:") and not status:
                status = True; loaded = True
                await ws.send_str("clientvisiblearea x=0 y=0 width=12000 height=12000")
                await ws.send_str("clientzoom tilepixelwidth=256 tilepixelheight=256 tiletwipwidth=3000 tiletwipheight=3000")
                if do_edit:
                    await ws.send_str("mouse type=buttondown x=1500 y=1500 count=1 buttons=1 modifier=0")
                    await ws.send_str("mouse type=buttonup x=1500 y=1500 count=1 buttons=1 modifier=0")
                    await ws.send_str(f"textinput id=0 text={MARK}")
                    typed = True
                    await asyncio.sleep(1.5)
                    await ws.send_str("save dontTerminateEdit=1 dontSaveIfUnmodified=0")
                else:
                    await asyncio.sleep(hold)
                    break
            if s.startswith("unocommandresult:") and "save" in s.lower(): saved = True; break
        elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR): break
    return ws, loaded, got_err, typed, saved

async def main():
    mode = sys.argv[1]; runner = await start_wopi(); http = aiohttp.ClientSession()
    if mode == "edit":
        log = []
        ws, loaded, err, typed, saved = await session(http, "1", do_edit=True, log=log)
        await asyncio.sleep(2)
        n = len(state["puts"].get("1", []))
        print(f"loaded={loaded} err={err} typed={typed} unocommandresult_save={saved} putfile_calls={n} getfile={state['gets']} checkfileinfo={state['checks']}")
        if n:
            body = state["puts"]["1"][-1]; open("/tmp/putfile_body.docx", "wb").write(body)
            import docx
            d = docx.Document(io.BytesIO(body)); text = "\n".join(p.text for p in d.paragraphs)
            print(f"PutFile body bytes={len(body)} sha256={hashlib.sha256(body).hexdigest()[:16]}")
            print("MARKER_IN_PUTFILE_DOCX =", MARK in text); print("paragraph text:", repr(text[:200]))
            print("RESULT:", "PASS" if MARK in text else "FAIL")
        else:
            print("last server messages:", *log[-12:], sep="\n  "); print("RESULT: FAIL (no PutFile)")
        await ws.close()
    elif mode in ("many", "conns"):
        N = int(sys.argv[3]); t0 = time.time()
        fids = [str(i) for i in range(N)] if mode == "many" else ["1"] * N
        res = await asyncio.gather(*[session(http, fid, uidx=i, hold=25) for i, fid in enumerate(fids)], return_exceptions=True)
        ok = sum(1 for r in res if not isinstance(r, Exception) and r[1])
        errs = [r if isinstance(r, Exception) else r[2] for r in res if isinstance(r, Exception) or r[2] or not r[1]]
        print(f"mode={mode} requested={N} loaded_ok={ok} failures={len(errs)} elapsed={time.time()-t0:.1f}s")
        for e in errs[:5]: print("  failure:", repr(e)[:200])
        print("RESULT:", "PASS" if ok == N else "FAIL")
    await http.close(); await runner.cleanup()
asyncio.run(main())
