#!/usr/bin/env python3
"""How long does a SERVER-CREATED calendar event (CalDAV PUT) take to show up in a running Evolution EWS session?
Runs inside ou-desk2 next to cc_evo.py (needs `evo-servers.sh start`, `setup` done for evo1). Creates N events one after the other, polls the client
every 5 s (`cal-list` = ECalClient.get_object_list_sync) and prints the seconds until each one is listed; also prints the EWS requests Evolution made in
that window (nginx is not needed: the count comes from the client's own EWS_DEBUG=1 journal when available). Usage: cc_evo_latency.py [N] [max_seconds]"""
import json, sys, time, uuid
sys.path.insert(0, "/root/cc")
import cc_lib as L
import socket

U = "ccev1"


def cmd(*argv, timeout=200):
    s = socket.create_connection(("127.0.0.1", 7001), timeout=timeout)
    f = s.makefile("rw")
    f.write(json.dumps({"argv": list(argv)}) + "\n")
    f.flush()
    r = json.loads(f.readline())
    s.close()
    return r


n = int(sys.argv[1]) if len(sys.argv) > 1 else 3
maxs = int(sys.argv[2]) if len(sys.argv) > 2 else 400
res = []
for i in range(n):
    tag = uuid.uuid4().hex[:6]
    uid = "evolat-%s" % tag
    ics = ("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//OU Lab//EN\r\nBEGIN:VEVENT\r\nUID:%s\r\nDTSTAMP:20261116T120000Z\r\nDTSTART:2026120%dT100000Z\r\n"
           "DTEND:2026120%dT110000Z\r\nSUMMARY:Latency %s\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n" % (uid, 5 + i, 5 + i, tag))
    t0 = time.time()
    pr = L.dav(U, "PUT", "/calendars/%s/Calendar/%s.ics" % (L.addr(U), uid), data=ics, headers={"Content-Type": "text/calendar"})
    seen = None
    while time.time() - t0 < maxs:
        if ("Latency %s" % tag) in json.dumps(cmd("cal-list")):
            seen = time.time() - t0
            break
        time.sleep(5)
    print("event %d: PUT %s, listed by the client after %s s" % (i + 1, pr.status_code, "%.0f" % seen if seen else "NOT within %d" % maxs))
    res.append(seen)
    L.dav(U, "DELETE", "/calendars/%s/Calendar/%s.ics" % (L.addr(U), uid))
ok = [r for r in res if r]
print("latency: %d/%d seen, min %.0f s, max %.0f s" % (len(ok), n, min(ok) if ok else -1, max(ok) if ok else -1))
