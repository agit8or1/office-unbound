#!/usr/bin/env python3
"""T11 CalDAV event create/read against grommunio-dav.

Discovery: /.well-known/caldav -> current-user-principal -> calendar-home-set
-> first VEVENT-capable calendar; then PUT an iCalendar event with a unique
SUMMARY, GET it back, and delete it.
PROVES: DAV endpoint reachable with LDAP-backed credentials, calendar
collection discovery, event write/read round-trip.
DOES NOT PROVE: free/busy, invitations/scheduling, recurrence/timezones,
visibility of the event in MAPI/EWS/EAS clients, DAVx5/Apple client behaviour.
Paths are discovered, not assumed, because the grommunio-dav URL layout is UNVERIFIED.
"""
import os
import sys
import urllib.parse
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ou_lab as L

rep = L.Report("T11 CalDAV")
if not L.need_requests(rep):
    rep.finish()
import requests
user, pw = "alice", L.password_for("alice")
if not (L.CA_FILE and pw):
    rep.skipped("config", "need OU_CA_FILE, OU_PASSWORD_ALICE"); rep.finish()
V = L.verify()
auth = ("alice@" + L.MAIL_DOMAIN, pw)
base = "https://%s" % L.HOST_MAIL
NS = {"d": "DAV:", "c": "urn:ietf:params:xml:ns:caldav"}

def propfind(url, body, depth="0"):
    return requests.request("PROPFIND", url, data=body, auth=auth, verify=V, timeout=30,
                            headers={"Depth": depth, "Content-Type": "application/xml"})

r = requests.request("PROPFIND", base + "/.well-known/caldav", auth=auth, verify=V, timeout=30, allow_redirects=True,
                     headers={"Depth": "0"})
start = r.url if r.status_code in (207, 200) else base + "/dav/"
rep.check("well-known/caldav reachable", r.status_code in (200, 207), "resolved to %s" % r.url,
          "HTTP %s; falling back to %s (grommunio-dav not installed/exposed?)" % (r.status_code, start))
cup = propfind(start, '<d:propfind xmlns:d="DAV:"><d:prop><d:current-user-principal/></d:prop></d:propfind>')
if not rep.check("principal discovery", cup.status_code == 207, "HTTP 207", "HTTP %s %s" % (cup.status_code, cup.text[:120])):
    rep.finish()
href = ET.fromstring(cup.content).find(".//d:current-user-principal/d:href", NS)
principal = urllib.parse.urljoin(start, href.text) if href is not None else start
chs = propfind(principal, '<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><c:calendar-home-set/></d:prop></d:propfind>')
h = ET.fromstring(chs.content).find(".//c:calendar-home-set/d:href", NS) if chs.status_code == 207 else None
home = urllib.parse.urljoin(principal, h.text) if h is not None else None
if not rep.check("calendar-home-set", home is not None, home, "none (HTTP %s)" % chs.status_code):
    rep.finish()
cal = propfind(home, '<d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/><d:displayname/></d:prop></d:propfind>', "1")
target = None
for resp in ET.fromstring(cal.content).findall("d:response", NS):
    if resp.find(".//c:calendar", NS) is not None:
        target = urllib.parse.urljoin(home, resp.find("d:href", NS).text); break
if not rep.check("calendar collection", bool(target), target, "no calendar collection under %s" % home):
    rep.finish()
uid = "ou-lab-%s@%s" % (L.RUN_ID, L.LAB_DOMAIN)
summary = "OU lab event %s" % L.RUN_ID
ics = ("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//OU lab//EN\r\nBEGIN:VEVENT\r\nUID:%s\r\nDTSTAMP:20261115T100000Z\r\n"
       "DTSTART:20261201T100000Z\r\nDTEND:20261201T110000Z\r\nSUMMARY:%s\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n") % (uid, summary)
ev = target.rstrip("/") + "/" + uid.split("@")[0] + ".ics"
p = requests.put(ev, data=ics.encode(), auth=auth, verify=V, timeout=30, headers={"Content-Type": "text/calendar", "If-None-Match": "*"})
rep.check("PUT event", p.status_code in (201, 204), "HTTP %s" % p.status_code, "HTTP %s %s" % (p.status_code, p.text[:120]))
g = requests.get(ev, auth=auth, verify=V, timeout=30)
rep.check("GET event", g.status_code == 200 and summary in g.text, "SUMMARY round-trips", "HTTP %s, summary missing" % g.status_code)
d = requests.delete(ev, auth=auth, verify=V, timeout=30)
rep.check("DELETE event", d.status_code in (200, 204), "HTTP %s" % d.status_code, "HTTP %s" % d.status_code)
rep.finish()
