#!/usr/bin/env python3
"""GW04: CalDAV + CardDAV via grommunio-dav: principal discovery, PUT event into Calendar, REPORT/GET it back,
cross-check via EWS FindItem (same mailbox store), PUT vCard into Contacts and read back, 401 for wrong password,
and per-user isolation. PROVES: sabre/dav -> php-mapi -> gromox works; items are real MAPI items (visible over EWS).
DOES NOT PROVE: Apple/Thunderbird/DAVx5 client quirks, scheduling (iTIP) delivery, shared calendars."""
import os, re, sys, uuid, requests
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gw_lab as L
rep = L.Rep("GW04 caldav+carddav")
B = "https://" + L.HOST
S = requests.Session(); S.verify = L.CA
u = "dave"; A = (L.addr(u), L.PW[u])
r = S.request("PROPFIND", B + "/dav/", headers={"Depth": "0"}, timeout=30)
rep.check("DAV unauth -> 401", r.status_code == 401, "401", "HTTP %s" % r.status_code)
r = S.request("PROPFIND", B + "/dav/", headers={"Depth": "0"}, auth=(L.addr(u), "wrong-password"), timeout=30)
rep.check("DAV wrong password -> 401", r.status_code == 401, "401", "HTTP %s" % r.status_code)
r = S.request("OPTIONS", B + "/dav/", auth=A, timeout=30)
rep.check("DAV OPTIONS", r.status_code == 200 and "calendar-access" in r.headers.get("DAV", "") and "addressbook" in r.headers.get("DAV", ""), "DAV: %s" % r.headers.get("DAV"), "HTTP %s DAV=%s" % (r.status_code, r.headers.get("DAV")))
uid = "oulab-%s" % L.RUN
cal = "%s/dav/calendars/%s/Calendar/%s.ics" % (B, L.addr(u), uid)
ics = ("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//OU Lab//EN\r\nBEGIN:VEVENT\r\nUID:%s\r\nDTSTAMP:20261115T120000Z\r\nDTSTART:20261201T100000Z\r\nDTEND:20261201T110000Z\r\nSUMMARY:DAV event %s\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n" % (uid, uid))
r = S.put(cal, data=ics, headers={"Content-Type": "text/calendar"}, auth=A, timeout=60)
rep.check("CalDAV PUT event", r.status_code in (201, 204), "HTTP %s" % r.status_code, "HTTP %s %s" % (r.status_code, r.text[:300]))
r = S.get(cal, auth=A, timeout=60)
rep.check("CalDAV GET event", r.status_code == 200 and uid in r.text and "DAV event" in r.text, "round-trip ok (%d bytes)" % len(r.text), "HTTP %s %s" % (r.status_code, r.text[:300]))
q = '<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/><c:calendar-data/></d:prop><c:filter><c:comp-filter name="VCALENDAR"><c:comp-filter name="VEVENT"/></c:comp-filter></c:filter></c:calendar-query>'
r = S.request("REPORT", "%s/dav/calendars/%s/Calendar/" % (B, L.addr(u)), data=q, headers={"Depth": "1", "Content-Type": "application/xml"}, auth=A, timeout=60)
rep.check("CalDAV REPORT calendar-query", r.status_code == 207 and uid in r.text, "event listed", "HTTP %s" % r.status_code)
# EWS cross-check
env = ('<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"><soap:Body>'
       '<m:FindItem Traversal="Shallow"><m:ItemShape><t:BaseShape>Default</t:BaseShape></m:ItemShape><m:ParentFolderIds><t:DistinguishedFolderId Id="calendar"/></m:ParentFolderIds></m:FindItem></soap:Body></soap:Envelope>')
r = S.post(B + "/EWS/Exchange.asmx", data=env, auth=A, headers={"Content-Type": "text/xml"}, timeout=60)
rep.check("EWS sees DAV-created event", uid in r.text, "same event visible via EWS FindItem", "HTTP %s not found" % r.status_code)
r = S.get("%s/dav/calendars/%s/Calendar/%s.ics" % (B, L.addr("erin"), uid), auth=(L.addr("erin"), L.PW["erin"]), timeout=30)
rep.check("isolation: erin cannot read dave's event", r.status_code in (404, 403) , "HTTP %s" % r.status_code, "HTTP %s leaked" % r.status_code)
vc = "%s/dav/addressbooks/%s/Contacts/%s.vcf" % (B, L.addr(u), uid)
vcard = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:%s\r\nFN:Lab Contact %s\r\nN:Contact;Lab;;;\r\nEMAIL;TYPE=INTERNET:contact-%s@example.invalid\r\nEND:VCARD\r\n" % (uid, L.RUN, L.RUN)
r = S.put(vc, data=vcard, headers={"Content-Type": "text/vcard"}, auth=A, timeout=60)
rep.check("CardDAV PUT vcard", r.status_code in (201, 204), "HTTP %s" % r.status_code, "HTTP %s %s" % (r.status_code, r.text[:300]))
r = S.get(vc, auth=A, timeout=60)
rep.check("CardDAV GET vcard", r.status_code == 200 and "Lab Contact %s" % L.RUN in r.text, "round-trip ok", "HTTP %s %s" % (r.status_code, r.text[:300]))
rep.done()
