#!/usr/bin/env python3
"""CC-EVO: GNOME Evolution's real evolution-ews backends (Evolution Data Server + evolution-ews 3.52) against Gromox EWS.
Runs inside ou-desk2 as root. Two EDS sessions (unix users evo1/evo2, started by cc_evo_run.sh) hold the account of
ccev1 / ccev2. DRIVEN THROUGH THE CLIENT: calendar and address book operations via the EDS client API (ECalClient /
EBookClient: the same calls Evolution's calendar and contacts views make; the evolution-ews backend talks EWS/SOAP to Gromox).
VERIFIED SERVER-SIDE with independent protocols (CalDAV/CardDAV on grommunio-dav, EWS FindItem, IMAP) and, in the reverse
direction, server-side changes are checked to appear in the client. NOT driven: the Evolution GUI."""
import json, re, socket, sys, time, requests
sys.path.insert(0, "/root/cc")
import cc_lib as L

rep = L.Rep("EVO ews")
HOSTURL = "https://%s/EWS/Exchange.asmx" % L.HOST
tag = L.RUN


def cmd(user, *argv, timeout=200):
    s = socket.create_connection(("127.0.0.1", {"evo1": 7001, "evo2": 7002}[user]), timeout=timeout)
    f = s.makefile("rw"); f.write(json.dumps({"argv": list(argv)}) + "\n"); f.flush()
    r = json.loads(f.readline()); s.close()
    return r


def caldav_events(uid):
    q = ('<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/><c:calendar-data/></d:prop>'
         '<c:filter><c:comp-filter name="VCALENDAR"><c:comp-filter name="VEVENT"/></c:comp-filter></c:filter></c:calendar-query>')
    r = L.dav(uid, "REPORT", "/calendars/%s/Calendar/" % L.addr(uid), data=q, headers={"Depth": "1", "Content-Type": "application/xml"})
    return r.text.replace("&#13;", "").replace("&amp;", "&")


def carddav_cards(uid):
    q = ('<card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><d:prop><d:getetag/><card:address-data/></d:prop></card:addressbook-query>')
    return L.dav(uid, "REPORT", "/addressbooks/%s/Contacts/" % L.addr(uid), data=q, headers={"Depth": "1", "Content-Type": "application/xml"}).text


def wait(fn, secs=60, every=3):
    end = time.time() + secs
    while time.time() < end:
        v = fn()
        if v: return v
        time.sleep(every)
    return None


# ---- 1. Autodiscover (server side) + account setup
body = ('<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>%s</EMailAddress>'
        '<AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>' % L.addr("ccev1"))
r = requests.post("https://autodiscover.%s/autodiscover/autodiscover.xml" % L.HOST, data=body, auth=(L.addr("ccev1"), L.pw("ccev1")), headers={"Content-Type": "text/xml"}, timeout=30)
ews = re.search(r"<EwsUrl>([^<]+)</EwsUrl>", r.text); oab = re.search(r"<OABUrl>([^<]+)</OABUrl>", r.text)
rep.check("Autodiscover (POX) answers EwsUrl/OABUrl", bool(ews and oab and ews.group(1) == HOSTURL), "Gromox autodiscover.xml returned EwsUrl=%s OABUrl=%s (Basic auth)" % (ews and ews.group(1), oab and oab.group(1)), "HTTP %s %s" % (r.status_code, r.text[:200]), "raw POX Autodiscover POST (server-side check of what Evolution's EWS lookup consumes)")
rep.partial("Evolution's own Autodiscover lookup", "NOT exercised: Evolution's EWS lookup derives autodiscover.<mail domain> (autodiscover.ou-lab.internal), which the lab certificate/DNS does not cover (cert has only gw1.* names); the account was configured with the EwsUrl/OabUrl taken from the Autodiscover response above", "n/a")
for u in ("evo1", "evo2"):
    r = cmd(u, "setup", ews.group(1), oab.group(1), timeout=240)
    if "Calendar" not in (r.get("sources") or []):  # first start of a fresh EDS profile can need a second pass
        r = cmd(u, "setup", ews.group(1), oab.group(1), timeout=240)
    rep.check("%s: EWS collection created, folders discovered" % u, r.get("sources") and "Calendar" in r["sources"] and "Contacts" in r["sources"],
              "evolution-ews backend authenticated (Basic over TLS, lab CA) and created sources %s" % r["sources"], str(r), "EDS ESourceRegistry + evolution-ews collection backend (SyncFolderHierarchy)")

import os
SECTIONS = os.environ.get("CC_EVO_SECTIONS", "all")  # all | mail (mail-only re-run)
if SECTIONS == "all":
    # ---- 2. calendar: create / edit / server->client / delete
    U = "ccev1"; tag = L.RUN
    sA = "Evo event %s" % tag
    r = cmd("evo1", "cal-create", "evo-%s" % tag, sA, "20261203T100000Z", "20261203T110000Z")
    rep.check("Calendar: create event in client (EWS CreateItem)", r.get("ok"), "ECalClient.create_object ok", str(r), "ECalClient.create_object_sync (evolution-ews)")
    got = wait(lambda: sA in caldav_events(U), 30)
    rep.check("server-side: event visible via CalDAV", bool(got), "grommunio-dav REPORT lists the event created over EWS", "not listed", "raw CalDAV REPORT")
    e = L.ews(U, '<m:FindItem Traversal="Shallow"><m:ItemShape><t:BaseShape>Default</t:BaseShape></m:ItemShape><m:ParentFolderIds><t:DistinguishedFolderId Id="calendar"/></m:ParentFolderIds></m:FindItem>')
    rep.check("server-side: event visible via EWS FindItem", sA in e.text, "listed", "not listed", "raw EWS FindItem")
    r = cmd("evo1", "cal-modify", sA, sA + " EDITED")
    txt = wait(lambda: (lambda t: t if "EDITED" in t else None)(caldav_events(U)), 30) or ""
    rep.check("Calendar: edit event (title, location)", r.get("ok") and "EDITED" in txt and "Room 9" in txt, "server shows edited SUMMARY and LOCATION=Room 9", "%s; server text has EDITED=%s" % (r, "EDITED" in txt), "ECalClient.modify_object_sync; raw CalDAV REPORT")
    uid2 = "evosrv-%s" % tag
    ics = ("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//OU Lab//EN\r\nBEGIN:VEVENT\r\nUID:%s\r\nDTSTAMP:20261115T120000Z\r\nDTSTART:20261204T100000Z\r\nDTEND:20261204T110000Z\r\nSUMMARY:Server made %s\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n" % (uid2, tag))
    pr = L.dav(U, "PUT", "/calendars/%s/Calendar/%s.ics" % (L.addr(U), uid2), data=ics, headers={"Content-Type": "text/calendar"})
    seen = wait(lambda: ("Server made %s" % tag) in json.dumps(cmd("evo1", "cal-list")), 260, 10)  # EWS change sync interval is 3 min
    rep.check("server-created event appears in client", pr.status_code in (201, 204) and bool(seen), "client lists the CalDAV-created event (EWS change sync)", "PUT %s; not seen within 260 s (backend StoreChangesInterval=3 min)" % pr.status_code, "raw CalDAV PUT; ECalClient.get_object_list_sync")
    L.dav(U, "DELETE", "/calendars/%s/Calendar/%s.ics" % (L.addr(U), uid2))
    r = cmd("evo1", "cal-delete", sA + " EDITED")
    gone = wait(lambda: "EDITED" not in caldav_events(U), 30)
    rep.check("Calendar: delete event in client", r.get("deleted", 0) >= 1 and bool(gone), "gone on the server", str(r), "ECalClient.remove_object_sync; raw CalDAV REPORT")

    # ---- 3. contacts
    cn = "Evo Contact %s" % tag
    r = cmd("evo1", "book-add", "evo-card-%s" % tag, cn, "evo-%s@example.invalid" % tag)
    got = wait(lambda: (cn in carddav_cards(U)) or None, 30)
    rep.check("Contacts: create contact in client", r.get("ok") and bool(got), "contact visible on server via CardDAV (same MAPI store)", str(r), "EBookClient.add_contact_sync (evolution-ews); raw CardDAV REPORT")
    r = cmd("evo1", "book-modify", cn, "evo-edited-%s@example.invalid" % tag)
    got = wait(lambda: ("evo-edited-%s@example.invalid" % tag in carddav_cards(U)) or None, 30)
    rep.check("Contacts: edit contact in client", r.get("ok") and bool(got), "server shows the edited e-mail", str(r), "EBookClient.modify_contact_sync; raw CardDAV REPORT")
    uidc = "evosrvc-%s" % tag
    vc = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:%s\r\nFN:Server Evo %s\r\nN:Evo;Server;;;\r\nEMAIL;TYPE=INTERNET:srv-evo-%s@example.invalid\r\nEND:VCARD\r\n" % (uidc, tag, tag)
    pr = L.dav(U, "PUT", "/addressbooks/%s/Contacts/%s.vcf" % (L.addr(U), uidc), data=vc, headers={"Content-Type": "text/vcard"})
    seen = wait(lambda: ("Server Evo %s" % tag) in json.dumps(cmd("evo1", "book-list", "Server Evo")), 260, 10)
    rep.check("Contacts: server-created contact appears in client", pr.status_code in (201, 204) and bool(seen), "client lists it", "PUT %s; not seen in 90 s" % pr.status_code, "raw CardDAV PUT; EBookClient.get_contacts_sync")
    L.dav(U, "DELETE", "/addressbooks/%s/Contacts/%s.vcf" % (L.addr(U), uidc))
    r = cmd("evo1", "book-delete", cn)
    gone = wait(lambda: (cn not in carddav_cards(U)) or None, 30)
    rep.check("Contacts: delete contact in client", r.get("deleted", 0) >= 1 and bool(gone), "gone on the server", str(r), "EBookClient.remove_contact_sync; raw CardDAV REPORT")

    # ---- 4. meeting invitation (organizer ccev1 -> attendee ccev2), accept, free/busy
    mt = "Evo meeting %s" % tag
    org = "ORGANIZER;CN=ccev1:mailto:%s" % L.addr("ccev1")
    att = "ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;CN=ccev2:mailto:%s\nATTENDEE;ROLE=CHAIR;PARTSTAT=ACCEPTED;CN=ccev1:mailto:%s" % (L.addr("ccev2"), L.addr("ccev1"))
    r = cmd("evo1", "cal-create", "evo-mtg-%s" % tag, mt, "20261207T100000Z", "20261207T110000Z", org + "\n" + att)
    created = bool(r.get("ok"))
    rep.check("Meeting: organizer creates event with attendee in client (EWS CreateItem + SendMeetingInvitations)", created,
              "created; Gromox accepted the item", "%s (gromox-http logged E-3117 'failed to send mail (The desired service is unavailable)': Gromox's own SMTP submission to localhost fails, see report)" % r,
              "ECalClient.create_object_sync (evolution-ews)")
    inv = L.imap_find("ccev2", mt, wait=30 if created else 5)
    rep.check("server-side: invitation mail delivered to attendee (IMAP)", bool(inv), "meeting request present in ccev2 INBOX", "no invitation mail in ccev2 INBOX", "imaplib SEARCH")
    cmd("evo1", "cal-delete", mt)

    # Fallback so that the attendee-side flow is still exercised: the organizer's event and the iTIP REQUEST mail are made server-side
    # (CalDAV PUT + SMTP :25), then ccev2's Evolution imports the invitation and accepts it.
    uidm = "evo-mtg2-%s" % tag
    ical = ("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//OU Lab//EN\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:%s\r\nDTSTAMP:20261115T120000Z\r\nDTSTART:20261207T100000Z\r\nDTEND:20261207T110000Z\r\n"
            "SUMMARY:%s\r\nORGANIZER;CN=ccev1:mailto:%s\r\nATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;CN=ccev2:mailto:%s\r\nATTENDEE;PARTSTAT=ACCEPTED;CN=ccev1:mailto:%s\r\nSEQUENCE:0\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
            % (uidm, mt + " B", L.addr("ccev1"), L.addr("ccev2"), L.addr("ccev1")))
    pr = L.dav("ccev1", "PUT", "/calendars/%s/Calendar/%s.ics" % (L.addr("ccev1"), uidm), data=ical.replace("METHOD:REQUEST\r\n", ""), headers={"Content-Type": "text/calendar"})
    import email.message, smtplib
    em = email.message.EmailMessage(); em["From"] = L.addr("ccev1"); em["To"] = L.addr("ccev2"); em["Subject"] = mt + " B"
    em.set_content("You are invited"); em.add_alternative(ical, subtype="calendar", params={"method": "REQUEST"})
    with smtplib.SMTP(L.HOST, 25, timeout=30) as sm:
        sm.starttls(); sm.send_message(em)
    inv = L.imap_find("ccev2", mt + " B", wait=30)
    rep.check("fallback invitation: iTIP REQUEST mail delivered (SMTP :25) and readable via IMAP", bool(inv) and b"text/calendar" in inv[2].lower(), "present with text/calendar part", "not delivered", "smtplib; imaplib")
    FI = '<m:FindItem Traversal="Shallow"><m:ItemShape><t:BaseShape>Default</t:BaseShape></m:ItemShape><m:ParentFolderIds><t:DistinguishedFolderId Id="%s"/></m:ParentFolderIds></m:FindItem>'
    r = L.ews("ccev2", FI % "inbox")
    rep.check("server-side: delivered invitation is a native meeting request (EWS ItemClass)", "IPM.Schedule.Meeting.Request" in r.text and (mt + " B") in r.text,
              "Gromox converted the iTIP mail into IPM.Schedule.Meeting.Request on delivery", "not a meeting request item", "raw EWS FindItem(inbox)")
    c0 = L.ews("ccev2", FI % "calendar")
    rep.check("server-side: no automatic calendar entry before the attendee acts", (mt + " B") not in c0.text, "calendar of ccev2 has no entry yet (attendee must accept/tentative)", "entry already present", "raw EWS FindItem(calendar)")
    open("/home/evo2/inv.ics", "w").write(ical)
    import shutil; shutil.chown("/home/evo2/inv.ics", "evo2", "evo2")
    r = cmd("evo2", "cal-accept", "/home/evo2/inv.ics", "ACCEPTED")
    rep.partial("Meeting: attendee accept through the calendar API (ECalClient.receive_objects)", "refused by evolution-ews itself: %s. Evolution-EWS accepts meeting requests from the MAIL view (EWS AcceptItem on the message), which needs the GUI; not driven headless" % str(r.get("error"))[:230], "ECalClient.receive_objects_sync (evolution-ews)")
    rm = re.search(r'<t:ItemId Id="([^"]+)" ChangeKey="([^"]*)"/>(?:(?!</t:MeetingRequest>).)*?<t:Subject>%s B</t:Subject>' % re.escape(mt), L.ews("ccev2", FI % "inbox").text, re.S)
    items = re.findall(r"<t:MeetingRequest>.*?</t:MeetingRequest>", L.ews("ccev2", FI % "inbox").text, re.S)
    mi = next((re.search(r'<t:ItemId Id="([^"]+)" ChangeKey="([^"]*)"', it) for it in items if (mt + " B") in it), None)
    if mi:
        a = L.ews("ccev2", '<m:CreateItem MessageDisposition="SendAndSaveCopy"><m:Items><t:AcceptItem><t:ReferenceItemId Id="%s" ChangeKey="%s"/></t:AcceptItem></m:Items></m:CreateItem>' % (mi.group(1), mi.group(2)))
        time.sleep(4)
        c1 = L.ews("ccev2", FI % "calendar")
        rep.check("server-side: EWS AcceptItem creates the attendee's calendar entry", (mt + " B") in c1.text, "calendar entry created by Gromox (raw EWS, NOT via Evolution)", "no entry (AcceptItem HTTP %s)" % a.status_code, "raw EWS CreateItem/AcceptItem")
        ok = a.status_code == 200 and "NoError" in a.text
        if ok:
            rep.passed("server-side: EWS AcceptItem returns success", "HTTP 200 NoError", "raw EWS CreateItem/AcceptItem")
        else:
            rep.fail("server-side: EWS AcceptItem returns success", "HTTP %s although the calendar entry was created: Gromox then fails to send the response mail to the organizer (gromox-http E-3117, same SMTP submission problem as EWS SendItem)" % a.status_code, "raw EWS CreateItem/AcceptItem")
        cmd("evo2", "cal-delete", mt + " B")
    L.dav("ccev1", "DELETE", "/calendars/%s/Calendar/%s.ics" % (L.addr("ccev1"), uidm))
    # free/busy: ccev2 creates a busy slot in Evolution; ccev1's Evolution asks for ccev2's availability
    busy = "Evo busy %s" % tag
    cmd("evo2", "cal-create", "evo-busy-%s" % tag, busy, "20261209T100000Z", "20261209T110000Z")
    time.sleep(5)
    r = cmd("evo1", "fb", "20261209T000000Z", "20261210T000000Z", L.addr("ccev2"))
    fbtxt = " ".join(r.get("fb", [])).replace("\r\n", " ")
    rep.check("Free/busy: attendee availability from client (EWS GetUserAvailability)", r.get("ok") and "FBTYPE=BUSY" in fbtxt.upper() and "20261209T1000" in fbtxt, "client received VFREEBUSY with the busy slot 2026-12-09 10:00-11:00Z for ccev2: %s" % fbtxt[:300], "%s" % fbtxt[:500] or str(r)[:300], "ECalClient.get_free_busy_sync")
    cmd("evo2", "cal-delete", busy)


import email.message, smtplib
# ---- 5. mail through Evolution's mail layer (CamelEwsStore / CamelEwsTransport), account ccev1
def deliver(frm, to, subject, body="body delivered by SMTP :25 for the evolution client test\nümlaut"):
    m = email.message.EmailMessage(); m["From"] = frm; m["To"] = to; m["Subject"] = subject; m.set_content(body)
    with smtplib.SMTP(L.HOST, 25, timeout=30) as sm:
        sm.starttls(); sm.send_message(m)

cmd("evo1", "mail-list", "Inbox")  # warm-up: folder sync
s_recv = "evo-recv-%s" % tag
deliver(L.addr("ccev2"), L.addr("ccev1"), s_recv)
g = wait(lambda: (lambda r: r if r.get("found") else None)(cmd("evo1", "mail-get", s_recv, "Inbox")), 60, 4)
rep.check("Mail: receive + read (mail delivered by SMTP, listed and opened in client)", bool(g) and "body delivered by SMTP" in g.get("text", ""), "client lists the message and reads its body via CamelEwsFolder", "not found / body unreadable: %s" % str(g)[:200], "SMTP :25 delivery; CamelFolder.get_message_sync (evolution-ews)")
r = cmd("evo1", "mail-flag", s_recv, "Inbox", "seen")
cmd("evo1", "mail-flag", s_recv, "Inbox", "answered")
time.sleep(3)
fl = L.imap_flags("ccev1", s_recv) or ""
rep.check("Mail: set read + answered in client -> server flags", "\\Seen" in fl and "\\Answered" in fl, "server FLAGS (%s)" % fl, "server FLAGS (%s) from client %s" % (fl, r), "CamelFolder.set_message_flags + synchronize; imaplib FETCH FLAGS")
# Evolution's "Mark for Follow-Up" (user tag follow-up) is what evolution-ews pushes (PidTagFlagStatus 0x1090 = 2); the CAMEL "important"
# flag (the star in some views) is NOT sent by evolution-ews at all (evidence: EWS_DEBUG=2 request log, gw-client-fixes-results.md section 5)
r = cmd("evo1", "mail-followup", s_recv, "Inbox")
time.sleep(3)
fl = L.imap_flags("ccev1", s_recv) or ""
rep.check("Mail: follow-up flag in client -> server \\Flagged", "\\Flagged" in fl, "server FLAGS (%s): PidTagFlagStatus=2 over EWS maps to \\Flagged" % fl, "client set follow-up but the server shows (%s) %s" % (fl, r), "CamelMessageInfo user tag follow-up + synchronize; imaplib FETCH FLAGS")
fname = "CC-%s" % tag
r = cmd("evo1", "mail-mkfolder", fname)
fo = L.imap_folders("ccev1")
rep.check("Mail: create folder in client -> server", r.get("ok") and any(fname in f for f in fo), "folder visible on the server (IMAP LIST: %s)" % [f for f in fo if fname in f], "%s %s" % (r, fo), "CamelStore.create_folder_sync; imaplib LIST")
r = cmd("evo1", "mail-search", tag)
rep.check("Mail: search in client (subject)", s_recv in (r.get("hits") or []), "folder search finds the message: %s" % r.get("hits"), str(r), "CamelFolder.search_by_expression (local summary)")
r = cmd("evo1", "mail-move", s_recv, "Inbox/" + fname)
moved = L.imap_find("ccev1", s_recv, "INBOX/" + fname, wait=20)
rep.check("Mail: move message to the new folder (client -> server)", r.get("moved") == 1 and moved is not None, "message now in server folder INBOX/%s" % fname, "%s; on server: %s" % (r, bool(moved)), "CamelFolder.transfer_messages_to_sync; imaplib SEARCH")
s_srv = "evo-srvflag-%s" % tag
deliver(L.addr("ccev2"), L.addr("ccev1"), s_srv)
wait(lambda: (lambda r: r if r.get("found") else None)(cmd("evo1", "mail-get", s_srv, "Inbox")), 60, 4)
L.imap_store("ccev1", s_srv, "+FLAGS", "(\\Seen)")
def seen_in_client():
    r = cmd("evo1", "mail-list", "Inbox")
    for it in r.get("items", []):
        if it[0] == s_srv: return it if it[1] & 16 else None
rep.check("Mail: server-side \\Seen change appears in client", bool(wait(seen_in_client, 260, 10)), "client shows the message as read after refresh", "client still shows it unread", "imaplib STORE; CamelFolder.refresh_info_sync")
r = cmd("evo1", "mail-delete", s_srv, "Inbox")
gone = wait(lambda: (L.imap_find("ccev1", s_srv, "INBOX", wait=1) is None) or None, 20, 2)
rep.check("Mail: delete message in client", r.get("deleted") == 1 and bool(gone), "removed from server INBOX", str(r), "CamelFolder DELETED flag + expunge; imaplib SEARCH")
s_send = "evo-send-%s" % tag
r = cmd("evo1", "mail-send", L.addr("ccev2"), s_send, "hello from Evolution\nümlaut")
arrived = L.imap_find("ccev2", s_send, wait=20) if r.get("ok") else None
if r.get("ok") and arrived:
    rep.passed("Mail: send via EWS (SendItem)", "message arrived in ccev2 INBOX", "CamelEwsTransport.send_to_sync; imaplib SEARCH")
else:
    rep.fail("Mail: send via EWS (SendItem)", "%s; message did not arrive. Server-side cause (gromox-http journal): 'E-3117: failed to send mail (The desired service is unavailable)'; Gromox's submission target localhost resolves to ::1 first while Postfix on ou-gw1 listens on IPv4 only (::1:25 refused, 127.0.0.1:25 open) - config, not a Thunderbird/Evolution defect (hypothesis: not changed in the lab)" % r, "CamelEwsTransport.send_to_sync; imaplib SEARCH")

# cleanup of the test folder
L.imap_store  # (folder is left empty; the mailbox of lab test users is disposable)
rep.done()
