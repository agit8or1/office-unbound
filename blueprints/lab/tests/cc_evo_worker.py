#!/usr/bin/env python3
"""Worker for cc_evo.py: runs inside an Evolution Data Server D-Bus session (blueprints/lab/spike-desk/evo-session.sh) of one
unix user (evo1/evo2) and drives the REAL evolution-ews backends through the EDS client API (ECalClient / EBookClient) =
what Evolution's calendar and contacts views use. Prints one JSON object on the last line. Commands:
  setup | cal-create | cal-get | cal-modify | cal-delete | cal-list | cal-invite | cal-accept | cal-find-invite | fb |
  book-add | book-get | book-modify | book-delete | book-list
Credentials: ~/pw.env (one OU_PASSWORD_*=... line, written by the orchestrator). Never printed."""
import gi, json, os, sys, time
gi.require_version("EDataServer", "1.2"); gi.require_version("ECal", "2.0"); gi.require_version("ICalGLib", "3.0")
gi.require_version("EBook", "1.2"); gi.require_version("EBookContacts", "1.2")
from gi.repository import EDataServer as E, ECal, ICalGLib, EBook, EBookContacts, GLib

USER = os.environ.get("EVO_UID") or os.path.basename(os.path.expanduser("~"))
MAIL = {"evo1": "ccev1", "evo2": "ccev2", "evom": "ccev1"}[USER] + "@ou-lab.internal"
HOST = "gw1.ou-lab.internal"
COL = "ews-" + USER


_OUT = {}
_CACHE = {}


MAIL_ACCOUNT = """[Data Source]
DisplayName=%(m)s
Enabled=true
Parent=%(c)s

[Mail Account]
BackendName=ews
IdentityUid=%(c)s-identity

[Authentication]
Host=%(h)s
Port=443
User=%(m)s
Method=PLAIN

[Ews Backend]
Email=%(m)s
Hosturl=%(hu)s
Oaburl=%(ou)s

[Security]
Method=none

[Offline]
StaySynchronized=false
"""
MAIL_IDENTITY = """[Data Source]
DisplayName=%(m)s
Enabled=true
Parent=%(c)s

[Mail Identity]
Address=%(m)s
Name=Lab %(m)s

[Mail Submission]
TransportUid=%(c)s-transport
SentFolder=folder://%(c)s-mail/Sent%%20Items
"""
MAIL_TRANSPORT = """[Data Source]
DisplayName=%(m)s
Enabled=true
Parent=%(c)s

[Mail Transport]
BackendName=ews

[Authentication]
Host=%(h)s
Port=443
User=%(m)s
Method=PLAIN

[Ews Backend]
Email=%(m)s
Hosturl=%(hu)s
"""


def out(**kw):
    _OUT.clear(); _OUT.update(kw)


def setup(hosturl, oaburl):
    _CACHE["hosturl"] = hosturl
    d = os.path.expanduser("~/.config/evolution/sources"); os.makedirs(d, exist_ok=True)
    pw = open(os.path.expanduser("~/pw.env")).read().split("=", 1)[1].strip()
    if not os.path.exists(d + "/%s.source" % COL):
        open(d + "/%s.source" % COL, "w").write("""[Data Source]
DisplayName=%(m)s
Enabled=true
Parent=

[Collection]
BackendName=ews
IdentityUid=%(u)s-identity

[Authentication]
Host=%(h)s
Port=443
User=%(m)s
Method=NTLM

[Ews Backend]
Email=%(m)s
Hosturl=%(hu)s
Oaburl=%(ou)s
""" % dict(m=MAIL, u=COL, h=HOST, hu=hosturl, ou=oaburl))
    # Evolution's EWS *mail* account is created by its account assistant, not by the collection backend: write the three
    # sources (mail account, identity, transport) the assistant would create, parented to the collection.
    for name, body in (("%s-mail.source" % COL, MAIL_ACCOUNT), ("%s-identity.source" % COL, MAIL_IDENTITY), ("%s-transport.source" % COL, MAIL_TRANSPORT)):
        if not os.path.exists(d + "/" + name):
            open(d + "/" + name, "w").write(body % dict(m=MAIL, c=COL, hu=hosturl, ou=oaburl, h=HOST))
    reg = E.SourceRegistry.new_sync(None)
    src = reg.ref_source(COL)
    src.store_password_sync(pw, True, None)
    for i in range(40):
        ls = [s for s in reg.list_sources(None) if (s.get_parent() or "") == COL]
        names = sorted(s.get_display_name() for s in ls)
        if "Calendar" in names and "Contacts" in names:
            return names
        time.sleep(3)
    return names


def reg_src(kind, name):
    reg = E.SourceRegistry.new_sync(None)
    for s in reg.list_sources(None):
        if s.has_extension(kind) and s.get_display_name() == name and (s.get_parent() or "") == COL:
            return s
    raise SystemExit("source %s/%s not found" % (kind, name))


def cal_client():
    if "cal" not in _CACHE:
        _CACHE["cal"] = ECal.Client.connect_sync(reg_src("Calendar", "Calendar"), ECal.ClientSourceType.EVENTS, 90, None)
    return _CACHE["cal"]


def book_client():
    if "book" not in _CACHE:
        _CACHE["book"] = EBook.BookClient.connect_sync(reg_src("Address Book", "Contacts"), 90, None)
    return _CACHE["book"]


def camel_store():
    """Evolution's mail layer for EWS: a CamelSession + the CamelEwsStore/CamelEwsTransport services (what Evolution's mail
    shell instantiates for an EWS account). Credentials come from ~/pw.env via the session's authenticate callback."""
    if "store" in _CACHE:
        return _CACHE["store"], _CACHE["transport"]
    gi.require_version("Camel", "1.2")
    from gi.repository import Camel
    pw = open(os.path.expanduser("~/pw.env")).read().split("=", 1)[1].strip()
    base = os.path.expanduser("~/camel"); os.makedirs(base, exist_ok=True)

    class Sess(Camel.Session):
        def do_authenticate_sync(self, service, mechanism, cancellable):
            service.set_password(pw)
            return service.authenticate_sync(mechanism, cancellable)

        def do_get_password(self, service, prompt, item, flags):
            return pw

    Camel.init(base, False)
    if hasattr(Camel, "provider_init"): Camel.provider_init()
    sess = Sess(user_data_dir=base + "/data", user_cache_dir=base + "/cache")
    svcs = []
    for suffix, ptype in (("mail", Camel.ProviderType.STORE), ("transport", Camel.ProviderType.TRANSPORT)):
        svc = sess.add_service("%s-%s" % (COL, suffix), "ews", ptype)
        st = svc.ref_settings()
        for k, v in (("hosturl", _CACHE["hosturl"]), ("email", MAIL), ("user", MAIL), ("host", HOST), ("auth-mechanism", "PLAIN"), ("port", 443)):
            st.set_property(k, v)
        svcs.append(svc)
    _CACHE.update(session=sess, store=svcs[0], transport=svcs[1], Camel=Camel)
    svcs[0].connect_sync(None)
    svcs[1].connect_sync(None)
    return svcs[0], svcs[1]


def mail_folder(name="Inbox", refresh=True):
    store, _ = camel_store()
    Camel = _CACHE["Camel"]
    # keep the CamelFolder referenced between commands: when the last reference is dropped Camel unloads the folder summary and the
    # next command sees an empty folder until the background re-sync finished
    f = _CACHE.setdefault("folders", {}).get(name)
    if f is None:
        f = _CACHE["folders"][name] = store.get_folder_sync(name, Camel.StoreGetFolderFlags.NONE, None)
    if refresh:
        f.refresh_info_sync(None)
    return f


def mail_text(msg):
    Camel = _CACHE["Camel"]
    stream = Camel.StreamMem.new()
    msg.write_to_stream_sync(stream, None)
    ba = stream.get_byte_array()
    return bytes(ba if isinstance(ba, (bytes, bytearray)) else ba.data).decode("utf-8", "replace")


def find_uids(folder, subject, wait=25):
    """Retry wrapper: right after refresh_info_sync the EWS folder summary can still be (re)filling, so an empty result is
    retried for up to `wait` seconds (no extra refresh)."""
    end = time.time() + wait
    while True:
        r = _find_uids_once(folder, subject)
        if r or time.time() > end:
            return r
        time.sleep(2)


def _find_uids_once(folder, subject):
    """One folder search (a single list-returning call per command: repeated get_uids()/search calls on a folder that is being
    synchronised produced garbage uid strings / crashes through pygobject)."""
    try:
        return list(folder.search_by_expression('(match-all (header-contains "subject" "%s"))' % subject, None) or [])
    except Exception:
        return []


def vevent(uid, summary, start, end, extra=""):
    ics = ("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//OU Lab//EN\r\nBEGIN:VEVENT\r\nUID:%s\r\nDTSTAMP:20261115T120000Z\r\n"
           "DTSTART:%s\r\nDTEND:%s\r\nSUMMARY:%s\r\nTRANSP:OPAQUE\r\n%sEND:VEVENT\r\nEND:VCALENDAR\r\n" % (uid, start, end, summary, extra))
    return ICalGLib.Component.new_from_string(ics).get_first_component(ICalGLib.ComponentKind.VEVENT_COMPONENT)


def comp_info(c):
    return dict(uid=c.get_uid(), summary=c.get_summary(), location=c.get_location(),
                start=c.get_dtstart().as_ical_string() if c.get_dtstart() else None,
                attendees=[(a.get_value(), a.get_partstat().__str__() if a.get_partstat() is not None else None)
                           for a in [p for p in iter_props(c, ICalGLib.PropertyKind.ATTENDEE_PROPERTY)]])


def iter_props(c, kind):
    p = c.get_first_property(kind)
    while p:
        yield p
        p = c.get_next_property(kind)


def find_by_summary(client, summary):
    ok, objs = client.get_object_list_sync('(contains? "summary" "%s")' % summary, None)
    return objs if ok else []


def main(argv):
    cmd, args = argv[0], argv[1:]
    _CACHE.setdefault("hosturl", "https://%s/EWS/Exchange.asmx" % HOST)
    if cmd == "setup":
        out(sources=setup(args[0], args[1])); return
    if cmd == "cal-reset":
        _CACHE.pop("cal", None); out(ok=True); return
    if cmd.startswith("cal-") or cmd == "fb":
        c = cal_client()
        if cmd == "cal-create":
            uid, summary, start, end = args[:4]
            extra = (args[4].replace("\\n", "\r\n") + "\r\n") if len(args) > 4 else ""
            ok, nuid = c.create_object_sync(vevent(uid, summary, start, end, extra), ECal.OperationFlags.NONE, None)
            out(ok=ok, uid=nuid)
        elif cmd == "cal-list":
            try: c.refresh_sync(None)
            except Exception: pass
            ok, objs = c.get_object_list_sync("#t", None)
            out(items=[comp_info(o) for o in objs])
        elif cmd == "cal-modify":
            summary = args[0]; new = args[1]
            objs = find_by_summary(c, summary)
            o = objs[0]
            o.set_summary(new); o.set_location("Room 9")
            c.modify_object_sync(o, ECal.ObjModType.THIS, ECal.OperationFlags.NONE, None)
            out(ok=True, uid=o.get_uid())
        elif cmd == "cal-delete":
            objs = find_by_summary(c, args[0])
            for o in objs:
                c.remove_object_sync(o.get_uid(), None, ECal.ObjModType.THIS, ECal.OperationFlags.NONE, None)
            out(deleted=len(objs))
        elif cmd == "cal-accept":
            # args: ics file with the received METHOD:REQUEST invitation, partstat. Import it (what Evolution does when the
            # user opens the invitation mail), then set our own PARTSTAT and let the backend send the response.
            ics = open(args[0]).read()
            vcal = ICalGLib.Component.new_from_string(ics)
            ok = c.receive_objects_sync(vcal, ECal.OperationFlags.NONE, None)
            ev = vcal.get_first_component(ICalGLib.ComponentKind.VEVENT_COMPONENT)
            objs = find_by_summary(c, ev.get_summary())
            o = objs[0]
            for a in iter_props(o, ICalGLib.PropertyKind.ATTENDEE_PROPERTY):
                if MAIL in a.get_value().lower():
                    a.remove_parameter_by_kind(ICalGLib.ParameterKind.PARTSTAT_PARAMETER)
                    a.add_parameter(ICalGLib.Parameter.new_partstat(ICalGLib.ParameterPartstat.ACCEPTED))
            c.modify_object_sync(o, ECal.ObjModType.THIS, ECal.OperationFlags.NONE, None)
            out(ok=True, imported=ok, found=len(objs), info=comp_info(o))
        elif cmd == "fb":
            start, end, who = args[0], args[1], args[2:]
            t0 = ICalGLib.Time.new_from_string(start); t1 = ICalGLib.Time.new_from_string(end)
            ok, fb = c.get_free_busy_sync(t0.as_timet_with_zone(ICalGLib.Timezone.get_utc_timezone()),
                                           t1.as_timet_with_zone(ICalGLib.Timezone.get_utc_timezone()), who, None)
            out(ok=ok, fb=[f.get_as_string() for f in (fb or [])])
        return
    if cmd.startswith("mail-"):
        Camel = None
        store, transport = camel_store(); Camel = _CACHE["Camel"]
        if cmd == "mail-send":
            to, subject, body = args[:3]
            msg = Camel.MimeMessage.new()
            frm = Camel.InternetAddress.new(); frm.add("Lab " + MAIL, MAIL)
            rcp = Camel.InternetAddress.new(); rcp.add(to.split("@")[0], to)
            msg.set_from(frm); msg.set_recipients("To", rcp); msg.set_subject(subject)
            msg.set_content(body.encode("utf-8"), "text/plain; charset=utf-8")
            r = transport.send_to_sync(msg, frm, rcp, None)
            out(ok=True, r=str(r))
        elif cmd == "mail-list":
            f = mail_folder(args[0] if args else "Inbox")
            us = list(f.search_by_expression("(match-all #t)", None) or [])
            items = []
            for u in us:
                i = f.get_message_info(u)
                if i: items.append((i.get_subject(), i.get_flags()))
            out(items=items)
        elif cmd == "mail-get":
            f = mail_folder(args[1] if len(args) > 1 else "Inbox")
            us = find_uids(f, args[0])
            if not us:
                out(found=False); return
            msg = f.get_message_sync(us[0], None)
            out(found=True, text=mail_text(msg)[:1500], flags=f.get_message_info(us[0]).get_flags())
        elif cmd == "mail-flag":
            f = mail_folder(args[1] if len(args) > 1 else "Inbox", refresh=False)
            us = find_uids(f, args[0])
            fl = {"seen": Camel.MessageFlags.SEEN, "flagged": Camel.MessageFlags.FLAGGED, "answered": Camel.MessageFlags.ANSWERED}[args[2] if len(args) > 2 else "seen"]
            for u in us: f.set_message_flags(u, fl, fl)
            f.synchronize_sync(False, None)
            out(changed=len(us))
        elif cmd == "mail-mkfolder":
            fi = store.create_folder_sync("Inbox", args[0], None)
            out(ok=True, name=fi.full_name)
        elif cmd == "mail-search":
            f = mail_folder(args[1] if len(args) > 1 else "Inbox", refresh=False)
            us = find_uids(f, args[0])
            out(hits=[f.get_message_info(u).get_subject() for u in us])
        elif cmd == "mail-move":
            f = mail_folder("Inbox", refresh=False); dst = mail_folder(args[1], refresh=False)
            us = find_uids(f, args[0])
            try:
                f.transfer_messages_to_sync(us, dst, False, None)
            except UnicodeDecodeError:
                pass  # pygobject cannot decode the binary uid list returned by the call; the transfer itself ran
            out(moved=len(us))
        elif cmd == "mail-delete":
            f = mail_folder(args[1] if len(args) > 1 else "Inbox", refresh=False)
            us = find_uids(f, args[0])
            for u in us: f.set_message_flags(u, Camel.MessageFlags.DELETED, Camel.MessageFlags.DELETED)
            f.synchronize_sync(True, None)
            out(deleted=len(us))
        return
    if cmd.startswith("book-"):
        b = book_client()
        try: b.refresh_sync(None)
        except Exception: pass
        if cmd == "book-add":
            vc = EBookContacts.Contact.new_from_vcard("BEGIN:VCARD\r\nVERSION:3.0\r\nUID:%s\r\nFN:%s\r\nN:%s;%s;;;\r\nEMAIL;TYPE=INTERNET:%s\r\nEND:VCARD\r\n" % (args[0], args[1], args[1].split()[-1], " ".join(args[1].split()[:-1]), args[2]))
            ok, uid = b.add_contact_sync(vc, EBookContacts.BookOperationFlags.NONE, None)
            out(ok=ok, uid=uid)
        elif cmd in ("book-get", "book-modify", "book-delete", "book-list"):
            ok, cs = b.get_contacts_sync('(contains "full_name" "%s")' % (args[0] if args else ""), None)
            if cmd == "book-list":
                out(items=[(c.get_property("full-name"), c.get_property("email-1")) for c in cs]); return
            if cmd == "book-get":
                out(items=[(c.get_property("full-name"), c.get_property("email-1")) for c in cs]); return
            if cmd == "book-modify":
                c = cs[0]; c.set_property("email-1", args[1]); b.modify_contact_sync(c, EBookContacts.BookOperationFlags.NONE, None); out(ok=True); return
            if cmd == "book-delete":
                for c in cs:
                    b.remove_contact_sync(c, EBookContacts.BookOperationFlags.NONE, None)
                out(deleted=len(cs)); return
        return
    raise SystemExit("unknown command " + cmd)


def serve(port):
    """One long-lived EDS session per unix user; the orchestrator sends one JSON line {"argv": [...]} per command."""
    import socket
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); ls.bind(("127.0.0.1", port)); ls.listen(5)
    while True:
        conn, _ = ls.accept()
        f = conn.makefile("rw")
        for line in f:
            req = json.loads(line)
            try:
                _OUT.clear(); main(req["argv"]); resp = dict(_OUT, ok_=True)
            except BaseException as e:
                resp = dict(error=repr(e)[:600])
            f.write(json.dumps(resp) + "\n"); f.flush()
        conn.close()


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve(int(sys.argv[2]))
    else:
        main(sys.argv[1:]); print("RESULT " + json.dumps(_OUT))
