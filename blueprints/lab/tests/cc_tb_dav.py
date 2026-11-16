#!/usr/bin/env python3
"""CC-TB-2: Thunderbird's built-in CalDAV calendar and CardDAV address book against grommunio-dav (sabre/dav on Gromox).
Driven THROUGH the client (Marionette chrome JS, same modules as the "New Calendar / New Address Book" dialogs):
provider detection against https://gw1.../dav/, calendar registration, addItem/modifyItem/deleteItem, CardDAV directory
creation + card create/modify/delete + sync. Verified SERVER-SIDE with raw CalDAV/CardDAV requests and EWS FindItem, and
the reverse (server-created items appear in the client after a refresh). NOT driven: GUI dialogs."""
import json, sys, time, re
sys.path.insert(0, "/root/cc")
import cc_lib as L
from marionette import Marionette

rep = L.Rep("TB dav")
L_ = None
m = Marionette()
m.sync("Services.prefs.setBoolPref('signon.rememberSignons', true); return 1")


def js(body, args=None):
    code = "(async()=>{try{const r=await (async()=>{%s})();resolve(JSON.stringify(r===undefined?null:r));}catch(e){resolve(JSON.stringify({__err:String(e)+' '+(e.stack||'')}));}})();" % body
    v = m.run_robust(code, args, timeout=120)
    if v is None: raise TimeoutError("no result")
    r = json.loads(v)
    if isinstance(r, dict) and "__err" in r: raise RuntimeError(r["__err"][:800])
    return r


PRE = """const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const waitFor=async(f,ms=60000)=>{const e=Date.now()+ms;while(Date.now()<e){const v=await f();if(v)return v;await sleep(500);}return null;};
"""
U = "cctb1"
mail = L.addr(U)
BASE = "https://%s/dav/" % L.HOST
uid = "tbcal-%s" % L.RUN
summ = "TB event %s" % L.RUN

import glob
for f in sorted(glob.glob("/usr/local/share/ca-certificates/ou-lab*.crt")):
    pem = open(f).read()
    js("const db=Cc['@mozilla.org/security/x509certdb;1'].getService(Ci.nsIX509CertDB); db.addCertFromBase64(arguments[0][0],'C,,'); return 1;",
       [["".join(l for l in pem.splitlines() if "CERTIFICATE" not in l)]])

# cleanup of calendars/address books from earlier runs (they would raise auth prompts)
js(PRE + """const {cal}=ChromeUtils.importESModule('resource:///modules/calendar/calUtils.sys.mjs');
for(const c of cal.manager.getCalendars()) cal.manager.unregisterCalendar(c);
const {MailServices}=ChromeUtils.importESModule('resource:///modules/MailServices.sys.mjs');
for(const d of MailServices.ab.directories) if(d.dirType==Ci.nsIAbManager.CARDDAV_DIRECTORY_TYPE) MailServices.ab.deleteAddressBook(d.URI);
return 1;""")

# ---- CalDAV: detect + register (the New Calendar > On the Network flow)
r = js(PRE + """
const {cal}=ChromeUtils.importESModule('resource:///modules/calendar/calUtils.sys.mjs');
const [user,pw,loc]=arguments[0];
const found=await cal.provider.detection.detect(user,pw,loc,true,[],{});
const out=[]; for(const [prov,cals] of found){ for(const c of cals) out.push([prov.type||String(prov),c.uri.spec,c.name]); }
return out;
""", [[mail, L.pw(U), BASE]])
rep.check("CalDAV provider detection", len(r) > 0, "client discovered %d calendar(s): %s" % (len(r), r), str(r), "cal.provider.detection.detect (New Calendar > Network)")
caldav = [x for x in r if "caldav" in str(x[0]).lower() or "Calendar" in x[1]]
cal_uri = next((x[1] for x in r if x[1].rstrip("/").endswith("/Calendar")), r[0][1] if r else None)
print("calendar uri:", cal_uri)
# Thunderbird deletes a saved login that it handed out < 60 s ago and is asked for again (calAuthUtils: guards against
# loops on wrong passwords). Detection just used it, so wait before the calendar uses the same login.
time.sleep(5)

r = js(PRE + """
const {cal}=ChromeUtils.importESModule('resource:///modules/calendar/calUtils.sys.mjs');
const [user,pw,uri,uid,summ]=arguments[0];
const u=Services.io.newURI(uri);
Services.prefs.setBoolPref('signon.rememberSignons',true); Services.logins.setLoginSavingEnabled(u.prePath,true);
const li=Cc['@mozilla.org/login-manager/loginInfo;1'].createInstance(Ci.nsILoginInfo); li.init(u.prePath,null,'grommunio dav',user,pw,'','');
try{ await Services.logins.addLoginAsync(li); }catch(e){}
const c=cal.manager.createCalendar('caldav',u); c.name='cc-'+uid; c.setProperty('username',user); c.setProperty('cache.enabled',false);
cal.manager.registerCalendar(c);
// registration fires several parallel requests; Thunderbird's calendar auth deletes a saved login when it is asked twice
// within 60 s (see below). Let them settle, make sure the login is present, then use the calendar sequentially.
await sleep(10000);
const have=await Services.logins.searchLoginsAsync({origin:u.prePath,httpRealm:'grommunio dav'});
if(!have.length){ await Services.logins.addLoginAsync(li); }
try{ await c.getItem('nonexistent-'+uid); }catch(e){}
const res={relogin:!have.length};
const {CalEvent}=ChromeUtils.importESModule('resource:///modules/CalEvent.sys.mjs'); const item=new CalEvent(); item.icalString=('BEGIN:VCALENDAR\\r\\nVERSION:2.0\\r\\nPRODID:-//TB//\\r\\nBEGIN:VEVENT\\r\\nUID:'+uid+'\\r\\nDTSTAMP:20261115T120000Z\\r\\nDTSTART:20261201T100000Z\\r\\nDTEND:20261201T110000Z\\r\\nSUMMARY:'+summ+'\\r\\nLOCATION:Room 1\\r\\nEND:VEVENT\\r\\nEND:VCALENDAR\\r\\n');
const added=await c.addItem(item); res.added=added.id;
const got=await c.getItem(uid); res.readback=got&&got.title;
return res;
""", [[mail, L.pw(U), cal_uri, uid, summ]])

rep.check("CalDAV create event in client", r.get("added") == uid and r.get("readback") == summ, "addItem ok, client reads it back (%s)" % r, str(r), "calICalendar.addItem/getItem (caldav provider) via Marionette")
g = L.dav(U, "GET", "/calendars/%s/Calendar/%s.ics" % (mail, uid))
rep.check("server-side: event stored (CalDAV GET)", g.status_code == 200 and summ in g.text and "Room 1" in g.text, "GET 200, SUMMARY+LOCATION as created by client", "HTTP %s %s" % (g.status_code, g.text[:200]), "raw CalDAV GET")
e = L.ews(U, '<m:FindItem Traversal="Shallow"><m:ItemShape><t:BaseShape>Default</t:BaseShape></m:ItemShape><m:ParentFolderIds><t:DistinguishedFolderId Id="calendar"/></m:ParentFolderIds></m:FindItem>')
rep.check("server-side: client event visible over EWS", summ in e.text, "EWS FindItem(calendar) lists the event: same store as MAPI/webmail", "HTTP %s not listed" % e.status_code, "EWS FindItem")

GETC = "const c=cal.manager.getCalendars().find(x=>x.name=='cc-'+arguments[0][0]);"
CALMOD = "const {cal}=ChromeUtils.importESModule('resource:///modules/calendar/calUtils.sys.mjs');"
r = js(PRE + CALMOD + GETC + """
const old=await c.getItem(arguments[0][0]); const nw=old.clone();
nw.title=arguments[0][1]; nw.setProperty('LOCATION','Room 2'); nw.startDate=cal.createDateTime('20261201T120000Z'); nw.endDate=cal.createDateTime('20261201T130000Z');
const m=await c.modifyItem(nw,old); return m.title;
""", [[uid, summ + " EDITED"]])
g = L.dav(U, "GET", "/calendars/%s/Calendar/%s.ics" % (mail, uid))
rep.check("CalDAV edit event in client (title, location, time)", g.status_code == 200 and "EDITED" in g.text and "Room 2" in g.text and "T120000Z" in g.text, "server shows edited SUMMARY/LOCATION/DTSTART", "HTTP %s %s" % (g.status_code, g.text[:300]), "calICalendar.modifyItem; raw CalDAV GET")

# server -> client
uid2 = "tbsrv-%s" % L.RUN
ics = ("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//OU Lab//EN\r\nBEGIN:VEVENT\r\nUID:%s\r\nDTSTAMP:20261115T120000Z\r\nDTSTART:20261202T100000Z\r\nDTEND:20261202T110000Z\r\nSUMMARY:Server made %s\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n" % (uid2, L.RUN))
pr = L.dav(U, "PUT", "/calendars/%s/Calendar/%s.ics" % (mail, uid2), data=ics, headers={"Content-Type": "text/calendar"})
r = js(PRE + CALMOD + GETC + """
let t=[]; const end=Date.now()+30000;
while(Date.now()<end){ c.refresh(); await sleep(4000); const items=await c.getItemsAsArray(Ci.calICalendar.ITEM_FILTER_ALL_ITEMS|Ci.calICalendar.ITEM_FILTER_TYPE_EVENT,0,null,null); t=items.map(i=>i.title); if(t.some(x=>x.startsWith('Server made'))) break; await sleep(3000); }
return t;
""", [[uid]])
rep.check("server-created event appears in client (after calICalendar.refresh)", pr.status_code in (201, 204) and ("Server made %s" % L.RUN) in r, "client lists both events: %s" % r, "PUT %s, client sees %s" % (pr.status_code, r), "raw CalDAV PUT; calICalendar.getItemsAsArray")

r = js(PRE + CALMOD + GETC + """
const it=await c.getItem(arguments[0][0]); await c.deleteItem(it); return 1;
""", [[uid]])
g = L.dav(U, "GET", "/calendars/%s/Calendar/%s.ics" % (mail, uid))
rep.check("CalDAV delete event in client", g.status_code == 404, "server returns 404 for the deleted event", "HTTP %s" % g.status_code, "calICalendar.deleteItem; raw CalDAV GET")
L.dav(U, "DELETE", "/calendars/%s/Calendar/%s.ics" % (mail, uid2))
for stale in ('dbg1', 'pct1', 'pct2'):
    L.dav(U, 'DELETE', '/calendars/%s/Calendar/%s.ics' % (mail, stale))
rep.nosup("CalDAV scheduling (iTIP invite/accept) in Thunderbird", "not exercised here; meeting invitation/accept is tested with Evolution (EWS) instead", "not tested")

# ---- CardDAV
r = js(PRE + """
const {CardDAVUtils}=ChromeUtils.importESModule('resource:///modules/CardDAVUtils.sys.mjs');
const [user,pw,loc]=arguments[0];
const books=await CardDAVUtils.detectAddressBooks(user,pw,loc,false,true);
return books.map(b=>[b.name,String(b.url&&b.url.href||b.url)]);
""", [[mail, L.pw(U), BASE]])
rep.check("CardDAV address book detection", len(r) > 0, "client discovered: %s" % r, str(r), "CardDAVUtils.detectAddressBooks (New Address Book > CardDAV)")
card_name = next((b[0] for b in r if b[0] == "Contacts"), r[0][0] if r else "Contacts")
r = js(PRE + """
const {CardDAVUtils}=ChromeUtils.importESModule('resource:///modules/CardDAVUtils.sys.mjs');
const {MailServices}=ChromeUtils.importESModule('resource:///modules/MailServices.sys.mjs');
const [user,pw,loc,bookname,tag]=arguments[0];
const books=await CardDAVUtils.detectAddressBooks(user,pw,loc,false,true);
const b=books.find(x=>x.name==bookname);
const dir=b.create();
await sleep(3000);
const card=Cc['@mozilla.org/addressbook/cardproperty;1'].createInstance(Ci.nsIAbCard);
card.displayName='TB Contact '+tag; card.firstName='TB'; card.lastName='Contact '+tag; card.primaryEmail='tb-'+tag+'@example.invalid';
card.setProperty('Notes','made in thunderbird');
const added=dir.addCard(card);
await sleep(5000);
return {dirName:dir.dirName,uid:added.UID,type:dir.dirType};
""", [[mail, L.pw(U), BASE, card_name, L.RUN]])
print("carddav dir:", r)
vc = None
for href in [None]:
    q = L.dav(U, "REPORT", "/addressbooks/%s/Contacts/" % mail, headers={"Depth": "1", "Content-Type": "application/xml"},
              data='<card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><d:prop><d:getetag/><card:address-data/></d:prop></card:addressbook-query>')
    vc = q.text
rep.check("CardDAV create contact in client -> server", ("TB Contact %s" % L.RUN) in (vc or "") and ("tb-%s@example.invalid" % L.RUN) in (vc or ""), "vCard with FN/EMAIL found on server by REPORT addressbook-query", "HTTP %s, contact not on server" % q.status_code, "nsIAbDirectory.addCard (CardDAV dir); raw CardDAV REPORT")

r = js(PRE + """
const {MailServices}=ChromeUtils.importESModule('resource:///modules/MailServices.sys.mjs');
const dir=MailServices.ab.directories.find(d=>d.dirType==Ci.nsIAbManager.CARDDAV_DIRECTORY_TYPE);
let found=null; for(const c of dir.childCards){ if(c.displayName=='TB Contact '+arguments[0][0]) found=c; }
if(!found) return {found:false};
const e=found.vCardProperties.getFirstEntry('email'); e.value='tb-edited-'+arguments[0][0]+'@example.invalid';
dir.modifyCard(found); await sleep(5000); return {found:true};
""", [[L.RUN]])
q = L.dav(U, "REPORT", "/addressbooks/%s/Contacts/" % mail, headers={"Depth": "1", "Content-Type": "application/xml"},
          data='<card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><d:prop><d:getetag/><card:address-data/></d:prop></card:addressbook-query>')
rep.check("CardDAV edit contact in client -> server", r.get("found") and ("tb-edited-%s@example.invalid" % L.RUN) in q.text, "server vCard shows the edited EMAIL", "%s; server=%s" % (r, q.status_code), "nsIAbDirectory.modifyCard; raw CardDAV REPORT")

uidc = "srvc-%s" % L.RUN
vcard = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:%s\r\nFN:Server Contact %s\r\nN:Contact;Server;;;\r\nEMAIL;TYPE=INTERNET:srv-%s@example.invalid\r\nEND:VCARD\r\n" % (uidc, L.RUN, L.RUN)
pr = L.dav(U, "PUT", "/addressbooks/%s/Contacts/%s.vcf" % (mail, uidc), data=vcard, headers={"Content-Type": "text/vcard"})
r = js(PRE + """
const {MailServices}=ChromeUtils.importESModule('resource:///modules/MailServices.sys.mjs');
const dir=MailServices.ab.directories.find(d=>d.dirType==Ci.nsIAbManager.CARDDAV_DIRECTORY_TYPE);
await dir.wrappedJSObject.syncWithServer();
const f=await waitFor(()=>{ for(const c of dir.childCards){ if(c.displayName=='Server Contact '+arguments[0][0]) return c.primaryEmail; } return null; },30000);
return f||'not synced';
""", [[L.RUN]])
rep.check("server-created contact synced into client", pr.status_code in (201, 204) and r == "srv-%s@example.invalid" % L.RUN, "client sync lists the contact (email %s)" % r, "PUT %s client=%s" % (pr.status_code, r), "raw CardDAV PUT; CardDAVDirectory.syncWithServer")

r = js(PRE + """
const {MailServices}=ChromeUtils.importESModule('resource:///modules/MailServices.sys.mjs');
const dir=MailServices.ab.directories.find(d=>d.dirType==Ci.nsIAbManager.CARDDAV_DIRECTORY_TYPE);
const cs=[]; for(const c of dir.childCards){ if(c.displayName=='TB Contact '+arguments[0][0]) cs.push(c); }
dir.deleteCards(cs); await sleep(5000); return cs.length;
""", [[L.RUN]])
q = L.dav(U, "REPORT", "/addressbooks/%s/Contacts/" % mail, headers={"Depth": "1", "Content-Type": "application/xml"},
          data='<card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><d:prop><d:getetag/><card:address-data/></d:prop></card:addressbook-query>')
rep.check("CardDAV delete contact in client -> server", r == 1 and ("TB Contact %s" % L.RUN) not in q.text, "contact gone on server", "deleted=%s, still on server=%s" % (r, ("TB Contact %s" % L.RUN) in q.text), "nsIAbDirectory.deleteCards; raw CardDAV REPORT")
L.dav(U, "DELETE", "/addressbooks/%s/Contacts/%s.vcf" % (mail, uidc))
rep.done()
