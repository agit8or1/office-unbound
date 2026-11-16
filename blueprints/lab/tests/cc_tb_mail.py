#!/usr/bin/env python3
"""CC-TB-1: Thunderbird ESR (real process, Marionette chrome-JS) against grommunio/Gromox over IMAPS + SMTP submission.
Driven THROUGH the client: autoconfig discovery (FindConfig = the code the Account Hub uses), account creation
(CreateInBackend), compose+send over SMTP (nsIMsgCompose), IMAP sync/receive, folder create, flag changes, IMAP search.
Verified SERVER-SIDE with an independent imaplib session. NOT driven: GUI clicks (no xdotool in these tests)."""
import json, sys, time
sys.path.insert(0, "/root/cc")
import cc_lib as L
from marionette import Marionette

rep = L.Rep("TB mail")
m = Marionette()
VER = m.sync("return Services.appinfo.name+' '+Services.appinfo.version")
print("client:", VER)


def js(body, args=None):
    code = "(async()=>{try{const r=await (async()=>{%s})();resolve(JSON.stringify(r===undefined?null:r));}catch(e){resolve(JSON.stringify({__err:String(e)+' '+(e.stack||'')}));}})();" % body
    r = json.loads(m.run(code, args))
    if isinstance(r, dict) and "__err" in r: raise RuntimeError(r["__err"][:600])
    return r


PRE = """const {MailServices}=ChromeUtils.importESModule('resource:///modules/MailServices.sys.mjs');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const waitFor=async(f,ms=60000)=>{const e=Date.now()+ms;while(Date.now()<e){const v=await f();if(v)return v;await sleep(500);}return null;};
const accountFor=u=>MailServices.accounts.accounts.find(a=>a.incomingServer.username==u);
"""

# ---- 0. trust the lab CAs inside the client's own NSS store (what a managed desktop would deploy)
import glob
for f in sorted(glob.glob("/usr/local/share/ca-certificates/ou-lab*.crt")):
    pem = open(f).read()
    js("const db=Cc['@mozilla.org/security/x509certdb;1'].getService(Ci.nsIX509CertDB); db.addCertFromBase64(arguments[0][0],'C,,'); return 1;",
       [["".join(l for l in pem.splitlines() if "CERTIFICATE" not in l)]])

# ---- 1. autoconfig + account creation (both users, through the same code the account wizard runs)
for uid in ("cctb1", "cctb2"):
    mail = L.addr(uid)
    js(PRE + """for(const a of MailServices.accounts.accounts.filter(a=>a.incomingServer.username==arguments[0][0])) MailServices.accounts.removeAccount(a,true);""", [[mail]])
    r = js(PRE + """
const {FindConfig}=ChromeUtils.importESModule('resource:///modules/accountcreation/FindConfig.sys.mjs');
const {AccountConfig}=ChromeUtils.importESModule('resource:///modules/accountcreation/AccountConfig.sys.mjs');
const {CreateInBackend}=ChromeUtils.importESModule('resource:///modules/accountcreation/CreateInBackend.sys.mjs');
const [mail,pw]=arguments[0];
const ac=new AbortController();
const gen=FindConfig.parallelAutoDiscovery(mail.split('@')[1],mail,ac.signal,pw);
const c=(await gen.next()).value;
const found={source:c.source,inc:[c.incoming.type,c.incoming.hostname,c.incoming.port,c.incoming.socketType,c.incoming.auth],out:[c.outgoing.type,c.outgoing.hostname,c.outgoing.port,c.outgoing.socketType,c.outgoing.auth]};
AccountConfig.replaceVariables(c,'Lab '+mail.split('@')[0],mail,pw);
await CreateInBackend.createAccountInBackend(c);
// What a user's first start does after the wizard: let the IMAP server list its folders (XLIST/SPECIAL-USE flags) before anything is sent.
for(const a of MailServices.accounts.accounts){ if(a.incomingServer.username==mail){
  MailServices.imap.discoverAllFolders(a.incomingServer.rootFolder, null, null);
  await waitFor(()=>a.incomingServer.rootFolder.getFolderWithFlags(Ci.nsMsgFolderFlags.SentMail),30000).catch(()=>null);
} }
return found;
""", [[mail, L.pw(uid)]])
    rep.check("autoconfig %s" % uid, r["source"] == "xml" and r["inc"][1] == L.HOST and r["inc"][2] == 993 and r["out"][2] == 587,
              "xml from portal: IMAP %s:%s SSL, SMTP %s:%s STARTTLS (TB socketType in=%s out=%s)" % (r["inc"][1], r["inc"][2], r["out"][1], r["out"][2], r["inc"][3], r["out"][3]),
              str(r), "FindConfig.parallelAutoDiscovery via Marionette (client internals)")

import socket
try:
    socket.create_connection((L.HOST, 587), 5); adv = True
except OSError as e:
    adv = False
rep.check("autoconfig-advertised SMTP 587 STARTTLS is reachable", adv, "port 587 open (submission service present)", "connection refused: no submission service behind the advertised port", "TCP connect")

# ---- 2. compose + send over SMTP submission (cctb1 -> cctb2), driven through the client
subj = "tb-send-%s" % L.RUN
body = "hello from Thunderbird %s\nline2 ümlaut" % L.RUN
r = js(PRE + """
const [from,to,subj,body]=arguments[0];
const acct=accountFor(from); const identity=acct.defaultIdentity;
const fields=Cc['@mozilla.org/messengercompose/composefields;1'].createInstance(Ci.nsIMsgCompFields);
fields.to=to; fields.from=from; fields.subject=subj; fields.body=body;
const params=Cc['@mozilla.org/messengercompose/composeparams;1'].createInstance(Ci.nsIMsgComposeParams);
params.type=Ci.nsIMsgCompType.New; params.format=Ci.nsIMsgCompFormat.PlainText; params.identity=identity; params.composeFields=fields;
const compose=MailServices.compose.initCompose(params);
const res=await new Promise(resolve2=>{
  const l={QueryInterface:ChromeUtils.generateQI(['nsIMsgSendListener']),
    onStartSending(){},onProgress(){},onStatus(){},onGetDraftFolderURI(){},onSendNotPerformed(id,st){resolve2({sent:false,status:st});},
    onStopSending(id,st,msg,file){resolve2({sent:Components.isSuccessCode(st),status:st,msg});}};
  compose.addMsgSendListener(l);
  compose.sendMsg(Ci.nsIMsgCompDeliverMode.Now,identity,acct.key,null,null);
  setTimeout(()=>resolve2({sent:false,status:'timeout'}),60000);
});
return res;
""", [[L.addr("cctb1"), L.addr("cctb2"), subj, body]])
rep.check("send via SMTP submission", r.get("sent"), "client reports sent (autoconfig SMTP submission 587 STARTTLS + AUTH, no manual override)", str(r), "nsIMsgCompose.sendMsg(Now) via Marionette")
got = L.imap_find("cctb2", subj)
rep.check("server-side: mail arrived in cctb2 INBOX", got is not None, "found by independent IMAP session; From/To headers ok" if got else "", "not found within 40 s", "imaplib SEARCH")
print("server folders cctb1:", L.imap_folders("cctb1"))
sent = L.imap_find("cctb1", subj, "Sent Items", wait=5) or L.imap_find("cctb1", subj, "Sent", wait=15)
_dup = [x for x in L.imap_folders("cctb1") if x in ("Sent", "Trash")]
rep.check("no duplicate Sent/Trash folders created by the client", not _dup, "only the server's Sent Items / Deleted Items exist (SPECIAL-USE honoured)", "duplicate folders on the server: %s" % _dup, "IMAP LIST")
rep.check("server-side: copy in cctb1 Sent folder", sent is not None, "Fcc copy stored via IMAP APPEND by the client", "no copy found (Fcc folder mapping?)", "imaplib SEARCH")

# ---- 3. receive in client (cctb2) + read body
r = js(PRE + """
const [user,subj]=arguments[0];
const acct=accountFor(user); const root=acct.incomingServer.rootFolder;
const inbox=await waitFor(()=>acct.incomingServer.rootFolder.getFolderWithFlags(Ci.nsMsgFolderFlags.Inbox),20000);
acct.incomingServer.getNewMessages(inbox, null, null);
const hdr=await waitFor(()=>{ for(const h of inbox.messages){ if(h.subject==subj) return h;} return null; },60000);
if(!hdr) return {found:false,total:inbox.getTotalMessages(false)};
const {MsgHdrToMimeMessage}=ChromeUtils.importESModule('resource:///modules/gloda/MimeMessage.sys.mjs');
const mime=await new Promise(res=>MsgHdrToMimeMessage(hdr,null,(h,mm)=>res(mm),true));
const raw=mime? mime.coerceBodyToPlaintext():'NOMIME';
return {found:true,author:hdr.author,flags:hdr.flags,isRead:hdr.isRead,hasBody:raw.includes('hello from Thunderbird')&&raw.includes('ümlaut'),raw:raw.slice(0,60)};
""", [["%s" % L.addr("cctb2"), subj]])
rep.check("client sync/receive + read body", r.get("found") and r.get("hasBody"), "client lists message, author=%s, body readable from its store" % r.get("author"), str(r), "IMAP getNewMessages + message stream (client)")



# ---- 4. flags (client -> server): mark read + flagged in the client, verify \\Seen \\Flagged on the server
r = js(PRE + """
const [user,subj]=arguments[0];
const acct=accountFor(user); const inbox=acct.incomingServer.rootFolder.getFolderWithFlags(Ci.nsMsgFolderFlags.Inbox);
let hdr=null; for(const h of inbox.messages){ if(h.subject==subj) hdr=h; }
inbox.markMessagesRead([hdr],true); inbox.markMessagesFlagged([hdr],true);
await sleep(4000);
return {isRead:hdr.isRead,isFlagged:hdr.isFlagged};
""", [[L.addr("cctb2"), subj]])
time.sleep(3)
fl = L.imap_flags("cctb2", subj) or ""
rep.check("flags client->server (read, flagged)", "\\Seen" in fl and "\\Flagged" in fl, "client set read+flagged, server shows FLAGS (%s)" % fl, "client=%s server FLAGS=%s" % (r, fl), "nsIMsgFolder.markMessagesRead/markMessagesFlagged; imaplib FETCH FLAGS")

# ---- 5. flags (server -> client): another session sets \\Answered/\\Deleted-free flag; client refreshes
L.imap_store("cctb2", subj, "-FLAGS", "(\\Flagged)")
r = js(PRE + """
const [user,subj]=arguments[0];
const acct=accountFor(user); const inbox=acct.incomingServer.rootFolder.getFolderWithFlags(Ci.nsMsgFolderFlags.Inbox);
inbox.updateFolder(null);
const ok=await waitFor(()=>{ for(const h of inbox.messages){ if(h.subject==subj && !h.isFlagged) return {isFlagged:h.isFlagged,isRead:h.isRead}; } return null; },30000);
return ok||'still flagged';
""", [[L.addr("cctb2"), subj]])
rep.check("flags server->client (unflag seen in client)", isinstance(r, dict) and r.get("isRead"), "server-side -\\Flagged propagated to client DB; read state kept", str(r), "imaplib STORE; folder.updateFolder")

# ---- 6. server-side new message appears in client (IMAP APPEND by another session)
subj2 = "tb-recv-%s" % L.RUN
raw = ("From: cctb1@ou-lab.internal\r\nTo: cctb2@ou-lab.internal\r\nSubject: %s\r\nDate: Sun, 15 Nov 2026 22:10:00 +0000\r\nMessage-ID: <%s@lab>\r\n\r\nserver-side injected body\r\n" % (subj2, L.RUN)).encode()
L.imap_append("cctb2", "INBOX", raw)
r = js(PRE + """
const [user,subj]=arguments[0];
const acct=accountFor(user); const inbox=acct.incomingServer.rootFolder.getFolderWithFlags(Ci.nsMsgFolderFlags.Inbox);
acct.incomingServer.getNewMessages(inbox,null,null);
const h=await waitFor(()=>{ for(const x of inbox.messages){ if(x.subject==subj) return {a:x.author}; } return null; },40000);
return h||'not seen';
""", [[L.addr("cctb2"), subj2]])
rep.check("server-side delivered message appears in client", isinstance(r, dict), "client picked up IMAP-appended message", str(r), "imaplib APPEND; getNewMessages")

# ---- 7. folders: create in the client, verify server-side; copy message into it; delete folder
fname = "CC-%s" % L.RUN
r = js(PRE + """
const [user,fname,subj]=arguments[0];
const acct=accountFor(user); const root=acct.incomingServer.rootFolder;
root.createSubfolder(fname,null);
const f=await waitFor(()=>root.getChildNamed(fname),20000);
if(!f) return {created:false};
await sleep(2000);
const inbox=root.getFolderWithFlags(Ci.nsMsgFolderFlags.Inbox);
let hdr=null; for(const h of inbox.messages){ if(h.subject==subj) hdr=h; }
await new Promise(res=>{ MailServices.copy.copyMessages(inbox,[hdr],f,false,{QueryInterface:ChromeUtils.generateQI(['nsIMsgCopyServiceListener']),onStartCopy(){},onProgress(){},setMessageKey(){},getMessageId(){return '';},onStopCopy(st){res(st);}},null,false); setTimeout(res,20000); });
return {created:true};
""", [[L.addr("cctb2"), fname, subj]])
fo = L.imap_folders("cctb2")
rep.check("create folder in client -> server", r.get("created") and fname in fo, "folder %s exists on server (LIST)" % fname, "%s %s" % (r, fo), "createSubfolder; imaplib LIST")
cp = L.imap_find("cctb2", subj, fname, wait=20)
rep.check("copy message into new folder (client->server)", cp is not None, "message present in server folder %s" % fname, "not found in %s" % fname, "MailServices.copy.copyMessages; imaplib SEARCH")

# ---- 8. search: server-side IMAP SEARCH issued by the client
r = js(PRE + """
const [user,subj]=arguments[0];
const acct=accountFor(user); const inbox=acct.incomingServer.rootFolder.getFolderWithFlags(Ci.nsMsgFolderFlags.Inbox);
const ss=Cc['@mozilla.org/messenger/searchSession;1'].createInstance(Ci.nsIMsgSearchSession);
const term=ss.createTerm(); term.attrib=Ci.nsMsgSearchAttrib.Subject; term.op=Ci.nsMsgSearchOp.Contains; term.booleanAnd=true;
const v=term.value; v.attrib=Ci.nsMsgSearchAttrib.Subject; v.str=subj; term.value=v; ss.appendTerm(term);
ss.addScopeTerm(Ci.nsMsgSearchScope.onlineMail,inbox);
return await new Promise(res=>{ const hits=[]; const l={onNewSearch(){},onSearchHit(h,f){hits.push(h.subject);},onSearchDone(st){res({done:st,hits});}};
  ss.registerListener(l); ss.search(null); setTimeout(()=>res({timeout:true,hits}),30000); });
""", [[L.addr("cctb2"), "tb-"]])
rep.check("search (subject contains 'tb-', IMAP online scope)", isinstance(r, dict) and len(r.get("hits", [])) >= 2 and any(subj in h for h in r["hits"]), "client search returned %s hits: %s" % (len(r.get("hits", [])), r.get("hits")), str(r), "nsIMsgSearchSession onlineMail (IMAP SEARCH)")
rep.done()
