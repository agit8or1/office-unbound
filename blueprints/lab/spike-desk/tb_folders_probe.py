#!/usr/bin/env python3
"""Diagnostic (inside ou-desk2): print the folders of a Thunderbird IMAP account with their special-use flags, and where the identity files sent mail.
Usage: python3 tb_folders_probe.py <user-address>. Needs the running Marionette Thunderbird of cc_tb_mail.py."""
import json, sys
sys.path.insert(0, "/root/cc")
from marionette import Marionette

m = Marionette()
user = sys.argv[1]
code = """(async()=>{try{
const {MailServices}=ChromeUtils.importESModule('resource:///modules/MailServices.sys.mjs');
const a=MailServices.accounts.accounts.find(a=>a.incomingServer.username==arguments[0][0]);
const out={folders:[],fcc:a.defaultIdentity.fccFolder,fccUseDefault:a.defaultIdentity.fccFolderPickerMode,
 sent:a.incomingServer.rootFolder.getFolderWithFlags(Ci.nsMsgFolderFlags.SentMail)?.URI,
 trash:a.incomingServer.rootFolder.getFolderWithFlags(Ci.nsMsgFolderFlags.Trash)?.URI};
for(const f of a.incomingServer.rootFolder.descendants){out.folders.push([f.name,f.flags.toString(16)]);}
resolve(JSON.stringify(out));}catch(e){resolve(JSON.stringify({err:String(e)}));}})();"""
print(json.dumps(json.loads(m.run(code, [[user]])), indent=1))
