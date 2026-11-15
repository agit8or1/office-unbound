#!/usr/bin/env python3
"""GW07: mailbox backup/restore smoke test with gromox-exm2mt (GXMT export) + gromox-import.
grace gets 4 token messages -> full export (-ars IPM_SUBTREE) -> delete one message by IMAP (+expunge) -> wipe INBOX with
gromox-mbop emptyfld -> import dump -> all 4 tokens present again exactly once in INBOX.
Runs gromox CLI tools inside the lab machine via `sudo systemd-run -M ou-gw1` (set GW_MACHINE to change).
PROVES: the documented export/import tooling round-trips mail through a real mailbox.
DOES NOT PROVE: restore of ACLs (export docs: ACLs not extracted), calendar-sharing state, point-in-time/consistent
snapshot of the sqlite stores (gromox-snapshot / filesystem snapshot is the production approach, not exercised here)."""
import imaplib, os, ssl, subprocess, sys, time, smtplib, email.message, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gw_lab as L
rep = L.Rep("GW07 backup/restore")
M = os.environ.get("GW_MACHINE", "ou-gw1"); U = L.addr("grace"); ctx = ssl.create_default_context(cafile=L.CA)
def mx(cmd):
    p = subprocess.run(["sudo", "systemd-run", "-M", M, "--wait", "-P", "--pipe", "/bin/bash", "-c", cmd], capture_output=True, text=True, timeout=300)
    return p.returncode, (p.stdout + p.stderr)
def imap():
    im = imaplib.IMAP4_SSL(L.HOST, 993, ssl_context=ctx, timeout=30); im.login(U, L.PW["grace"]); im.select("INBOX"); return im
def count(tok):
    im = imap(); t, d = im.search(None, "SUBJECT", '"%s"' % tok); im.logout(); return len(d[0].split())
mx("gromox-mbop -u %s emptyfld -R -a --nuke-folders drafts >/dev/null 2>&1" % U)  # clean leftovers of earlier import experiments
toks = ["OU-BK%d-%s" % (i, L.RUN) for i in range(1, 5)]
for t in toks:
    m = email.message.EmailMessage(); m["From"], m["To"], m["Subject"] = L.addr("alice"), U, "backup probe " + t; m.set_content("body " + t * 20)
    smtplib.SMTP(L.HOST, 25, timeout=30).send_message(m)
time.sleep(6)
rep.check("seed 4 messages", all(count(t) == 1 for t in toks), "4 tokens in grace INBOX", [count(t) for t in toks])
rc, out = mx("mkdir -p /root/backup && gromox-exm2mt -u %s -ars IPM_SUBTREE > /root/backup/grace.mt; echo rc=$?; ls -l /root/backup/grace.mt; sha256sum /root/backup/grace.mt" % U)
print(out.strip()[-400:])
rep.check("export mailbox (gromox-exm2mt -ars IPM_SUBTREE)", "rc=0" in out and "grace.mt" in out, "dump written", out[-300:])
rc, out = mx("grep -c OU-BK /root/backup/grace.mt; strings /root/backup/grace.mt | grep -c 'OU-BK.*%s'" % L.RUN)
rep.check("dump contains tokens", rc == 0 and out.split()[-1] != "0", "tokens present in dump (%s)" % " ".join(out.split()), out)
# disaster 1: user deletes one message
im = imap(); t, d = im.search(None, "SUBJECT", '"%s"' % toks[1]); [im.store(n, "+FLAGS", "\\Deleted") for n in d[0].split()]; im.expunge(); im.logout(); time.sleep(2)
rep.check("message deleted", count(toks[1]) == 0, "%s gone" % toks[1], "still present")
# disaster 2: wipe INBOX completely
rc, out = mx("gromox-mbop -u %s emptyfld -a inbox 2>&1; echo rc=$?" % U); print(out.strip()[-300:])
time.sleep(2)
rep.check("INBOX wiped", all(count(t) == 0 for t in toks), "all 4 gone", [count(t) for t in toks])
rc, out = mx("gromox-import -u %s -x -c < /root/backup/grace.mt > /root/backup/import.log 2>&1; echo rc=$?; tail -5 /root/backup/import.log" % U); print(out.strip()[-500:])
rep.check("import exit code", "rc=0" in out, "gromox-import rc=0", out[-300:])
time.sleep(3)
mx("gromox-mbop -u %s sync-midb -f all >/dev/null 2>&1" % U)
cs = [count(t) for t in toks]
rep.check("restored: each token exactly once", cs == [1, 1, 1, 1], "counts=%s (incl. the message deleted before wipe)" % cs, "counts=%s (placed elsewhere or duplicated?)" % cs)
rep.done()
