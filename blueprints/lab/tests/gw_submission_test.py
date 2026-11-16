#!/usr/bin/env python3
"""Client mail submission on the groupware node (gw-mta.sh): 587 STARTTLS + AUTH, 465 TLS + AUTH, no AUTH on :25, wrong password refused,
sender spoofing refused, delivery to the recipient's mailbox (IMAP). TLS is always verified against OU_CA_FILE.
Env (never printed): OU_PASSWORD_ALICE, OU_PASSWORD_BOB, OU_CA_FILE; OU_GW_HOST (default gw1.ou-lab.internal), OU_LAB_DOMAIN (default ou-lab.internal).
Prints PASS/FAIL, exit 1 on a FAIL. OU_STRICT_SKIP=1: missing env is a FAIL."""
import imaplib, os, smtplib, ssl, sys, time, uuid

HOST = os.environ.get("OU_GW_HOST", "gw1.ou-lab.internal")
DOM = os.environ.get("OU_LAB_DOMAIN", "ou-lab.internal")
CA, PWA, PWB = os.environ.get("OU_CA_FILE"), os.environ.get("OU_PASSWORD_ALICE"), os.environ.get("OU_PASSWORD_BOB")
if not (CA and PWA and PWB):
    print("SKIP gw_submission: need OU_CA_FILE, OU_PASSWORD_ALICE, OU_PASSWORD_BOB")
    sys.exit(1 if os.environ.get("OU_STRICT_SKIP") else 0)
ctx = ssl.create_default_context(cafile=CA)
A, B = "alice@" + DOM, "bob@" + DOM
fails = n = 0


def res(ok, name, detail=""):
    global fails, n
    n += 1
    fails += not ok
    print("%s %s %s" % ("PASS" if ok else "FAIL", name, detail))


def msg(frm, to, subj):
    return "From: %s\r\nTo: %s\r\nSubject: %s\r\nMessage-ID: <%s@%s>\r\n\r\nsubmission test\r\n" % (frm, to, subj, uuid.uuid4().hex, DOM)


def inbox_has(user, pw, subj, wait=60):  # a cold midb (right after gromox restarts / other suites) has needed more than 20 s once or twice
    t = time.time() + wait
    while time.time() < t:
        M = imaplib.IMAP4_SSL(HOST, 993, ssl_context=ctx)
        M.login(user, pw)
        M.select("INBOX")
        _, d = M.search(None, "SUBJECT", subj)
        hit = bool(d[0])
        for i in d[0].split():
            M.store(i, "+FLAGS", "\\Deleted")
        M.expunge()
        M.logout()
        if hit:
            return True
        time.sleep(2)
    return False


# 1. STARTTLS on 587: AUTH must not be offered before TLS, must be after
s = smtplib.SMTP(HOST, 587, timeout=30)
s.ehlo()
res("auth" not in s.esmtp_features, "587: no AUTH offered before STARTTLS")
s.starttls(context=ctx)
s.ehlo()
res("auth" in s.esmtp_features, "587: AUTH offered after STARTTLS (verified TLS)", s.esmtp_features.get("auth", ""))
s.login(A, PWA)
subj = "sub587-" + uuid.uuid4().hex[:8]
s.sendmail(A, [B], msg(A, B, subj))
s.quit()
res(inbox_has(B, PWB, subj), "587: alice -> bob delivered after AUTH")

# 2. implicit TLS on 465
s = smtplib.SMTP_SSL(HOST, 465, context=ctx, timeout=30)
s.login(B, PWB)
subj = "sub465-" + uuid.uuid4().hex[:8]
s.sendmail(B, [A], msg(B, A, subj))
s.quit()
res(inbox_has(A, PWA, subj), "465: bob -> alice delivered after AUTH")

# 3. wrong password refused
s = smtplib.SMTP(HOST, 587, timeout=30)
s.starttls(context=ctx)
try:
    s.login(A, "definitely-wrong-" + uuid.uuid4().hex)
    res(False, "587: wrong password refused")
except smtplib.SMTPAuthenticationError as e:
    res(e.smtp_code == 535, "587: wrong password refused", str(e.smtp_code))
s.close()

# 4. sender spoofing refused (alice authenticated, From/envelope = bob)
s = smtplib.SMTP(HOST, 587, timeout=30)
s.starttls(context=ctx)
s.login(A, PWA)
try:
    s.sendmail(B, [A], msg(B, A, "spoof-" + uuid.uuid4().hex[:6]))
    res(False, "587: authenticated sender cannot use another user's address")
except (smtplib.SMTPSenderRefused, smtplib.SMTPRecipientsRefused) as e:
    res(True, "587: authenticated sender cannot use another user's address", "refused 553")
s.close()

# 5. no AUTH on port 25 (unchanged relay behaviour)
s = smtplib.SMTP(HOST, 25, timeout=30)
s.ehlo()
res("auth" not in s.esmtp_features, "25: AUTH is not offered (unchanged)")
s.close()
print("gw_submission: %d checks, %d FAIL" % (n, fails))
sys.exit(1 if fails else 0)
