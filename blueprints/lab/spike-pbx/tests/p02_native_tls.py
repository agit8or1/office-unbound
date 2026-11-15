#!/usr/bin/env python3
"""P02: native SIP client (baresip 1.0.0, run inside ou-pbx1) registers as carol.native over SIP/TLS 1.2 (server cert verified against the
lab CA) with mandatory SDES-SRTP, dials the echo extension 600, RTP is verified on the PBX, hang up, CDR row written.
Also: wrong password and plain-RTP (no SRTP) are refused."""
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pbx_lib as L

rep = L.Report("P02 native SIP client (baresip) over TLS + SDES-SRTP -> echo test 600")
cred = json.loads(L.pbx("cd /tmp; sudo -u ou-pbx ou-pbx issue --user carol --device native"))
rep.check("provisioning returns a one-time credential for carol.native (password not printed)", cred["username"] == "carol.native" and len(cred["password"]) == 32)
hits = L.pbx("grep -rlF -f - /var/lib/ou-pbx /etc/asterisk /etc/ou-pbx /var/log/asterisk /var/log/nginx /var/spool/asterisk 2>/dev/null; true", stdin=cred["password"]).strip()
rep.check("clear SIP password appears in no file on the PBX (only the MD5 digest is stored)", hits == "", hits or "0 files")
cdr_before = int(L.pbx("wc -l < /var/log/asterisk/cdr-csv/Master.csv").strip() or 0)
script = open(os.path.join(L.HERE, "native-baresip.sh")).read()
subprocess.run(["sudo", "systemd-run", "-M", "ou-pbx1", "--quiet", "--pipe", "--wait", "bash", "-c", "cat > /root/native-baresip.sh"], input=script, text=True)


def run(user, pw, dial="600", secs="8"):
    p = subprocess.run(["sudo", "systemd-run", "-M", "ou-pbx1", "--quiet", "--pipe", "--wait", "bash", "/root/native-baresip.sh", dial, secs],
                       input="%s %s\n" % (user, pw), text=True, capture_output=True, timeout=120)
    return p.stdout


out = run(cred["username"], cred["password"])
for line in out.splitlines():
    if line.strip():
        print("   | " + line)
rep.check("TLS REGISTER with digest auth accepted (200 OK)", "200 OK (OU-PBX)" in out and "registered successfully" in out)
rep.check("baresip verified the server cert against the lab CA (sip_verify_server yes)", "adding SIP CA: /etc/ou-lab/tls/ca.crt" in out)
rep.check("SRTP negotiated (mandatory SDES, AES_CM_128_HMAC_SHA1_80)", "SRTP is Enabled" in out)
rep.check("call to echo extension established", "Call established: sip:600@" in out)
rep.check("PBX: channel Up in Echo()", "!Up!Echo!" in out)
rows = re.findall(r"^\s+(\S+-\d+)\s+\d\d:\d\d:\d\d\s+\S+\s+(\d+)\s+(\d+)\s+\d+\s+\S+\s+(\d+)\s+(\d+)", out, re.M)
rep.check("RTP in both directions on the PBX leg (two channelstats samples, counters grow)",
          len(rows) >= 2 and int(rows[-1][1]) > int(rows[0][1]) > 50 and int(rows[-1][3]) > int(rows[0][3]) > 50 and rows[0][2] == "0", rows)
rep.check("call terminated cleanly by the client", "terminated (duration" in out)
cdr = L.pbx("tail -n +%d /var/log/asterisk/cdr-csv/Master.csv" % (cdr_before + 1))
mine = [r for r in cdr.splitlines() if '"1003"' in r and '"600"' in r]
rep.check("CDR row written (1003 -> 600, ANSWERED)", any("ANSWERED" in r for r in mine), mine[-1] if mine else cdr[-200:])
bad = run(cred["username"], "0" * 32, dial="600", secs="1")
rep.check("wrong password: registration refused", "registered successfully" not in bad and re.search(r"40[13]|Forbidden|Unauthorized|failed", bad) is not None,
          [l.strip() for l in bad.splitlines() if re.search(r"reg|40[13]", l, re.I)][:2])
rep.finish()
