#!/usr/bin/env python3
"""Add a MAS OAuth2 client dedicated to the ICS identity lifecycle (client credentials, scope urn:mas:admin) and put it in policy.data.admin_clients.
Runs INSIDE ou-chat1 as root (idempotent). The secret goes to /root/ou-lab-secrets/mas-ics-client-secret (0600) and is never printed.
MAS has a single admin scope: the client cannot be narrowed by scope. Narrowing is: its own client id (revocable on its own), a secret that lives
only in the ICS vault, the admin API reachable only from the ICS network (nginx allow-list), and the ICS code calling only lookup/lock/unlock/deactivate/finish.
"""
import os
import secrets
import time

import yaml

ULID = "01K9" + "".join(secrets.choice("0123456789ABCDEFGHJKMNPQRSTVWXYZ") for _ in range(22))
CFG = "/etc/mas/config.yaml"
SEC = "/root/ou-lab-secrets/mas-ics-client-secret"
c = yaml.safe_load(open(CFG))
if os.path.exists(SEC) and any(x.get("client_auth_method") == "client_secret_basic" and x["client_id"] == open("/root/ou-lab-secrets/mas-ics-client-id").read() for x in c["clients"]):
    print("ICS client already present")
    raise SystemExit(0)
secret = secrets.token_hex(32)
fd = os.open(SEC, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, secret.encode())
os.close(fd)
c["clients"].append({"client_id": ULID, "client_auth_method": "client_secret_basic", "client_secret": secret})
c["policy"]["data"]["admin_clients"] = sorted(set(c["policy"]["data"].get("admin_clients", [])) | {ULID})
yaml.safe_dump(c, open(CFG, "w"), sort_keys=False)
os.system("chown root:mas %s; chmod 0640 %s" % (CFG, CFG))
open("/root/ou-lab-secrets/mas-ics-client-id", "w").write(ULID)
print("client id", ULID)
os.system("systemctl restart mas; sleep 4; systemctl is-active mas")
