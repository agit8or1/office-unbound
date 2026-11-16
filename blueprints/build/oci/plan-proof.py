#!/usr/bin/env python3
"""Proof for the catalog: a deployment plan for profile `medium` with chat + meetings (and office/files/identity as the profile requires) has NO blocking artifact error,
asked through the public API of a RUNNING dev ICS instance (never the production service): POST /api/v1/deployments/plan.
usage: OU_ICS_BASE=http://127.0.0.1:8127/api/v1 OU_DEMO_CREDS=<creds.json of scripts/lab_ics_instance.py> OU_DB_OWNER_URL=<owner sqlalchemy url of the instance DB> plan-proof.py
The instance DB gets one throw-away endpoint `lab` + one inventory snapshot (two online nodes) so that the planner has capacity to plan against."""
import json
import os
import re
import sys
import time

import httpx
import pyotp
from sqlalchemy import create_engine, text

BASE = os.environ["OU_ICS_BASE"]
creds = json.load(open(os.environ["OU_DEMO_CREDS"]))
GiB = 1024 ** 3
eng = create_engine(os.environ["OU_DB_OWNER_URL"])
with eng.begin() as c:
    eid = c.execute(text("SELECT id FROM endpoints WHERE name = 'lab'")).scalar()
    if eid is None:
        eid = c.execute(text("INSERT INTO endpoints (name, type, base_url, token_id, token_secret_enc, fingerprint_sha256) VALUES ('lab', 'proxmox', 'https://pve.test:8006', 'u@pve!t', :s, :f) RETURNING id"),
                        {"s": b"x", "f": "ab" * 32}).scalar()
    data = {"nodes": [{"node": f"pve{i + 1}", "status": "online", "info": {"maxcpu": 64, "maxmem": 256 * GiB}, "qemu": [], "lxc": [],
                       "storage": [{"storage": "local-lvm", "content": "images", "avail": 4000 * GiB, "active": 1}], "network": [{"iface": "vmbr0", "type": "bridge"}]} for i in range(2)]}
    c.execute(text("INSERT INTO inventory_snapshots (endpoint_id, collected_at, data) VALUES (:e, now(), CAST(:d AS jsonb))"), {"e": str(eid), "d": json.dumps(data)})
h = httpx.Client(timeout=30)
u = "lab-op"
for off in (0, 1, 2, 3):          # a TOTP code is single use: take the next window if this one was spent
    r = h.post(f"{BASE}/auth/login", json={"username": u, "password": creds[u]["password"], "totp_code": pyotp.TOTP(creds[u]["secret"]).at(time.time() + 30 * off)})
    if r.status_code == 200:
        break
r.raise_for_status()
csrf = r.json()["csrf_token"]
sess = re.search(r"__Host-ics_session=([^;]+)", r.headers["set-cookie"]).group(1)
hdr = {"Cookie": f"__Host-ics_session={sess}", "X-CSRF-Token": csrf}
spec = {"customer_id": "acme", "deployment_id": "prod", "profile": "medium", "users": 100, "domain": "acme.example", "endpoint": "lab", "pool": "acme", "optional": {"chat": True, "meetings": True}}
r = h.post(f"{BASE}/deployments/plan", json=spec, headers=hdr)
print("HTTP", r.status_code)
p = r.json()
art = [e for e in p["errors"] if e["code"].startswith("artifact_")]
print("executable:", p["executable"], "| errors:", [e["code"] for e in p["errors"]], "| artifact errors:", art)
print("catalog:", p["catalog"], "| vms:", [v["logical"] for v in p["vms"]])
imgs = sorted({c["image"].split("/", 1)[1] for c in p["containers"]})
print("images in the plan (%d):" % len(imgs), ", ".join(imgs))
sys.exit(0 if r.status_code == 200 and not art and p["executable"] else 1)
