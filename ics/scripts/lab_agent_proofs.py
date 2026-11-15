#!/usr/bin/env python3
"""Agent-level negative proofs against the real agent on ou-gw1. Run as the ICS service user (it needs the signing key and the node row):
  cd /opt/office-unbound/ics && sudo -u ics .venv/bin/python scripts/lab_agent_proofs.py
Requests are built with the ICS signing key but bypass every ICS-side validation, so what is shown is the AGENT's own enforcement."""
import json
import time
import uuid

from sqlalchemy import text

from ics import agentclient
from ics.runtime import Runtime

rt = Runtime()
with rt.session() as db:
    node = db.execute(text("SELECT * FROM nodes WHERE name = 'ou-gw1'")).first()
priv = agentclient.load_signing_key(rt.settings.signing_key_file)
nid = str(node.id)


def send(label, body):
    _, resp = agentclient.call(node, priv, action="", params={}, job_id="", req_override=body)
    print(f"{label:58s} -> status={resp['status']} code={resp['code']}", flush=True)
    return resp


def req(action, params, **kw):
    return agentclient.build_request(priv, action=action, params=params, node_id=nid, job_id=kw.pop("job_id", str(uuid.uuid4())), **kw)


ok = req("service.status", {"unit": "gromox-imap"})
send("1 valid signed service.status gromox-imap", ok)
send("2 REPLAY of the identical signed request", ok)
send("3 same job id, fresh nonce (job ids are single use)", req("service.status", {"unit": "gromox-imap"}, job_id=ok["req"]["job_id"]))
send("4 non-allowlisted unit sshd (service.restart)", req("service.restart", {"unit": "sshd"}))
send("5 unit not matching exactly (gromox-imap.service)", req("service.status", {"unit": "gromox-imap.service"}))
send("6 shell metacharacters in unit", req("service.status", {"unit": "nginx; id"}))
send("7 unknown runbook shell.exec", req("shell.exec", {"cmd": "id"}))
send("8 EXPIRED request (issued 300 s ago, ttl 60 s)", req("service.status", {"unit": "nginx"}, now=int(time.time()) - 300))
send("9 validity window too long (600 s)", req("service.status", {"unit": "nginx"}, ttl=600))
t = req("service.status", {"unit": "nginx"})
t["req"]["params"]["unit"] = "mariadb"
send("10 params tampered after signing", t)
send("11 request addressed to another node id", agentclient.build_request(priv, action="service.status", params={"unit": "nginx"}, node_id=str(uuid.uuid4()), job_id=str(uuid.uuid4())))
