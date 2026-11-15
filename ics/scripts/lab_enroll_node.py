"""LAB ONLY: enroll a node agent into a lab ICS without the plan/approval UI (the same agentclient calls + nodes row as actions._exec_node_enroll).
usage (inside the lab ICS host, as root): ICS_ENV_FILE=/etc/office-unbound/ics.env python -m scripts.lab_enroll_node NAME ADDR TLS_FP AGENT_KEY_FP TOKEN"""
import sys
import uuid

from sqlalchemy import text

from ics import agentclient, audit
from ics.runtime import Runtime


def main(name, addr, tls_fp, key_fp, token) -> int:
    rt = Runtime()
    priv = agentclient.load_signing_key(rt.settings.signing_key_file)
    ident = agentclient.identity(addr, 8443, tls_fp)
    assert agentclient.key_fingerprint(ident["agent_pubkey"]) == key_fp, "agent key fingerprint mismatch"
    nid = uuid.uuid4()
    resp = agentclient.enroll(addr, 8443, tls_fp, token=token, ics_pubkey_b64=agentclient.pub_b64(priv.public_key()), node_id=str(nid),
                              expect_agent_pubkey_b64=ident["agent_pubkey"])
    with rt.session() as db:
        db.execute(text("INSERT INTO nodes (id, name, address, port, tls_fingerprint_sha256, agent_pubkey, agent_key_fp, capabilities, agent_version, last_seen_at) "
                        "VALUES (:id, :n, :a, 8443, :t, :k, :f, CAST(:c AS jsonb), :v, now())"),
                   {"id": str(nid), "n": name, "a": addr, "t": tls_fp, "k": ident["agent_pubkey"], "f": key_fp,
                    "c": audit.canon(resp.get("capabilities", {})), "v": str(resp.get("agent_version"))[:40]})
        audit.append(db, "node.enrolled", actor_name="lab-script", resource="node", resource_id=str(nid), details={"name": name, "address": addr})
        db.commit()
    print("enrolled", nid)
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:6]))
