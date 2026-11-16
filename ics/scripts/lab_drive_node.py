"""LAB ONLY: send one harmless signed runbook to an enrolled node exactly like the worker does (epoch stamped by Runtime.agent_epoch(),
audit event runbook.executed) - used by the standby proof to show which controller can still drive an agent.
usage: ICS_ENV_FILE=... python -m scripts.lab_drive_node NODE_ID ACTION KEY=VALUE   (e.g. service.status unit=systemd-networkd)
`--epoch N` overrides the stamped epoch to emulate a controller whose DB still says N (resurrected old primary)."""
import sys

from sqlalchemy import text

from ics import agentclient, audit
from ics.runtime import Runtime


def main(argv) -> int:
    override = None
    if "--epoch" in argv:
        i = argv.index("--epoch")
        override = int(argv[i + 1])
        argv = argv[:i] + argv[i + 2:]
    node_id, action, kv = argv[0], argv[1], argv[2]
    params = dict([kv.split("=", 1)])
    rt = Runtime()
    with rt.session() as db:
        node = db.execute(text("SELECT * FROM nodes WHERE id = :i"), {"i": node_id}).first()
    priv = agentclient.load_signing_key(rt.settings.signing_key_file)
    jid = agentclient.new_job_id()
    ep = rt.agent_epoch() if override is None else override     # raises when this controller is standby/fenced
    body = agentclient.build_request(priv, action=action, params=params, node_id=str(node.id), job_id=jid, ttl=60, epoch=ep)
    _, resp = agentclient.call(node, priv, action=action, params=params, job_id=jid, deadline=30, req_override=body)
    print({"sent_epoch": ep, "status": resp.get("status"), "code": resp.get("code"), "agent_epoch": resp.get("agent_epoch"), "result": resp.get("result")})
    with rt.session() as db:
        audit.append(db, "runbook.executed", actor_name="lab-script", resource="node", resource_id=str(node.id),
                     details={"runbook": action, "params": params, "agent_status": resp.get("status"), "agent_code": resp.get("code"), "job_id": jid, "epoch": ep})
        db.commit()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
