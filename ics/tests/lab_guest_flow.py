"""LAB (not collected by default): drives the REAL agent in nspawn machine ou-guest1 through the ICS flow (node.enroll plan, two approvers, job,
then signed runbooks). Needs the machine prepared as in docs/status/guest-bootstrap-results.md.
  OU_LAB_DIR=<dir with enroll-token> OU_LAB_EVIDENCE=<file> ICS_TEST_ENV_FILE=... pytest -q -s tests/lab_guest_flow.py"""
import json
import os
import subprocess
import time
import uuid

import pytest

from tests.test_monitor import Env, H  # noqa: F401  (fixtures: rt, client, mk_user, login come from conftest)
from ics import agentclient
from ics.guest import agentcall

LAB = os.environ.get("OU_LAB_DIR")
pytestmark = pytest.mark.skipif(not LAB, reason="lab only")
EVID = os.environ.get("OU_LAB_EVIDENCE", "/dev/null")
MACHINE = "ou-guest1"
REG = "127.0.0.1:5000"


def gx(cmd, check=True):
    r = subprocess.run(["sudo", "-n", "machinectl", "shell", MACHINE, "/bin/sh", "-c", cmd], capture_output=True, text=True, timeout=300)
    out = "\n".join(l for l in r.stdout.splitlines() if not l.startswith("Connect"))
    return out.strip()


def ev(msg):
    print(msg, flush=True)
    with open(EVID, "a") as f:
        f.write(msg + "\n")


@pytest.fixture()
def lab(rt, client, mk_user, login):
    return Env(rt, login(mk_user("op", "operator")), login(mk_user("ap1", "approver")), login(mk_user("ap2", "approver")))


def test_guest_lab_flow(lab, rt):
    fps = json.loads(gx("cat /var/lib/ou-bootstrap/fingerprints.json"))
    token = open(os.path.join(LAB, "enroll-token")).read().strip()
    import hashlib
    if "trust.json" in gx("ls /var/lib/ou-agent"):   # re-run of the lab: the test ICS has fresh keys, so re-arm the node deliberately (console action)
        gx("systemctl stop ou-agent; rm -f /var/lib/ou-agent/trust.json; setpriv --reuid=ou-agent --regid=ou-agent --clear-groups env PYTHONPATH=/opt/ou-agent "
           "python3 -m ou_agent arm-enroll --token-sha256 %s --ttl 3600 >/dev/null; systemctl start ou-agent; sleep 2" % hashlib.sha256(token.encode()).hexdigest())
    res = lab.ok("node.enroll", {"name": MACHINE, "address": fps["address"], "port": fps["port"], "tls_fingerprint_sha256": fps["tls_fingerprint_sha256"],
                                 "agent_key_fingerprint_sha256": fps["agent_key_fingerprint_sha256"], "enrollment_token": token}, high=True)
    nid = res["node_id"]
    ev(f"ENROLL via ICS plan node.enroll (2 approvers) -> node {nid[:8]}..; capabilities: {sorted(res['capabilities'])}")
    ev("token file after enrollment on node: " + gx("ls /var/lib/ou-agent | tr '\\n' ' '") + " (enroll.json gone, trust.json present)")
    assert "enroll.json" not in gx("ls /var/lib/ou-agent")
    assert token not in json.dumps(res) and token not in gx("grep -rl %s /var/log /var/lib/cloud /var/lib/ou-bootstrap /etc/ou-agent 2>/dev/null; true" % token[:12])

    def rb(action, params, label):
        r = agentcall.execute(rt, nid, action, params)
        s = json.dumps(r.get("result"))
        ev(f"{label:62s} -> {r['status']}/{r['code']} {s[:230]}")
        return r

    f = rb("guest.facts", {}, "guest.facts")
    assert f["status"] == "ok"
    digests = dict(l.split("=") for l in gx("cd /root/lab; for n in signed unsigned wrongkey; do echo $n=$(cat $n.digest); done").splitlines())
    ev("digests: " + json.dumps(digests))
    ok_ref = f"{REG}/ou/whoami@{digests['signed']}"
    # ---- refusals
    for label, params in [("pull by TAG (unpinned)", {"image": f"{REG}/ou/whoami:1"}),
                          ("pull tag+digest", {"image": f"{REG}/ou/whoami:1@{digests['signed']}"}),
                          ("pull from non-allowlisted registry", {"image": f"evil.example/ou/whoami@{digests['signed']}"}),
                          ("pull + extra arg", {"image": ok_ref, "args": ["--tls-verify=false"]})]:
        r = rb("podman.pull_verified", params, label)
        assert r["status"] == "rejected"
    for label, patch in [("deploy privileged", {"privileged": True}), ("deploy host path mount", {"volumes": [{"name": "d", "path": "/data", "host": "/"}]}),
                         ("deploy docker/podman socket mount", {"volumes": [{"name": "s", "path": "/run/podman/podman.sock"}]}),
                         ("deploy extra podman args", {"args": ["--privileged"]})]:
        assert rb("podman.deploy_unit", {"component": "web", "name": "whoami", "type": "container", "image": ok_ref, **patch}, label)["status"] == "rejected"
    # signature checks
    r = rb("podman.pull_verified", {"image": f"{REG}/ou/unsigned@{digests['unsigned']}"}, "pull UNSIGNED image by digest")
    assert r["status"] == "ok" and r["result"]["result"]["verified"] is False
    r = rb("podman.pull_verified", {"image": f"{REG}/ou/wrongkey@{digests['wrongkey']}"}, "pull image signed by a DIFFERENT key")
    assert r["result"]["result"]["verified"] is False
    gx("cd /root/lab && python3 /root/mkimg.py tampered-oci 'tampered content' > tampered.digest && skopeo copy --dest-tls-verify=false oci:tampered-oci docker://127.0.0.1:5000/ou/whoami:1")
    tam = gx("cat /root/lab/tampered.digest")
    r = rb("podman.pull_verified", {"image": f"{REG}/ou/whoami@{tam}"}, "pull TAMPERED image (new content, same repo/tag, no valid sig)")
    assert r["result"]["result"]["verified"] is False
    r = rb("podman.deploy_unit", {"component": "web", "name": "whoami", "type": "container", "image": f"{REG}/ou/unsigned@{digests['unsigned']}"}, "deploy image that was never verified-pulled")
    assert r["result"].get("rejected", {}).get("code") == "image_not_verified"
    # ---- the good path
    r = rb("podman.pull_verified", {"image": ok_ref}, "pull SIGNED digest-pinned image")
    assert r["result"]["result"]["verified"] is True
    spec = {"component": "web", "name": "whoami", "type": "container", "image": ok_ref, "memory_mib": 64,
            "ports": [{"bind": "127.0.0.1", "host": 8080, "container": 8080, "proto": "tcp"}], "volumes": [{"name": "data", "path": "/var/lib/app"}], "user": "1000"}
    r = rb("podman.deploy_unit", spec, "podman.deploy_unit (Quadlet, rootless ou-svc)")
    assert r["result"]["result"]["started"] is True
    time.sleep(2)
    ev("HTTP from inside guest: " + gx("python3 -c \"import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8080/').read().decode().strip())\""))
    ev("process owner of container: " + gx("ps -eo user:12,comm | grep -E 'busybox|conmon' | sort -u | tr '\\n' ';'"))
    st = rb("podman.status", {}, "podman.status")
    assert st["result"]["result"]["units"][0]["active_state"] == "active"
    f2 = rb("guest.facts", {}, "guest.facts (with running unit)")
    ev("generated Quadlet:\n" + gx("cat /var/lib/ou-svc/.config/containers/systemd/ou-web-whoami.container"))
    r = rb("podman.remove_unit", {"component": "web", "name": "whoami", "purge_volumes": True}, "podman.remove_unit purge_volumes")
    assert r["result"]["result"]["removed"] is True
    st = rb("podman.status", {}, "podman.status after removal")
    assert st["result"]["result"]["units"] == []
    # ---- packages
    r = rb("pkg.install_pinned", {"packages": [{"name": "ou-hello", "version": "1.0-1"}]}, "pkg.install_pinned ou-hello=1.0-1 (allowlisted, pinned repo key)")
    assert r["result"]["result"]["ok"] is True
    for label, params, code in [("pkg wildcard version", {"packages": [{"name": "ou-hello", "version": "*"}]}, "bad_params"),
                                ("pkg not allowlisted (openssh-server)", {"packages": [{"name": "openssh-server", "version": "1:9.6p1-3ubuntu13"}]}, "not_allowed")]:
        assert rb("pkg.install_pinned", params, label)["code"] == code
    r = rb("pkg.install_pinned", {"packages": [{"name": "ou-hello", "version": "9.9-1"}]}, "pkg version that does not exist in the repo")
    assert r["result"]["result"]["ok"] is False
    ev("dpkg on guest: " + gx("dpkg -l ou-hello | tail -1 | cut -c1-60"))
    gx("cp /etc/ou-agent/apt/pinned-fingerprints /root/pf.bak; printf '0000000000000000000000000000000000000000\\n' > /etc/ou-agent/apt/pinned-fingerprints")
    try:
        r = rb("pkg.install_pinned", {"packages": [{"name": "ou-hello", "version": "2.0-1"}]}, "pkg with repo key NOT matching the pinned fingerprint")
        assert r["result"]["rejected"]["code"] == "repo_key_mismatch"
    finally:
        gx("cp /root/pf.bak /etc/ou-agent/apt/pinned-fingerprints")
    ev("dpkg after refused install: " + gx("dpkg -l ou-hello | tail -1 | cut -c1-60"))
