"""First-boot bootstrap of a golden-image guest (`ou-bootstrap.service`; docs/status/bootstrap-v2.md). Runs ONCE as root, makes OUTBOUND calls only.

  1. read the per-VM-instance material the ICS put into SMBIOS at clone time (serial = bootstrap id + random secret, sku = ICS callback URL,
     family = SHA-256 pin of the ICS certificate). Nothing is ever read from, or written to, a command line.
  2. generate the agent's keys + TLS certificate and arm enrollment with a token the guest draws itself (only its HASH is stored by the agent);
  3. call the ICS ONCE over TLS pinned to the SMBIOS-delivered certificate hash: the report carries the agent's address/port/TLS fingerprint/key
     fingerprint and the enrollment token, authenticated by an HMAC under the secret; the ICS' answer must carry an HMAC acknowledgement (ICS
     authentication beyond the pin) and a MAC'd, closed-schema configuration;
  4. only then: apply the configuration (agent allowlist, image policy, nftables with the agent port open to the ICS sources ONLY), start the agent.

FAIL CLOSED: the image ships SSH masked and an nftables default-deny ruleset with no inbound service. Any failure (no/invalid SMBIOS, pin mismatch,
bad ack, bad configuration, timeout) leaves exactly that state (a `failed` marker is written, the agent is never started, nothing listens) and the
unit exits non-zero. There is no retry that weakens anything, no fallback and no SSH at any point."""
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse

from . import guestspec

SMBIOS_DIR = "/sys/class/dmi/id"
STATE_DIR = "/var/lib/ou-bootstrap"
PATH = "/api/v1/guest-bootstrap/report"
RUNBOOKS = {"disk.usage", "guest.facts", "podman.status", "podman.remove_unit", "podman.pull_verified", "podman.deploy_unit", "pkg.install_pinned"}
CIDR_RE = re.compile(r"^[0-9a-f:.]{2,45}/\d{1,3}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.\[\]:-]{1,100}$")


class Refused(Exception):
    """A closed-schema or authentication failure; the message is secret-free and goes to the journal."""


def read_smbios(d: str = SMBIOS_DIR) -> dict:
    def rd(n):
        try:
            with open(os.path.join(d, n), "rb") as f:
                return f.read(512).decode("ascii", "strict").strip()
        except (OSError, UnicodeDecodeError):
            return ""
    serial, sku, family = rd("product_serial"), rd("product_sku"), rd("product_family")
    if not re.fullmatch(r"[0-9a-f]{16}[0-9a-f]{64}", serial):
        raise Refused("no valid bootstrap serial in SMBIOS (this is not a VM the ICS prepared)")
    u = urllib.parse.urlsplit(sku)
    if u.scheme != "https" or not u.hostname or u.path not in ("", "/") or u.query or u.fragment or u.username or not HOST_RE.match(u.netloc):
        raise Refused("no valid https callback URL in SMBIOS")
    m = re.fullmatch(r"sha256:([0-9a-f]{64})", family)
    if not m:
        raise Refused("no valid certificate pin in SMBIOS")
    return {"bid": serial[:16], "secret": serial[16:], "host": u.hostname, "port": u.port or 443, "pin": m.group(1)}


def _mac(secret_hex: str, msg: str) -> str:
    return hmac.new(bytes.fromhex(secret_hex), msg.encode(), hashlib.sha256).hexdigest()


def canon_json(v) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def build_report(cfg: dict, agent: dict, token: str, *, nonce: str | None = None, ts: int | None = None) -> dict:
    nonce = nonce or secrets.token_hex(16)
    ts = int(time.time()) if ts is None else ts
    msg = "\n".join(["ou-bootstrap-report-v1", cfg["bid"], nonce, str(ts), agent["address"], str(agent["port"]), agent["tls_fingerprint_sha256"],
                     agent["agent_key_fingerprint_sha256"], hashlib.sha256(token.encode()).hexdigest()])
    return {"v": 1, "bid": cfg["bid"], "nonce": nonce, "ts": ts, "agent": agent, "enroll_token": token, "proof": _mac(cfg["secret"], msg)}


def post_pinned(cfg: dict, body: dict, timeout: float = 20.0) -> dict:
    """POST the report over TLS pinned to the SMBIOS-delivered certificate hash. The pin is checked BEFORE a single byte of the request is sent."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE   # trust comes from the pin below, not from a CA store the image does not ship
    conn = http.client.HTTPSConnection(cfg["host"], cfg["port"], timeout=timeout, context=ctx)
    try:
        conn.connect()
        der = conn.sock.getpeercert(binary_form=True)
        if not der or not hmac.compare_digest(hashlib.sha256(der).hexdigest(), cfg["pin"]):
            raise Refused("the ICS certificate does not match the pin delivered through SMBIOS; nothing was sent")
        data = json.dumps(body).encode()
        conn.request("POST", PATH, body=data, headers={"Content-Type": "application/json", "Content-Length": str(len(data))})
        r = conn.getresponse()
        raw = r.read(256 * 1024)
        if r.status != 200:
            raise Refused(f"the ICS refused the report (HTTP {r.status})")
        return json.loads(raw)
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as e:
        raise Refused(f"the callback failed: {type(e).__name__}") from None
    finally:
        conn.close()


def verify_response(cfg: dict, nonce: str, resp: dict) -> dict:
    """The ICS must prove it knows the secret (ack) and the configuration must carry a valid MAC; then the closed schema is enforced."""
    if not isinstance(resp, dict) or resp.get("ok") is not True:
        raise Refused("unexpected answer from the ICS")
    if not hmac.compare_digest(str(resp.get("ack", "")), _mac(cfg["secret"], f"ou-bootstrap-ack-v1\n{nonce}")):
        raise Refused("the ICS did not prove knowledge of the bootstrap secret (bad acknowledgement)")
    conf = resp.get("config")
    if not isinstance(conf, dict) or not hmac.compare_digest(str(resp.get("config_mac", "")), _mac(cfg["secret"], "ou-bootstrap-config-v1\n" + nonce + "\n" + canon_json(conf))):
        raise Refused("the configuration from the ICS failed its MAC")
    return validate_config(conf)


def _cidrs(v) -> list[str]:
    if not isinstance(v, list) or not v or len(v) > 32:
        raise Refused("invalid source list")
    out = []
    for c in v:
        try:
            out.append(str(ipaddress.ip_network(c, strict=False)))
        except (ValueError, TypeError):
            raise Refused("invalid CIDR in the configuration") from None
    return out


def validate_config(c: dict) -> dict:
    """Closed schema (unknown fields refused); every value is validated again here, the image trusts nothing it has not checked itself."""
    allowed = {"v", "hostname", "agent_port", "mgmt_sources", "ports", "agent_config", "image_registries", "insecure_registries", "signing_pubkey_pem",
               "signing_key_sha256", "enroll_ttl_seconds"}
    if set(c) - allowed or c.get("v") != 1:
        raise Refused("the configuration has an unknown version or unknown fields")
    if not isinstance(c.get("hostname"), str) or not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", c["hostname"]):
        raise Refused("invalid hostname")
    if not isinstance(c.get("agent_port"), int) or not 1024 <= c["agent_port"] <= 65535:
        raise Refused("invalid agent port")
    ttl = c.get("enroll_ttl_seconds", 3600)
    if not isinstance(ttl, int) or not 300 <= ttl <= 7 * 86400:
        raise Refused("invalid enrollment ttl")
    out = {"hostname": c["hostname"], "agent_port": c["agent_port"], "mgmt_sources": _cidrs(c.get("mgmt_sources")), "enroll_ttl_seconds": ttl, "ports": []}
    for p in c.get("ports", []):
        if not isinstance(p, dict) or set(p) != {"port", "proto", "sources"} or not isinstance(p["port"], int) or not 1 <= p["port"] <= 65535 \
                or p["proto"] not in ("tcp", "udp") or p["port"] == c["agent_port"]:
            raise Refused("invalid declared port")
        out["ports"].append({"port": p["port"], "proto": p["proto"], "sources": _cidrs(p["sources"]) if p["sources"] else []})
    ac = c.get("agent_config")
    if not isinstance(ac, dict) or set(ac) != {"listen", "runbooks"} or not isinstance(ac["runbooks"], dict):
        raise Refused("invalid agent configuration")
    if set(ac["runbooks"]) - RUNBOOKS:
        raise Refused("the configuration enables a runbook this image does not know")
    for name, rc in ac["runbooks"].items():
        try:
            if name == "disk.usage":
                if not isinstance(rc, dict) or set(rc) != {"paths"} or not all(isinstance(x, str) and re.fullmatch(r"/[A-Za-z0-9_./-]{0,100}", x) for x in rc["paths"]):
                    raise ValueError
            else:
                guestspec.validate_runbook_config(name, rc)
        except ValueError:
            raise Refused(f"invalid configuration for runbook {name}") from None
    out["agent_config"] = {"listen": {"address": "0.0.0.0", "port": c["agent_port"]}, "runbooks": ac["runbooks"]}
    regs = c.get("image_registries", [])
    if not isinstance(regs, list) or not all(isinstance(r, str) and guestspec.REGISTRY_RE.fullmatch(r) for r in regs):
        raise Refused("invalid registries")
    out["image_registries"], out["insecure_registries"] = regs, [r for r in c.get("insecure_registries", []) if r in regs]
    pem = c.get("signing_pubkey_pem")
    if pem is not None and (not isinstance(pem, str) or len(pem) > 2000 or not pem.startswith("-----BEGIN PUBLIC KEY-----")):
        raise Refused("invalid image signing key")
    out["signing_pubkey_pem"], out["signing_key_sha256"] = pem, c.get("signing_key_sha256")
    return out


def nft_ruleset(conf: dict) -> str:
    rules = ["    ct state established,related accept", "    ct state invalid drop", '    iif "lo" accept',
             "    ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } accept", "    meta l4proto ipv6-icmp accept",
             "    udp sport 67 udp dport 68 accept", "    udp sport 547 udp dport 546 accept"]

    def add(port, proto, cidrs):
        v4 = [c for c in cidrs if ":" not in c]
        v6 = [c for c in cidrs if ":" in c]
        if not cidrs:
            rules.append(f"    {proto} dport {port} accept")
        if v4:
            rules.append(f"    ip saddr {{ {', '.join(v4)} }} {proto} dport {port} accept")
        if v6:
            rules.append(f"    ip6 saddr {{ {', '.join(v6)} }} {proto} dport {port} accept")
    add(conf["agent_port"], "tcp", conf["mgmt_sources"])
    for p in sorted(conf["ports"], key=lambda x: (x["port"], x["proto"])):
        add(p["port"], p["proto"], p["sources"])
    return ("#!/usr/sbin/nft -f\n# generated by Office Unbound first boot: default deny inbound; the agent port to the ICS sources and the declared ports only\n"
            "flush ruleset\ntable inet ou_guest {\n  chain input {\n    type filter hook input priority 0; policy drop;\n" + "\n".join(rules) +
            "\n  }\n  chain forward {\n    type filter hook forward priority 0; policy drop;\n  }\n  chain output {\n"
            "    type filter hook output priority 0; policy accept;\n  }\n}\n")


class Guest:
    """The file/process side effects, behind one object so that tests (and the lab emulation) run the real logic against a directory."""

    def __init__(self, root: str = "/", runner=None, address_towards=None):
        self.root = root
        self.run = runner or (lambda argv, **kw: subprocess.run(argv, check=True, capture_output=True, timeout=300, **kw))
        self.address_towards = address_towards or self._local_address_towards

    def p(self, path: str) -> str:
        return os.path.join(self.root, path.lstrip("/"))

    def write(self, path: str, data: str, mode: int = 0o644) -> None:
        fp = self.p(path)
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        tmp = fp + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "w") as f:
            f.write(data)
        os.replace(tmp, fp)

    @staticmethod
    def _local_address_towards(host: str) -> str:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:
            sk.connect((socket.gethostbyname(host), 9))   # no packet is sent: this only asks the kernel which local address routes there
            return sk.getsockname()[0]


def prepare_agent(g: Guest, address: str, hostname: str, ttl: int) -> tuple[str, dict]:
    """Keys, TLS certificate and an armed enrollment token drawn HERE (the agent stores only its hash). The agent is not started."""
    from . import cli, server
    state = g.p("/var/lib/ou-agent")
    os.makedirs(state, mode=0o700, exist_ok=True)
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if not os.path.exists(os.path.join(state, "agent_key.pem")):
        cli._w(os.path.join(state, "agent_key.pem"), Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        cli.make_tls(state, address, hostname)
    token = secrets.token_urlsafe(32)
    for f in ("enroll.json",):
        if os.path.exists(os.path.join(state, f)):
            os.unlink(os.path.join(state, f))
    cli.arm_enroll(state, ttl, hashlib.sha256(token.encode()).hexdigest())
    tls, key = cli.fingerprints(state)
    g.run(["chown", "-R", "ou-agent:ou-agent", state])
    return token, {"tls_fingerprint_sha256": tls, "agent_key_fingerprint_sha256": key}


def apply_config(g: Guest, conf: dict) -> None:
    g.write("/etc/ou-agent/agent.json", json.dumps(conf["agent_config"], indent=2, sort_keys=True) + "\n")
    if conf["signing_pubkey_pem"] and conf["image_registries"]:
        pub = conf["signing_pubkey_pem"] if conf["signing_pubkey_pem"].endswith("\n") else conf["signing_pubkey_pem"] + "\n"
        g.write("/etc/ou-agent/image-signing.pub", pub)
        d = "/opt/ou-agent/deploy/render_image_policy.py"
        for kind, dest in (("policy", "/etc/ou-agent/image-policy.json"), ("pullonly", "/etc/ou-agent/image-policy-pullonly.json"),
                           ("registries", "/etc/containers/registries.d/ou-agent.yaml")):
            out = g.run(["python3", d, g.p("/etc/ou-agent/agent.json"), g.p("/etc/ou-agent/image-signing.pub"), kind])
            g.write(dest, out.stdout.decode() if isinstance(out.stdout, bytes) else str(out.stdout))
        if conf["insecure_registries"]:
            g.write("/etc/containers/registries.conf.d/50-ou-insecure.conf", "".join(
                f'[[registry]]\nlocation = "{r}"\ninsecure = true\n\n' for r in sorted(conf["insecure_registries"])))
    pol = g.run(["python3", "/opt/ou-agent/deploy/render_polkit.py", g.p("/etc/ou-agent/agent.json")])   # the agent's only privilege: restart allowlisted units
    g.write("/etc/polkit-1/rules.d/50-ou-agent.rules", pol.stdout.decode() if isinstance(pol.stdout, bytes) else str(pol.stdout))
    rules = nft_ruleset(conf)
    g.write("/etc/nftables.conf.new", rules)
    g.run(["nft", "-c", "-f", g.p("/etc/nftables.conf.new")])                   # syntax checked before it replaces anything
    os.replace(g.p("/etc/nftables.conf.new"), g.p("/etc/nftables.conf"))
    g.run(["nft", "-f", g.p("/etc/nftables.conf")])
    g.run(["hostnamectl", "set-hostname", conf["hostname"]])
    g.run(["systemctl", "enable", "--now", "ou-agent.service"])


def bootstrap(g: Guest, smbios_dir: str = SMBIOS_DIR, post=post_pinned, *, retry_seconds: float = 0.0, sleep=time.sleep, clock=time.monotonic) -> dict:
    """The whole first boot. Returns the validated configuration; raises Refused (or any other error) after writing the `failed` marker."""
    done, failed = g.p(STATE_DIR + "/done"), g.p(STATE_DIR + "/failed")
    if os.path.exists(done):
        return {}
    try:
        cfg = read_smbios(smbios_dir)
        address = g.address_towards(cfg["host"])
        token, fps = prepare_agent(g, address, "guest", 3600)
        agent = {"address": address, "port": 8443, **fps}
        end = clock() + retry_seconds
        while True:   # only transport errors are retried (the ICS may not be reachable yet); an authentication failure is final
            body = build_report(cfg, agent, token)
            try:
                resp = post(cfg, body)
                break
            except Refused as e:
                if "pin" in str(e) or "refused the report" in str(e) or clock() >= end:
                    raise
                sleep(10)
        conf = verify_response(cfg, body["nonce"], resp)
        if conf["agent_port"] != agent["port"]:
            raise Refused("the ICS asked for another agent port than the one the agent listens on")
        apply_config(g, conf)
        g.write(STATE_DIR + "/fingerprints.json", json.dumps({"address": address, "port": agent["port"], **fps}) + "\n")
        g.write(STATE_DIR + "/done", str(int(time.time())) + "\n")
        return conf
    except BaseException as e:
        g.write(STATE_DIR + "/failed", f"{int(time.time())} {type(e).__name__}: {str(e)[:200]}\n")
        raise


def main(argv=None) -> int:
    g = Guest()
    try:
        bootstrap(g, retry_seconds=600.0)
    except Refused as e:
        print(f"ou-bootstrap: refused: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001
        print(f"ou-bootstrap: failed: {type(e).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
