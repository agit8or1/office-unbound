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
import base64
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

from . import cfgspec, guestspec

SMBIOS_DIR = "/sys/class/dmi/id"
STATE_DIR = "/var/lib/ou-bootstrap"
PATH = "/api/v1/guest-bootstrap/report"
RUNBOOKS = {"disk.usage", "guest.facts", "podman.status", "podman.remove_unit", "podman.pull_verified", "podman.deploy_unit", "pkg.install_pinned", *cfgspec.CFG_RUNBOOKS}
CFG_ALLOW_DIR = "/etc/ou-agent/nft-allow.d"   # cfg.firewall writes ou-peers.nft here (root); included by /etc/nftables.conf
CIDR_RE = re.compile(r"^[0-9a-f:.]{2,45}/\d{1,3}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.\[\]:-]{1,100}$")


class Refused(Exception):
    """A closed-schema or authentication failure; the message is secret-free and goes to the journal."""


class Busy(Refused):
    """The ICS answered 429/503: transient, retried with a bounded backoff (review 5 M1); only 401 and friends are final."""

    def __init__(self, msg: str, retry_after: int = 0):
        super().__init__(msg)
        self.retry_after = retry_after


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
        if r.status in (429, 503):
            ra = r.getheader("Retry-After", "0") or "0"
            raise Busy(f"the ICS is busy (HTTP {r.status})", int(ra) if ra.isdigit() else 0)
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
               "signing_key_sha256", "enroll_ttl_seconds", "ou_repos", "signed_registry", "image_repos", "artifact_ca_pem", "artifact_ca_sha256", "artifact_tls_hosts", "apt_base_sources"}
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
            elif name in cfgspec.CFG_RUNBOOKS:
                cfgspec.validate_runbook_config(name, rc)
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
    out.update(validate_artifacts(c, regs))
    return out


APT_DIR = "/etc/ou-agent/apt"
ARTIFACT_CA = "/etc/ou-agent/artifact-ca.crt"
SUITE_RE = re.compile(r"^(dev|staging|stable)$")
URL_RE = re.compile(r"^https://[a-z0-9][A-Za-z0-9.-]{0,100}(:[0-9]{1,5})?(/[A-Za-z0-9._~-]+){0,10}/?$")
SRC_RE = re.compile(r"deb \[signed-by=[A-Za-z0-9/._-]+\] [A-Za-z0-9.:/_~-]+ [a-z0-9-]+( [a-z0-9-]+){1,8}")


def validate_artifacts(c: dict, regs: list) -> dict:
    """ADR-0015: per-channel apt repositories (each with its OWN pinned key) and the artifact CA, scoped to named hosts. Everything is re-checked
    here: the key block must hash to the declared fingerprint (computed on the guest, the ICS only declares it), the CA must match its sha256."""
    out = {"ou_repos": [], "artifact_ca_pem": None, "artifact_tls_hosts": [], "apt_base_sources": c.get("apt_base_sources"), "signed_registry": None}
    sr = c.get("signed_registry")
    if sr is not None:
        if not isinstance(sr, str) or not guestspec.REGISTRY_RE.fullmatch(sr):
            raise Refused("invalid signed registry")
        out["signed_registry"] = sr
    ir = c.get("image_repos", [])
    if not isinstance(ir, list) or len(ir) > 64 or not all(isinstance(x, str) and re.fullmatch(r"ou/[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*){0,2}", x) for x in ir):
        raise Refused("invalid image repositories")
    if bool(sr) != bool(ir):
        raise Refused("signed_registry and image_repos go together")
    out["image_repos"] = sorted(set(ir))
    bs = c.get("apt_base_sources")
    if bs is not None and (not isinstance(bs, str) or len(bs) > 4000 or any(not SRC_RE.fullmatch(ln) for ln in bs.splitlines() if ln.strip())):
        raise Refused("invalid base apt sources")
    repos = c.get("ou_repos", [])
    if not isinstance(repos, list) or len(repos) > 3:
        raise Refused("invalid repositories")
    seen = set()
    for r in repos:
        if not isinstance(r, dict) or set(r) != {"suite", "url", "components", "key_armored", "key_fingerprint"}:
            raise Refused("invalid repository entry")
        if not isinstance(r["suite"], str) or not SUITE_RE.fullmatch(r["suite"]) or r["suite"] in seen:
            raise Refused("invalid or duplicate repository channel")
        seen.add(r["suite"])
        if not isinstance(r["url"], str) or not URL_RE.fullmatch(r["url"]):
            raise Refused("invalid repository url (https only)")
        if not isinstance(r["components"], list) or not r["components"] or not all(isinstance(x, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,30}", x) for x in r["components"]):
            raise Refused("invalid repository components")
        if not isinstance(r["key_armored"], str) or len(r["key_armored"]) > 20000 or not r["key_armored"].startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----") \
                or r["key_armored"].count("-----BEGIN") != 1:
            raise Refused("invalid repository key")
        if not isinstance(r["key_fingerprint"], str) or not re.fullmatch(r"[0-9A-F]{40}", r["key_fingerprint"]) or openpgp_fingerprint(r["key_armored"]) != r["key_fingerprint"]:
            raise Refused("the repository key does not match its pinned fingerprint")
        out["ou_repos"].append({k: r[k] for k in ("suite", "url", "components", "key_armored", "key_fingerprint")})
    pem, pin, hosts = c.get("artifact_ca_pem"), c.get("artifact_ca_sha256"), c.get("artifact_tls_hosts", [])
    if bool(pem) != bool(pin) or bool(pem) != bool(hosts):
        raise Refused("artifact CA, pin and hosts go together")
    if pem:
        m = re.fullmatch(r"\s*-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----\s*", pem) if isinstance(pem, str) and len(pem) < 8000 else None
        try:
            der = base64.b64decode("".join(m.group(1).split()), validate=True) if m else b""
        except ValueError:
            der = b""
        if not der or not isinstance(pin, str) or hashlib.sha256(der).hexdigest() != pin:
            raise Refused("the artifact CA does not match its pinned sha256")
        if not isinstance(hosts, list) or len(hosts) > 4 or not all(isinstance(h, str) and guestspec.REGISTRY_RE.fullmatch(h) for h in hosts):
            raise Refused("invalid artifact TLS hosts")
        out["artifact_ca_pem"], out["artifact_tls_hosts"] = pem if pem.endswith("\n") else pem + "\n", sorted(set(hosts))
    return out


def openpgp_fingerprint(armored: str) -> str:
    """v4 fingerprint of the primary key of an armored public key block (SHA-1 over 0x99 || len || key body); no gpg needed on the guest."""
    body, on, hdr = [], False, True
    for ln in armored.splitlines():
        ln = ln.strip()
        if ln.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----"):
            on, hdr = True, True
            continue
        if not on:
            continue
        if ln.startswith("-----END") or ln.startswith("="):
            break
        if hdr:
            if ": " in ln:
                continue
            hdr = False
            if not ln:
                continue
        if ln:
            body.append(ln)
    try:
        raw = base64.b64decode("".join(body), validate=True)
        tag = raw[0]
        if tag & 0x40:
            t, i, n = tag & 0x3F, 1, raw[1]
            if n < 192:
                i = 2
            elif n < 224:
                n, i = ((n - 192) << 8) + raw[2] + 192, 3
            else:
                return ""
        else:
            t, lt = (tag >> 2) & 0xF, tag & 3
            sz = {0: 1, 1: 2, 2: 4}.get(lt)
            if sz is None:
                return ""
            n, i = int.from_bytes(raw[1:1 + sz], "big"), 1 + sz
        kb = raw[i:i + n]
        if t != 6 or not kb or kb[0] != 4:
            return ""
        return hashlib.sha1(b"\x99" + len(kb).to_bytes(2, "big") + kb).hexdigest().upper()  # noqa: S324 (the OpenPGP v4 definition)
    except (ValueError, IndexError):
        return ""


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
    # peer allowances (cfg.firewall, agent >= 0.5.0): exact (source address, protocol, port) triples between the deployment's own VMs, known only
    # after they enrolled. The set starts EMPTY; the include adds what cfg.firewall wrote, so it survives a reboot. No match opens nothing.
    rules.append("    ip saddr . meta l4proto . th dport @cfg_allow4 accept")
    return ("#!/usr/sbin/nft -f\n# generated by Office Unbound first boot: default deny inbound; the agent port to the ICS sources and the declared ports only\n"
            "flush ruleset\ntable inet ou_guest {\n  set cfg_allow4 {\n    type ipv4_addr . inet_proto . inet_service\n  }\n"
            "  chain input {\n    type filter hook input priority 0; policy drop;\n" + "\n".join(rules) +
            "\n  }\n  chain forward {\n    type filter hook forward priority 0; policy drop;\n  }\n  chain output {\n"
            "    type filter hook output priority 0; policy accept;\n  }\n}\n"
            f'include "{CFG_ALLOW_DIR}/*.nft"\n')


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
    apply_trust(g, conf)
    pol = g.run(["python3", "/opt/ou-agent/deploy/render_polkit.py", g.p("/etc/ou-agent/agent.json")])   # the agent's only privilege: restart allowlisted units
    g.write("/etc/polkit-1/rules.d/50-ou-agent.rules", pol.stdout.decode() if isinstance(pol.stdout, bytes) else str(pol.stdout))
    rules = nft_ruleset(conf)
    os.makedirs(g.p(CFG_ALLOW_DIR), mode=0o755, exist_ok=True)   # the include's directory must exist for `nft -c`; empty = no peer allowance
    g.write("/etc/nftables.conf.new", rules)
    g.run(["nft", "-c", "-f", g.p("/etc/nftables.conf.new")])                   # syntax checked before it replaces anything
    os.replace(g.p("/etc/nftables.conf.new"), g.p("/etc/nftables.conf"))
    g.run(["nft", "-f", g.p("/etc/nftables.conf")])
    g.run(["hostnamectl", "set-hostname", conf["hostname"]])
    g.run(["systemctl", "enable", "--now", "ou-agent.service"])


def apply_trust(g: Guest, conf: dict) -> None:
    """Everything that decides WHAT this guest will install: runbook allowlists, the sigstoreSigned image policy with the one pinned key, registries.d,
    the per-channel apt sources/keys/pins and the artifact CA (ADR-0015). Split from apply_config so the lab and the tests exercise exactly this code."""
    g.write("/etc/ou-agent/agent.json", json.dumps(conf["agent_config"], indent=2, sort_keys=True) + "\n")
    if conf["signing_pubkey_pem"] and conf["image_registries"]:
        pub = conf["signing_pubkey_pem"] if conf["signing_pubkey_pem"].endswith("\n") else conf["signing_pubkey_pem"] + "\n"
        g.write("/etc/ou-agent/image-signing.pub", pub)
        if conf.get("signed_registry"):   # signatures name this registry; every allowlisted ARTIFACT registry is remapped onto it (ADR-0015)
            g.write("/etc/ou-agent/image-identity.json", json.dumps({h: {"signed": conf["signed_registry"], "repos": conf["image_repos"]}
                                                                     for h in conf["artifact_tls_hosts"] if h in conf["image_registries"]}) + "\n")
        d = "/opt/ou-agent/deploy/render_image_policy.py"
        for kind, dest in (("policy", "/etc/ou-agent/image-policy.json"), ("pullonly", "/etc/ou-agent/image-policy-pullonly.json"),
                           ("registries", "/etc/containers/registries.d/ou-agent.yaml")):
            out = g.run(["python3", d, g.p("/etc/ou-agent/agent.json"), g.p("/etc/ou-agent/image-signing.pub"), kind])
            g.write(dest, out.stdout.decode() if isinstance(out.stdout, bytes) else str(out.stdout))
        if conf["insecure_registries"]:
            g.write("/etc/containers/registries.conf.d/50-ou-insecure.conf", "".join(
                f'[[registry]]\nlocation = "{r}"\ninsecure = true\n\n' for r in sorted(conf["insecure_registries"])))
    apply_artifacts(g, conf)


def apply_artifacts(g: Guest, conf: dict) -> None:
    """apt sources (system archives + our channels), per-channel keyrings, pinned fingerprints, and the artifact CA scoped to the artifact hosts:
    apt reads it through the agent's private apt-extra.conf (`Acquire::https::<host>::CaInfo`), podman through /etc/containers/certs.d/<host>/ca.crt."""
    if conf["ou_repos"]:
        lines = [(conf["apt_base_sources"] or "").rstrip("\n")] if conf.get("apt_base_sources") else []
        for r in sorted(conf["ou_repos"], key=lambda r: r["suite"]):
            lines.append(f"deb [signed-by={APT_DIR}/keyrings/ou-{r['suite']}.asc] {r['url']} {r['suite']} {' '.join(r['components'])}")
            g.write(f"{APT_DIR}/keyrings/ou-{r['suite']}.asc", r["key_armored"] if r["key_armored"].endswith("\n") else r["key_armored"] + "\n")
        g.write(f"{APT_DIR}/sources.list", "# generated: the ONLY sources pkg.install_pinned uses\n" + "\n".join(lines) + "\n")
        g.write(f"{APT_DIR}/pinned-fingerprints", "# pinned OpenPGP fingerprints; pkg.install_pinned refuses any other key\n" +
                "".join(r["key_fingerprint"] + "\n" for r in sorted(conf["ou_repos"], key=lambda r: r["suite"])))
    if conf["artifact_ca_pem"]:
        g.write(ARTIFACT_CA, conf["artifact_ca_pem"])
        g.write(f"{APT_DIR}/apt-extra.conf", "# generated: artifact CA, scoped per host (not in the system trust store)\n" + "".join(
            f'Acquire::https::{h.split(":", 1)[0]}::CaInfo "{ARTIFACT_CA}";\n' for h in conf["artifact_tls_hosts"]))
        for h in conf["artifact_tls_hosts"]:
            if h in conf["image_registries"]:
                g.write(f"/etc/containers/certs.d/{h}/ca.crt", conf["artifact_ca_pem"])


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
        busy = 0
        while True:   # only transport errors are retried (the ICS may not be reachable yet); an authentication failure is final
            body = build_report(cfg, agent, token)
            try:
                resp = post(cfg, body)
                break
            except Busy as e:   # review 5 M1: rate limited / overloaded is NOT an authentication failure: back off (bounded) and try again
                if clock() >= end:
                    raise
                busy += 1
                sleep(min(max(e.retry_after, 5 * 2 ** min(busy, 4)), 120))
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
