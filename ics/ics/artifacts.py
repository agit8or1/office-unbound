"""Artifact distribution (ADR-0015): what guests on customer VNets install from.

Three independent pieces live here, all pure / stdlib-only so the installer scripts can run them with the system python3:

  1. ArtifactMap       the operator's configuration (`OU_ARTIFACT_BASE` ...). It replaces the catalog placeholder host `registry.ou.invalid`
                       at plan time and carries the apt URL, the TLS CA pin and the per-channel release key pins that are injected into
                       every guest's bootstrap metadata (guest/cloudinit.py, agentport._spec).
  2. server rendering  nginx front end (TLS, read-only, rate limits, no listings), registry configs (read-only reader + local push instance),
                       nftables allow-list for the customer subnets, systemd units. `python -m ics.artifacts render-server`.
  3. health            `probe()` checks the published service the way a guest sees it (TLS against the pinned CA, apt InRelease freshness,
                       registry /v2/); used by Administration > System and by `python -m ics.artifacts health`.

Trust model: transport integrity is NOT what protects guests. apt verifies the signed InRelease against the per-channel key the guest pinned;
podman verifies a sigstore signature against the one image key the guest pinned and pulls by digest. TLS (private CA, pinned in the metadata)
adds confidentiality and stops trivial redirection; a compromised artifact host can withhold or replay old content (bounded by the
InRelease `Valid-Until`) but cannot make a guest accept unsigned or wrongly-signed content.
"""
import base64
import hashlib
import ipaddress
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

SENTINEL_REGISTRY = "registry.ou.invalid"      # catalog placeholder host (blueprints/catalog); replaced by ArtifactMap.registry_host
CHANNELS = ("dev", "staging", "stable")
# catalog `repo:` value of a package artifact -> apt suite of our repository; anything else (ubuntu-noble ...) is a distribution archive
REPO_SUITE = {f"ob-apt-{c}": c for c in CHANNELS}
APT_PATH = "/apt"
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,120}[a-z0-9])?(:[0-9]{1,5})?$")
HEX40 = re.compile(r"^[0-9A-F]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_KEYS_DIR = "/etc/office-unbound/artifacts/keys"
DEFAULT_DATA = "/var/lib/office-unbound/artifacts"
DEFAULT_PORT = 8446   # 8444 is the guest-bootstrap callback listener (hardening); the lab proof used 8444 before the two were merged


class ArtifactError(ValueError):
    pass


# ------------------------------------------------------------------------------------------------ OpenPGP fingerprint (no gpg needed)
def _dearmor(armored: str) -> bytes:
    body, on, hdr = [], False, True
    for ln in armored.splitlines():
        ln = ln.strip()
        if ln.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----"):
            on, hdr = True, True
            continue
        if not on:
            continue
        if ln.startswith("-----END") or ln.startswith("="):   # end marker or CRC24 line
            break
        if hdr:
            if ": " in ln:        # armor header (Version: ...)
                continue
            hdr = False
            if not ln:
                continue
        if ln:
            body.append(ln)
    if not body:
        raise ArtifactError("not an armored OpenPGP public key")
    return base64.b64decode("".join(body), validate=True)


def _packets(raw: bytes):
    """(tag, body) of every OpenPGP packet; partial and indeterminate lengths are refused (a public key block never needs them)."""
    i = 0
    while i < len(raw):
        tag = raw[i]
        if not tag & 0x80:
            raise ArtifactError("bad OpenPGP packet")
        if tag & 0x40:                              # new format
            t, i = tag & 0x3F, i + 1
            if i >= len(raw):
                raise ArtifactError("truncated OpenPGP packet")
            n = raw[i]
            if n < 192:
                i += 1
            elif n < 224:
                if i + 1 >= len(raw):
                    raise ArtifactError("truncated OpenPGP packet")
                n = ((n - 192) << 8) + raw[i + 1] + 192
                i += 2
            elif n == 255:
                n = int.from_bytes(raw[i + 1:i + 5], "big")
                i += 5
            else:
                raise ArtifactError("partial-length key packet")
        else:                                       # old format
            t, lt = (tag >> 2) & 0xF, tag & 3
            sz = {0: 1, 1: 2, 2: 4}.get(lt)
            if sz is None:
                raise ArtifactError("indeterminate-length key packet")
            n, i = int.from_bytes(raw[i + 1:i + 1 + sz], "big"), i + 1 + sz
        if i + n > len(raw):
            raise ArtifactError("truncated OpenPGP packet")
        yield t, raw[i:i + n]
        i += n


def pgp_fingerprint(armored: str) -> str:
    """Fingerprint (40 upper-case hex) of the ONLY primary key of an armored v4 OpenPGP public key block. review 8 L-1: the whole file becomes the
    guests' apt keyring, so a block carrying a second primary key (e.g. the dev key exported along) is refused instead of pinning only the first."""
    pk = list(_packets(_dearmor(armored)))
    if not pk or pk[0][0] != 6:
        raise ArtifactError("first packet is not a public key")
    if sum(1 for t, _ in pk if t == 6) != 1:
        raise ArtifactError("the key file holds more than one primary key: export exactly the pinned channel key (gpg --export --armor <fingerprint>)")
    body = pk[0][1]
    if not body or body[0] != 4:
        raise ArtifactError("only v4 OpenPGP keys are supported")
    return hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).hexdigest().upper()  # noqa: S324 (OpenPGP v4 fingerprint definition)


def ca_sha256(pem: str) -> str:
    """sha256 of the DER of the (first) certificate in a PEM text: the pin the operator confirms out of band."""
    m = re.search(r"-----BEGIN CERTIFICATE-----\s*(.+?)\s*-----END CERTIFICATE-----", pem, re.S)
    if not m:
        raise ArtifactError("no certificate in the CA PEM")
    return hashlib.sha256(base64.b64decode("".join(m.group(1).split()), validate=True)).hexdigest()


# ------------------------------------------------------------------------------------------------ the operator's configuration
@dataclass(frozen=True)
class ArtifactMap:
    apt_host: str                       # host[:port] serving https://<apt_host>/apt/dists/<channel>
    registry_host: str                  # host[:port] OCI registry as it appears in image references
    ca_pem: str | None = None           # private CA the guests trust for these two hosts ONLY (never added to the system store)
    ca_sha256: str | None = None
    channel_keys: tuple = ()            # ((channel, armored_key, fingerprint), ...) only pinned channels
    signed_registry: str | None = None  # registry host the signer wrote into the image signatures, when not the serving host

    @property
    def apt_url(self) -> str:
        return f"https://{self.apt_host}{APT_PATH}"

    def key(self, channel: str):
        for c, armored, fpr in self.channel_keys:
            if c == channel:
                return armored, fpr
        return None

    def suite_for_repo(self, repo: str) -> str | None:
        return REPO_SUITE.get(repo)

    def describe(self) -> dict:
        """The plan section (inside the plan hash): addresses and pins only, never key material beyond fingerprints."""
        return {"apt_url": self.apt_url, "registry": self.registry_host, "ca_sha256": self.ca_sha256,
                "channels": {c: fpr for c, _, fpr in self.channel_keys}, "signed_registry": self.signed_registry}


def _host(v: str, what: str) -> str:
    v = (v or "").strip().lower()
    if not HOST_RE.fullmatch(v) or v.startswith("."):
        raise ArtifactError(f"{what} must be host[:port] (lower-case DNS name or IPv4), got {v!r}")
    if v.endswith(".invalid") or v.endswith(".invalid:443"):
        raise ArtifactError(f"{what} is still the .invalid placeholder")
    return v


def load_map(env=None) -> "ArtifactMap | None":
    """None when nothing is configured (the catalog placeholder stays and the plan says so). A set-but-broken configuration RAISES: it must
    never silently fall back to an unreachable or unverified source (same rule as OU_NETWORK_MODEL)."""
    env = os.environ if env is None else env
    base, apt, reg = (env.get(k, "").strip() for k in ("OU_ARTIFACT_BASE", "OU_ARTIFACT_APT_HOST", "OU_ARTIFACT_REGISTRY_HOST"))
    if not (base or apt or reg):
        return None
    apt_host, reg_host = _host(apt or base, "OU_ARTIFACT_APT_HOST/OU_ARTIFACT_BASE"), _host(reg or base, "OU_ARTIFACT_REGISTRY_HOST/OU_ARTIFACT_BASE")
    ca_file, ca_pin = env.get("OU_ARTIFACT_CA_FILE", "").strip(), env.get("OU_ARTIFACT_CA_SHA256", "").strip().lower()
    ca_pem = None
    if ca_file or ca_pin:
        if not (ca_file and ca_pin):
            raise ArtifactError("OU_ARTIFACT_CA_FILE and OU_ARTIFACT_CA_SHA256 go together")
        ca_pem = Path(ca_file).read_text()
        if not HEX64.fullmatch(ca_pin) or ca_sha256(ca_pem) != ca_pin:
            raise ArtifactError("the artifact CA does not match its pinned sha256 (OU_ARTIFACT_CA_SHA256)")
    keys_dir = Path(env.get("OU_ARTIFACT_KEYS_DIR") or DEFAULT_KEYS_DIR)
    pins = {}
    for item in filter(None, (x.strip() for x in env.get("OU_ARTIFACT_CHANNEL_FPRS", "").split(","))):
        c, _, f = item.partition("=")
        if c not in CHANNELS or not HEX40.fullmatch(f.strip().upper()):
            raise ArtifactError("OU_ARTIFACT_CHANNEL_FPRS must be dev=<40 hex>,stable=<40 hex> ...")
        pins[c] = f.strip().upper()
    keys = []
    for c in CHANNELS:
        if c not in pins:
            continue
        armored = (keys_dir / f"ou-release-{c}.pub.asc").read_text()
        if pgp_fingerprint(armored) != pins[c]:
            raise ArtifactError(f"release key for channel {c} does not match its pinned fingerprint")
        keys.append((c, armored, pins[c]))
    signed = env.get("OU_ARTIFACT_SIGNED_REGISTRY", "").strip().lower() or None
    if signed is not None and not HOST_RE.fullmatch(signed):
        raise ArtifactError("OU_ARTIFACT_SIGNED_REGISTRY must be host[:port]")
    if signed is not None and signed != reg_host and ca_pem is None:
        raise ArtifactError("OU_ARTIFACT_SIGNED_REGISTRY needs the artifact CA (the identity policy is delivered with it)")
    return ArtifactMap(apt_host, reg_host, ca_pem, ca_pin or None, tuple(keys), signed if signed != reg_host else None)


def rewrite_catalog(cat, amap: "ArtifactMap | None"):
    """Copy of the catalog whose OCI images point at the configured registry. The catalog file and its digest stay untouched (the catalog is
    reviewed source; where the artifacts are served from is deployment configuration)."""
    if amap is None:
        return cat
    comps = {}
    for n, c in cat.components.items():
        arts = []
        for a in c.artifacts:
            if getattr(a, "kind", None) == "oci" and a.image.split("/", 1)[0] == SENTINEL_REGISTRY:
                a = a.model_copy(update={"image": amap.registry_host + a.image[len(SENTINEL_REGISTRY):]})
            arts.append(a)
        comps[n] = c.model_copy(update={"artifacts": arts})
    return cat.model_copy(update={"components": comps})


def placeholder_images(cat, names) -> list[str]:
    """`<component>/<artifact>` of OCI artifacts that still carry the placeholder registry (no ArtifactMap configured)."""
    return sorted(f"{n}/{a.name}" for n in names for a in cat.components[n].artifacts
                  if getattr(a, "kind", None) == "oci" and a.image.split("/", 1)[0] == SENTINEL_REGISTRY)


def channels_needed(plan: dict, vm: str | None = None) -> list[str]:
    """Release channels (apt suites of our repo) the plan's package services come from, for one VM or all."""
    return sorted({REPO_SUITE[s["repo"]] for s in plan.get("services", []) if s.get("repo") in REPO_SUITE and (vm is None or s.get("vm") == vm)})


# ------------------------------------------------------------------------------------------------ server rendering
@dataclass(frozen=True)
class ServerConfig:
    listen_ip: str
    port: int = DEFAULT_PORT
    server_names: tuple = ()
    allow_cidrs: tuple = ("10.64.0.0/16",)          # customer VNets (docs/admin/proxmox-sdn-isolation.md); loopback and listen_ip are always added
    cert: str = "/etc/office-unbound/artifacts/tls/server.crt"
    key: str = "/etc/office-unbound/artifacts/tls/server.key"
    data_dir: str = DEFAULT_DATA
    ro_port: int = 5001                              # read-only registry (loopback)
    req_rate: int = 30                               # requests/second per source address (burst below)
    req_burst: int = 120
    conn_limit: int = 24
    log_dir: str = "/var/log/nginx"

    def __post_init__(self):
        a = ipaddress.ip_address(self.listen_ip)
        if a.version != 4 or a.is_unspecified:
            raise ArtifactError("listen_ip must be a specific IPv4 address")
        if not 1024 <= self.port <= 65535 or not 1024 <= self.ro_port <= 65535:
            raise ArtifactError("ports must be 1024..65535")
        if not self.allow_cidrs:
            raise ArtifactError("at least one allowed source network is required (fail closed)")
        for c in self.allow_cidrs:
            n = ipaddress.ip_network(c, strict=False)
            if n.version != 4 or n.prefixlen < 8:
                raise ArtifactError(f"allowed source {c} is too wide (IPv4, at least /8; the public internet is never allowed)")
        for h in self.server_names:
            if not re.fullmatch(r"[a-z0-9]([a-z0-9.-]{0,120}[a-z0-9])?", h):
                raise ArtifactError(f"invalid server name {h!r}")
        for p in (self.cert, self.key, self.data_dir, self.log_dir):
            if not re.fullmatch(r"/[A-Za-z0-9._/-]+", p):
                raise ArtifactError(f"unsafe path {p!r}")

    @property
    def allow(self) -> list[str]:
        out = ["127.0.0.1", self.listen_ip, *(str(ipaddress.ip_network(c, strict=False)) for c in self.allow_cidrs)]
        return list(dict.fromkeys(out))


def render_nginx(c: ServerConfig) -> str:
    names = " ".join([c.listen_ip, *c.server_names, "localhost"])
    allow = "\n".join(f"    allow {x};" for x in c.allow)
    return f"""# Office Unbound artifact distribution (ADR-0015). Generated by ics.artifacts render-server; do not edit.
# Read-only by construction: only GET/HEAD are routed, there is no write path to the apt tree or the registry from this server block
# (the registry behind it is a SEPARATE read-only process; pushes go through a local unix socket that nginx never touches).
limit_req_zone $binary_remote_addr zone=ou_art_req:10m rate={c.req_rate}r/s;
limit_conn_zone $binary_remote_addr zone=ou_art_conn:10m;
log_format ou_art '$remote_addr [$time_iso8601] "$request" $status $body_bytes_sent rt=$request_time ua="$http_user_agent"';

server {{
    listen {c.listen_ip}:{c.port} ssl;
    server_name {names};

    ssl_certificate     {c.cert};
    ssl_certificate_key {c.key};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_tickets off;

    # source restriction in nginx AND in nftables (table inet ou_artifacts)
{allow}
    deny all;

    server_tokens off;
    autoindex off;
    client_max_body_size 1k;                        # nothing is ever uploaded here
    limit_req zone=ou_art_req burst={c.req_burst} nodelay;
    limit_req_status 429;
    limit_conn ou_art_conn {c.conn_limit};
    access_log {c.log_dir}/ou-artifacts.access.log ou_art;
    error_log  {c.log_dir}/ou-artifacts.error.log warn;
    add_header X-Content-Type-Options nosniff always;
    add_header Cache-Control "public, max-age=60" always;

    if ($request_method !~ ^(GET|HEAD)$) {{ return 405; }}

    # a static file, NOT `return 200`: `return` runs in the rewrite phase, before the allow/deny access phase, and would answer anyone
    location = /healthz {{ alias {c.data_dir}/healthz; default_type text/plain; }}

    # signed apt repository: dists/<channel>/InRelease + pool/. A directory request is 403/404 (no listing), dotfiles never served.
    location {APT_PATH}/ {{
        alias {c.data_dir}/apt/current/;
        try_files $uri =404;
        location ~ /\\. {{ return 404; }}
        location ~ ^{APT_PATH}/dists/ {{ add_header Cache-Control "no-cache" always; }}
    }}

    # OCI registry (read-only distribution process). Catalog and tag listings are not served: guests pull by digest and need neither.
    location = /v2/_catalog {{ return 403; }}
    location ~ ^/v2/.+/tags/list$ {{ return 403; }}
    location ~ ^/v2/.+/referrers/ {{ return 403; }}
    location /v2/ {{
        proxy_pass http://127.0.0.1:{c.ro_port};
        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_read_timeout 300s;
        add_header Cache-Control "no-store" always;
    }}

    location / {{ return 404; }}
}}
"""


def render_registry(c: ServerConfig, role: str) -> str:
    """`ro`: the process nginx talks to; maintenance.readonly makes every write fail inside the registry itself.
    `push`: bound to a unix socket (mode 0660, group ou-publish), run only while publishing; no network listener, no delete."""
    if role not in ("ro", "push"):
        raise ArtifactError("role")
    root = f"{c.data_dir}/registry"
    http = f"  net: tcp\n  addr: 127.0.0.1:{c.ro_port}" if role == "ro" else "  net: unix\n  addr: /run/ou-artifacts/push.sock"
    ro = "\n  maintenance:\n    readonly:\n      enabled: true" if role == "ro" else ""
    return f"""# Office Unbound artifact registry ({role}); generated by ics.artifacts render-server; do not edit.
version: 0.1
log:
  level: info
  formatter: json
  fields:
    service: ou-registry-{role}
storage:
  filesystem:
    rootdirectory: {root}
  delete:
    enabled: false
  cache:
    blobdescriptor: inmemory{ro}
http:
{http}
  headers:
    X-Content-Type-Options: [nosniff]
health:
  storagedriver:
    enabled: false
"""


def render_nft(c: ServerConfig) -> str:
    s = ", ".join(c.allow)
    return f"""# Office Unbound artifact service exposure (ADR-0015): only these networks may reach the artifact port. Generated; do not edit.
table inet ou_artifacts {{
  chain input {{
    type filter hook input priority -10; policy accept;
    tcp dport {c.port} ip saddr {{ {s} }} accept
    tcp dport {c.port} drop
  }}
}}
"""


def render_server(c: ServerConfig) -> dict:
    return {"nginx/ou-artifacts.conf": render_nginx(c), "registry-ro.yml": render_registry(c, "ro"),
            "registry-push.yml": render_registry(c, "push"), "ou-artifacts-fw.nft": render_nft(c)}


# ------------------------------------------------------------------------------------------------ health (what a guest sees)
def _ctx(ca_pem: str | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cadata=ca_pem) if ca_pem else ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _get(url: str, ctx, timeout=8):
    try:
        with urllib.request.urlopen(urllib.request.Request(url), timeout=timeout, context=ctx) as r:
            return r.status, r.read(200_000)
    except urllib.error.HTTPError as e:
        return e.code, b""


def release_valid_until(inrelease: str) -> float | None:
    m = re.search(r"^Valid-Until:\s*(.+)$", inrelease, re.M)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1).strip(), "%a, %d %b %Y %H:%M:%S %Z").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def probe(amap: ArtifactMap, channels=CHANNELS, now: float | None = None) -> dict:
    """Read-only checks over TLS with the pinned CA. Never raises; every failure becomes ok=False with a short reason (no secrets)."""
    now = time.time() if now is None else now
    ctx = _ctx(amap.ca_pem)
    out: dict = {"apt_url": amap.apt_url, "registry": amap.registry_host, "checks": {}}
    try:
        st, _ = _get(f"https://{amap.apt_host}/healthz", ctx)
        out["checks"]["service"] = {"ok": st == 200, "status": st}
    except Exception as e:  # noqa: BLE001
        out["checks"]["service"] = {"ok": False, "error": type(e).__name__}
    try:
        st, _ = _get(f"https://{amap.registry_host}/v2/", ctx)
        out["checks"]["registry"] = {"ok": st == 200, "status": st}
    except Exception as e:  # noqa: BLE001
        out["checks"]["registry"] = {"ok": False, "error": type(e).__name__}
    for ch in channels:
        try:
            st, body = _get(f"{amap.apt_url}/dists/{ch}/InRelease", ctx)
            vu = release_valid_until(body.decode("utf-8", "replace")) if st == 200 else None
            out["checks"][f"apt:{ch}"] = {"ok": st == 200 and (vu is None or vu > now), "status": st,
                                          "valid_for_seconds": None if vu is None else int(vu - now)}
        except Exception as e:  # noqa: BLE001
            out["checks"][f"apt:{ch}"] = {"ok": False, "error": type(e).__name__}
    out["ok"] = all(v["ok"] for v in out["checks"].values())
    return out


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[0] == "render-server":
        import dataclasses
        cfg = json.loads(Path(argv[1]).read_text())
        cfg = {k: v for k, v in cfg.items() if k in {f.name for f in dataclasses.fields(ServerConfig)}}   # server.json also carries publisher settings
        cfg["server_names"] = tuple(cfg.get("server_names", ()))
        cfg["allow_cidrs"] = tuple(cfg.get("allow_cidrs", ("10.64.0.0/16",)))
        files = render_server(ServerConfig(**cfg))
        outdir = Path(argv[2])
        for n, t in files.items():
            p = outdir / n
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(t)
        return 0
    if argv and argv[0] == "health":
        amap = load_map()
        if amap is None:
            print("artifact distribution is not configured (OU_ARTIFACT_BASE)", file=sys.stderr)
            return 2
        r = probe(amap)
        print(json.dumps(r, indent=2))
        return 0 if r["ok"] else 1
    if len(argv) == 2 and argv[0] == "fingerprint":
        print(pgp_fingerprint(Path(argv[1]).read_text()))
        return 0
    if len(argv) == 2 and argv[0] == "ca-sha256":
        print(ca_sha256(Path(argv[1]).read_text()))
        return 0
    print("usage: python -m ics.artifacts render-server CONFIG.json OUTDIR | health | fingerprint KEY.asc | ca-sha256 CA.pem", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
