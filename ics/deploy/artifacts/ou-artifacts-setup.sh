#!/usr/bin/env bash
# Office Unbound artifact distribution service (ADR-0015): idempotent installer for the ICS host (placement (a)) or any Ubuntu 24.04 / Debian 12 machine.
#   sudo ics/deploy/artifacts/ou-artifacts-setup.sh --listen-ip 192.168.22.167 [--port 8444] [--hostname artifacts.ou.example] \
#        [--allow-cidr 10.64.0.0/16 ...] --channel-key dev=FILE --channel-key stable=FILE [--image-key dev=PEM ...]
# Installs: nginx site (TLS, GET/HEAD only, rate limits, no listings), the distribution registry as a READ-ONLY reader plus a push instance that only
# ever listens on a unix socket, a private TLS CA + server certificate, an nftables allow-list, and the publisher (ou-artifact-publish).
# Re-running changes only what differs. It prints the OU_ARTIFACT_* block the ICS needs (pins), it never prints key material.
set -euo pipefail
ETC=/etc/office-unbound/artifacts
DATA=/var/lib/office-unbound/artifacts
SYSD=/etc/systemd/system
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ART_PY="$HERE/../../ics/artifacts.py"
export LC_ALL=C
LISTEN_IP=""; PORT=8444; NAMES=(); ALLOW=(); CKEYS=(); IKEYS=(); SKIP_FW=0; CHANGES=()
die() { echo "ou-artifacts-setup: ERROR: $*" >&2; exit 1; }
log() { echo "ou-artifacts-setup: $*"; }
changed() { CHANGES+=("$*"); log "changed: $*"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --listen-ip) LISTEN_IP="${2:?}"; shift 2;;
    --port) PORT="${2:?}"; shift 2;;
    --hostname) NAMES+=("${2:?}"); shift 2;;
    --allow-cidr) ALLOW+=("${2:?}"); shift 2;;
    --channel-key) CKEYS+=("${2:?}"); shift 2;;
    --image-key) IKEYS+=("${2:?}"); shift 2;;
    --skip-firewall) SKIP_FW=1; shift;;
    -h|--help) sed -n 2,9p "$0"; exit 0;;
    *) die "unknown argument: $1";;
  esac
done
[ "$(id -u)" = 0 ] || die "run as root"
[ -f "$ART_PY" ] || die "cannot find ics/artifacts.py next to the deploy tree ($ART_PY)"
[ -n "$LISTEN_IP" ] || die "--listen-ip is required"
[[ "$PORT" =~ ^[0-9]{4,5}$ ]] || die "invalid --port"
[ ${#ALLOW[@]} -gt 0 ] || ALLOW=(10.64.0.0/16)       # customer VNets (docs/admin/proxmox-sdn-isolation.md); the management LAN is NOT included by default
for n in "${NAMES[@]}"; do [[ "$n" =~ ^[a-z0-9]([a-z0-9.-]{0,120}[a-z0-9])?$ ]] || die "invalid --hostname $n"; done
ip -4 -o addr show | awk '{print $4}' | cut -d/ -f1 | grep -qx "$LISTEN_IP" || die "--listen-ip $LISTEN_IP is not configured on this host"

put() { # put SRC MODE OWNER:GROUP DST -> 0 when written, 1 when identical
  local s=$1 mode=$2 own=$3 dst=$4
  if [ -f "$dst" ] && cmp -s "$s" "$dst"; then chmod "$mode" "$dst"; chown "$own" "$dst"; return 1; fi
  install -D -m "$mode" -o "${own%:*}" -g "${own#*:}" "$s" "$dst"; changed "wrote $dst"; return 0
}

# ------------------------------------------------------------------------------------------------------------ packages and users
PKGS=(nginx docker-registry openssl nftables python3 python3-cryptography gnupg ca-certificates)
MISSING=(); for p in "${PKGS[@]}"; do dpkg -s "$p" >/dev/null 2>&1 || MISSING+=("$p"); done
if [ ${#MISSING[@]} -gt 0 ]; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${MISSING[@]}" >/dev/null || die "apt-get install ${MISSING[*]} failed"
  changed "packages: ${MISSING[*]}"
fi
# the package's own unit (port 5000, /etc/docker/registry) is not ours: never run it
systemctl disable --now docker-registry.service >/dev/null 2>&1 || true
getent passwd ou-artifacts >/dev/null || { useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin ou-artifacts; changed "user ou-artifacts"; }
install -d -m 0755 -o root -g root /etc/office-unbound "$ETC" "$ETC/keys" "$DATA" "$DATA/apt"
install -d -m 0750 -o ou-artifacts -g ou-artifacts "$DATA/registry"
install -d -m 0711 -o root -g root "$ETC/tls"
printf 'ok\n' > "$DATA/healthz"; chmod 0644 "$DATA/healthz"
[ -L "$DATA/apt/current" ] || { install -d -m 0755 "$DATA/apt/releases/empty/dists"; ln -sfn "$DATA/apt/releases/empty" "$DATA/apt/current"; }

# ------------------------------------------------------------------------------------------------------------ release / image keys (public) + pins
CH_FPRS=""
for kv in "${CKEYS[@]}"; do
  c="${kv%%=*}"; f="${kv#*=}"; [[ "$c" =~ ^(dev|staging|stable)$ ]] && [ -f "$f" ] || die "--channel-key expects dev|staging|stable=FILE"
  fpr="$(python3 -I "$ART_PY" fingerprint "$f")" || die "$f is not an armored OpenPGP v4 public key"
  put "$f" 0644 root:root "$ETC/keys/ou-release-$c.pub.asc" || true
  CH_FPRS+="${CH_FPRS:+,}$c=$fpr"
done
for kv in "${IKEYS[@]}"; do
  c="${kv%%=*}"; f="${kv#*=}"; [[ "$c" =~ ^(dev|staging|stable)$ ]] && [ -f "$f" ] || die "--image-key expects dev|staging|stable=PEMFILE"
  openssl pkey -pubin -in "$f" -noout 2>/dev/null || die "$f is not a PEM public key"
  put "$f" 0644 root:root "$ETC/keys/ou-image-$c.pub.pem" || true
done

# ------------------------------------------------------------------------------------------------------------ TLS: private CA (name-constrained), server cert
SAN="IP:$LISTEN_IP"; NC="permitted;IP:$LISTEN_IP/255.255.255.255"
for n in "${NAMES[@]}"; do SAN+=",DNS:$n"; NC+=",permitted;DNS:$n"; done
CN="${NAMES[0]:-$LISTEN_IP}"
if [ ! -f "$ETC/tls/ca.crt" ]; then
  W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT; umask 077
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1825 -subj "/O=Office Unbound/CN=Office Unbound artifact CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" -addext "nameConstraints=critical,$NC" \
    -keyout "$ETC/tls/ca.key" -out "$ETC/tls/ca.crt" 2>/dev/null
  chmod 0600 "$ETC/tls/ca.key"; chmod 0644 "$ETC/tls/ca.crt"; changed "artifact CA created ($ETC/tls/ca.crt)"
fi
need_cert=0
[ -f "$ETC/tls/server.crt" ] || need_cert=1
if [ "$need_cert" = 0 ]; then
  openssl x509 -in "$ETC/tls/server.crt" -noout -checkend $((30*86400)) >/dev/null || need_cert=1
  openssl x509 -in "$ETC/tls/server.crt" -noout -checkip "$LISTEN_IP" | grep -q 'does match' || need_cert=1
  for n in "${NAMES[@]}"; do openssl x509 -in "$ETC/tls/server.crt" -noout -checkhost "$n" | grep -q 'does match' || need_cert=1; done
fi
if [ "$need_cert" = 1 ]; then
  W="$(mktemp -d)"; umask 077
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/O=Office Unbound/CN=$CN" -keyout "$W/server.key" -out "$W/server.csr" 2>/dev/null
  printf 'subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' "$SAN" > "$W/ext"
  openssl x509 -req -in "$W/server.csr" -CA "$ETC/tls/ca.crt" -CAkey "$ETC/tls/ca.key" -CAcreateserial -CAserial "$W/ca.srl" -days 397 -extfile "$W/ext" -out "$W/server.crt" 2>/dev/null
  install -m 0644 -o root -g root "$W/server.crt" "$ETC/tls/server.crt"
  install -m 0640 -o root -g www-data "$W/server.key" "$ETC/tls/server.key"
  rm -rf "$W"; changed "server certificate issued ($SAN)"
fi
chown root:www-data "$ETC/tls/server.key"; chmod 0640 "$ETC/tls/server.key"
CA_SHA="$(python3 -I "$ART_PY" ca-sha256 "$ETC/tls/ca.crt")"

# ------------------------------------------------------------------------------------------------------------ configuration
TMP="$(mktemp -d)"; chmod 700 "$TMP"
python3 -I - "$TMP/server.json" "$LISTEN_IP" "$PORT" "$DATA" "$CH_FPRS" "${NAMES[*]:-}" "${ALLOW[*]}" <<'PY'
import json, sys
out, ip, port, data, fprs, names, allow = sys.argv[1:8]
json.dump({"listen_ip": ip, "port": int(port), "server_names": names.split(), "allow_cidrs": allow.split(), "data_dir": data,
           "channel_fprs": dict(x.split("=") for x in fprs.split(",") if x), "push_socket": "/run/ou-artifacts/push.sock"}, open(out, "w"), indent=2)
PY
# keep fingerprints of channels configured earlier when this run names no keys
if [ -z "$CH_FPRS" ] && [ -f "$ETC/server.json" ]; then python3 -I - "$ETC/server.json" "$TMP/server.json" <<'PY'
import json, sys
old, new = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
new["channel_fprs"] = old.get("channel_fprs", {})
json.dump(new, open(sys.argv[2], "w"), indent=2)
PY
fi
python3 -I "$ART_PY" render-server "$TMP/server.json" "$TMP/out" || die "configuration rejected"
put "$TMP/server.json" 0644 root:root "$ETC/server.json" || true
put "$TMP/out/registry-ro.yml" 0644 root:root "$ETC/registry-ro.yml" && REG_CH=1 || true
put "$TMP/out/registry-push.yml" 0644 root:root "$ETC/registry-push.yml" || true
put "$TMP/out/ou-artifacts-fw.nft" 0644 root:root "$ETC/ou-artifacts-fw.nft" && FW_CH=1 || FW_CH=0
put "$TMP/out/nginx/ou-artifacts.conf" 0644 root:root /etc/nginx/conf.d/ou-artifacts.conf && NG_CH=1 || NG_CH=0
for u in ou-registry-ro.service ou-registry-push.service ou-artifacts-fw.service; do put "$HERE/$u" 0644 root:root "$SYSD/$u" && UN_CH=1 || true; done
put "$HERE/ou-artifact-publish" 0750 root:root /usr/local/sbin/ou-artifact-publish || true
[ "${UN_CH:-0}" = 0 ] || systemctl daemon-reload

# ------------------------------------------------------------------------------------------------------------ start
chown -R ou-artifacts:ou-artifacts "$DATA/registry"
[ -e /var/log/nginx/ou-artifacts.access.log ] || { : > /var/log/nginx/ou-artifacts.access.log; chown www-data:adm /var/log/nginx/ou-artifacts.access.log 2>/dev/null || true; }
systemctl enable ou-registry-ro.service >/dev/null 2>&1
if ! systemctl is-active -q ou-registry-ro.service; then systemctl start ou-registry-ro.service; changed "started ou-registry-ro"
elif [ "${REG_CH:-0}" = 1 ]; then systemctl restart ou-registry-ro.service; fi
if [ "$SKIP_FW" = 1 ]; then log "firewall unit skipped (--skip-firewall): the nginx allow-list still applies"
else
  systemctl enable ou-artifacts-fw.service >/dev/null 2>&1
  if [ "$FW_CH" = 1 ] || ! systemctl is-active -q ou-artifacts-fw.service || ! nft list table inet ou_artifacts >/dev/null 2>&1; then
    nft -c -f "$ETC/ou-artifacts-fw.nft" || die "generated nftables ruleset is invalid"
    systemctl restart ou-artifacts-fw.service || die "ou-artifacts-fw.service failed (use --skip-firewall to rely on the nginx allow-list only)"
    changed "nftables table inet ou_artifacts loaded"
  fi
fi
[ ! -e /etc/nginx/sites-enabled/default ] || { rm -f /etc/nginx/sites-enabled/default; NG_CH=1; changed "removed nginx default site (no port 80)"; }
nginx -t >/dev/null 2>&1 || { nginx -t; die "nginx configuration test failed"; }
systemctl enable nginx.service >/dev/null 2>&1
if ! systemctl is-active -q nginx.service; then systemctl start nginx.service; changed "started nginx"
elif [ "$NG_CH" = 1 ]; then systemctl reload nginx.service; changed "reloaded nginx"; fi
rm -rf "$TMP"

for _ in $(seq 1 30); do curl -fsS --cacert "$ETC/tls/ca.crt" "https://$LISTEN_IP:$PORT/healthz" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS --cacert "$ETC/tls/ca.crt" "https://$LISTEN_IP:$PORT/healthz" >/dev/null || die "https://$LISTEN_IP:$PORT/healthz failed"
for _ in $(seq 1 30); do curl -fsS --cacert "$ETC/tls/ca.crt" "https://$LISTEN_IP:$PORT/v2/" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS --cacert "$ETC/tls/ca.crt" "https://$LISTEN_IP:$PORT/v2/" >/dev/null || die "the registry does not answer behind nginx"

echo
echo "================ Office Unbound artifact service ================"
echo "base               : $LISTEN_IP:$PORT  (apt: https://$LISTEN_IP:$PORT/apt  registry: $LISTEN_IP:$PORT)"
echo "allowed sources    : 127.0.0.1 $LISTEN_IP ${ALLOW[*]}"
echo "CA certificate     : $ETC/tls/ca.crt"
echo "CA SHA-256         : $CA_SHA   <- verify out of band"
[ ${#CHANGES[@]} = 0 ] && echo "changes this run   : none" || printf 'changes this run   : %s\n' "${CHANGES[@]}"
echo "--- add to /etc/office-unbound/ics.env (the ICS injects these into every guest's bootstrap metadata) ---"
echo "OU_ARTIFACT_BASE=$LISTEN_IP:$PORT"
echo "OU_ARTIFACT_CA_FILE=$ETC/tls/ca.crt"
echo "OU_ARTIFACT_CA_SHA256=$CA_SHA"
echo "OU_ARTIFACT_KEYS_DIR=$ETC/keys"
echo "OU_ARTIFACT_CHANNEL_FPRS=$(python3 -I -c 'import json;d=json.load(open("'"$ETC"'/server.json"))["channel_fprs"];print(",".join(f"{k}={v}" for k,v in sorted(d.items())))')"
