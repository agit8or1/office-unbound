#!/usr/bin/env bash
# Office Unbound ICS - one-shot, idempotent installer for a FRESH Ubuntu 24.04 (or Debian 12) host. Run as root from a checkout:
#   sudo ics/deploy/bootstrap.sh --listen-ip 192.0.2.10 --allow-cidr 192.0.2.0/24 --hostname ics.example.internal --admin alice
# Re-running is a no-op apart from code updates (it compares file contents/modes and only touches what differs).
# Manual steps this replaces are recorded in docs/admin/installing-the-ics.md and docs/status/host-changes.md.
set -euo pipefail

ETC=/etc/office-unbound
OPT=/opt/office-unbound/ics
STATE=/var/lib/office-unbound
TLS=$ETC/tls
SYSD=/etc/systemd/system
NGX_AVAIL=/etc/nginx/sites-available/ics.conf
NGX_ENAB=/etc/nginx/sites-enabled/ics.conf
STAMP=$STATE/ics-release.sha256
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export LC_ALL=C

FROM_REPO=""; REPO_URL=""; REPO_KEY=""; REPO_FPR=""; PKG_VERSION=""
LISTEN_IP=""; HOSTNAME_FQDN=""; ADMIN=""; SKIP_TLS=0; SKIP_FW=0; UNINSTALL=0; PURGE=0
TLS_CERT=""; TLS_KEY=""; ALLOW=()
CHANGES=()
OS_RELEASE_FILE="${OU_OS_RELEASE:-/etc/os-release}"   # overridable only so the OS check can be unit-tested
CHECK_OS=0

usage() {
cat <<'EOF'
usage: bootstrap.sh --listen-ip IP --allow-cidr CIDR [--allow-cidr CIDR ...] [--hostname FQDN] [--admin USER]
                    [--tls-cert FILE --tls-key FILE] [--skip-firewall]
                    [--from-repo CHANNEL --repo-url URL [--repo-key FILE] [--repo-key-fingerprint FPR] [--version V]]
       bootstrap.sh --skip-tls [--admin USER]            loopback-only (no nginx, no firewall, no certificates)
       bootstrap.sh --uninstall [--purge]                remove services/config; keys, DB and certs are KEPT unless --purge
  --listen-ip IP     address nginx listens on (:443); must be configured on this host
  --allow-cidr C     source network allowed to reach the console (nginx + nftables); repeatable, at least one
  --hostname FQDN    DNS name for the certificate / nginx server_name (optional; the name-constrained CA permits it)
  --admin USER       create this admin and print its one-time enrollment token at the very end (skipped if it exists)
  --tls-cert/--tls-key  use an operator-provided certificate instead of the private ICS CA
  --skip-firewall    do not install the nftables source restriction (nginx allow-list still applies)
  --from-repo CH     install the ICS as the signed package ou-ics from channel CH (dev|staging|stable) of the Office Unbound apt repository
                     instead of copying this git tree (install.sh stays for development). Needs --repo-url. The repository key is PINNED:
                     --repo-key (default: blueprints/build/keys/ou-release-lab.pub.asc next to this script) must have the fingerprint given
                     by --repo-key-fingerprint (default: the .FINGERPRINT file beside the key); anything else is refused.
  --version V        with --from-repo: install exactly this package version (e.g. 0.1.0-ou1); allows a deliberate downgrade
EOF
}
die() { echo "bootstrap: ERROR: $*" >&2; exit 1; }
log() { echo "bootstrap: $*"; }
changed() { CHANGES+=("$*"); log "changed: $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --listen-ip) LISTEN_IP="${2:?}"; shift 2;;
    --allow-cidr) ALLOW+=("${2:?}"); shift 2;;
    --hostname) HOSTNAME_FQDN="${2:?}"; shift 2;;
    --admin) ADMIN="${2:?}"; shift 2;;
    --tls-cert) TLS_CERT="${2:?}"; shift 2;;
    --tls-key) TLS_KEY="${2:?}"; shift 2;;
    --skip-tls) SKIP_TLS=1; shift;;
    --skip-firewall) SKIP_FW=1; shift;;
    --uninstall) UNINSTALL=1; shift;;
    --purge) PURGE=1; shift;;
    --from-repo) FROM_REPO="${2:?}"; shift 2;;
    --repo-url) REPO_URL="${2:?}"; shift 2;;
    --repo-key) REPO_KEY="${2:?}"; shift 2;;
    --repo-key-fingerprint) REPO_FPR="${2:?}"; shift 2;;
    --version) PKG_VERSION="${2:?}"; shift 2;;
    --check-os) CHECK_OS=1; shift;;
    -h|--help) usage; exit 0;;
    *) usage >&2; die "unknown argument: $1";;
  esac
done
# Supported platforms and the PostgreSQL major version their archive ships (the code is tested on 16 and 15).
os_profile() { # prints "<codename> <postgres major>" or fails
  local ID="" VERSION_ID="" VERSION_CODENAME=""
  # shellcheck disable=SC1090
  . "$OS_RELEASE_FILE" 2>/dev/null || return 1
  case "${ID:-}:${VERSION_ID:-}" in
    ubuntu:24.04) echo "noble 16";;
    debian:12) echo "bookworm 15";;
    *) return 1;;
  esac
}
if [ "$CHECK_OS" = 1 ]; then os_profile || { echo "unsupported"; exit 1; }; exit 0; fi
[ "$(id -u)" = 0 ] || die "run as root"
TMP="$(mktemp -d)"; chmod 700 "$TMP"
cleanup() { if [ -f "$TMP.rc" ]; then rm -f /usr/sbin/policy-rc.d "$TMP.rc"; fi; rm -rf "$TMP"; }
trap cleanup EXIT

# ---------------------------------------------------------------------------------------------------------- uninstall
if [ "$UNINSTALL" = 1 ]; then
  [ "$PURGE" = 0 ] || {
    echo "PURGE deletes the ICS database (users, audit log, vault), ALL keys (vault/audit/signing: stored secrets become unrecoverable)"
    echo "and the TLS CA. Take a backup first (ics/deploy/backup/ics-backup.sh). To continue type exactly:  purge $(hostname)"
    IFS= read -r ans || ans=""
    [ "$ans" = "purge $(hostname)" ] || die "confirmation did not match; nothing was changed"
  }
  log "stopping and removing services and configuration (keys, database, certificates are kept unless --purge)"
  for u in ics ics-migrate ics-admin-fw; do systemctl disable --now "$u.service" 2>/dev/null || true; done
  rm -f "$SYSD/ics.service" "$SYSD/ics-migrate.service" "$SYSD/ics-admin-fw.service"
  systemctl daemon-reload
  nft delete table inet ics_admin 2>/dev/null || true
  rm -f "$NGX_ENAB" "$NGX_AVAIL" "$ETC/ics-admin-fw.nft"
  if systemctl is-active -q nginx 2>/dev/null; then nginx -t 2>/dev/null && systemctl reload nginx || true; fi
  if dpkg-query -W -f='${Status}' ou-ics 2>/dev/null | grep -q '^install ok installed$'; then
    log "removing the ou-ics package (its postrm keeps the database, keys, env files and backups)"
    dpkg --remove ou-ics
  fi
  rm -rf "$OPT" "$STAMP"; rmdir /opt/office-unbound 2>/dev/null || true
  if [ "$PURGE" = 1 ]; then
    runuser -u postgres -- psql -q -c "DROP DATABASE IF EXISTS ics" -c "DROP ROLE IF EXISTS ics_app" -c "DROP ROLE IF EXISTS ics_owner" 2>/dev/null || true
    rm -rf "$ETC" "$STATE"; userdel ics 2>/dev/null || true
    log "purged: database, roles, keys, env files, certificates, service user. Packages (postgresql, nginx, ...) were left installed."
  else
    log "kept: $ETC (env files, keys, tls), PostgreSQL database 'ics' and roles, service user 'ics', packages. Re-run bootstrap.sh to reinstall on the same data."
  fi
  exit 0
fi

# ------------------------------------------------------------------------------------------------------------ preflight
OSP="$(os_profile)" || die "Ubuntu 24.04 or Debian 12 required (found $(. "$OS_RELEASE_FILE" 2>/dev/null; echo "${PRETTY_NAME:-unknown}"))"
OS_CODENAME="${OSP% *}"; PGVER="${OSP#* }"
[ -f "$SRC/requirements.lock" ] && [ -d "$SRC/migrations" ] && [ -f "$SRC/deploy/install.sh" ] || die "not an ICS source tree: $SRC"
if [ -n "$FROM_REPO" ]; then
  case "$FROM_REPO" in dev|staging|stable) ;; *) die "--from-repo must be dev, staging or stable";; esac
  [[ "$REPO_URL" =~ ^https?://[A-Za-z0-9._:/-]+$ ]] || die "--from-repo needs --repo-url http(s)://host[:port][/path]"
  [ -n "$REPO_KEY" ] || REPO_KEY="$SRC/../blueprints/build/keys/ou-release-lab.pub.asc"
  [ -f "$REPO_KEY" ] || die "repository key $REPO_KEY not found (--repo-key)"
  if [ -z "$REPO_FPR" ]; then
    FPRF="${REPO_KEY%.pub.asc}.FINGERPRINT"; [ -f "$FPRF" ] || die "no pinned fingerprint: give --repo-key-fingerprint (no $FPRF)"
    REPO_FPR="$(tr -d ' \n' < "$FPRF")"
  fi
  REPO_FPR="$(printf '%s' "$REPO_FPR" | tr -d ' ' | tr a-f A-F)"
  [[ "$REPO_FPR" =~ ^[0-9A-F]{40}$ ]] || die "--repo-key-fingerprint must be 40 hex characters"
  [[ -z "$PKG_VERSION" || "$PKG_VERSION" =~ ^[0-9A-Za-z.+~:-]+$ ]] || die "invalid --version"
elif [ -n "$REPO_URL$REPO_KEY$REPO_FPR$PKG_VERSION" ]; then die "--repo-url/--repo-key/--repo-key-fingerprint/--version only make sense with --from-repo"; fi
[[ -z "$ADMIN" || "$ADMIN" =~ ^[a-z0-9._-]{1,64}$ ]] || die "--admin must match [a-z0-9._-]{1,64}"
if [ "$SKIP_TLS" = 1 ]; then
  [ -z "$LISTEN_IP$HOSTNAME_FQDN$TLS_CERT$TLS_KEY" ] && [ ${#ALLOW[@]} = 0 ] || die "--skip-tls (loopback only) cannot be combined with --listen-ip/--allow-cidr/--hostname/--tls-*"
else
  [ -n "$LISTEN_IP" ] || die "--listen-ip is required (or --skip-tls)"
  [ ${#ALLOW[@]} -gt 0 ] || die "at least one --allow-cidr is required (fail closed; there is no default allow-list)"
  { [ -z "$TLS_CERT" ] && [ -z "$TLS_KEY" ]; } || { [ -f "$TLS_CERT" ] && [ -f "$TLS_KEY" ]; } || die "--tls-cert and --tls-key must both be given and exist"
  [[ -z "$HOSTNAME_FQDN" || "$HOSTNAME_FQDN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] || die "invalid --hostname"
  LISTEN_IP="$(python3 -I -c 'import ipaddress,sys; a=ipaddress.ip_address(sys.argv[1]); assert a.version==4 and not a.is_unspecified; print(a)' "$LISTEN_IP" 2>/dev/null)" || die "--listen-ip must be a specific IPv4 address"
  ip -4 -o addr show | awk '{print $4}' | cut -d/ -f1 | grep -qx "$LISTEN_IP" || die "--listen-ip $LISTEN_IP is not configured on this host"
  NORM=()
  for c in "${ALLOW[@]}"; do
    n="$(python3 -I -c 'import ipaddress,sys; n=ipaddress.ip_network(sys.argv[1],strict=False); assert n.version==4; print(n)' "$c" 2>/dev/null)" || die "invalid --allow-cidr: $c"
    case "$n" in 0.0.0.0/0) die "--allow-cidr 0.0.0.0/0 would expose the console to everyone; refusing";; esac
    NORM+=("$n")
  done
  ALLOW=("${NORM[@]}")
fi

# ------------------------------------------------------------------------------------------------------------ packages
PKGS=(python3 python3-venv "postgresql-$PGVER" rsync openssl curl sudo ca-certificates)
[ -z "$FROM_REPO" ] || PKGS+=(gnupg)
[ "$SKIP_TLS" = 1 ] || PKGS+=(nginx nftables)
MISSING=()
for p in "${PKGS[@]}"; do dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q '^install ok installed$' || MISSING+=("$p"); done
if [ ${#MISSING[@]} -gt 0 ]; then
  log "installing packages ($OS_CODENAME archive; major versions pinned by package name): ${MISSING[*]}"
  # a fresh cloud image may still be running its first-boot apt job: wait for the dpkg lock (found in the Debian 12 dry run)
  # keep nginx/postgres from auto-starting with default (port 80) configuration during dpkg; we start them explicitly below
  if [ ! -e /usr/sbin/policy-rc.d ]; then printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod 755 /usr/sbin/policy-rc.d; : > "$TMP.rc"; fi
  for i in $(seq 1 120); do pgrep -x 'apt|apt-get|dpkg' >/dev/null || break; [ "$i" != 1 ] || log "another apt/dpkg job is running (first boot?): waiting for it to finish (up to 10 min)"; sleep 5; done
  # the lists lock has no timeout option: retry a few times (the unattended-upgrades helper takes it briefly between steps)
  for i in 1 2 3 4 5 6 7 8 9 10; do apt-get -o DPkg::Lock::Timeout=600 -qq update && break; [ "$i" != 10 ] || die "apt-get update failed"; sleep 10; done
  DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 -qq install -y --no-install-recommends "${MISSING[@]}" >/dev/null
  rm -f /usr/sbin/policy-rc.d "$TMP.rc"
  changed "apt packages: ${MISSING[*]}"
fi

# ------------------------------------------------------------------------------------------------------------ helpers
gen_secret() { python3 -I -c 'import secrets; print(secrets.token_urlsafe(32))'; }
put() { # put SRC MODE OWNER:GROUP DST -> 0 when content changed (written), 1 when already identical (modes still enforced)
  local s=$1 mode=$2 own=$3 dst=$4
  if [ -f "$dst" ] && cmp -s "$s" "$dst"; then
    if [ "$(stat -c '%a %U:%G' "$dst")" != "${mode#0} $own" ]; then chmod "$mode" "$dst"; chown "$own" "$dst"; changed "mode/owner of $dst"; fi
    return 1
  fi
  install -m "$mode" -o "${own%:*}" -g "${own#*:}" "$s" "$dst"; changed "wrote $dst"; return 0
}
psqlpg() { runuser -u postgres -- psql -X -q -v ON_ERROR_STOP=1 "$@"; }
envget() { ENVF="$1" ENVK="$2" python3 -I - <<'PY'
import os
for l in open(os.environ["ENVF"]) if os.path.isfile(os.environ["ENVF"]) else []:
    k, _, v = l.strip().partition("=")
    if k == os.environ["ENVK"]:
        print(v); break
PY
}
envset() { # envset FILE KEY VALUE [force]: append KEY when absent; replace only with force. value via environment, never argv
  ENVF="$1" ENVK="$2" ENVV="$3" ENVFORCE="${4:-}" python3 -I - <<'PY'
import os, sys
f, k, v, force = os.environ["ENVF"], os.environ["ENVK"], os.environ["ENVV"], os.environ["ENVFORCE"]
lines = open(f).read().splitlines() if os.path.exists(f) else []
idx = [i for i, l in enumerate(lines) if l.strip().partition("=")[0].strip() == k]
if idx:
    if not force or lines[idx[0]].strip() == f"{k}={v}":
        sys.exit(0)
    lines[idx[0]] = f"{k}={v}"
else:
    lines.append(f"{k}={v}")
st = os.stat(f) if os.path.exists(f) else None
fd = os.open(f + ".new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, ("\n".join(lines) + "\n").encode()); os.close(fd)
if st: os.chown(f + ".new", st.st_uid, st.st_gid); os.chmod(f + ".new", st.st_mode & 0o7777)
os.replace(f + ".new", f)
print("changed")
PY
}
env_kv() { local out; out="$(envset "$@")"; [ -z "$out" ] || changed "$1: $2"; }
unit_wait() { local i; for i in $(seq 1 "$2"); do eval "$1" && return 0; sleep 1; done; return 1; }

# ------------------------------------------------------------------------------------------------- user, dirs, postgres
getent passwd ics >/dev/null || { useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin ics; changed "user ics"; }
[ -d "$ETC" ] || changed "created $ETC"
install -d -o root -g root -m 0711 "$ETC"
install -d -o root -g root -m 0755 "$STATE"
systemctl enable --now postgresql.service >/dev/null 2>&1
unit_wait "pg_isready -q -h 127.0.0.1" 60 || die "PostgreSQL did not become ready on 127.0.0.1"

DB_EXISTS="$(runuser -u postgres -- psql -X -Atc "select 1 from pg_database where datname='ics'")"
DB_HAS_DATA=""
if [ -n "$DB_EXISTS" ]; then
  [ "$(runuser -u postgres -- psql -X -Atd ics -c "select to_regclass('public.alembic_version') is not null")" = t ] && DB_HAS_DATA=1
fi

# ------------------------------------------------------------------------------------------------------------- keys
# Never overwritten: created with O_EXCL only when absent. A key that exists but cannot be used stops the install.
ensure_key() { # path min_bytes exact(0/1)
  local f=$1 n=$2 exact=$3 sz
  if [ -L "$f" ]; then die "$f is a symlink; the ICS refuses symlinked keys. Not touching it."; fi
  if [ -e "$f" ]; then
    [ -f "$f" ] || die "$f exists but is not a regular file. Not touching it."
    head -c1 "$f" >/dev/null 2>&1 || die "$f exists but is unreadable. Not touching it (restore it from backup; a new key would orphan existing data)."
    sz="$(stat -c %s "$f")"
    if [ "$exact" = 1 ] && [ "$sz" != "$n" ]; then die "$f has $sz bytes, expected exactly $n. Not touching it."; fi
    [ "$sz" -ge "$n" ] || die "$f has only $sz bytes (need >= $n). Not touching it."
  else
    [ -z "$DB_HAS_DATA" ] || die "$f is missing but database 'ics' already holds data: a new key would make stored secrets/audit unverifiable. Restore the key from backup (docs/runbooks/ics-recovery.md)."
    KEYF="$f" python3 -I - <<'PY'
import os, grp
f = os.environ["KEYF"]
fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)   # EXCL: can never overwrite
os.write(fd, os.urandom(32)); os.fchown(fd, 0, grp.getgrnam("ics").gr_gid); os.fchmod(fd, 0o640); os.close(fd)
PY
    changed "generated $f (32 random bytes)"
  fi
  if [ "$(stat -c '%a %U:%G' "$f")" != "640 root:ics" ]; then chown root:ics "$f"; chmod 0640 "$f"; changed "mode/owner of $f"; fi
  runuser -u ics -- head -c1 "$f" >/dev/null 2>&1 || die "$f is not readable by the service user 'ics'"
}
ensure_key "$ETC/vault.key" 32 1
ensure_key "$ETC/audit.key" 32 0
ensure_key "$ETC/ics-signing.key" 32 1

# --------------------------------------------------------------------------------------------- database roles + db
url_pw() { ENVU="$(envget "$1" "$2")" python3 -I -c 'import os,urllib.parse as u; print(u.urlsplit(os.environ["ENVU"]).password or "")'; }
role_exists() { [ "$(runuser -u postgres -- psql -X -Atc "select 1 from pg_roles where rolname='$1'")" = 1 ]; }
login_ok() { PGPASSWORD="$2" psql -X -q -h 127.0.0.1 -U "$1" -d ics -Atc 'select 1' >/dev/null 2>&1; }
OWNER_PW="$(url_pw "$ETC/ics-migrate.env" ICS_MIGRATE_DATABASE_URL)"
APP_PW="$(url_pw "$ETC/ics.env" ICS_DATABASE_URL)"
ROT_OWNER=0; ROT_APP=0
if ! role_exists ics_owner; then
  [ -n "$OWNER_PW" ] || { OWNER_PW="$(gen_secret)"; ROT_OWNER=1; }
  printf "CREATE ROLE ics_owner LOGIN PASSWORD '%s';\n" "$OWNER_PW" | psqlpg; changed "postgres role ics_owner"
fi
if [ -z "$DB_EXISTS" ]; then psqlpg -c "CREATE DATABASE ics OWNER ics_owner"; changed "database ics"; fi
if ! role_exists ics_app; then
  [ -n "$APP_PW" ] || { APP_PW="$(gen_secret)"; ROT_APP=1; }
  printf "CREATE ROLE ics_app LOGIN PASSWORD '%s';\n" "$APP_PW" | psqlpg; changed "postgres role ics_app"
fi
psqlpg -c "REVOKE ALL ON DATABASE ics FROM PUBLIC" -c "GRANT CONNECT ON DATABASE ics TO ics_app"
# a role exists but its password is not recorded (or no longer works): rotate it, it is ours
if [ "$ROT_OWNER" = 0 ] && { [ -z "$OWNER_PW" ] || ! login_ok ics_owner "$OWNER_PW"; }; then
  OWNER_PW="$(gen_secret)"; ROT_OWNER=1; printf "ALTER ROLE ics_owner PASSWORD '%s';\n" "$OWNER_PW" | psqlpg; changed "rotated password of ics_owner (env file missing/stale)"
fi
if [ "$ROT_APP" = 0 ] && { [ -z "$APP_PW" ] || ! login_ok ics_app "$APP_PW"; }; then
  APP_PW="$(gen_secret)"; ROT_APP=1; printf "ALTER ROLE ics_app PASSWORD '%s';\n" "$APP_PW" | psqlpg; changed "rotated password of ics_app (env file missing/stale)"
fi

# ------------------------------------------------------------------------------------------------------- env files
# Passwords exist only here (root-only files). Existing files are never rewritten: only absent keys are appended
# (operator edits such as ICS_WORKER_ENABLED=false survive), a password is replaced only after a rotation above.
for spec in "ics.env 640 root:ics" "ics-migrate.env 600 root:root"; do
  set -- $spec
  [ -e "$ETC/$1" ] || { ( umask 077; : > "$ETC/$1" ); chown "$3" "$ETC/$1"; chmod "$2" "$ETC/$1"; changed "created $ETC/$1"; }
done
F=""; [ "$ROT_APP" = 1 ] && F=force
env_kv "$ETC/ics.env" ICS_DATABASE_URL "postgresql+psycopg://ics_app:${APP_PW}@127.0.0.1:5432/ics" "$F"
env_kv "$ETC/ics.env" ICS_VAULT_KEY_FILE "$ETC/vault.key"
env_kv "$ETC/ics.env" ICS_AUDIT_KEY_FILE "$ETC/audit.key"
env_kv "$ETC/ics.env" ICS_SIGNING_KEY_FILE "$ETC/ics-signing.key"
[ "$SKIP_TLS" = 1 ] || env_kv "$ETC/ics.env" ICS_TRUSTED_PROXY 127.0.0.1
F=""; [ "$ROT_OWNER" = 1 ] && F=force
env_kv "$ETC/ics-migrate.env" ICS_MIGRATE_DATABASE_URL "postgresql+psycopg://ics_owner:${OWNER_PW}@127.0.0.1:5432/ics" "$F"
unset OWNER_PW APP_PW
for spec in "ics.env 640 root:ics" "ics-migrate.env 600 root:root"; do
  set -- $spec
  if [ "$(stat -c '%a %U:%G' "$ETC/$1")" != "$2 $3" ]; then chown "$3" "$ETC/$1"; chmod "$2" "$ETC/$1"; changed "mode/owner of $ETC/$1"; fi
done

# ----------------------------------------------------------------------------------------------------------- TLS
CA_FPR=""; CERT_FPR=""; SERVER_NAME=""
want_tokens() { # expected name tokens, one per line, sorted
  { echo "IP:$LISTEN_IP"; echo "IP:127.0.0.1"; echo "DNS:localhost"; [ -z "$HOSTNAME_FQDN" ] || echo "DNS:$HOSTNAME_FQDN"; } | sort -u
}
cert_tokens() { # SAN tokens of a certificate
  openssl x509 -noout -ext subjectAltName -in "$1" | grep -oE '(DNS:[^,[:space:]]+|IP Address:[0-9.]+)' | sed 's/IP Address:/IP:/' | sort -u
}
ca_permitted() { openssl x509 -noout -ext nameConstraints -in "$1" | sed -n '/Permitted/,/Excluded/p' | grep -oE '(DNS:[^,[:space:]]+|IP:[0-9./]+)' | sed 's#/255.255.255.255$##' | sort -u; }
setup_tls() {
  install -d -o root -g root -m 0700 "$TLS"
  if [ -n "$TLS_CERT" ]; then
    # operator-provided certificate: must match the key, be valid, and cover the names we serve
    [ "$(openssl x509 -in "$TLS_CERT" -noout -pubkey | sha256sum)" = "$(openssl pkey -in "$TLS_KEY" -pubout | sha256sum)" ] || die "--tls-cert does not match --tls-key"
    openssl x509 -in "$TLS_CERT" -noout -checkend 86400 >/dev/null || die "--tls-cert is expired or expires within a day"
    openssl x509 -in "$TLS_CERT" -noout -checkip "$LISTEN_IP" | grep -q 'does match' || die "--tls-cert does not cover $LISTEN_IP"
    [ -z "$HOSTNAME_FQDN" ] || openssl x509 -in "$TLS_CERT" -noout -checkhost "$HOSTNAME_FQDN" | grep -q 'does match' || die "--tls-cert does not cover $HOSTNAME_FQDN"
    if put "$TLS_CERT" 0644 root:root "$TLS/ics.crt"; then :; fi
    if put "$TLS_KEY" 0600 root:root "$TLS/ics.key"; then :; fi
    CERT_FPR="$(openssl x509 -in "$TLS/ics.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
    return
  fi
  local ca_tokens_expected need_ca=0 need_cert=0
  [ -f "$TLS/ca.key" ] && [ -f "$TLS/ca.crt" ] || need_ca=1
  if [ "$need_ca" = 1 ]; then
    [ ! -e "$TLS/ca.key" ] && [ ! -e "$TLS/ca.crt" ] || die "$TLS has only half of a CA (ca.key/ca.crt). Not touching it."
    local nc="permitted;IP:${LISTEN_IP}/255.255.255.255,permitted;IP:127.0.0.1/255.255.255.255,permitted;DNS:localhost"
    [ -z "$HOSTNAME_FQDN" ] || nc="$nc,permitted;DNS:${HOSTNAME_FQDN}"
    ( umask 077; openssl ecparam -name prime256v1 -genkey -noout -out "$TLS/ca.key" )
    openssl req -new -x509 -key "$TLS/ca.key" -sha256 -days 1826 -set_serial "0x$(openssl rand -hex 15)" \
      -subj "/O=Office Unbound/CN=Office Unbound ICS CA $(hostname)" -out "$TLS/ca.crt" \
      -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -addext "subjectKeyIdentifier=hash" -addext "nameConstraints=critical,${nc}" 2>/dev/null
    chmod 0644 "$TLS/ca.crt"; chmod 0600 "$TLS/ca.key"; changed "private ICS CA (P-256, 5 years, name-constrained)"
  fi
  # the (existing) CA must be allowed to issue every name we need; a name-constrained CA cannot be extended
  local permitted; permitted="$(ca_permitted "$TLS/ca.crt")"
  want_tokens | while read -r t; do echo "$permitted" | grep -qxF "$t" || { echo "$t"; }; done > "$TMP/uncovered"
  [ ! -s "$TMP/uncovered" ] || die "the existing CA's name constraints do not cover: $(tr '\n' ' ' < "$TMP/uncovered"). A name-constrained CA cannot be widened: move $TLS aside and re-run to create a new CA (admins must re-import it)."
  if [ ! -f "$TLS/ics.crt" ] || [ ! -f "$TLS/ics.key" ]; then need_cert=1
  elif ! openssl x509 -in "$TLS/ics.crt" -noout -checkend 2592000 >/dev/null; then need_cert=1; log "server certificate expires within 30 days: renewing"
  elif [ "$(cert_tokens "$TLS/ics.crt")" != "$(want_tokens)" ]; then need_cert=1; log "server certificate names differ from the requested ones: re-issuing"
  elif ! openssl verify -CAfile "$TLS/ca.crt" "$TLS/ics.crt" >/dev/null 2>&1; then need_cert=1
  fi
  if [ "$need_cert" = 1 ]; then
    local san; san="$(want_tokens | tr '\n' ',' | sed 's/,$//')"
    ( umask 077; openssl ecparam -name prime256v1 -genkey -noout -out "$TMP/ics.key"
      openssl req -new -key "$TMP/ics.key" -subj "/O=Office Unbound/CN=ics" -out "$TMP/ics.csr" )
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' "$san" > "$TMP/ext.cnf"
    openssl x509 -req -in "$TMP/ics.csr" -CA "$TLS/ca.crt" -CAkey "$TLS/ca.key" -sha256 -days 397 -set_serial "0x$(openssl rand -hex 15)" -extfile "$TMP/ext.cnf" -out "$TMP/ics.crt" 2>/dev/null
    openssl verify -CAfile "$TLS/ca.crt" -verify_ip "$LISTEN_IP" "$TMP/ics.crt" >/dev/null || die "issued certificate fails verification against the CA name constraints"
    install -m 0600 -o root -g root "$TMP/ics.key" "$TLS/ics.key"; install -m 0644 -o root -g root "$TMP/ics.crt" "$TLS/ics.crt"
    changed "server certificate (P-256, 397 days)"
  fi
  chown root:root "$TLS"/*; chmod 0600 "$TLS/ca.key" "$TLS/ics.key"; chmod 0644 "$TLS/ca.crt" "$TLS/ics.crt"
  CA_FPR="$(openssl x509 -in "$TLS/ca.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
  CERT_FPR="$(openssl x509 -in "$TLS/ics.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
}
[ "$SKIP_TLS" = 1 ] || setup_tls

# ------------------------------------------------------------------------------------- code + venv + migrations
REL="$( cd "$SRC" && find . \( -name .venv -o -name __pycache__ -o -name .pytest_cache -o -name tests -o -name node_modules \) -prune -o -type f -print0 \
        | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1 )"
# a VERSION/VERSIONS.json bump outside ics/ must also trigger a reinstall (BUILD_INFO.json is derived from them)
REL="$( { echo "$REL"; cat "$SRC/../VERSION" "$SRC/../VERSIONS.json" 2>/dev/null; } | sha256sum | cut -d' ' -f1 )"
need_install=0
if [ -n "$FROM_REPO" ]; then
  # ---- signed package path: pinned key -> apt source with signed-by -> apt-get install ou-ics (postinst: wheels, backup gate, migrations, start)
  KR=/usr/share/keyrings/ou-release.gpg
  got="$(gpg --show-keys --with-colons "$REPO_KEY" 2>/dev/null | awk -F: '/^fpr/{print $10; exit}')"
  [ "$got" = "$REPO_FPR" ] || die "repository key fingerprint is ${got:-unreadable}, pinned ${REPO_FPR}: refusing to trust it"
  gpg --dearmor < "$REPO_KEY" > "$TMP/ou-release.gpg"
  put "$TMP/ou-release.gpg" 0644 root:root "$KR" || true
  echo "deb [signed-by=$KR] $REPO_URL $FROM_REPO main" > "$TMP/ou.list"
  put "$TMP/ou.list" 0644 root:root /etc/apt/sources.list.d/office-unbound.list || true
  for i in 1 2 3 4 5; do apt-get -o DPkg::Lock::Timeout=600 -qq update && break; [ "$i" != 5 ] || die "apt-get update failed (is $REPO_URL reachable and its Release signed by the pinned key?)"; sleep 5; done
  CUR="$(dpkg-query -W -f='${Version}' ou-ics 2>/dev/null || true)"
  CAND="$(apt-cache policy ou-ics | sed -n 's/^  Candidate: //p')"
  [ -n "$CAND" ] && [ "$CAND" != "(none)" ] || die "ou-ics is not available in channel $FROM_REPO of $REPO_URL"
  WANT="${PKG_VERSION:-$CAND}"
  if [ "$CUR" = "$WANT" ]; then log "ou-ics $CUR already installed: nothing to do (upgrade later with: apt-get install ou-ics, after ics upgrade-preflight)"
  else
    log "installing ou-ics $WANT from channel $FROM_REPO (the package postinst runs migrations; an existing database is backed up first)"
    DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 -q install -y --no-install-recommends --allow-downgrades "ou-ics=$WANT" >/dev/null \
      || { journalctl -u ics-migrate -u ics --no-pager -n 20 >&2 || true; die "apt-get install ou-ics=$WANT failed (see above; a failed backup/migration leaves the old data untouched)"; }
    changed "package ou-ics ${CUR:-none} -> $WANT (channel $FROM_REPO)"
  fi
  REL="ou-ics $(dpkg-query -W -f='${Version}' ou-ics)"
else
[ -x "$OPT/.venv/bin/python" ] || need_install=1
[ "$(cat "$STAMP" 2>/dev/null)" = "$REL" ] || need_install=1
for u in ics.service ics-migrate.service; do cmp -s "$SRC/deploy/$u" "$SYSD/$u" || need_install=1; done
if [ "$need_install" = 1 ]; then
  log "installing code, hash-pinned venv and units via deploy/install.sh (restarts ics-migrate + ics; migrations run)"
  sh "$SRC/deploy/install.sh"
  echo "$REL" > "$STAMP"; changed "ICS release $REL installed to $OPT"
else
  log "code already at release ${REL:0:12}: install.sh skipped"
  for u in ics-migrate ics; do systemctl is-enabled -q $u.service || systemctl enable $u.service >/dev/null 2>&1; systemctl is-active -q $u.service || { systemctl start $u.service; changed "started $u"; }; done
fi
fi

# ------------------------------------------------------------------------------------- firewall + nginx front end
if [ "$SKIP_TLS" = 0 ]; then
  SERVER_NAME="$LISTEN_IP${HOSTNAME_FQDN:+ $HOSTNAME_FQDN} localhost"
  # the host itself (loopback and its own address) is always allowed so health checks work from the machine
  SETLIST="127.0.0.1, $LISTEN_IP$(printf ', %s' "${ALLOW[@]}")"
  cat > "$TMP/fw.nft" <<EOF
# Office Unbound ICS console exposure: only the listed networks may reach 443 on this host. Generated by bootstrap.sh.
table inet ics_admin {
  chain input {
    type filter hook input priority -10; policy accept;
    tcp dport 443 ip saddr { $SETLIST } accept
    tcp dport 443 drop
    tcp dport 80 drop
  }
}
EOF
  cat > "$TMP/ics-admin-fw.service" <<'EOF'
[Unit]
Description=Office Unbound ICS console source restriction
Before=nginx.service
After=network-pre.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/usr/sbin/nft delete table inet ics_admin
ExecStart=/usr/sbin/nft -f /etc/office-unbound/ics-admin-fw.nft
ExecStop=/usr/sbin/nft delete table inet ics_admin
[Install]
WantedBy=multi-user.target
EOF
  {
    cat <<EOF
# Office Unbound ICS console - TLS front end. Backend stays on 127.0.0.1:8088. Generated by bootstrap.sh.
# Source restriction is enforced in nftables (table inet ics_admin) AND here.
server {
    listen $LISTEN_IP:443 ssl http2;
    server_name $SERVER_NAME;

    ssl_certificate     $TLS/ics.crt;
    ssl_certificate_key $TLS/ics.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_tickets off;

    allow 127.0.0.1;
    allow $LISTEN_IP;
EOF
    for c in "${ALLOW[@]}"; do echo "    allow $c;"; done
    cat <<'EOF'
    deny all;

    server_tokens off;
    client_max_body_size 300k;
    add_header Strict-Transport-Security "max-age=86400" always;

    location / {
        proxy_pass http://127.0.0.1:8088;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;   # OVERWRITE: never trust client-supplied XFF
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 120s;
    }
}
EOF
  } > "$TMP/ics.conf"

  FW_CH=0; NG_CH=0
  put "$TMP/ics-admin-fw.service" 0644 root:root "$SYSD/ics-admin-fw.service" && { systemctl daemon-reload; FW_CH=1; }
  put "$TMP/fw.nft" 0644 root:root "$ETC/ics-admin-fw.nft" && FW_CH=1
  if [ "$SKIP_FW" = 1 ]; then log "firewall unit skipped (--skip-firewall)"
  else
    systemctl is-enabled -q ics-admin-fw.service || systemctl enable ics-admin-fw.service >/dev/null 2>&1
    if [ "$FW_CH" = 1 ] || ! systemctl is-active -q ics-admin-fw.service; then
      nft -c -f "$ETC/ics-admin-fw.nft" || die "generated nftables ruleset is invalid"
      systemctl restart ics-admin-fw.service || die "ics-admin-fw.service failed (does this container/host allow nftables? use --skip-firewall to rely on the nginx allow-list only)"
      changed "nftables table inet ics_admin loaded"
    fi
  fi
  put "$TMP/ics.conf" 0644 root:root "$NGX_AVAIL" && NG_CH=1
  [ -L "$NGX_ENAB" ] && [ "$(readlink "$NGX_ENAB")" = "$NGX_AVAIL" ] || { ln -sfn "$NGX_AVAIL" "$NGX_ENAB"; NG_CH=1; changed "enabled nginx site ics.conf"; }
  [ ! -e /etc/nginx/sites-enabled/default ] || { rm -f /etc/nginx/sites-enabled/default; NG_CH=1; changed "removed nginx default site (no port 80)"; }
  nginx -t >/dev/null 2>&1 || { nginx -t; die "nginx configuration test failed"; }
  systemctl is-enabled -q nginx.service || systemctl enable nginx.service >/dev/null 2>&1
  if ! systemctl is-active -q nginx.service; then systemctl start nginx.service; changed "started nginx"
  elif [ "$NG_CH" = 1 ]; then systemctl reload nginx.service; changed "reloaded nginx"; fi
fi

# ------------------------------------------------------------------------------------------------------- readiness
log "waiting for /readyz (backend, 127.0.0.1:8088)"
PASSIVE=0; [ "$(envget "$ETC/ics.env" ICS_WORKER_ENABLED)" = false ] && PASSIVE=1
ready() { # ready URL [curl args...]: 200, or (PASSIVE restored controller, worker disabled) 503 with database + audit chain ok
  local u=$1 code; shift
  code="$(curl -s -o "$TMP/ready.json" -w '%{http_code}' "$@" "$u" 2>/dev/null)" || return 1
  [ "$code" = 200 ] && return 0
  [ "$PASSIVE" = 1 ] && [ "$code" = 503 ] && python3 -I -c 'import json,sys; c=json.load(open(sys.argv[1]))["checks"]; sys.exit(0 if c["database"]["ok"] and c["audit_chain"]["ok"] else 1)' "$TMP/ready.json"
}
unit_wait "ready http://127.0.0.1:8088/readyz" 120 || { journalctl -u ics-migrate -u ics --no-pager -n 30 >&2 || true; die "/readyz did not become ready within 120 s"; }
[ "$PASSIVE" = 0 ] || log "ICS_WORKER_ENABLED=false (passive/restored controller): /readyz 503 on the worker check is expected; database and audit chain are ok"
URL="http://127.0.0.1:8088/"
if [ "$SKIP_TLS" = 0 ]; then
  CAF="$TLS/ca.crt"; [ -z "$TLS_CERT" ] || CAF=/etc/ssl/certs/ca-certificates.crt
  ready "https://$LISTEN_IP/readyz" --cacert "$CAF" || die "https://$LISTEN_IP/readyz failed (TLS/nginx)"
  [ -z "$HOSTNAME_FQDN" ] || ready "https://$HOSTNAME_FQDN/readyz" --cacert "$CAF" --resolve "$HOSTNAME_FQDN:443:$LISTEN_IP" || die "https://$HOSTNAME_FQDN/readyz failed"
  URL="https://${HOSTNAME_FQDN:-$LISTEN_IP}/"
fi

# ----------------------------------------------------------------------------------------------------- first admin
TOKEN_OUT=""; ADMIN_NOTE=""
if [ -n "$ADMIN" ]; then
  if [ "$(runuser -u postgres -- psql -X -Atd ics -c "select count(*) from users where username='$ADMIN'")" != 0 ]; then
    ADMIN_NOTE="account '$ADMIN' already exists: no token issued (re-issue deliberately with: cd $OPT && sudo -u ics .venv/bin/python -m ics.cli issue-enrollment --username $ADMIN)"
  else
    TOKEN_OUT="$(cd "$OPT" && runuser -u ics -- "$OPT/.venv/bin/python" -m ics.cli create-admin --username "$ADMIN" --role admin)" || die "create-admin failed"
    changed "admin account $ADMIN created"
  fi
fi

# ------------------------------------------------------------------------------------------------------- summary
echo
echo "================ Office Unbound ICS: bootstrap summary ================"
echo "console URL        : $URL"
if [ -n "$FROM_REPO" ]; then echo "release            : $REL (signed package, channel $FROM_REPO, repo $REPO_URL, key $REPO_FPR) -> $OPT"
else echo "release            : ${REL:0:16}... ($OPT)"; fi
dpkg-query -W -f='package            : ${Package} ${Version}\n' "postgresql-$PGVER" python3-venv $([ "$SKIP_TLS" = 1 ] || echo nginx nftables)
if [ "$SKIP_TLS" = 1 ]; then echo "mode               : loopback only (127.0.0.1:8088, no TLS, no nginx, no firewall)"
else
  echo "listen / allow     : $LISTEN_IP:443  <-  127.0.0.1 $LISTEN_IP ${ALLOW[*]}"
  if [ -n "$TLS_CERT" ]; then echo "certificate        : operator-provided, SHA-256 $CERT_FPR"
  else
    echo "CA certificate     : $TLS/ca.crt  (import into admin workstations)"
    echo "CA SHA-256         : $CA_FPR   <- verify out of band"
    echo "server cert SHA-256: $CERT_FPR"
  fi
fi
echo "config / keys      : $ETC (env files and keys are root-only; DB passwords exist only there)"
if [ ${#CHANGES[@]} = 0 ]; then echo "changes this run   : none"; else printf 'changes this run   : %s\n' "${CHANGES[0]}"; for c in "${CHANGES[@]:1}"; do printf '                     %s\n' "$c"; done; fi
[ -z "$ADMIN_NOTE" ] || echo "admin              : $ADMIN_NOTE"
if [ -n "$TOKEN_OUT" ]; then
  echo "======================================================================="
  echo "$TOKEN_OUT"
fi
