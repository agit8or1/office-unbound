#!/usr/bin/env bash
# Shared helpers. Source, do not execute.
set -euo pipefail

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
warn() { printf '[%s] WARN: %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die()  { printf '[%s] FATAL: %s\n' "$(date +%H:%M:%S)" "$*" >&2; exit 1; }

need_root() { [ "$(id -u)" -eq 0 ] || die "run as root (sudo)"; }

# Random secret, URL/shell/XML/LDAP-safe alphabet, 32 chars.
# (hex via openssl: the earlier tr|head pipeline died with SIGPIPE under pipefail - found in lab run)
gen_secret() { printf "%s" "$(openssl rand -hex 16)"; }

secrets_dir_init() {
  install -d -m 0700 -o root -g root "${SECRETS_DIR}"
}

# secret_get NAME -> prints existing secret or generates + stores it (idempotent).
# Stored as root-only file ${SECRETS_DIR}/NAME (mode 0600).
secret_get() {
  local f="${SECRETS_DIR}/$1"
  if [ ! -s "$f" ]; then
    ( umask 077; gen_secret > "$f" )
  fi
  cat "$f"
}

verify_sha256() { echo "$2  $1" | sha256sum -c - >/dev/null || die "sha256 mismatch for $1"; }
verify_sha1()   { echo "$2  $1" | sha1sum   -c - >/dev/null || die "sha1 mismatch for $1"; }

# Download to a path, refusing non-https.
fetch() {
  case "$1" in https://*) ;; *) die "non-https URL refused: $1";; esac
  curl -fsSL --retry 3 -o "$2" "$1"
}

add_lab_hosts() {
  grep -q "127.0.1.1 $(hostname)" /etc/hosts || echo "127.0.1.1 $(hostname)" >> /etc/hosts
  # Idempotently pin the lab names in /etc/hosts (no public DNS exists).
  local marker="# ou-lab hosts"
  grep -q "^${marker}" /etc/hosts && return 0
  cat >> /etc/hosts <<HOSTS
${marker}
${IP_KC} ${HOST_KC} ${HOST_LDAP}
${IP_FILES} ${HOST_FILES}
${IP_OFFICE} ${HOST_OFFICE}
${IP_MAIL} ${HOST_MAIL} ${HOST_AUTODISCOVER}
HOSTS
}

# Extract the per-VM TLS bundle (ca.crt, <role>.crt, <role>.key) from BUNDLE_PATH
# and trust the lab CA system-wide.
install_bundle() {
  [ -s "${BUNDLE_PATH}" ] || die "missing ${BUNDLE_PATH}: run common/fetch-bundle.sh from the operator workstation first"
  install -d -m 0755 "${TLS_DIR}"
  tar -xzf "${BUNDLE_PATH}" -C "${TLS_DIR}"
  chmod 0644 "${TLS_DIR}"/*.crt
  chmod 0600 "${TLS_DIR}"/*.key
  install -m 0644 "${TLS_DIR}/ca.crt" /usr/local/share/ca-certificates/ou-lab-ca.crt
  update-ca-certificates >/dev/null
}
