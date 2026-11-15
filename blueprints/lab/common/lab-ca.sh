#!/usr/bin/env bash
# Create the LAB-ONLY internal CA and one leaf cert per lab host.
# Run as root on the "kc" VM (CA key never leaves it except inside per-role
# bundles, which contain only that role's own key + the public CA cert).
# Idempotent: existing CA/leafs are kept.
#
# THIS CA IS FOR THE LAB ONLY. Never import it into a customer or production
# trust store. No public CA, no public DNS, no ACME is involved.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lab.env
. "${HERE}/lab.env"
# shellcheck source=lib.sh
. "${HERE}/lib.sh"
need_root

# Name-constrain the CA to the lab domain + lab subnet so a leaked CA key
# cannot mint certs for public names. Set to 0 if some client rejects it.
NAME_CONSTRAINTS="${LAB_CA_NAME_CONSTRAINTS:-1}"
LEAF_DAYS="${LAB_LEAF_DAYS:-397}"
CA_DAYS="${LAB_CA_DAYS:-1095}"

install -d -m 0700 "${CA_DIR}" "${CA_DIR}/out" "${CA_DIR}/leaf"
cd "${CA_DIR}"

if [ ! -s ca.key ]; then
  log "generating lab CA"
  ( umask 077; openssl genrsa -out ca.key 4096 2>/dev/null )
  ext="basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash"
  if [ "${NAME_CONSTRAINTS}" = "1" ]; then
    subnet="${IP_KC%.*}.0/255.255.255.0"
    ext="${ext}
nameConstraints=critical,permitted;DNS:${LAB_DOMAIN},permitted;IP:${subnet}"
  fi
  printf '[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nO=Office Unbound LAB ONLY\nCN=OU Lab Internal CA (do not trust outside lab)\n[v3]\n%s\n' "${ext}" > ca.cnf
  openssl req -x509 -new -key ca.key -sha256 -days "${CA_DAYS}" -config ca.cnf -out ca.crt
  chmod 0644 ca.crt
fi

# issue ROLE FQDN [extra SAN DNS names...]
issue() {
  local role="$1" ip="$2"; shift 2
  local names=("$@")
  local d="leaf/${role}"
  install -d -m 0700 "$d"
  if [ ! -s "$d/${role}.crt" ]; then
    log "issuing cert for ${role}: ${names[*]} (${ip})"
    ( umask 077; openssl genrsa -out "$d/${role}.key" 2048 2>/dev/null )
    local san="" i=1
    for n in "${names[@]}"; do san="${san}DNS.${i}=${n}"$'\n'; i=$((i+1)); done
    cat > "$d/${role}.cnf" <<CNF
[req]
distinguished_name=dn
req_extensions=v3
prompt=no
[dn]
O=Office Unbound LAB ONLY
CN=${names[0]}
[v3]
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@san
[san]
${san}IP.1=${ip}
CNF
    openssl req -new -key "$d/${role}.key" -config "$d/${role}.cnf" -out "$d/${role}.csr"
    openssl x509 -req -in "$d/${role}.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
      -days "${LEAF_DAYS}" -sha256 -extfile "$d/${role}.cnf" -extensions v3 -out "$d/${role}.crt" 2>/dev/null
  fi
  # bundle: ca.crt + <role>.crt (full chain = leaf only, CA pathlen 0) + <role>.key
  cp ca.crt "$d/ca.crt"
  tar -czf "out/${role}.tar.gz" -C "$d" ca.crt "${role}.crt" "${role}.key"
  chmod 0600 "out/${role}.tar.gz"
}

issue kc     "${IP_KC}"     "${HOST_KC}" "${HOST_LDAP}"
issue files  "${IP_FILES}"  "${HOST_FILES}"
issue office "${IP_OFFICE}" "${HOST_OFFICE}"
issue mail   "${IP_MAIL}"   "${HOST_MAIL}" "${HOST_AUTODISCOVER}"

log "CA: ${CA_DIR}/ca.crt ; per-role bundles in ${CA_DIR}/out/ (root-only)"
log "Operator client trust: copy ca.crt to the test workstation and set LAB_CA_FILE for tests/."
