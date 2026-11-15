#!/usr/bin/env bash
# VM "office": Collabora CODE (pinned image digest) in Docker behind nginx
# (lab CA cert). CODE is LAB ONLY (ADR-0005): not for customer production.
# Prereq: /root/ou-lab-bundle.tar.gz via common/fetch-bundle.sh <kc> office <this-vm>.
# STATUS: PREPARED, NOT EXECUTED.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="$(cd "${HERE}/../../common" && pwd)"
. "${LAB}/lab.env"; . "${LAB}/versions.env"; . "${LAB}/lib.sh"
need_root; secrets_dir_init
. /etc/os-release; [ "${VERSION_ID:-}" = "24.04" ] || warn "tested-for OS is Ubuntu 24.04"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq docker.io nginx curl ca-certificates openssl ufw fonts-crosextra-carlito fonts-crosextra-caladea
add_lab_hosts
install_bundle
log "docker: $(docker --version)  (Ubuntu archive package; record this in the test report)"

log "pull pinned image ${COLLABORA_IMAGE}"
docker pull "${COLLABORA_IMAGE}"

# WOPI proof key, same approach as opencloud-compose weboffice/collabora.yml
install -d -m 0700 /etc/collabora
if [ ! -s /etc/collabora/proof_key ]; then
  ( umask 077; openssl genrsa -traditional -out /etc/collabora/proof_key 4096 2>/dev/null )
  chown 1001:1001 /etc/collabora/proof_key; chmod 0400 /etc/collabora/proof_key
fi
install -m 0644 "${TLS_DIR}/ca.crt" /etc/collabora/lab-ca.pem
( umask 077
  cat > /etc/collabora/collabora.env <<ENV
username=admin
password=$(secret_get collabora-admin-password)
aliasgroup1=https://${HOST_FILES}
ENV
)

cat > /etc/systemd/system/collabora.service <<UNIT
[Unit]
Description=Collabora CODE (lab only)
After=docker.service network-online.target
Requires=docker.service
[Service]
Restart=always
RestartSec=5
ExecStartPre=-/usr/bin/docker rm -f collabora
ExecStart=/usr/bin/docker run --rm --name collabora \\
  --env-file /etc/collabora/collabora.env \\
  --add-host ${HOST_FILES}:${IP_FILES} \\
  --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined \\
  -p 127.0.0.1:9980:9980 \\
  -v /etc/collabora/lab-ca.pem:/etc/coolwsd/lab-ca.pem:ro \\
  -v /etc/collabora/proof_key:/etc/coolwsd/proof_key:ro \\
  -e "extra_params=--o:ssl.enable=false --o:ssl.termination=true --o:ssl.ssl_verification=true --o:ssl.ca_file_path=/etc/coolwsd/lab-ca.pem --o:welcome.enable=false --o:net.frame_ancestors=${HOST_FILES} --o:net.lok_allow.host[14]=${HOST_FILES} --o:home_mode.enable=false" \\
  ${COLLABORA_IMAGE}
ExecStop=/usr/bin/docker stop collabora
[Install]
WantedBy=multi-user.target
UNIT

sed -e "s#__OFFICE_HOST__#${HOST_OFFICE}#g" "${HERE}/nginx-office.conf.tmpl" > /etc/nginx/sites-available/ou-lab-office
ln -sf /etc/nginx/sites-available/ou-lab-office /etc/nginx/sites-enabled/ou-lab-office
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl daemon-reload; systemctl enable --now collabora; systemctl reload nginx

ufw --force reset >/dev/null; ufw default deny incoming >/dev/null; ufw default allow outgoing >/dev/null
ufw allow 22/tcp >/dev/null; ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null
ufw --force enable >/dev/null

log "waiting for discovery"
for i in $(seq 1 60); do
  curl -fsS --cacert "${TLS_DIR}/ca.crt" "https://${HOST_OFFICE}/hosting/discovery" >/dev/null 2>&1 && { OK=1; break; }
  sleep 3
done
[ "${OK:-0}" = 1 ] && log "Collabora discovery OK" || warn "no discovery yet: journalctl -u collabora"
log "Collabora admin console password (root-only): ${SECRETS_DIR}/collabora-admin-password"
log "NOTE: docker publishes 9980 on 127.0.0.1 only; note that docker manipulates iptables and can bypass ufw for published ports - hence the loopback bind."
