#!/bin/bash
# Run INSIDE ou-id1 as root (secrets never leave the machine): registers client ou-portal via the Keycloak admin API.
set -euo pipefail
export KC_URL=https://auth.ou-lab.internal KC_CA=/root/ou-lab-ca/ca.crt KC_ADMIN_USER=kcadmin
KC_ADMIN_PASSWORD="$(cat /root/ou-lab-secrets/keycloak-admin-password)"; export KC_ADMIN_PASSWORD
export PORTAL_URL="${PORTAL_URL:-https://portal.ou-lab.internal}"
export PORTAL_CLIENT_ID="${PORTAL_CLIENT_ID:-ou-portal}"
export OUT_SECRET_FILE="${OUT_SECRET_FILE:-/root/ou-lab-secrets/kc-portal-client-secret}"
exec python3 "$(dirname "$0")/kc-portal-client.py"
