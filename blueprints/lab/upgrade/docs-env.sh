# source me: loads the OpenCloud test env for the document-tier drill (CA from ou-id1, passwords loaded without printing)
# needs OU_CA_WORK (a directory for the CA copy)
: "${OU_CA_WORK:?}"
sudo systemd-run -M ou-id1 --quiet --pipe --wait /bin/cat /root/ou-lab-ca/ca.crt > "$OU_CA_WORK/ca.crt"
set -a; eval "$(sudo systemd-run -M ou-id1 --quiet --pipe --wait /bin/cat /root/ou-lab-secrets/test-users.env | grep -E '^(export )?OU_PASSWORD_[A-Z]+=')" 2>/dev/null; set +a
export OU_CA_FILE="$OU_CA_WORK/ca.crt" OU_RESTART_CMD='sudo systemctl -M {machine} restart {unit}' OU_MACHINE_FILES=ou-files1 OU_MACHINE_OFFICE=ou-office1 OU_MACHINE_KC=ou-id1
