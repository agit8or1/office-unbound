#!/usr/bin/env bash
# End-to-end test of apply-privsep.sh / revert-privsep.sh inside a SCRATCH machine (never the ICS host): the machine must have been installed with
# ics/deploy/bootstrap.sh (so ics, ics-migrate, ics-admin-fw, nginx, postgresql exist). Run as root INSIDE the machine from a copy of the checkout:
#   bash /root/src/ics/deploy/privsep/tests/in-machine-test.sh
# It simulates the host (account `administrator` with the cloud-init and claude NOPASSWD ALL files, the signer users and key files with the production
# modes, stub signer programs), then: baseline -> dry run -> apply -> key separation -> every sandboxed unit restarts -> idempotent re-apply -> revert.
# shellcheck disable=SC2015,SC2016,SC2012  # `A && ok || ko` is the report idiom here; the printf payloads are literal
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
pass=0; fail=0
ok() { printf 'PASS  %s\n' "$1"; pass=$((pass+1)); }
ko() { printf 'FAIL  %s\n' "$1"; fail=$((fail+1)); }
t() { local label=$1; shift; if "$@" >/dev/null 2>&1; then ok "$label"; else ko "$label"; fi; }
tn() { local label=$1; shift; if "$@" >/dev/null 2>&1; then ko "$label"; else ok "$label"; fi; }

rm -f /etc/sudoers.d/x
command -v machinectl >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd-container >/dev/null 2>&1
mkdir -p /var/lib/machines/ou-x
echo "== fixture: operator account, legacy sudoers, signer users and keys (production modes)"
id administrator >/dev/null 2>&1 || useradd -m -s /bin/bash administrator
echo 'administrator:Fixture-Only-1' | chpasswd
usermod -aG sudo administrator
printf '# cloud-init\nadministrator ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/90-cloud-init-users
printf 'administrator ALL=(ALL:ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/90-claude-administrator
printf 'administrator ALL=(ou-release) NOPASSWD: /usr/local/sbin/ou-release-sign\nadministrator ALL=(ou-testrunner) NOPASSWD: /usr/local/sbin/ou-test-attest\n' > /etc/sudoers.d/ou-release
printf 'administrator ALL=(ou-imgsign) NOPASSWD: /usr/local/sbin/ou-image-sign *\n' > /etc/sudoers.d/ou-image-sign
chmod 0440 /etc/sudoers.d/90-* /etc/sudoers.d/ou-*
for u in ou-release ou-imgsign ou-testrunner; do id "$u" >/dev/null 2>&1 || useradd --system --home-dir "/var/lib/$u" --create-home --shell /usr/sbin/nologin "$u"; done
install -d -m 0700 -o ou-release /var/lib/ou-release/gnupg /var/lib/ou-release/gnupg/private-keys-v1.d
install -d -m 0755 -o root /var/lib/ou-release/trust
chmod 0755 /var/lib/ou-release
head -c 32 /dev/urandom | base64 > /var/lib/ou-release/passphrase; chown ou-release /var/lib/ou-release/passphrase; chmod 0400 /var/lib/ou-release/passphrase
head -c 32 /dev/urandom > /var/lib/ou-release/gnupg/private-keys-v1.d/k.key; chown ou-release /var/lib/ou-release/gnupg/private-keys-v1.d/k.key; chmod 0600 /var/lib/ou-release/gnupg/private-keys-v1.d/k.key
chmod 0700 /var/lib/ou-imgsign /var/lib/ou-testrunner
head -c 32 /dev/urandom > /var/lib/ou-imgsign/key.pem; head -c 32 /dev/urandom | base64 > /var/lib/ou-imgsign/passphrase; chown ou-imgsign /var/lib/ou-imgsign/*; chmod 0600 /var/lib/ou-imgsign/key.pem; chmod 0400 /var/lib/ou-imgsign/passphrase
head -c 32 /dev/urandom > /var/lib/ou-testrunner/key; chown ou-testrunner /var/lib/ou-testrunner/key; chmod 0400 /var/lib/ou-testrunner/key
for p in ou-release-sign ou-test-attest ou-image-sign; do printf '#!/bin/sh\necho "stub %s $*"\n' "$p" > "/usr/local/sbin/$p"; chmod 0755 "/usr/local/sbin/$p"; done
# units that exist on the host but not on a bootstrap-only machine
install -m 0644 "$HERE/../ics-callback.service" /etc/systemd/system/ics-callback.service
printf '[Unit]\nDescription=lab fw stand-in\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/sbin/nft -f /etc/office-unbound/lab-fw-test.nft\n' > /etc/systemd/system/ou-lab-fw.service
printf 'table inet ou_lab_test {\n chain input {\n  type filter hook input priority 10; policy accept;\n }\n}\n' > /etc/office-unbound/lab-fw-test.nft
printf '[Unit]\nDescription=backup helper stand-in\n[Service]\nType=oneshot\nUser=root\nExecStart=/usr/local/sbin/ou-backup %%i\nRuntimeDirectory=ou-rb-backup\nUMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\nProtectHome=true\n' > /etc/systemd/system/ou-rb-backup@.service
printf '#!/bin/sh\nid -u >/dev/null && runuser -u postgres -- true && echo backup-helper-ok "$1"\n' > /usr/local/sbin/ou-backup; chmod 0755 /usr/local/sbin/ou-backup
systemctl daemon-reload
KS="$HERE/tests/key-separation.sh"

echo "== baseline (before): the blanket rules are live and the key-separation test must FAIL"
sudo -l -U administrator | grep -Eq 'NOPASSWD:[[:space:]]*ALL' && ok "baseline: NOPASSWD ALL present" || ko "baseline: NOPASSWD ALL present"
tn "baseline: key-separation reports violations" bash "$KS"
before=$(find /etc/sudoers.d /usr/local/lib /etc/polkit-1 -type f -exec sha256sum {} + 2>/dev/null | sort | sha256sum)

echo "== dry run changes nothing"
t "dry run exits 0" bash "$HERE/apply-privsep.sh"
after=$(find /etc/sudoers.d /usr/local/lib /etc/polkit-1 -type f -exec sha256sum {} + 2>/dev/null | sort | sha256sum)
[ "$before" = "$after" ] && ok "dry run left every file untouched" || ko "dry run left every file untouched"

echo "== refuses to lock the owner out"
passwd -l administrator >/dev/null 2>&1
tn "apply refuses when the operator has a locked password" bash "$HERE/apply-privsep.sh" --apply
echo 'administrator:Fixture-Only-1' | chpasswd

echo "== apply"
bash "$HERE/apply-privsep.sh" --apply > /root/apply.out 2>&1 && ok "apply exits 0" || { ko "apply exits 0"; tail -20 /root/apply.out; }
sed -n '/sudo -l -U/,/DONE/p' /root/apply.out | head -30
for f in 90-cloud-init-users 90-claude-administrator ou-release ou-image-sign; do tn "legacy $f removed" test -e /etc/sudoers.d/$f; done
for f in ou-priv-signers ou-priv-lab ou-priv-testrunner; do t "$f installed 0440 root" test "$(stat -c '%a %U' /etc/sudoers.d/$f)" = "440 root"; done
t "visudo -c valid" visudo -c
tn "no sudoers file mentions NOPASSWD: ALL" grep -rEq 'NOPASSWD:[[:space:]]*ALL([[:space:]]|$)' /etc/sudoers.d /etc/sudoers

echo "== key separation and sudo reach after apply"
bash "$KS" --build-user administrator && ok "key-separation.sh exit 0" || ko "key-separation.sh exit 0"
runuser -u administrator -- sudo -n /usr/local/lib/ou-priv/bin/machinectl list-images 2>&1 | head -3
# the lab shim must also be reached by plain `sudo machinectl` (secure_path), the way the existing lab scripts call it
out=$(runuser -u administrator -- sudo -n machinectl poweroff ou-base-noble 2>&1); case $out in *"protected base"*) ok "plain sudo machinectl poweroff ou-base-noble: policy refusal" ;; *) ko "plain sudo machinectl poweroff ou-base-noble: policy refusal" ;; esac
t "owner path: the password-protected group rule is still listed (interactive sudo)" bash -c "sudo -l -U administrator | grep -q '(ALL : ALL) ALL'"

echo "== every sandboxed unit still starts with its drop-in"
t "postgresql@.service drop-in installed" test -e /etc/systemd/system/postgresql@.service.d/10-privsep.conf
for u in postgresql@16-main.service ics-migrate.service ics.service ics-callback.service nginx.service ics-admin-fw.service ou-lab-fw.service; do
  systemctl restart "$u" >/dev/null 2>&1; sleep 3
  if systemctl is-active --quiet "$u"; then ok "$u active after restart with the drop-in"; else ko "$u active after restart with the drop-in"; systemctl status "$u" --no-pager 2>&1 | tail -8; journalctl -u "$u" -n 8 --no-pager 2>&1 | cut -c1-200; fi
done
systemctl start ou-rb-backup@x.service >/dev/null 2>&1; systemctl show -p Result --value ou-rb-backup@x.service | grep -q success && ok "ou-rb-backup@x runs (runuser postgres still works) with the drop-in" || { ko "ou-rb-backup@x runs with the drop-in"; journalctl -u ou-rb-backup@x -n 6 --no-pager | cut -c1-200; }
for u in ics.service nginx.service postgresql@16-main.service ics-migrate.service; do
  printf 'security %-26s %s\n' "$u" "$(systemd-analyze security "$u" --no-pager 2>/dev/null | tail -1 | cut -c1-80)"
done
t "console answers through nginx (https)" bash -c "curl -sk -o /dev/null -w '%{http_code}' https://\$(hostname -I | awk '{print \$1}')/ | grep -Eq '^(200|30[0-9]|401|403)\$'"
t "ics and the callback listener listen on loopback" bash -c "ss -ltn | grep -q '127.0.0.1:8088' && ss -ltn | grep -q '127.0.0.1:8089'"

echo "== idempotent second apply"
bash "$HERE/apply-privsep.sh" --apply > /root/apply2.out 2>&1 && ok "second apply exits 0" || { ko "second apply exits 0"; tail -5 /root/apply2.out; }
bash "$KS" >/dev/null && ok "key separation still holds" || ko "key separation still holds"

echo "== revert"
bash "$HERE/revert-privsep.sh" > /root/revert-dry.out 2>&1 && ok "revert dry run exits 0" || ko "revert dry run exits 0"
t "revert dry run changed nothing (shims still there)" test -e /usr/local/lib/ou-priv/bin/machinectl
LB=$(ls -d /root/sudoers-backup-* | head -1)
bash "$HERE/revert-privsep.sh" --apply --backup "$LB" > /root/revert.out 2>&1 && ok "revert --apply exits 0 (first backup = original state)" || { ko "revert --apply exits 0"; tail -8 /root/revert.out; }
sudo -l -U administrator | grep -Eq 'NOPASSWD:[[:space:]]*ALL' && ok "after revert the original NOPASSWD ALL rules are back" || ko "after revert the original NOPASSWD ALL rules are back"
tn "after revert the shims are gone" test -e /usr/local/lib/ou-priv
tn "after revert the drop-ins are gone" test -e /etc/systemd/system/ics.service.d/10-privsep.conf
t "visudo -c valid after revert" visudo -c
systemctl restart ics.service >/dev/null 2>&1; sleep 3; systemctl is-active --quiet ics.service && ok "ics.service active after revert + restart" || ko "ics.service active after revert + restart"
echo "== summary: pass=$pass fail=$fail"
[ "$fail" = 0 ]
