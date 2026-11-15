#!/bin/sh
# Security review 4, M1: zcore.sock is created 0666 by gromox (exch/zcore/main.cpp, FMODE_PUBLIC) and offers logon_np = mailbox logon WITHOUT a
# password to anyone who can connect. Make the socket reachable only for the php-fpm pool users that need MAPI (groweb = grommunio-web,
# grosync = ActiveSync, grodav = CalDAV/CardDAV). Runs INSIDE the groupware machine as root; idempotent. Used by lab-configure.sh, lab-sso.sh,
# lab-sso-existing.sh and (inline copy) backup/gw-restore-inner.sh; restart gromox-zcore + php8.2-fpm afterwards.
#
# Two layers, both survive restarts (a systemd drop-in re-applies them after every zcore start):
#   1. /run/gromox is 0710 gromox:gromox-zcore  -> other uids cannot even traverse to the socket (closes the window before layer 2 runs)
#   2. zcore.sock is 0660 gromox:gromox-zcore    -> group-restricted
set -e
getent group gromox-zcore >/dev/null || groupadd -r gromox-zcore
for u in groweb grosync grodav; do id "$u" >/dev/null 2>&1 && usermod -aG gromox-zcore "$u"; done
cat > /usr/local/sbin/ou-zcore-sockperm <<'EOS'
#!/bin/sh
# re-applied by gromox-zcore.service (ExecStartPost; ExecStartPre removes the stale socket first so the wait below sees the NEW one).
for i in $(seq 1 240); do [ -S /run/gromox/zcore.sock ] && break; sleep 0.25; done   # up to 60 s (zcore creates it after its DB/ldap init)
chgrp gromox-zcore /run/gromox && chmod 0710 /run/gromox
chgrp gromox-zcore /run/gromox/zcore.sock && chmod 0660 /run/gromox/zcore.sock
EOS
chmod 0755 /usr/local/sbin/ou-zcore-sockperm
install -d /etc/systemd/system/gromox-zcore.service.d
printf "[Service]\nExecStartPre=+/bin/rm -f /run/gromox/zcore.sock\nExecStartPost=+/usr/local/sbin/ou-zcore-sockperm\n" > /etc/systemd/system/gromox-zcore.service.d/ou-sockperm.conf
systemctl daemon-reload
