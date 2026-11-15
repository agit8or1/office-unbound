#!/bin/bash
# Root, inside the runtime machine, after extracting ou-docs-*.tar at /. Idempotent.
set -e
setcap cap_fowner,cap_chown,cap_sys_chroot=ep /usr/bin/coolforkit-caps
setcap cap_sys_admin=ep /usr/bin/coolmount || true
id cool >/dev/null 2>&1 || adduser --quiet --system --group --home /opt/cool cool   # coolforkit hard-requires the user name "cool"
rm -rf /opt/ou-docs/systemplate /opt/ou-docs/child-roots /opt/ou-docs/cache
mkdir -p /opt/ou-docs/child-roots /opt/ou-docs/cache
coolwsd-systemplate-setup /opt/ou-docs/systemplate /opt/officeunbound-office >/var/log/ou-docs-systemplate-setup.log 2>&1
chown -R cool:cool /opt/ou-docs
chown root:cool /etc/coolwsd/coolwsd.xml; chmod 640 /etc/coolwsd/coolwsd.xml
chown cool:cool /etc/coolwsd/proof_key; chown root:cool /etc/coolwsd/proof_key.pub; chmod 600 /etc/coolwsd/proof_key
