#!/bin/bash
# Run as root inside the runtime machine (ou-office2) after extracting ou-docs-*.tar at /.
set -e
setcap cap_fowner,cap_chown,cap_sys_chroot=ep /usr/bin/coolforkit-caps
setcap cap_sys_admin=ep /usr/bin/coolmount || true
id cool >/dev/null 2>&1 || adduser --quiet --system --group --home /opt/cool cool
rm -rf /opt/cool; mkdir -p /opt/cool/child-roots /opt/cool/cache
coolwsd-systemplate-setup /opt/cool/systemplate /opt/officeunbound-office >/var/log/systemplate-setup.log 2>&1
touch /var/log/coolwsd.log; chown cool:cool /var/log/coolwsd.log; chown -R cool:cool /opt/cool /etc/coolwsd
