#!/bin/sh
# Runs INSIDE the image root (mmdebstrap customize hook, chroot), as root, once at build time. Everything the guest needs EXCEPT the per-VM material, which
# arrives through SMBIOS at first boot (ou_agent/firstboot.py). The result has: NO SSH server (not installed, units masked), no cloud-init user (cloud-init
# installed but disabled), default-deny inbound firewall, no passwords (root locked), the node agent installed (from the signed Office Unbound apt repo)
# but NOT initialised and NOT enabled: no keys, no certificate, no token (drawn per VM at first boot), rootless podman user.
# Env: OU_OS, ROOT_UUID, ESP_UUID.   Payload dir: /tmp/payload (ourrepo/, ou-release-lab.pub.asc, ou-bootstrap.service, nftables.conf, ...).
set -eu
export DEBIAN_FRONTEND=noninteractive
P=/tmp/payload

# --- Office Unbound apt repository: the release key is installed from the payload only after its full fingerprint equals the pinned one
want=$(cat "$P/ou-release.FINGERPRINT")
have=$(gpg --show-keys --with-colons "$P/ou-release.pub.asc" | awk -F: '/^fpr:/{print $10; exit}')
[ "$have" = "$want" ] || { echo "release key fingerprint $have != pinned $want" >&2; exit 4; }
gpg --dearmor < "$P/ou-release.pub.asc" > /usr/share/keyrings/ou-release.gpg
cat > /etc/apt/sources.list.d/ou-build.sources <<EOF
Types: deb
URIs: file:///tmp/payload/ourrepo
Suites: dev
Components: main
Signed-By: /usr/share/keyrings/ou-release.gpg
EOF
apt-get update
apt-get install -y --no-install-recommends ou-node-agent
rm -f /etc/apt/sources.list.d/ou-build.sources          # a file: build repo does not belong in the shipped image; the keyring stays for the real channel
apt-get update >/dev/null

# --- rootless workload user (same shape as guest/cloudinit.py: nologin, locked, explicit subuid/subgid, linger)
getent passwd ou-svc >/dev/null || useradd --create-home --home-dir /var/lib/ou-svc --shell /usr/sbin/nologin ou-svc
passwd -l ou-svc >/dev/null
sed -i '/^ou-svc:/d' /etc/subuid /etc/subgid
echo 'ou-svc:100000:65536' | tee -a /etc/subuid >> /etc/subgid
install -d /var/lib/systemd/linger; : > /var/lib/systemd/linger/ou-svc

# --- first boot + root growth
install -m 0755 "$P/ou-seal" /usr/local/sbin/ou-seal
install -m 0644 "$P/ou-bootstrap.service" /etc/systemd/system/ou-bootstrap.service
install -m 0644 "$P/ou-growroot.service" /etc/systemd/system/ou-growroot.service
install -m 0755 "$P/ou-growroot" /usr/local/sbin/ou-growroot
systemctl enable ou-bootstrap.service ou-growroot.service
install -d -m 0755 /var/lib/ou-bootstrap
systemctl disable ou-agent.service >/dev/null 2>&1 || true   # started by the first-boot unit only after the ICS authenticated itself

# --- network: DHCP on every ethernet interface (networkd), default-deny inbound until the ICS-authenticated configuration replaces it
install -d /etc/systemd/network
printf '[Match]\nType=ether\n\n[Network]\nDHCP=yes\n\n[DHCPv4]\nUseDomains=no\n' > /etc/systemd/network/10-ou-dhcp.network
systemctl enable systemd-networkd.service systemd-resolved.service
ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
install -m 0644 "$P/nftables.conf" /etc/nftables.conf
nft -c -f /etc/nftables.conf   # the shipped ruleset must at least parse (needs /etc/protocols from netbase: found by the first boot test)
systemctl enable nftables.service

# --- hostname, machine-id (empty = regenerated per VM at first boot), time
echo ou-guest > /etc/hostname
printf '127.0.0.1 localhost\n127.0.1.1 ou-guest\n' > /etc/hosts
: > /etc/machine-id; rm -f /var/lib/dbus/machine-id
systemctl enable systemd-timesyncd.service >/dev/null 2>&1 || true

# --- no SSH, no cloud-init accounts. (openssh-server is NOT installed; the masks keep a later accidental install from starting it.)
systemctl mask ssh.service ssh.socket sshd.service >/dev/null 2>&1 || true
rm -f /etc/ssh/ssh_host_* /root/.ssh/authorized_keys
passwd -l root >/dev/null
# cloud-init is not installed at all (absent). If a later package pulls it in, it stays inert: the disabled marker + a datasource list without network sources.
install -d /etc/cloud/cloud.cfg.d
touch /etc/cloud/cloud-init.disabled
printf 'datasource_list: [ None ]\nssh_pwauth: false\ndisable_root: true\nmanage_etc_hosts: false\n' > /etc/cloud/cloud.cfg.d/99-ou.cfg
# persistent journal (forensics survive a reboot; the boot test reads it offline and asserts the bootstrap secret never reached it)
install -d -m 2755 -g systemd-journal /var/log/journal
install -d /etc/systemd/journald.conf.d
printf '[Journal]\nStorage=persistent\nSystemMaxUse=64M\n' > /etc/systemd/journald.conf.d/10-ou.conf

# --- unattended security updates (Debian-Security origin only; the ICS schedules reboots, the guest never reboots by itself)
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
cat > /etc/apt/apt.conf.d/52ou-unattended <<EOF
Unattended-Upgrade::Origins-Pattern { "$UNATTENDED_ORIGIN"; };
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF

# --- bootloader config (SeaBIOS via syslinux + UEFI via systemd-boot, both reading the FAT /boot partition); see /usr/local/sbin/ou-bootcfg
install -m 0755 "$P/ou-bootcfg" /usr/local/sbin/ou-bootcfg
install -d /etc/kernel/postinst.d /etc/kernel/postrm.d
printf '#!/bin/sh\nexec /usr/local/sbin/ou-bootcfg\n' > /etc/kernel/postinst.d/zz-ou-bootcfg
cp /etc/kernel/postinst.d/zz-ou-bootcfg /etc/kernel/postrm.d/zz-ou-bootcfg
chmod 0755 /etc/kernel/postinst.d/zz-ou-bootcfg /etc/kernel/postrm.d/zz-ou-bootcfg
printf 'PARTUUID=%s /boot vfat umask=0077,nofail 0 2\nPARTUUID=%s / ext4 errors=remount-ro 0 1\n' "$ESP_UUID" "$ROOT_UUID" > /etc/fstab
ROOT_UUID=$ROOT_UUID /usr/local/sbin/ou-bootcfg

apt-get -y autoremove --purge >/dev/null 2>&1 || true
apt-get clean
rm -rf /var/lib/apt/lists/* /var/log/*.log /var/log/apt/* /root/.bash_history /tmp/payload
find /var/log -type f -name '*.log' -delete 2>/dev/null || true
