#!/bin/sh
# Runs INSIDE the image (virt-customize), as root, once at build time. Everything the guest needs EXCEPT the per-VM material, which arrives through
# SMBIOS at first boot (ou_agent/firstboot.py). The result has: no SSH (masked, not installed where avoidable), no cloud-init user, no inbound firewall
# opening, the node agent installed but NOT initialised (no keys, no certificate, no token: those are drawn per VM at first boot), rootless podman user.
set -eu
export DEBIAN_FRONTEND=noninteractive
P=/tmp/payload
apt-get update
apt-get install -y --no-install-recommends podman uidmap slirp4netns passt crun netavark aardvark-dns systemd-container systemd-timesyncd dbus-user-session \
  nftables polkitd python3 python3-cryptography gnupg ca-certificates unattended-upgrades apt-utils
# qemu-guest-agent is deliberately NOT installed (ADR-0002 s7: no hypervisor exec channel)

# --- node agent (code only; `ou_agent init` is NOT run here)
getent passwd ou-agent >/dev/null || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin ou-agent
install -d -m 0755 /opt/ou-agent /etc/ou-agent
cp -r "$P/ou_agent" /opt/ou-agent/ou_agent
cp -r "$P/deploy" /opt/ou-agent/deploy
chown -R root:root /opt/ou-agent; chmod -R go-w /opt/ou-agent
install -m 0644 "$P/deploy/ou-agent.service" /etc/systemd/system/ou-agent.service
for u in "$P"/deploy/runbooks/ou-rb-podman@.service "$P"/deploy/runbooks/ou-rb-pkg@.service; do [ -f "$u" ] && install -m 0644 "$u" /etc/systemd/system/; done
install -d -m 0700 -o ou-agent -g ou-agent /var/lib/ou-agent
systemctl disable ou-agent.service >/dev/null 2>&1 || true   # started by the first-boot unit only after the ICS authenticated itself
# polkit rule for the agent's allowlisted restarts is rendered per VM from the received configuration by the first-boot unit

# --- rootless workload user (same shape as guest/cloudinit.py: nologin, locked, explicit subuid/subgid, linger)
getent passwd ou-svc >/dev/null || useradd --create-home --home-dir /var/lib/ou-svc --shell /usr/sbin/nologin ou-svc
passwd -l ou-svc >/dev/null
sed -i '/^ou-svc:/d' /etc/subuid /etc/subgid
echo 'ou-svc:100000:65536' | tee -a /etc/subuid >> /etc/subgid
install -d /var/lib/systemd/linger; : > /var/lib/systemd/linger/ou-svc

# --- first boot
install -m 0644 "$P/ou-bootstrap.service" /etc/systemd/system/ou-bootstrap.service
systemctl enable ou-bootstrap.service
install -d -m 0755 /var/lib/ou-bootstrap

# --- network: default-deny inbound (DHCP/ICMP only) until the ICS-authenticated configuration replaces it
install -m 0644 "$P/nftables.conf" /etc/nftables.conf
systemctl enable nftables.service

# --- no SSH, no cloud-init accounts
systemctl disable ssh.service ssh.socket >/dev/null 2>&1 || true
systemctl mask ssh.service ssh.socket >/dev/null 2>&1 || true
rm -f /etc/ssh/ssh_host_* /root/.ssh/authorized_keys
passwd -l root >/dev/null
touch /etc/cloud/cloud-init.disabled     # nothing creates users or keys from a cloud-init drive; per-VM material comes only through ou-bootstrap
apt-get clean; rm -rf /var/lib/apt/lists/* /var/log/*.log /root/.bash_history
