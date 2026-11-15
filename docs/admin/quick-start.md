# Quick start: fresh Ubuntu 24.04 / Debian 12 host to "Proxmox connected"

For an IT administrator who is not a developer. Time: about 30 minutes plus the approvals. Pre-alpha lab software, not for production ([index](index.md)). Terms are in the [Glossary](glossary.md).
Steps 1-4 were executed on two fresh Ubuntu lab machines ([ics-installer-results.md](../status/ics-installer-results.md)) and, end to end, on a fresh Debian 12 VM on a real Proxmox node ([quickstart-dryrun-results.md](../status/quickstart-dryrun-results.md)). Steps 5-7 use the real-cluster procedure ([provider-proxmox-real.md](../status/provider-proxmox-real.md)); the one gap is flagged in step 7.

**You need:** a fresh Ubuntu 24.04 or Debian 12 host with a sudo-capable user (or root) and a fixed IP address; three people (one requester, two approvers) and an admin workstation; root on a Proxmox VE node (PVE 9.2 was tested).

## 1. Install
Put the Office Unbound source tree on the host and open a shell in its top folder, for example `sudo apt-get install -y git && git clone https://github.com/agit8or1/office-unbound.git && cd office-unbound`, or copy a tarball made with `git archive` and unpack it (the tarball route is the one the dry run used; a fresh Debian image has no `git`). Then run (replace the addresses with the host's console IP, your admin network and a DNS name):
```
sudo ics/deploy/bootstrap.sh --listen-ip 192.168.186.137 --allow-cidr 192.168.186.0/24 \
     --hostname ics1.ou-lab.internal --admin alice
```
Wait for the summary (about 3-5 minutes on a fresh machine; on a just-booted cloud image the installer waits for the system's own first-boot package job to release the apt lock, which can take a minute or two). It shows the console URL, the certificate authority (CA) **SHA-256** and, last, a one-time token for `alice`. Running the same command again is safe.

## 2. Trust the console certificate
Compare the CA fingerprint in the summary with `sudo openssl x509 -in /etc/office-unbound/tls/ca.crt -noout -fingerprint -sha256` on the host (the directory is root-only, so `sudo` is required, here and for copying the file: `sudo cat /etc/office-unbound/tls/ca.crt`) (read it on the host console, not copy it over the network). Then copy `ca.crt` (public) to your workstation and import it into the OS/browser trust store.

## 3. Create the first admin
Open `https://<listen-ip>/` (it redirects to `/ui/`), follow the enrollment page: token, your own password, then a TOTP code from your authenticator app. Log in. You land on the **Overview** dashboard; nothing opens automatically.

## 4. Create the two approvers
Registering Proxmox is a high-risk change: two approvers who are not the requester must approve it. On the ICS host, once per person (hand each printed token over privately; they enroll like step 3):
```
cd /opt/office-unbound/ics && sudo -u ics .venv/bin/python -m ics.cli create-admin --username approver1 --role approver
cd /opt/office-unbound/ics && sudo -u ics .venv/bin/python -m ics.cli create-admin --username approver2 --role approver
```
Each must be a different real person.

## 5. Prepare Proxmox (on a Proxmox node, as root)
Follow [Connecting Proxmox](connecting-proxmox.md): sections 1 (inventory token) and, if you want the ICS to create machines later, 2 and 3 (provision token, role, ACLs, template, ICS VM out of the pool). Minimum for "connected": the inventory token. Note the token secret once; do not paste it into chat.
Read the node's certificate fingerprint **on the node console**:
```
openssl x509 -in /etc/pve/local/pve-ssl.pem -noout -fingerprint -sha256
```

## 6. Connect from the console
On the Overview page choose **Start guided setup** (this is optional; **Integrations** offers the same). Enter the node address, check that the certificate fingerprint shown matches step 5, enter the token id and secret, run the connection test, review what was found, and send it for approval.

## 7. Approve and confirm
Log in as `approver1` and `approver2` in turn and approve the `endpoint.register` plan under **Approvals**. The job runs once. Then open **Infrastructure > Clusters/Nodes**: your cluster appears with live status within about 5 minutes.
**Status of this step:** the probe, inventory, and every Proxmox call it relies on were run against a real cluster, and the plan/approval/job path was exercised in the lab. Registering through this console wizard on a real cluster is not recorded in any evidence document yet; if it fails, send the error text, and note the console shows the exact `pveum` fix commands for missing permissions.

## Next
- Optional: **Start deployment wizard** builds a deployment plan and sends it for approval. Running a deployment on Proxmox is **In development** ([Operating](operating-the-ics.md#deployments-in-development)).
- Take a backup now: `sudo ics/deploy/backup/ics-backup.sh` ([Backup and restore](backup-and-restore.md)).
- Troubleshooting: [troubleshooting.md](troubleshooting.md).
