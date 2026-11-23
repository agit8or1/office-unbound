# Alpha install guide: from an empty host to people signing in

**Office Unbound 0.10.0 "Juniper" is an alpha.** What that means (ADR-0011 section 9):

* You can install it from the release tag by following this page, and it deploys the full stack (sign-in, portal, mail with webmail,
  calendar and contacts, files, documents) onto your own Proxmox VE node, reachable from the internet with a trusted certificate.
* Features, data formats and the deployment layout may still change between 0.x releases. **Do not put production data in it**:
  an upgrade can require rebuilding a deployment, and rebuilding a deployment today starts it empty (see [Known limitations](known-limitations.md)).
* It has been run end to end on one reference installation (one ICS host, one Proxmox node, one public IP). Each step below names where it
  was run; read [Known limitations](known-limitations.md) before you start.

Terms (plan, approval, job, deployment, gateway) are in the [Glossary](glossary.md).

## What you need

| Item | Notes |
|---|---|
| ICS host | Ubuntu 24.04 (Debian 12 also installs), fixed IP, root, internet access. 2 vCPU, 4 GB RAM, 40 GB disk is enough for the controller. A VM on the same Proxmox works (the reference ICS is VM 126, outside the deployment pool). |
| Proxmox VE | One node (PVE 9.2 tested) with a storage for VM disks and a directory storage (`local`) for image imports, and a bridge the VMs can use (`vmbr0` tested). Each deployment uses 3 VMs; every VM gets at least 8 vCPU, 8 GB RAM and 40 GB disk. |
| A domain | DNS you can edit. The deployment uses `app.`, `auth.`, `cloud.`, `office.`, `mail.` and `autodiscover.` under it, plus `chat.`, `matrix.` and `mas.` when the deployment includes chat (shown by the console). |
| One public IPv4 address | Your router forwards TCP 80 and 443 to the ICS host. The ICS routes each name to the right VM without decrypting it. Mail (25/587/993) forwarding is listed by the console. |
| Signed images and packages | The golden VM image and the packages are signed by the release pipeline and served by the ICS's artifact service. **Read "Step 4" first**: there is no public download yet. |

## 1. Install the ICS (about 5 minutes)
```
sudo apt-get install -y git
git clone --branch v0.10.0 https://github.com/agit8or1/office-unbound.git && cd office-unbound
sudo ics/deploy/bootstrap.sh --listen-ip <ICS IP> --allow-cidr <your admin network, e.g. 192.168.22.0/24> \
     --hostname <console name, e.g. console.example.com> --admin <your user name>
```
The summary ends with the console URL, the certificate authority's SHA-256 and a one-time enrollment token. All flags are described in
[Installing the ICS](installing-the-ics.md). Run on two fresh Ubuntu machines and a fresh Debian 12 VM ([ics-installer-results.md](../status/ics-installer-results.md)).

## 2. One administrator? Switch to single-admin approvals
Every change is a plan that someone approves. With one person, set `ICS_APPROVAL_MODE=single_admin` in `/etc/office-unbound/ics.env` and
`sudo systemctl restart ics`. You then approve your own plans; each is still recorded in the audit log ([ADR-0017](../adr/0017-single-admin-approval-mode.md)).
The reference installation runs this way. With two or more people, leave the default (two-person rule).

## 3. Trust the console and sign in
Compare the printed SHA-256 with `sudo openssl x509 -in /etc/office-unbound/tls/ca.crt -noout -fingerprint -sha256`, import
`/etc/office-unbound/tls/ca.crt` into your workstation's trust store, open `https://<ICS IP>/`, enter the token, choose a password and confirm
an authenticator (TOTP) code. Details: [Quick start](quick-start.md) steps 2-3.

## 4. Images and packages (the step that is not packaged yet)
Deployments install only signed artifacts: the golden VM image (with the node agent) and the `ou-*` packages, served by the ICS's artifact
service over its own TLS port. On the reference installation they are built with the recipes in `blueprints/build/` and signed by the
release signer on the ICS host ([RELEASING.md](../RELEASING.md), [ADR-0008](../adr/0008-build-release-pipeline.md),
[ADR-0015](../adr/0015-artifact-distribution.md)). For this alpha:

* Install the artifact service with `bootstrap.sh --artifacts-listen-ip ...` ([Installing the ICS](installing-the-ics.md), flags table).
* Build and sign the golden image and the packages as described in RELEASING.md. This needs the build machines and signing keys of the release
  pipeline; **a public, signed download of the release artifacts is Planned**. Until then an outside installation needs the project's help for
  this step (open an issue).

## 5. Connect Proxmox
On the Overview page choose **Start guided setup**: node address, its certificate fingerprint (read on the node:
`openssl x509 -in /etc/pve/local/pve-ssl.pem -noout -fingerprint -sha256`), then sign in to Proxmox once; the ICS creates its own restricted
access and shows every change before it is saved. Approve the plan under **Approvals**. Details: [Connecting Proxmox](connecting-proxmox.md).
Run on the reference node (pve06).

## 6. Import the golden image
**Administration > Images**: choose the node, the release (for example `ubuntu-24.04-20261122`, version 14) and its SHA-256 from the signed
manifest, the import storage (`local`) and the target storage. Approve. The ICS verifies the signature and the hash, then creates the template
`ou-tpl-ubuntu-2404-v14`.

## 7. Deploy
**Deployments > New deployment**: customer, domain, size (the reference deployment uses the custom layout: identity + gateway, files + Office,
mail), node, storage and bridge. Review the plan (every VM, disk and step is listed) and approve. A deployment takes about 8 minutes and ends
with its health checks green. Run repeatedly on the reference node (officeunbound .. officeunbound7, 2026-11-20 to 2026-11-23).

## 8. Make it reachable from the internet
1. **Administration > Network & domains** lists the DNS records and router port forwards the deployment needs. Create the DNS records (all public
   names point to your public IP) and the forwards (80 and 443 to the ICS host, mail ports as listed).
2. On the ICS host, install the public entry once: copy `ics/deploy/public-entry/ou-public-sni.conf` to `/etc/nginx/`,
   `ou-public-http.conf` to `/etc/nginx/sites-available/` (and enable it), add `include /etc/nginx/ou-public-sni.conf;` to `nginx.conf`'s main
   context (needs `libnginx-mod-stream`), and install `ics-admin-fw.nft` from the same folder as `/etc/office-unbound/ics-admin-fw.nft` (80/443
   accepted; nginx decides). The console then answers only from your LAN/VPN unless you change **Management access** ([public-entry README](../../ics/deploy/public-entry/README.md)).
3. **Point the names at the deployment's gateway VM** (its address is on the deployment page): in `ou-public-sni.conf` the `proxy_pass` of the
   gateway upstream, and in `ou-public-http.conf` the `proxy_pass` of port 80. Then `sudo nginx -t && sudo systemctl reload nginx`.
   **Repeat this after every rebuild** (the VM gets a new address); the ICS does not write this map yet.
4. The same page's **Run checks** button proves which machine answers each name from outside.

## 9. Public certificate
**Administration > Network & domains**, section *Public certificates*: run **Test (staging)** first (proves every name validates from the
internet without counting against Let's Encrypt limits), then **Get certificates**. The gateway then serves a Let's Encrypt certificate for all names and renews it itself.
Since 0.9.4 the ICS keeps an encrypted copy, and a rebuilt deployment with the same names gets it back instead of ordering a new one (Let's
Encrypt allows 5 certificates for the same names per week). Run on officeunbound7, 2026-11-23: all six names verify; on its rebuild as officeunbound8 the same certificate came back without a new order.

## 10. Add people and sign in
On the deployment's page, **People**: add administrators and users (each gets a password you hand over). They sign in at `https://app.<domain>/`:
the portal opens Mail, Calendar, Contacts, Files and new documents with one sign-in. Mail apps: the deployment page lists the server settings.

## 11. Look after it
* Back up the controller before every upgrade: `sudo ics/deploy/backup/ics-backup.sh` ([Backup and restore](backup-and-restore.md)).
* Upgrade the ICS: check out the next release tag and run `sudo ics/deploy/install.sh` (or the same `bootstrap.sh` command). Migrations run
  automatically ([Upgrades](upgrades.md)).
* Health, incidents and alerts: [Day-2 operations](day-2-operations.md).

If a step fails, the job page shows the error in plain words; [Troubleshooting](troubleshooting.md) lists the known ones. Please report
problems as GitHub issues (security problems privately, see [SECURITY.md](../../SECURITY.md)).
