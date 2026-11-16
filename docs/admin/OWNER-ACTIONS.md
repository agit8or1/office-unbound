# Owner actions: one batched list for the Dec 31 beta

This page lists what only the owner can do: infrastructure, credentials, DNS, signing keys and devices. Items are in the order they unblock the beta stages. Commands are copy-paste ready.

**Nothing here is run by the controller.** Mark an item done by telling the controller. It verifies and records the result in `docs/status/ALPHA-EXECUTION-QUEUE.md`.

## Now (Stage 1, Nov 16–22)

### 1. Remove blanket sudo from `administrator` (least privilege)
Run this when the controller says the signer/attestor install is final; it does on Stage 1 completion. Keep a second root shell open while you run it.
```sh
cd /home/administrator/office-unbound
sudo ics/deploy/privsep/apply-privsep.sh            # dry run: prints every change
sudo ics/deploy/privsep/apply-privsep.sh --apply    # backs up to /root/sudoers-backup-<ts>/, validates with visudo first
sudo -l -U administrator                             # must NOT show (ALL) ALL
# undo if needed: sudo ics/deploy/privsep/revert-privsep.sh --apply
```

### 2. Create one extra console account to approve your own requests
SSH onboarding needs one approver who is not you.

Console → Administration → Users → Invite. Role: `approver`. Use a second person if you can; a second account of your own works for the lab but weakens two-person control.

### 3. Connect pve06 with "Connect with SSH"
The controller tells you when this is deployed.

Console → Setup → **Connect with SSH**:
1. Enter host `pve.agit8or.net` and SSH as root.
2. Check the host key on the pve06 console:
   ```sh
   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
   ```
   Confirm it matches the fingerprint the wizard shows.
3. Choose **Single node: pve06**, the pool, the storage (include `local` with "Import images"), the network, and the rights presets.
4. Approve with the account from item 2.
5. Verify on pve06:
   ```sh
   pveum user list | grep officeunbound
   pveum user token list officeunbound@pve
   pveum acl list | grep -i officeunbound
   id ou-ics
   ```
   Full checklist and undo: `docs/status/ssh-onboard-results.md`.

The wizard's discovery also reports the thin-pool totals and whether pve01–05 have node firewall rules. That answer decides SDN option A or B (decision recorded in the queue).

### 4. Rotate the Proxmox token that was pasted in chat (`officeunbound@pam!ics`)
After item 3 succeeds, the ICS uses its own `officeunbound@pve` token. Remove the old one:
```sh
pveum user token remove 'officeunbound@pam' ics
```
Remove the user too if nothing else uses it:
```sh
pveum user delete 'officeunbound@pam'
```
Then tell the controller, so it can delete `/etc/office-unbound/bootstrap/pve06-ics.token` from the ICS host.

### 5. Golden-image import storage
Only needed if the SSH wizard's "Import images" preset reports that `local` lacks the `import` content type. Run once on pve06:
```sh
pvesm set local --content "$(pvesm config local | sed -n 's/^\tcontent //p'),import"
```

## Stage 2–3 (Nov 23–Dec 6)

### 6. External mail: domain, DNS and reputation
These are needed for the beta gate "external mail delivery verified". Tell the controller:
- **Domain:** a test mail domain you control, for example `beta.officeunbound.com`.
- **Public IP:** the public IP that will send and receive mail. Outbound TCP 25 must be allowed by your ISP and firewall.
- **Inbound path:** how inbound 25, 587 and 443 reach the mail VM (NAT on `fw.agit8or.net`).

The controller then generates the exact records for you to create: MX, SPF, DKIM selector, DMARC, autodiscover/autoconfig SRV and CNAMEs, and the PTR request text for your ISP. **No DNS change is made by the controller.**

### 7. Release signing-key ceremony
Production and beta packages and images must not be signed with lab keys. About 30 minutes with the controller:
- generate offline primary keys and per-channel signing subkeys (dev/staging/stable) on an offline machine or YubiKey
- export public keys and pins
- store the revocation certificate offline (also copy `/root/ou-release-revocation-*.asc` offline now)

The controller prepares the script and the checklist when you schedule this.

## Stage 4 (Dec 7–13)

### 8. Per-customer network isolation (Proxmox SDN)
The full script, with pre-flight, verification and undo, is `docs/admin/proxmox-sdn-isolation.md`:
1. Fill in its variables (section 1).
2. Run the pre-flight. It is read-only.
3. Then run sections 2–4. Decided: **option A** if the pre-flight shows no node firewall rules on pve01–05, otherwise **option B** (the ICS deploys a router VM per customer, and you run no cluster-wide switch).

Also enable anti-spoofing on guest NICs. That is part of section 3: `macfilter` and `ipfilter` on.

After SDN, add the route on the ICS host. The controller can apply it with your OK, because it's a host change:
```sh
sudo ip route add 10.64.0.0/16 via 192.168.22.17   # and persist via netplan
```

## Stage 5–7 (Dec 14–31)

### 9. Outlook and mobile clients
For the client-compatibility evidence, you need to provide:
- **Windows desktop:** a Windows machine or VM with classic Outlook (Microsoft 365 Apps or Outlook 2021/2024) and the new Outlook.
- **Phones:** an iPhone and an Android phone (native mail plus the Outlook app).

Each client gets tested separately, and differences are documented, not assumed.

### 10. Beta partners
For each of 1–2 friendly MSPs, send:
- a contact
- the expected number of users (20–30 in total)
- their acceptance of the beta terms (invite-only, not production supported)

The controller prepares the onboarding pack: the install/admin/onboarding guides and known limitations.
