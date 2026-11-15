# Office Unbound lab integration spikes

**Collaboration spike (chat+meetings): see spike-collab/README.md, executed 2026-11-15.** **Status: identity + files spike (t01-t06, kc/files/office scripts) EXECUTED in nspawn machines on 2026-11-15, results in `docs/status/identity-files-lab-results.md`. Groupware spike (t10-t16, spike-groupware/) remains prepared, not executed.**

Original preparation note: Nothing in this directory has been run against a VM. No installer, test, or
CA script (apart from a local openssl dry run of `common/lab-ca.sh`, see "Validation done") has been executed
against real services. Treat every script as a first draft that will need fixes on first contact; each script header
says what is UNVERIFIED. Test results from this lab prove nothing about production.

Spikes answer the open items of ADR-0003 (groupware), ADR-0004 (identity), ADR-0005 (files/documents) using the
lab plans in `docs/status/groupware-eval.md` and `docs/status/files-identity-eval.md`. ADR-0006 applies: one isolated
stack, VMs from pinned cloud images via cloud-init, pinned versions.

## Layout

```
common/            lab.env (topology, non-secret), versions.env (pins + source URLs), lib.sh, lab-ca.sh, fetch-bundle.sh
spike-identity-files/
  cloud-init/      kc | files | office  .user-data.yaml
  kc/              install-kc.sh, install-openldap.sh, ldap-user.sh, realm-ou-lab.json
  files/           install-files.sh, opencloud.env.tmpl, csp.yaml.tmpl, nginx-cloud.conf.tmpl
  office/          install-office.sh, nginx-office.conf.tmpl
spike-groupware/
  cloud-init/      mail.user-data.yaml
  install-grommunio.sh (phase 1), post-setup-grommunio.sh (phase 3)
tests/             t01..t05 files+identity, t10..t16 groupware, run_all.sh, MANUAL-CHECKLIST.md, requirements.txt
```

## OS choice: Ubuntu 24.04 LTS on all four VMs

Ubuntu 24.04 ships PostgreSQL 16 and OpenJDK 21 (Keycloak 26 needs JDK 21) in its main archive, so no third-party
repos for the identity VM; grommunio's community repo has a **verified** Ubuntu_24.04 build (see below); one cloud
image and one patch process for the lab; supported to 2029. Debian 12 is also in the grommunio repo but ships
PostgreSQL 15 / JDK 17, which would need extra repos. Note: grommunio's *primary* supported path is the appliance
ISO/OVA (openSUSE-based); the deb path is the "best effort" community route (groupware-eval.md 1.3, 3). Control
comparison against the appliance is in the eval plan but not prepared here.

**Cloud image:** import the Ubuntu 24.04 (noble) amd64 cloud image once, record its `SHA256SUMS` entry and build
serial in the test report, and clone all VMs from it. (Not pinned in files: the image URL/serial was not fetched in
this preparation.)

## VM list and sizing (starting points from the eval docs, UNVERIFIED under load)

| VM | Role | vCPU | RAM | Disk | Lab IP (edit `common/lab.env`) |
|---|---|---|---|---|---|
| kc | lab CA, Keycloak, PostgreSQL 16, OpenLDAP | 2 | 4 GB | 20 GB | 10.99.0.11 `auth.ou-lab.internal`, `ldap.ou-lab.internal` |
| files | OpenCloud + WOPI, nginx | 4 | 8 GB | 40 GB OS + data disk (ext4/xfs) | 10.99.0.12 `cloud.ou-lab.internal` |
| office | Collabora CODE (Docker), nginx | 4 | 4-8 GB | 20 GB | 10.99.0.13 `office.ou-lab.internal` |
| mail | grommunio (MariaDB, postfix, nginx, gromox) | 4 | 6 GB min (8 recommended) | 32 GB + mailbox storage | 10.99.0.14 `mail.ou-lab.internal`, `autodiscover.ou-lab.internal` |

IPv6 must remain enabled on mail (cloud-init keeps it on). No VM has a public IP, public DNS name, port-forward or
public certificate. The operator workstation (and any Outlook test client) needs the four names in its hosts file.

## Pinned versions (verified 2026-11-15)

| Component | Pin | Source |
|---|---|---|
| Keycloak | 26.8.2 tar.gz, sha1 `7918de27...` | https://github.com/keycloak/keycloak/releases/tag/26.8.2 |
| OpenLDAP slapd | 2.6.10+dfsg-0ubuntu0.24.04.1 (Ubuntu archive; replaced lldap) | Ubuntu archive |
| OpenCloud | 9.1.0 linux-amd64, sha256 `183d95c3...` (published) | https://github.com/opencloud-eu/opencloud/releases/tag/v9.1.0 (9.1.1-rc.* deliberately not used) |
| Collabora CODE | `collabora/code:26.04.6.1.1@sha256:95f29f1c...` | https://hub.docker.com/r/collabora/code/tags ; same tag as https://github.com/opencloud-eu/opencloud-compose/blob/d4695d235639f7b14b63efef12d67cfbaab557a6/weboffice/collabora.yml |
| PostgreSQL / OpenJDK | 16 / 21 from Ubuntu 24.04 archive (versions unrecorded: log `dpkg -l`) | Ubuntu archive |
| grommunio (community, Ubuntu_24.04) | gromox 3.13.532.m667460b-1+170.1, web 5.2.104.g0bb6ff8de-1+745.1, sync 2.7.11.0d1fa88-1, dav 1.9.2.2555abd-1, admin-api 1.21.38.m4b3cd9c-1+98.1, setup 1.8.4 | https://download.grommunio.com/community/Ubuntu_24.04/dists/Ubuntu_24.04/main/binary-amd64/Packages (repo root listing https://download.grommunio.com/community/ shows Ubuntu_24.04 and Debian_12 present) |
| grommunio signing key | fingerprint `87B1B28E...231D9` | https://download.grommunio.com/RPM-GPG-KEY-grommunio (trust on first use; confirm out of band) |
| Python test deps | requests 2.34.2, python-docx 1.2.0, openpyxl 3.1.5, python-pptx 1.0.2 | PyPI |

Exact values and comments are in `common/versions.env`. OpenCloud is installed from the **binary** (checksum-pinned)
rather than `opencloud-compose`, because Collabora must live on its own VM and the compose module bundles it; env
semantics were copied from opencloud-compose commit `d4695d2` (docker-compose.yml, idm/external-idp.yml,
weboffice/collabora.yml, config/opencloud/csp.yaml) and are UNVERIFIED against the 9.1.0 binary until the first run.
The upstream compose Keycloak realm (`config/keycloak/opencloud-realm*.dist.json`) was used as a reference only;
our `realm-ou-lab.json` is written fresh.

## Lab TLS (internal CA, no public certs)

`common/lab-ca.sh` (run by `install-kc.sh`) creates a lab-only CA on the kc VM (`/root/ou-lab-ca`, root-only, name-
constrained to `ou-lab.internal` and the lab /24 so a leaked key cannot sign public names) and one RSA-2048 leaf
(397 days) per role with the right SANs. `common/fetch-bundle.sh` streams each role's bundle (CA cert + own cert + own
key) from kc to the target VM via the operator's ssh, writing only to `/root/ou-lab-bundle.tar.gz` (0600) on the target.
Installers extract it to `/etc/ou-lab/tls` and add the CA to the OS trust store. Tests and Outlook clients get only
the public `ca.crt`. The CA must never be trusted outside the lab. Name constraints are untested with every client
(set `LAB_CA_NAME_CONSTRAINTS=0` before first CA creation if one rejects it). No ACME, no certbot (the grommunio
setup is told to use the supplied certificate).

## Secrets

None in files. Installers generate secrets at runtime into `/root/ou-lab-secrets/` (0700 dir, 0600 files) and render
configs from them: Keycloak admin/DB, LDAP admin, LDAP bind, test-user passwords, OpenCloud internal
admin, Collabora admin, grommunio admin/DB. Test passwords reach the tests via environment (see
`tests/lab-test.env.example`), never via a file in the repo. `realm-ou-lab.json` contains a placeholder
`__LDAP_BIND_PASSWORD__` replaced at install time into a 0600 file readable only by the keycloak user.

## Order of execution

1. Create 4 VMs from the pinned cloud image with `cloud-init/*.user-data.yaml` (insert operator SSH public key, set
   static IPs matching `common/lab.env`); add the lab names to the operator workstation hosts file.
2. Copy `blueprints/lab/` to each VM (scp/rsync).
3. **kc:** `sudo spike-identity-files/kc/install-kc.sh`, then `sudo spike-identity-files/kc/install-openldap.sh test-users`.
4. From the operator workstation: `common/fetch-bundle.sh <kc> files <files>`, `... office <office>`, `... mail <mail>`.
5. **office:** `sudo spike-identity-files/office/install-office.sh`.
6. **files:** `sudo spike-identity-files/files/install-files.sh` (after kc + office).
7. **mail:** put the LDAP bind password on the VM (command printed by `post-setup`), `sudo spike-groupware/install-grommunio.sh`
   (phase 1), run `grommunio-setup -X` interactively with the printed answers (phase 2), then
   `sudo spike-groupware/post-setup-grommunio.sh` (phase 3).
8. Operator: `pip install -r tests/requirements.txt`, source `tests/lab-test.env.example` (edited) and the test-user
   passwords, run `tests/run_all.sh files` and `tests/run_all.sh groupware`; then work through `tests/MANUAL-CHECKLIST.md`.

## What each automated test proves, and what it does NOT

| Test | Proves | Does NOT prove |
|---|---|---|
| t01_oidc | lab-CA TLS to Keycloak; 4 client registrations + redirect/PKCE acceptance; roles claim per LDAP group; no-role user has no role and is refused by OpenCloud; token lifetime; offline token; user resolved from the shared LDAP (no autoprovisioning) | browser/MFA, native desktop/mobile login, back-channel logout, disable-user latency |
| t02_files_webdav | WebDAV write/read byte-exact, rename, delete; data intact after `opencloud` restart | desktop sync/conflicts, VM reboot, snapshot restore |
| t03_office_roundtrip | DOCX/XLSX/PPTX with known content stored unchanged and parseable (headings, table, formulas, notes, image) before/after restart | Collabora can open/edit/save them; fidelity after an editor save; formula cached values; co-editing |
| t04_wopi | Collabora discovery up; OpenCloud registers Collabora; `/app/open` mints WOPI token; CheckFileInfo/GetFile correct and TLS-valid; tampered token refused | Collabora -> OpenCloud reachability, rendering, PutFile/saves (needs UI) |
| t05_versions | version list on overwrite + restore via API; restore is versioned | versions from Collabora saves, retention, quota |
| t10_smtp_imap | LDAP-bound AUTH on 587/993, local delivery, token round-trip; outbound external submit handled | DKIM/SPF/DMARC, antispam, real inbound, attachments |
| t11/t12 DAV | DAV discovery + create/read/delete of event / contact | scheduling, free/busy, client behaviour |
| t13_ews | EWS endpoint challenges and answers GetFolder + FindItem | full EWS coverage; Outlook for Mac / Apple Mail behaviour |
| t14_activesync | EAS OPTIONS capabilities + FolderSync status 1 (449 provisioning = SKIP) | item sync, push, policies, real phones |
| t15_autodiscover | POX Autodiscover returns account + advertises MAPI/HTTP / EWS | Outlook accepting it (DNS/SCP/cert/profile) |
| t16_mapihttp | MAPI/HTTP framing: 401 challenge, PING emsmdb/nspi, best-effort Connect | profile creation, cached-mode sync, any ROP: needs **real classic Outlook** |

Output per check is `PASS|FAIL|SKIP name - reason`; exit 1 on any FAIL; SKIP exits 0 unless `OU_STRICT_SKIP=1` (exit
77, use for sign-off). Client-matrix items that cannot be automated (all Outlook builds, Apple, phones, desktop sync UI,
MFA, Collabora editing, disable-user timing) are in `tests/MANUAL-CHECKLIST.md`.

## Isolation guarantees for the mail VM (and how to confirm)

No public MX or DNS; domain `ou-lab.internal` only; postfix `default_transport`/`relay_transport` = `error:`; ufw denies
egress 25/465/587 and allows inbound only from the lab /24; no certbot. Confirm with MANUAL-CHECKLIST C6.

## Validation done during preparation (no installer executed)

See the preparation report: `bash -n` on every shell script, `py_compile` on every test, JSON/YAML parse of the realm
and cloud-init files, a local openssl run of `common/lab-ca.sh` in a scratch directory (CA + 4 leaf chains verify,
name constraints present), smoke run of the tests with no configuration (all SKIP, exit 0), and Report exit-code
checks (FAIL -> 1, strict SKIP -> 77). Python deps (python-docx, openpyxl, python-pptx) were not installed locally, so
t03's document generators/checkers have not been exercised at all.

## Known gaps / open questions

1. `grommunio-setup` is dialog-driven; unattended operation from `GSETUP_*` is UNVERIFIED -> phase 2 is manual.
2. The community repo may drop old builds; the exact-version pins in `/etc/apt/preferences.d` then fail loudly; update `versions.env` deliberately.
3. OpenCloud `init` flags, env var names (esp. roles claim handling, `/app/open`, `/graph/v1.0/me`, meta-version endpoints) are
   copied from compose/oCIS docs and unverified for 9.1.0; role UUIDs in t01 are oCIS values.
4. Keycloak LDAP `role-ldap-mapper` against lldap groups (groupOfUniqueNames, `member`), `uuidLDAPAttribute=uid`: from
   lldap docs for the user mapper; role mapper is our extrapolation. Fallback: group-ldap-mapper + manual group-role mapping.
5. gromox `ldap_object_id=entryUUID` and `ldap_user_displayname=cn` against lldap are guesses; `grommunio-admin ldap info/search` will show.
6. lldap `lldap_set_password` flag names (`--token`, `--base-url`) unverified.
7. Collabora -> OpenCloud TLS trust is via `ssl.ca_file_path` pointing at the lab CA: unverified; fallback is `ssl_verification=false` (lab only, record it).
8. Licensing (5-user community cap, trademark) and CODE production use remain owner decisions; this lab does not settle them.
9. Docker `docker.io` and Ubuntu archive packages are not version-pinned by the blueprint; versions are only logged.

## Identity/files lab status (2026-11-15, executed)
Directory = OpenLDAP (not lldap); Collabora = vendor CODE .deb (no Docker); OpenCloud binary 9.1.0 + separate
`opencloud-collaboration` unit; Keycloak 26.8.2 + OpenJDK 21 + Postgres 16 on Ubuntu 24.04 nspawn machines. Scripts
under spike-identity-files/ and tests t01-t06 were fixed against real behaviour; see the results file for deviations.
Items 4-6 of "Known gaps" (lldap) are obsolete; gromox against OpenLDAP is still untested (only LDAP-level facts verified).

## Lead note (2026-11-15) — superseded assumptions
- Substrate: Proxmox VMs are out of scope for now; spikes run in isolated systemd-nspawn machines on the ICS host (zone `oulab`, see docs/status/host-changes.md). Scripts written for cloud-init VMs are adapted per machine.
- Groupware: per ADR-0007 we ship our own source builds, not grommunio community packages. `spike-groupware/install-grommunio.sh` is kept only as a vendor-package reference; the authoritative path is `spike-groupware/build-from-source.sh`.
- Collabora CODE images are lab-only; production = own build (pending docs/status/docengine-source-eval.md).
- Licensing questions in "Unresolved questions" #5 are resolved by ADR-0007 + groupware-source-eval.md (no subscriptions).
