# Public alpha readiness (authoritative tracker)

Owner directive 2026-11-25: "Office Unbound — Public Alpha Release Directive". This file is the one place that says whether the public
alpha may be published. It supersedes the scorecard in `ALPHA-EXECUTION-QUEUE.md` for the public alpha. That file remains as history.
Status words: ADR-0000. "Verified" means executed evidence at the named commit. A row with no evidence is not done.

**Established 2026-11-25 on `ui-redesign` @ 64e0951** (after 0.13.6 "Meridian", released 2026-11-25, tag `v0.13.6` = 9374d80).
- Current version: `VERSION` = 0.13.6. The next public alpha is planned as **0.14.0**.
- Stabilization cycle: from 2026-11-25. New features are frozen, as in directive §3. Exceptions: the UI-audit release already in flight,
  and ADR-0021 step 1 (tenant naming, settings and DNS checker), an administration usability fix.

## Decision so far
**The public alpha is NOT publishable yet.** Three mandatory gates fail outright. Each needs owner action or new work:
1. **No public signed artifacts** (PA-01). GitHub releases carry notes only (0 assets on v0.13.6). An outside installation stops at
   alpha-install step 4.
2. **No clean-room install from public artifacts** (PA-02). It depends on PA-01 and on disposable infrastructure.
3. **Five High findings Partial** (PA-10). Their common root is OA-1: `administrator` still has `NOPASSWD: ALL`. Verified 2026-11-25
   with `sudo -n -l`.

## Gate status (directive §22)
| Gate | State | Evidence / blocker |
|---|---|---|
| 0 unresolved Critical | **Met** (no review found one) | SECURITY-REMEDIATION.md counts |
| 0 unresolved High in scope | **Not met** | PA-10 |
| Least privilege verified | **Not met** | OA-1 |
| Secret scanning (full history) | **Met** 2026-11-25 | gitleaks 8.30.1 over 531 commits: 0 findings after triaging 1 false positive (64e0951). CI `security` had failed on main since the finding was introduced (5f38cee, 76cdee6) |
| Artifact signing verified | **Partial** | the signed apt repo and OCI path are verified in the lab (ADR-0015). The public release key and public distribution do not exist yet (PA-01, OA-7) |
| Supported isolation verified | **Not met for multi-tenant** | PA-20. Single-tenant (one deployment per installation) is the only mode to advertise |
| Unverified destructive functions gated | **Partial** | PA-30 (ActiveSync wipe is an opt-in flag, not gated as experimental) |
| Public signed artifacts available | **Not met** | PA-01 |
| Public install docs complete | **Not met** | alpha-install.md step 4 says "needs the project's help" |
| No dependency on private infrastructure | **Not met** | PA-01, PA-03 |
| Clean-room install successful | **Not met** | PA-02 (the lab clean-room runs of A22 used internal scripts, not public artifacts) |
| Repeatable deployment | **Met (reference install)** | officeunbound..officeunbound8, the 3/3 core runs (multi-vm-deploy-results.md); in-place change succeeded on officeunbound8 (job 9dbe8139, 0.13.6) |
| Unauthenticated download access | **Not met** | PA-01 |
| Identity/SSO, portal, files, documents | **Met (reference)** | officeunbound8 live 2026-11-25: 14/14 checks ok, SSO into portal, webmail, files, office, chat |
| Mail/calendar/contacts in documented scope | **Partial** | webmail, EAS, DAV answer. Internet mail in and out is not verified (PA-40); anti-spam and AV are not deployed (PA-41) |
| Every advertised feature verified | **Not met** | PA-50 (docs and website reconciliation) |
| Backup and restore of core components | **Partial** | lab restores verified (restore-drill-results.md). Not scheduled, not encrypted, not off-host, and no restore of a real deployment (PA-60) |
| Upgrade verified or unsafe paths blocked | **Partial** | the in-place change works (0.13.6). Failure and interruption cases are untested on real infrastructure (PA-61) |
| Mandatory automated tests passing | **Met at 9374d80** | gate0121: pytest 1874, vitest 211, e2e 463+27, portal 52, all rc=0 |
| No unexplained skips | **To check** | PA-70 |
| Version metadata, SBOMs, license compliance | **Partial** | SBOM generation exists in the build pipeline (ADR-0008); not attached to releases. Counsel items are open (third-party-inventory.md) |
| Website accurate | **Owner** | the website is owner-managed: paste-ready copy will be supplied (PA-80) |
| Security reporting available | **Met** | SECURITY.md, private vulnerability reporting enabled on the repo |

## Issues
Severity: P0 = release blocker, P1 = operational blocker, P2 = quality, P3 = after the alpha. "Blocks" = blocks the public alpha.

| ID | Description | Sev | Component | Status | Required remediation | Verification | Blocks | Commit / evidence | Owner action |
|---|---|---|---|---|---|---|---|---|---|
| PA-01 | No public, signed, downloadable artifacts (golden image, `ou-*` debs, OCI images, manifest, SBOMs, public key) | P0 | release pipeline | Open | Implement ADR-0020 step 1: a release bundle attached to GitHub Releases, plus a signed release manifest, plus an ICS import from a downloaded bundle (offline-capable). Measure the sizes first (GitHub: 2 GiB per asset, no bandwidth charge for public repos) | An unauthenticated download plus `ou-verify` on a clean host; the ICS refuses a tampered or unsigned bundle | Yes | — | OA-7 key ceremony |
| PA-02 | Clean-room installs from public artifacts only (3 cycles; Ubuntu 24.04 and Debian 12; a different network) | P0 | installation | Open | Run after PA-01 | Recorded per directive §15 | Yes | — | disposable Proxmox capacity and DNS names (OA-11) |
| PA-03 | Public entry (nginx SNI map on the ICS) is hand-edited and repeated after every rebuild | P1 | gateway | Open | The ICS writes, validates (`nginx -t`), atomically activates and rolls back the map (ADR-0018 G1, GitHub #23) | Unit tests plus a rebuild on the reference install without hand edits | Yes (installer must not need hand edits) | — | sudoers for the narrow reload helper (with OA-1) |
| PA-10 | High findings Partial: R4-H2, R5-H2, R6-H1, R7-H3, R7-H5 (plus R5-H1, R5-H3, R6-H2, R7-H1, R7-H2, R7-H4 not Fixed on main as of 2026-11-16) | P0 | signing, privsep, HA fencing | To re-verify | Re-verify each against current main (branches merged since 2026-11-16); apply privsep (OA-1); signer and test-runner separation; R7-H5: document the HA standby as not supported in the alpha, or close it | `scripts/security_remediation_check.py` plus each row's tests | Yes | SECURITY-REMEDIATION.md | OA-1 |
| PA-11 | Fresh independent security assessment of the integrated platform (directive §5, incl. OWASP/API, auth, disable-revokes-everywhere) | P0 | all | Open | Owner approval is needed for a reviewer agent (§25); otherwise the controller does it, slower | A new review document with findings and fixes | Yes | — | approve the reviewer agent |
| PA-12 | Disabling a user must revoke every credential: known gaps are OpenCloud app tokens resurrecting on enable, the Gromox open-session workaround, and KI-2 Keycloak offline tokens | P0 | identity lifecycle | Partial | Close the gaps or document them as limitations with the exact scope | user-lifecycle acceptance script on a deployment | Yes (account takeover class) | user-lifecycle-results.md | — |
| PA-20 | Multi-tenant on shared infrastructure: network isolation (SDN) not applied or verified on real Proxmox | P0 | tenancy | Open | Gate multi-tenant mode as **experimental** (explicit opt-in); advertise single-tenant only | Test: multi mode needs an experimental acknowledgement; two disposable organisations cross-tenant test (directive §5.5) | Yes (as gating) | tenant-isolation-results.md (lab 209/0) | OA-8 SDN |
| PA-30 | ActiveSync remote wipe is a plain flag on `idm.user.disable` | P0 | identity | Open | Gate it behind the experimental setting (off by default), with explicit confirmation listing the devices | Test: refused unless enabled | Yes | known-limitations.md | — |
| PA-31 | Meetings and telephony catalog components (lab prototypes) | P1 | catalog | To check | Confirm they are `experimental` and not offered by default | Catalog test | Yes (claims) | `catalog.py` maturity | — |
| PA-40 | Internet mail (MX in and out, SPF, DKIM, DMARC, no open relay, no spoofing) not verified end to end | P1 | groupware | Open | Test on officeunbound.com (has public DNS) with a dedicated test address; open-relay and spoof tests | Recorded delivery and headers | No (documented scope) / Yes for a mail claim | — | OA-6 outbound 25 and PTR |
| PA-41 | Anti-spam and antivirus (rspamd, ClamAV) not deployed | P1 | groupware | Open | Catalog component or documented limitation | Spam and EICAR tests | Claim-dependent | — | — |
| PA-50 | README, ROADMAP, STATUS, alpha-install, known-limitations, website disagree (STATUS still says 0.10.0; README is 18 lines) | P1 | docs | Open | Reconcile with this tracker (directive §17) | `doclinks`, manual review | Yes | — | — |
| PA-51 | GitHub community files: CODE_OF_CONDUCT, SUPPORT, issue and PR templates, labels (alpha, installation, deployment, …) | P2 | repo | Open | Add the files; create the labels (`gh label create`) | Visible on GitHub | Yes (§18) | — | — |
| PA-60 | Backups: ICS backups are manual, unencrypted and on-host; deployment backups lack a schedule and a verified full restore | P1 | backup | Partial | Scheduled, encrypted, off-host-capable ICS backup; a deployment backup plus a restore to disposable VMs with data checks | Restore report with RPO/RTO | Yes (data-integrity gate) | restore-drill-results.md (lab) | off-host target (OA-12) |
| PA-61 | Upgrade failure paths (interrupted, failed, retry, controller restart, artifact verification failure) untested on real infrastructure | P1 | deploy | Partial | Drill on a disposable deployment | Upgrade report | Yes | upgrade-drill-results.md (lab) | — |
| PA-62 | The data mount of components added later is not mounted | P1 | deploy | Open | Mount on the change, or block adding a data-bearing component in place | Test plus a real change | Yes (data) | known-limitations.md | — |
| PA-70 | Skip audit of all suites | P2 | tests | Open | List the skips per suite with reasons | Recorded counts | Yes | — | — |
| PA-71 | Webmail calendar deep link opened an empty calendar (dashboard Calendar tile) | P1 | groupware | Fixed on branch (`uiaudit/groupware` 6ba3d6a), not built | Build and publish grommunio-web ou6, deploy | Live browser check | No | 6ba3d6a | — |
| PA-72 | UI audit (portal, org admin mobile, console, files, sign-in, chat, groupware) | P2 | UI | Merged on ui-redesign (4 of 5) | Gate and deploy (owner authorised 2026-11-25) | Gate plus live screenshots | No | 503b2ee | — |
| PA-80 | Website update (download, alpha testing, progress, MSP pages) | P2 | website | Open | Paste-ready copy after the gates pass | — | Yes (§22) | — | owner publishes |
| PA-81 | Optional diagnostic report with redaction (§21) | P2 | ICS | To check | Reuse `diagnostics.ts` / the console diagnostics panel; add an export with a redaction test | Unit test with seeded secrets | No | — | — |
| PA-82 | Client compatibility matrix with directive §14 levels | P2 | docs | Partial | Restructure client-compat-results.md | — | No | — | OA-9 devices and licences |
| PA-90 | Counsel items: GPL-2.0-only gromox files, trademarks, AGPL §13, ONLYOFFICE §7, fonts | P1 | legal | Open | Owner or counsel | — | Yes (license compliance) | third-party-inventory.md | OA-13 |

## Owner actions (consolidated; details and commands in `docs/admin/OWNER-ACTIONS.md`)
| ID | Action | Why | Blocks |
|---|---|---|---|
| OA-1 | Apply privilege separation: remove `NOPASSWD: ALL` from `administrator` (`ics/deploy/privsep/apply-privsep.sh`, dry-run first) | Root of the Partial Highs; least-privilege gate | Yes |
| OA-6 | Outbound TCP 25 and a PTR record for the public IP; a test mailbox at an external provider | Internet mail verification | Mail claim |
| OA-7 | Release signing-key ceremony: an offline primary key and a release subkey; publish the public key | Public signed artifacts | Yes |
| OA-8 | pve06 SDN or VLAN isolation | Multi-tenant (otherwise experimental) | No (if gated) |
| OA-9 | Outlook licence and devices for client tests | Compatibility matrix | No |
| OA-11 | Disposable capacity and DNS names for 3 clean-room cycles; a Debian 12 host | Clean-room gate | Yes |
| OA-12 | Off-host backup target (any SFTP, S3-compatible or NFS share) | Backup gate | Yes |
| OA-13 | Counsel answers (third-party-inventory.md) | License compliance | Yes |
| OA-14 | Approve one independent reviewer agent for the final security review (§25) | Independent review | Yes |

## Order of work (controller)
1. In flight: the UI-audit release (merge groupware, gate, deploy; owner authorised).
2. P0 work the controller can do without owner action:
   - PA-20 and PA-30 experimental gating; PA-31 check;
   - PA-10 re-verification against current main;
   - PA-01 bundle design and size measurement, then implementation (it ends at OA-7);
   - PA-03 gateway map;
   - PA-12 revocation gaps.
3. P1: PA-60 backups, PA-62, PA-61 drills, PA-40 once OA-6 arrives.
4. P2: docs reconciliation, community files and labels, diagnostics, skip audit, compatibility matrix.
5. Final: clean-room cycles (OA-11), independent review (OA-14), release 0.14.0 "Public Alpha" as a GitHub pre-release, website copy.
