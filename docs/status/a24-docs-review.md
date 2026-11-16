# A24 administrator documentation review (agent BG)

Scope: `docs/admin/**`, `docs/runbooks/**`, `docs/RELEASING.md`, `ics/README.md`, `ics/deploy/**`, ADRs and `docs/status/*-results.md`, read against the tree of `main` (416aafe) and, for the warm standby, branch `integration-6`.
Method: every cited repository path and every `ics.cli` sub-command in the guide is now checked by `scripts/check_doc_links.py` (also run in `.github/workflows/roadmap.yml`). No command was executed against any host; the guide documents only commands whose script or CLI sub-command exists in the repo. Acceptance A24 stays **Implementing**: the guide was not followed end to end by a person who did not write it, which is what A24 needs (see "Not verified").

## What was added or changed
New: `docs/admin/README.md` (index, labels, reading order), `customers-and-approvals.md`, `deploying-a-customer.md`, `day-2-operations.md`, `upgrades.md`, `ics-recovery-and-standby.md`, `security-model.md`, `scripts/check_doc_links.py`. `docs/admin/index.md` is now a pointer to the README.

## Contradictions fixed in this change
| Where | Problem | Fix |
|---|---|---|
| `docs/admin/connecting-proxmox.md` (capability table), `operating-the-ics.md` ("Deployments"), `known-limitations.md`, `quick-start.md`, `glossary.md` | Said no `docs/status/first-real-deployment.md` exists and labelled deployment "In development". The file exists on main; progress.json labels the deployment engine **Implementing** | Relabelled, linked the evidence, new page `deploying-a-customer.md` |
| `docs/admin/known-limitations.md` | "Product-grade backup ... is Planned". progress.json has "Encrypted off-host backups with measured RPO/RTO" as Integrated in lab | Reworded, with the real gaps (ICS tier, replication, S3) |
| `docs/admin/known-limitations.md` | "No HA/standby ICS" with no mention of the standby work | Points to the standby page, marked pending merge |
| `docs/admin/lab-proven-components.md` | Cited `0001-context-deep-link.patch`; the file is `0002-context-deep-link.patch` | Corrected (found by the new checker) |
| `docs/admin/users-and-access.md` | Customer section duplicated in the new page | Replaced by a pointer |

## Contradictions still open (not changed here; owner of the file should decide)
| File | Problem |
|---|---|
| `ics/README.md` ("Not implemented yet") | Says no Proxmox mutation or deployment execution exists, and no user-disable endpoint. Both exist (`ics/ics/deploy/`, `user.disable` in `ics/ics/actions.py`, `ics.cli disable-user`) |
| `ics/README.md` (API summary) | `POST users` documented as "viewer/operator only"; the plan flow `user.invite` is the current path (the summary lists it separately; the two should be reconciled) |
| `docs/runbooks/ics-recovery.md` on main | "Not yet covered: HA/standby controller". The integration-6 version of this runbook adds the standby section; merge it together with the code, or the guide and the runbook disagree |
| `docs/admin/installing-the-ics.md` vs `quick-start.md` | Install time stated as "about 2 minutes" and "3-5 minutes" |
| `docs/admin/installing-the-ics.md` ("Production contains no sample data") | Says the hand-run purge has no tool; fine, but `docs/status/host-changes.md` is the only record of the commands. A generic purge procedure is Planned |
| `docs/RELEASING.md` step 9 | Tells an operator to use `bootstrap.sh ...` without saying "with the same arguments as the first install"; the upgrades page says it |

## Features undocumented (exist in code, not in the guide)
| Feature | Where | Note |
|---|---|---|
| Telephony user actions `idm.user.set_extension`, `idm.user.issue_sip_credential`, `idm.user.devices` | `ics/ics/actions.py` | Absent from `users-and-access.md` action table (telephony lifecycle evidence: `docs/status/telephony-lab-results.md`) |
| `backup.prune` and the `backup.run/verify` action semantics | `ics/ics/actions.py`, `ics/ics/backups/` | Mentioned only as a list in `backup-and-restore.md`; no procedure for reading backup views or acting on RPO breaches beyond the product summary |
| `image.import` and the golden image build (`blueprints/build/guest-image/`, `docs/status/bootstrap-v2.md`, golden-image results on integration-6) | ICS provider, build recipe | Only summarised in `deploying-a-customer.md`; no admin procedure for importing the image because it has not been done on a real cluster. Needs an owner prerequisite page once it is |
| Guest bootstrap settings `ICS_ENVIRONMENT`, `ICS_GUEST_CALLBACK_URL`, `ICS_GUEST_CALLBACK_PIN_SHA256`, `ICS_GUEST_BOOTSTRAP_TTL_SECONDS` | `ics/ics/config.py` | Named in the deployment page; missing from the env-file table in `installing-the-ics.md` |
| Console **Administration > System** page and `/api/v1/version` | frontend `System.vue` | Now in `upgrades.md`; not in the console tour of `operating-the-ics.md` |
| Customers page of the Providers console (`CustomersPage.vue`) | `ics/frontend/src/views/providers/` | The guide describes the actions, not the screen; the screen was never exercised on a real backend |
| `ics.cli migrate-credentials`, `rewrap-master` | `ics/ics/cli.py` | Documented in `security.md`; not in the day-2 checklist |
| Chat, meetings and telephony deployment | `blueprints/` | No ICS deployment; documented as lab-only in `lab-proven-components.md`. A new engineer will look for an install procedure and find none |
| Clean-room installers (A22), tenant build scripts (`blueprints/lab/tenant/`) | `docs/status/tenant-isolation-results.md` | Lab tools; not in the guide because they are not product procedures |
| Warm standby (ADR-0012) | branch `integration-6` | Documented in `ics-recovery-and-standby.md`, marked pending merge; the links and commands listed in its `<!-- pending: -->` comment must be removed from that comment when the branch is merged (the checker fails until they are) |

## Procedures that are written but have no real-cluster evidence
Registering an endpoint through the console wizard; Mode A and Mode B permission setup; token rotation actions; scope change; customer approval links; credential vault pages; deployment of anything but one test container; the production (no-SSH) guest bootstrap; golden image import. These are labelled **Implementing** or "simulator-proven" in the guide.

## Not verified
- No person followed the guide cold. A24 needs a dry run by an engineer who has not seen the project, using only `docs/admin/`. The earlier quick-start dry run ([quickstart-dryrun-results.md](quickstart-dryrun-results.md)) covers install to inventory on Debian 12 only.
- Commands were checked for existence, not executed. Flags were taken from `--help` text and script headers, not run.
- The checker validates paths and sub-command names, not flag spelling or that an anchor in a non-Markdown file exists.
- No owner personal data or secrets were added; lab addresses are not repeated in the new pages (older pages still contain documented lab addresses and the `ou-lab.internal` name).
