# Document-tier upgrade and rollback drill on ou-office1 (agent BC)

Date: 2026-11-15. Branch `docs-rollout` (from `docs-ou2`). Same pattern as the A21 drill (`upgrade-drill-results.md` on `release-ag`). Status words per ADR-0000: PASS/FAIL = executed in this session, logs in `docs/status/docs-upgrade-drill-evidence/`. Only the **dev** channel was used (nothing promoted; promotion is being replaced by BA). The production `ics` service/DB, Proxmox and every machine other than `ou-office1` (repo `ou-repo1` only read via HTTP, `ou-files1`/`ou-id1` only used by the tests) were not touched. Scripts: `blueprints/lab/upgrade/{docs-pkg-upgrade.sh,docs-suite.sh,docs-env.sh,docs_integrity.py}`.

## 1. Verdict

| Claim | Result |
|---|---|
| Current ou1 build published to dev as package 26.04.6-ou1 (rollback target next to ou2) | PASS (section 2, defect D1) |
| ou-office1 migrated from the tar-installed ou1 to the signed package ou-docs 26.04.6-ou1: pinned (Pin-Priority 1001), held, config preserved, vendor `coolwsd` removed (config state `rc`), engine tree byte-identical | PASS |
| t03 / t04 / t05 / t08 through OpenCloud on the package ou1 | PASS 28/13/9/5 checks, 0 FAIL |
| Pinned upgrade to 26.04.6-ou2, suite re-run | t03/t04/t05 PASS; **t08 FAILED twice right after the upgrade (22/30 and 17/30 sessions), then PASSED in 5 later runs on ou2** (section 6, D4, open) |
| Product name end to end: PDF `Producer` after a real edit/save through OpenCloud | PASS: ou1 `Collabora Office 26.04.6.1 (X86_64)`, ou2 `Office Unbound Docs 26.04.6.1 (X86_64)` |
| Rollback by pinned downgrade to ou1, verified | PASS (Producer back to "Collabora Office", engine tree hash identical to the original) |
| Roll forward to ou2 | PASS (full suite 28/13/9/5, Producer "Office Unbound Docs") |
| Document data integrity across all steps | PASS (section 5) |
| ou-office1 final state | ou-docs 26.04.6-ou2, held, pinned, coolwsd active |

## 2. Preparation: ou1 into dev (D1)

`repo.sh publish` replaces the dev pool of a component with the current build only (it does `rm -rf` of the component's dev pool and the artifact check pins the version to `recipe.yaml`, now ou2), so a downgrade target cannot be published through it. New subcommand **`repo.sh retain <component> <suite>`**: copies the older versions of the component that are in another channel's pool (here the ou1 `.deb` of `stable`, sha256 `b1c5383b...52f8dd`, the same build as the tar that AF installed: engine tree hash comparison below) into dev, admits them through `ou-release-sign admit dev` (hash ledger) and re-indexes/signs. Executed `repo.sh retain collabora stable` then `repo.sh serve`: dev now lists `ou-docs 26.04.6-ou1` and `26.04.6-ou2`. First attempt put nothing in (bug in my function: `strict_dir` overwrites the global `$d`; admitted 1 file, ou2 only), fixed by not reusing that variable. Nothing was promoted.

## 3. Procedure (`docs-pkg-upgrade.sh`, runs from the ICS host through `systemd-run -M ou-office1`, no ssh)

`pre`: backup `/var/backups/ou-docs-drill/20261115T232718Z` on the node (config tar of `/etc/coolwsd`, the unit, nginx sites, apt config; dpkg state and holds; sha256 inventory of `/opt/officeunbound-office` (4729 files, tree hash `00f16b7a964b24a5`), `/usr/bin/cool*`, `/usr/share/coolwsd` (3261 files)). Documents are not stored on this machine (OpenCloud holds them); the integrity check is therefore end to end (section 5).
`migrate <v>`: fetch the repo key, **check fingerprint `5D2750D0...F84C1B`**, dearmor, apt source `deb [signed-by=...] http://192.168.186.149:8077 dev main`, pin file, `apt-get update`, unhold the vendor `coolwsd`/`code-brand`, `apt-get install --download-only` while the node still serves, stop `coolwsd`, `apt-get install ou-docs=<v> --force-confold`, `apt-mark hold ou-docs`, install the lab unit, start, wait for `/hosting/capabilities`.
`change <v>`: same for upgrade/downgrade (`--allow-downgrades --allow-change-held-packages`), download first so that a failed download never leaves the node down.
A probe loop on the ICS host requests `https://office.ou-lab.internal/hosting/capabilities` (through nginx) every ~0.2 s during every step.

## 4. Timings (measured)

| Step | Download (service up) | coolwsd stopped (stop to start) | Until capabilities answer on loopback | External probe, first non-200 to last non-200 | Suite |
|---|---|---|---|---|---|
| migrate tar-ou1 to package ou1 (incl. vendor removal) | 10.3 s | 21.9 s | 32.4 s | 32.0 s (probe stopped too early, window slightly longer) | all PASS |
| upgrade ou1 to ou2 | 9.7 s | 17.4 s | 27.5 s | 26.4 s | t08 FAIL (D4) |
| rollback ou2 to ou1 (pinned downgrade) | 4.3 s | 19.0 s | 29.3 s | 28.2 s | all PASS |
| roll forward ou1 to ou2 | 4.7 s | 17.0 s | 30.3 s | 29.6 s | all PASS |

External pattern of every change (probe logs in the evidence directory): HTTP 502 from nginx for ~21 s (stop, package unpack, systemplate rebuild by the postinst, engine start), then 5 to 8 probes that time out after 1 s each (first request after start is slow), then 200. Open sessions are cut at the stop (coolwsd restarts; clients reconnect and reload). A zero-downtime path does not exist for a single node; with the OCI image or a second instance behind nginx it could (not done).
Suite runtimes: t03 27 to 52 s, t04 4 to 5 s, t05 1 s, t08 25 to 44 s.

## 5. Data integrity

`docs_integrity.py seed` created `bob/docdrill/` with six documents written twice each (DOCX x2, XLSX, PPTX, TXT, plus `edit-target.docx`). `check` re-reads every file through OpenCloud WebDAV after every step and compares sha256 and the version count (via the meta endpoint) with the recorded values; `edit` does the intended edits.

| After step | 5 untouched canaries (sha256 prefix `86d54782`, `6a71091b`, `4f3773c1`, `f58cca95`, `b317167f`) | edit-target.docx | Versions |
|---|---|---|---|
| seed (baseline, tar ou1) | recorded | `d318b14b` | 1 each |
| after real edits on tar-ou1 (2 Collabora saves) | unchanged | `71ba5f2c` (recorded after the edit) | 5 (the test runs and my edits each add a version) |
| after migrate to package ou1 | unchanged, 0 FAIL | `71ba5f2c` == recorded | 5 == recorded |
| after ou2 upgrade | unchanged | `88f2ee54` == recorded | 6 == recorded |
| after rollback | unchanged | `47295fed` == recorded | 7 == recorded |
| final (after roll forward + edit) | unchanged, 0 FAIL | `b953bfe1` / `4b57c090` (recorded after the last intended edit) | 8 / 9, never decreased |

Every check line is PASS: only the intended edit-target changes, and each change was an intended Collabora save (marker found in the stored DOCX). The three upgrade steps themselves never changed a stored byte (check immediately after each step precedes the next edit). Engine-level identity: after the migration the sha256 tree of `/opt/officeunbound-office` was `00f16b7a964b24a5`, equal to the tar-installed one (so the repo ou1 deb is the same build AF installed); after the rollback again `00f16b7a964b24a5`; ou2 `fc742cb3aa93207b`.

## 6. Product name end to end

`downloadas` (the browser's Download as PDF) is silently ignored when the document comes from OpenCloud (no reply at all within 60 s; export is not allowed by the CheckFileInfo of OpenCloud; `exportas` is a syntax error in this version). The working real path: Collabora `saveas url=wopi:<name>.pdf format=pdf` in the same session = WOPI PutRelativeFile, the PDF is stored into bob's OpenCloud folder (HTTP 200, `%PDF`, ~10 KB) and its `/Producer` (a UTF-16 hex string) was decoded:

| Version | PDF Producer |
|---|---|
| tar ou1 / package ou1 / after rollback | `Collabora Office 26.04.6.1 (X86_64)` |
| ou2 (first install and after roll forward) | `Office Unbound Docs 26.04.6.1 (X86_64)` |
`/hosting/capabilities` says `Office Unbound Docs` already on ou1 (config-level name), the engine string changes only in ou2.

## 7. Defects and fixes

| # | Defect | Fix / status |
|---|---|---|
| D1 | `repo.sh publish` cannot keep an older version in dev (pool replaced; version pinned to recipe) | `repo.sh retain` (section 2). Own bug in the first version of it fixed |
| D2 | The AF unit used `/opt/ou-docs/systemplate`, but the package postinst only (re)builds `/opt/cool/systemplate`. After a package upgrade the unit would have kept running on the stale systemplate (old engine libraries: the PDF producer would not have changed) | Unit changed to the package's work dirs `/opt/cool/{systemplate,child-roots,cache}` (`blueprints/build/collabora/deploy/coolwsd.service`); `/opt/ou-docs` (44 MB) is left over on the node, unused |
| D3 | Installing `ou-docs` fails when the vendor packages are on hold ("held broken packages"): `ou-docs` Conflicts/Replaces `coolwsd`, and AF had held `coolwsd` and `code-brand` | `migrate` unholds them before the download-only step. First attempt failed in that download step with the node still serving (no downtime). The vendor `coolwsd` is now state `rc` (removed, config left), `collaboraoffice*` still installed; vendor recovery is the AF tar in `/var/backups/vendor-code/` |
| D4 | **t08 (30 concurrent sessions) failed twice directly after the first upgrade to ou2**: 22/30 then 17/30 loaded; journal: 60 x `getNewChild: No child available. Sending spawn request to forkit and failing`, `Kit for DocBroker connection lost`, unlock 500; no OOM (cgroup `memory.events` all 0, machine peak 3.07 GB of 3 GB cap incl. page cache, coolwsd peak 2.43 GB), host load average 10 to 18 (other agents' builds). Not reproduced in the following 5 ou2 runs (4 with a fresh service after the roll forward, one in the full sequence) and the ou1 runs passed | **Open, intermittent, cause not proven.** Hypotheses: forkit cannot spawn kits fast enough when the host is CPU-loaded right after a fresh service start (coolwsd refuses instead of queueing) or the ou2 kits are slower to start; ou2 peak memory is close to the 3 GB cap. Not changed. Recommended before production: `num_prespawn_children` is 4 here, test with a higher value and a 4G machine, and run t08 several times under load on ou1 vs ou2 |
| D5 | `eval` of `test-users.env` prints an error containing a value when the file has a key that is not a shell identifier (`OU_PASSWORD_SVC-OCQUOTA=...` in this lab): the value of the service account **appeared once in this session's terminal output** | `docs-env.sh`/`docs-suite.sh` now only eval `OU_PASSWORD_[A-Z]+` lines with errors discarded. The value is a lab service-account password and appeared in the agent transcript: rotate it if that transcript is retained |
| D6 | Probe stopped before the migrate recovery | `probe_stop` now waits 6 s (the window of the three later steps is complete) |

## 8. Not done / limits

- No browser UI test; the PDF export is the PutRelativeFile route, not the download dialog. The `downloadas` ignore is OpenCloud's export policy (not verified in OpenCloud config).
- No co-editing and no sessions open during the stop (they are simply cut); no data lost because every save had completed.
- Packages are in `dev` only; no promotion; the repo `Valid-Until` of dev is 2026-11-29 (re-sign needed after).
- D4 is open. Reproducibility of the engine build is still NOT PROVEN (AZ).
- The vendor `collaboraoffice*` packages and `/opt/collaboraoffice` remain installed (purge after sign-off).
