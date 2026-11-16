# Document engine reliability results (agent BK)

Date: 2026-11-16. Branch `docs-reliability` (from `docs-rollout`). Status words per ADR-0000: PASS/FAIL = executed in this session; evidence in `docs/status/docs-reliability-evidence/`. Only the **dev** channel was used. The production `ics` service/DB and Proxmox were not touched. Lab machines used: `ou-office1` (MemoryMax 3G), `ou-build1` (MemoryMax 8G, powered off afterwards).

## 1. Verdict

| Claim | Result |
|---|---|
| Root cause of the t08 "No child available" failure (D4 of `docs-upgrade-drill-results.md`) | **Found in the source** (section 2). The warning was **reproduced and measured**; a hard t08 failure was NOT reproduced again (0 of 25 rounds failed for that reason) |
| Fix: 16 pre-spawned kits + service start only returns when a real conversion works through a kit | PASS: warnings per t08 round under host load 60: before 24, 27, 28, 28, 22 (129 in 5 rounds), after 16 spares 0, 0, 4, 2, 0 (6 in 5 rounds); without load before 0, 10, 13, 24 (round 2 invalid, see 2.3), after 14, 8, 0, 0, 0 (8 spares) |
| Health check detects "no kit available" | PASS (section 3): probe = real text-to-PDF conversion; catalog check `kit-ready` |
| Rebrand of engine InfoURL and help URLs | PASS for InfoURL, help base URL, formula-error help, FAQ link, AI assistant name; Help dialog text needs no change (section 4) |
| ou-docs 26.04.6-ou3 built (online rebuilt, ~5 min, rc 0), packaged by the pipeline, dev channel only, install-smoke attested | PASS (section 5). Not promoted |
| `ou-office1` left on ou3; t03 28/0, t04 13/0, t05 9/0, t08 5/0 PASS directly after the upgrade; convert_roundtrip 9/9 | PASS (section 6); WOPI edit through OpenCloud is t03/t04; `wopi_edit_test.py` itself was NOT run (needs a WOPI host reachable from the node) |
| OCI image `ou/office:26.04.6-ou3` built and lab-signed, catalog office component updated | PASS built+signed; image start under a container runtime not exercised (only `ou-docs-ready` and the healthcheck executed inside it, rc 1 = "not ready" with no coolwsd, as expected) |

## 2. Root cause

### 2.1 Mechanism (source: `wsd/COOLWSD.cpp`, `kit/ForKit.cpp`, `common/Common.hpp`)

- A document needs a ready spare kit. `getNewChild_Blocks` waits `ChildSpawnTimeoutMs / 2` for one. With `mount_jail_tree=false` (our nspawn lab) `ChildSpawnTimeoutMs` is never reset to the short value, so it is 20 s / 2 = **10 s**; then it logs `getNewChild: No child available. Sending spawn request to forkit and failing.` and the connection fails.
- The pool is refilled only to `num_prespawn_children + 1` (was 4, so 5), and only when **no fork request is outstanding** (`rebalanceChildren`: `OutstandingForks != 0` returns). forkit takes one `spawn N` at a time (`ForkCounter = count`, it overwrites). A burst of 30 documents therefore needs about 6 sequential fork rounds. If a round takes more than about 1.7 s (cold files after an upgrade, CPU-loaded host) the last requests wait more than 10 s and fail.
- Right after `systemctl start` the web server answers HTTP (16 s unloaded, 33 to 41 s under load 60) while the first kits are still being created: the old health criterion (`/hosting/discovery` 200) reported healthy too early, and the drill ran t08 in that window.
- Memory is not the cause: cgroup `memory.events` oom 0 in all runs; a spare kit costs about 14 MB marginal (63 MB PSS each, mostly shared), 16 spares idle = 818 MB unit memory vs 654 MB with 4.

### 2.2 Reproduction (`blueprints/lab/upgrade/docs-t08-repro.sh`)
Stop coolwsd, delete child roots, evict the engine tree from the page cache (`posix_fadvise DONTNEED`, 8328 files), optionally 60 busy loops inside `ou-office1` (host load average 57 to 80, 48 cores), start, t08 at once, count the journal warning.

| Config | Rounds | t08 FAIL | "No child" warnings per round |
|---|---|---|---|
| before (4 spares), cold, no load | 5 | 1 (round 2: `/app/open` 500 = OpenCloud, 0 warnings, not kit related) | 0, 0(inv.), 10, 13, 24 |
| before (4), cold, load 60 | 5 | 0 | 24, 27, 28, 28, 22 |
| 8 spares + blocking start, cold, no load | 5 | 0 | 14, 8, 0, 0, 0 |
| 8 spares + blocking start, cold, load 60 | 5 | 0 | 0, 0, 0, 21, 4 |
| **16 spares + blocking start (shipped)**, cold, load 60 | 5 | 0 | 0, 0, 4, 2, 0 |

t08 itself retries `/app/open`, so the warnings are the defect signature; the original hard failure (22/30, 17/30) needed more adverse timing than reproduced here. Evidence: `repro-*-summary.txt`.

### 2.3 Honest limits
The hard failure was not reproduced; the claim is "mechanism confirmed in source, signature reduced about 20 fold under the same load". The 16 value comes from measurements at 4, 8, 16 only.

## 3. Health check

- `blueprints/build/collabora/deploy/ou-docs-ready`: bash only (no new package dependency; a `curl` dependency was tried and dropped because it added 38 advisories to the SBOM scan): POST of a tiny text file to `/cool/convert-to/pdf` over `/dev/tcp`, ready only for HTTP 200 and `%PDF`. Modes: one probe, `--wait SECS`, `--http` (5 s cache so polling cannot drain kits).
- Unit: `ExecStartPost=-ou-docs-ready --wait 150`, `TimeoutStartSec=200`: `systemctl start/restart` (and the upgrade) returns only when documents convert. Measured: start returned 16 to 20 s unloaded, 40 to 74 s at load 60, equal to "kits ready".
- Socket-activated `ou-docs-health.socket` on `[::1]:9981` (`Accept=yes`, user `cool`), nginx `location = /hosting/ou-ready` (`nginx-ou-ready.conf`; lab nginx and `nginx-office.conf.tmpl` updated). Executed: direct 0 rc, socket 200 "ready", via nginx TLS 200. Negative: nothing listening, wrong port and a server answering 501 all give rc 1 / "not ready: ..." (503 over HTTP).
- Catalog `office.yaml`: second check `kit-ready` (http, `/hosting/ou-ready`, 200); `ics/tests/test_deploy_plan.py` 24 passed. The edge component must route that path to `[::1]:9981`.
- OCI image: `HEALTHCHECK` now runs `ou-docs-ready`.

## 4. Rebrand

Executed on the built tree (ou3):
| Item | Change |
|---|---|
| `main.xcd` InfoURL | `https://collaboraoffice.com` to `https://officeunbound.com` (set in `recipe.sh install`, fails unless exactly one value matches; no engine rebuild) |
| Help URL | already a runtime option `help_url` (empty hides Help buttons); `ou-docs-configure.py` sets it from `OU_HELP_BASE_URL`, else `OU_PORTAL_URL` + `/help` (customer portal), else empty; image `OU_HELP_BASE_URL` |
| Browser formula-error help and FAQ link | patch `0003`: base from hidden input `init-help-url` (cool.html, filled by `FileServer.cpp` from `help_url`); no hard-coded `help.collaboraoffice.com` / `collaboraoffice.org` left in `bundle.js` (grep 0) |
| AI assistant prompt, WOPI console error, `--help` header, security hint | "Collabora Online" to "Office Unbound Docs" |
| Help dialog text (`cool-help.html`, `l10n/help-*.json`) | checked: contains no vendor name (only "collaborative"); the earlier note in `docengine-ou2-results.md` was wrong, nothing to change |
| Kept on purpose | copyright/licence texts, SDK links in the admin console only, gerrit commit link in About |
| Remaining | translated catalogs and one engine-sourced string (citation-unlink dialog, "Collabora Online") need an engine string change; welcome/update texts are disabled features |

**Open: the customer portal has no `/help` page yet** (`portal/app/main.py` has no such route), so a configured `help_url` would 404 until one exists.

## 5. Package and pipeline

- `recipe.yaml` ou_revision ou3, patch 0003; `build.sh package-prebuilt collabora` then `sbom` and `scan`: 16 packages, 0 advisories. `ou-docs_26.04.6-ou3_amd64.deb` sha256 `ec50edb1c9bc3aabf762b71e30869e26d41fd484c78ce62717646b777122afad`; stage tar sha256 `b2daf8f3...568b77` (engine unchanged; online rebuilt).
- `repo.sh publish collabora` (dev), new `repo.sh keep` re-admits ou1 and ou2 into dev as rollback targets (the signer only accepts hashes it knows); `serve`.
- `pkgtest-docs.sh dev`: 9 PASS, 0 FAIL (log in evidence). The old `record-installed` call is refused by the new signer (attestation scheme, security review 7); instead `ou-test-attest run deb-install-smoke <sha>` was run through its stable interface and `ou-release-sign record-test` accepted it ("recorded install-smoke=pass attestation a076dfbfbac98385"). Attestation: `attestation-ou-docs-ou3.json`. `pkgtest-docs.sh` still uses the old call (to update).
- The signer now signs each channel with its own key: `docs-pkg-upgrade.sh rekey` trusts the dev key (fingerprint asked from the signer, file from the repo must match: `3082B558DE35...D6322A4`).
- Not reproducible-build proven (unchanged status).

## 6. ou-office1 on ou3

- Downtime measured on a clean machine (after power-cycling `ou-office1` to drop thousands of leaked units): rollback ou3 to ou2: stopped 20.2 s, external non-200 31.8 s; **ou2 to ou3: stopped 47.5 s (includes waiting for kits), external non-200 45.5 s (145 failed probes at 0.2 s)**. ou2 returned at HTTP up (kits not ready), ou3 returns at kits ready.
- First measurement (194 s) was inflated by 7.8k leaked `run-u*.service` units from my own repro loop (`systemctl daemon-reload` took 50 s, twice in the postinst): fixed by `--collect` on every `systemd-run` in the repro and upgrade scripts.
- Right after the upgrade (OU_STRICT_SKIP=1): t03 28 PASS / 0 FAIL / 0 SKIP, t04 13/0/0, t05 9/0/0, t08 5/0/0 (27 s). convert_roundtrip through nginx: 9/9 (PDF text-marker check replaced by magic + Producer `Office Unbound Docs` because no PDF text tool exists on this host). coolwsd cgroup: oom 0, peak 2.77 GB of 3 GB.
- Final state: ou-docs 26.04.6-ou3 held and pinned, coolwsd active, 16 spares.

## 7. Defects found on the way

| # | Defect | Status |
|---|---|---|
| E1 | The lab coolwsd listens on `[::1]` only; `127.0.0.1` health probes (OCI `healthcheck.sh`, AF/BC scripts) fail there | probe tries both; OCI image listens `any` |
| E2 | Repro/upgrade scripts leaked failed transient units; systemd on the node became unusable (50 s reload) | fixed (`--collect`) |
| E3 | The postinst `find|cat` warm-up added is harmless (4 s cold) but not needed | left |
| E4 | `pkgtest-docs.sh` uses the removed record interface | open |

Residual risk: 16 spares are verified at 30 concurrent documents only, on a 3 GB machine whose peak is 2.77 GB; size production nodes at 4 GB (catalog `memory_mb` base 2048 is a lab figure).
