# Golden images for production: Debian 12 + Ubuntu 24.04, reproducible, independently boot-tested, signed manifest (agent BV, 2026-11-16)

Branch `golden-prod` (from `integration-7`). Status vocabulary: ADR-0000 / ADR-0009 s8. Everything marked "executed" was run in the isolated builder machine `ou-img1` (nspawn, `MemoryMax=3G`, powered off afterwards) and on the ICS host (pytest only). **Nothing was imported into, or created on, Proxmox; the production `ics` service and database were not touched.** Builds fetched packages only from `deb.debian.org` and `archive.ubuntu.com` (authorized, anonymous read) and keys from `keyserver.ubuntu.com`.

## 1. Summary

| Item | Result |
|---|---|
| Ubuntu 24.04 image | **Built** the same way as Debian: `mmdebstrap` from `archive.ubuntu.com` (main+universe, noble, -updates, -security) verified against the pinned **Ubuntu Archive Automatic Signing Key (2018)** `F6EC B376 2474 EDA9 D21B 7022 8719 20D1 991B C93C`; no loop mount, no libguestfs (`systemd-repart` + `CopyBlocks` of a prebuilt ext4 + FAT via repart). 220 packages, kernel `linux-image-virtual`. |
| Debian 12 image | Rebuilt with the new recipe (cloud-init no longer installed, persistent journal, `ou-seal`, reproducibility work). 229 packages. |
| Reproducibility | **Executed: two independent builds of each OS from the same recipe, epoch and package lock give a byte-identical qcow2** (and identical SBOM, package list, provenance, licence report). Hashes in s3. Residual non-reproducible inputs listed honestly in s3. |
| Independent boot test | `blueprints/build/guest-image/tests/image-boot-suite`: 6 stages, ~100 checks, qemu TCG, throw-away ICS simulator, restricted network. **Executed on both images**, results in s5. |
| Signed manifest v2 | schema, builder tool (`manifest.py`) and ICS verifier (`ics.guest.golden.verify_release`) with 26 refusal tests; rollback floor in the ICS database (migration `0012`), trust only from Settings. Signer side is **not** implemented here (owned by the signer agent; contract in s6). |
| Tests | see s8 |

## 2. Ubuntu 24.04 trust anchor (cross-checked)

| Source | What it showed (2026-11-16) |
|---|---|
| 1. `ubuntu-keyring` 2023.11.28.1 (`/usr/share/keyrings/ubuntu-archive-keyring.gpg`, `dpkg --verify` clean) | holds the 2012 archive key `790B C727 ...`, the 2012 CD-image key, and **`F6EC B376 2474 EDA9 D21B 7022 8719 20D1 991B C93C`** (2018) |
| 2. `https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xF6ECB3762474EDA9D21B7022871920D1991BC93C` | the same primary key, uid "Ubuntu Archive Automatic Signing Key (2018) <ftpmaster@ubuntu.com>"; shipped as `keys/ubuntu-archive-automatic-2018.asc` |
| 3. live `https://archive.ubuntu.com/ubuntu/dists/noble/InRelease` | `gpg --verify`: "Good signature", signing key = that fingerprint; the -updates and -security InRelease files verify against the same pinned key during every build (apt refuses otherwise) |
| (not used) `wiki.ubuntu.com/SecurityTeam/FAQ` | HTTP 503 on every attempt; reported, not relied on |

Only the 2018 key is pinned (noble is not signed by the 2012 key). `recipe.sh` refuses (exit 4) a key file whose primary fingerprint is not in `ARCHIVE_KEY_FPRS`. The earlier cloud-image mode (UEC key `D2EB 4462 ...`, `SHA256SUMS.gpg`) stays as `recipe.sh ubuntu-24.04 verify-upstream` only to cross-check the upstream image.

## 3. Reproducibility

**Inputs that are pinned:** `SOURCE_DATE_EPOCH` (required, no wall-clock fallback; names the image and clamps every file timestamp); the **package lock** `os/<os>.packages.lock` (every installed package as `name=version`, 229 / 220 lines, enforced with apt pin priority 1001; a version the archive no longer serves makes the build refuse; after the build the final `dpkg` list is diffed against the lock and a difference refuses with exit 6; `OU_RELOCK=1` is the deliberate way to refresh); the archive keys (fingerprint-pinned); the Office Unbound agent `.deb` (from the signed repo); the tool versions (recorded in the provenance); a pinned `mke2fs.conf`, fixed filesystem UUID and hash seed, fixed GPT/partition UUIDs and repart seed.
**Why not snapshot.debian.org:** it is not in `authorized-endpoints.md`. Instead the exact versions served by the signed archive of the day are recorded (lock + SBOM + the SHA-256 of every signed `InRelease` used, in the provenance). The lock is only reusable while the archive still serves those versions (Debian removes superseded versions from the pool; `snapshot` would lift that limit and needs the owner's authorization).

**Non-determinism found by building twice and diffing the raw disks (and fixed):**
1. ext4 inode `ctime/atime` copied by `mke2fs -d` from the builder's own file times (build wall clock) -> every inode rewritten to the epoch with `debugfs`; superblock times via `faketime`.
2. `lost+found`/journal times, hash seed, UUID -> `E2FSPROGS`-independent: pinned `mke2fs.conf`, `-U`, `-E hash_seed=`, `libfaketime` frozen at the epoch for mkfs/repart.
3. FAT directory creation timestamps from `mcopy` -> repart under `libfaketime`.
4. `/root/.gnupg/pubring.kbx` (written by `gpg` during the build, holds `time(NULL)`) -> removed from the tree.
5. syft's random CycloneDX `serialNumber` and wall-clock `metadata.timestamp` -> replaced by values derived from the package lock and the epoch (`sbom_normalise.py`).
6. `/etc/shadow` last-change days, `*.log`, `ldconfig` aux-cache, dpkg/debconf `-old` files -> clamped/removed.

**Executed result (builder `ou-img1`, epoch 1794787200 = 2026-11-16T00:00:00Z):**

| OS | build A | build B | result |
|---|---|---|---|
| Debian 12 | qcow2 `41f1c236bbb0d9bec878ab12f9b862fc08a8c44dd0c71e28a1155c1bad86894a` | same | **`cmp` identical** (190 MiB); SBOM `dc719087...`, package list `c3d73dae...`, provenance `5aea56c5...` identical too |
| Ubuntu 24.04 | qcow2 `2f25ddd54bae26edc865c85434a8f001712a8fe1e43b44088b1d3b44e7e62089` | same | **`cmp` identical** (168 MiB); SBOM `07f15a98...`, package list `47f362dc...`, provenance `a041c5e5...` identical too |

The path to that result is the evidence that the check is real: build 1 vs 2 first differed in ~161,000 bytes (inode times), then 2 bytes (FAT creation times), then 3 bytes (`/root/.gnupg/pubring.kbx` timestamps), then 0. The two builds of each pair ran concurrently on the same builder. The licence report is also identical (Debian 240 components, 87 allowed, 153 review, 0 denied; Ubuntu 234 / 89 / 144 / 0).

**Remaining honest limits.** (a) Reproducibility was demonstrated on **one builder** (same host file system, same tool versions): readdir order for `mke2fs -d` and the exact `mmdebstrap`/`systemd-repart`/`e2fsprogs`/`libfaketime` versions are part of the input; they are recorded in `*.provenance.json` and a different builder with different versions is not claimed to match. (b) The package lock is only as old as the archive keeps those versions. (c) The agent `.deb` is taken from the lab repo (`dev` suite); its own reproducibility was shown earlier (identical sha256 on two builds) but the repo's `Valid-Until` and signature are not part of the image bytes. (d) `unattended-upgrades` changes a running guest by design (security origin only); the golden image is the *initial* state.

## 4. Image content changes (both OSes)

* **cloud-init is not installed at all** (previously installed but disabled). The inert `/etc/cloud/cloud-init.disabled` marker and a `datasource_list: [ None ]` file stay so that a later accidental install is harmless.
* **`ou-seal`** (`ExecStartPost` of `ou-bootstrap.service`, runs only after a successful bootstrap): writes `/var/lib/ou-bootstrap/sealed`, disables the unit (no wants symlink). The unit has `ConditionPathExists=!.../sealed`, `!done`, `!failed` and `Restart=no`.
* **Persistent journal** (`Storage=persistent`, 64 MiB cap) so the independent tester (and an operator) can inspect what the first boot logged; the suite asserts the SMBIOS secret and the enrollment token never appear in it.
* `unattended-upgrades` origin is per distribution (`Debian-Security` / `Ubuntu` security pocket); the apt sources of the shipped image point at the pinned archive keyring.
* Not changed (still open from `golden-image-results.md`): 154 licence "review" items, no vulnerability scan, `systemd-boot`/UEFI path untested (BIOS/syslinux is what boots).

## 5. Independent boot-test suite (`kind=image-first-boot`)

`blueprints/build/guest-image/tests/`: `image-boot-suite` (program), `staticchecks.py`, `icssim.py`, `tcprelay.py`, `install-testsuite.sh`, `README`. Exit 0 = every check passed and every stage ran (`complete=True`, >= 70 checks), 1 = a check failed, 2 = infrastructure error (no attestation). It never trusts anything the image or the builder says: it generates the SMBIOS secret, the TLS certificate and its pin itself per run, simulates the ICS (protocol pinned to the real `ics.guest.callback` by a unit test), puts the guest on a `restrict=on` user-mode network where the **only** reachable host is the simulator (qemu `guestfwd` to a relay), and inspects the disk and persistent journal **offline after a clean ACPI power-off** (`debugfs rdump`, no mount, no loop device; symlinks in the untrusted tree are never followed).

| Stage | What it proves (check ids) |
|---|---|
| OFFLINE (S01-S23) | pristine image: no sshd/ssh packages, binary, unit, config or host keys; no authorized_keys / private ssh keys; **root locked, no account with a usable or empty password**, only root has uid 0, no `pam_permit` auth bypass; shipped nftables **policy drop** on input and forward, no tcp service rule, service enabled; **agent not enabled**, no agent state/keys in the image; bootstrap unit enabled, unsealed, with the seal/refuse-rerun conditions; **cloud-init absent**; no qemu-guest-agent; empty machine-id; no leftover secret files |
| A: first boot | **callback with valid HMAC** (exactly one valid report); *while the callback is in flight*: agent port silent, no ssh banner on 22, an unlisted port is **dropped, not reset** (control run in s5: with `nftables.service` masked the same probe is reset, so the check does discriminate a loaded default-deny policy); agent comes up only after the authenticated answer; its TLS certificate equals the fingerprint the guest reported (pinned enrollment) and its key fingerprint equals the reported one; unsigned `/v1/exec` refused, no other execution endpoint; **wrong enrollment token refused, the guest-generated token enrolls once, a second use is refused (one-time token)**; signed-but-not-allowlisted action refused (`not_allowed`: no unrestricted command execution); request signed by another key refused; clean power-off. Offline after boot: `done` + `sealed` present, `failed` absent, **bootstrap unit disabled itself**, agent enabled, `enroll.json` (token hash) consumed and `trust.json` written, firewall replaced by the ICS-authenticated ruleset that is still policy drop with no ssh rule, no ssh packages/keys; **the SMBIOS secret and the enrollment token are not anywhere on the disk (whole-disk byte scan incl. free blocks and journal), not on the serial console, not in the decoded persistent journal**; journal shows the bootstrap ran and finished |
| B: reboot with the SMBIOS values still present | enrolled agent comes back (`enrolled=true`); **the sealed bootstrap does not run and does not call the ICS a second time** (simulator counters unchanged: requests, TLS handshakes, valid reports); still no ssh and default-deny; still sealed, no leak |
| C: wrong certificate pin | the guest completes a TLS handshake with the simulator and then **sends nothing** (0 HTTP requests); agent never starts; `failed` marker, no `done`; firewall still the shipped default-deny; agent not enabled/never enrolled |
| D: impostor ICS (right certificate, acknowledgement made with the wrong secret) | the guest sent one authenticated report, **refused the bad acknowledgement**, agent never starts, `failed` marker, firewall unchanged |
| E: wrong HMAC secret in the guest (clone/stolen serial) | the ICS side **rejects the report** (`valid=0`), nothing enrolled, agent never starts |

**Executed results (2026-11-16, inside builder machine `ou-img1`, qemu TCG, no KVM; the final fixed suite, logs in `docs/status/golden-image-prod-evidence/suite-*.log`):**

| Image (sha256 prefix) | checks | passed | failed | complete | wall clock |
|---|---|---|---|---|---|
| `ou-golden-debian-12-20261116.qcow2` (`41f1c236bbb0d9be`) | 97 | **97** | 0 | yes | 14 min (02:10:18 - 01:56:23), while two builds and a pytest run shared the machine |
| `ou-golden-ubuntu-24.04-20261116.qcow2` (`2f25ddd54bae26ed`) | 97 | **97** | 0 | yes | 22 min under the same kind of load |

Defects the suite found in its own first run (fixed, then re-run from scratch): the persistent `/root/.ssh` directory exists but is empty (check relaxed from "absent" to "no files in it"); a guest that fails the callback still has its own freshly generated agent key/cert/token-hash files because `firstboot` prepares them *before* calling the ICS (they are unusable without the ICS answer; check C07 now asserts "never enabled, never enrolled" instead of "no files"). **Control for the default-deny probe:** the same image booted with `systemd.mask=nftables.service` answers a connection to an unused forwarded port with a reset ("closed"), the shipped image answers with silence ("silent"): the check distinguishes a loaded default-deny policy from "nothing listening".
**What the suite does not prove:** it did not run against a *mutant* image in the boot stages (static checks are exercised against good and bad synthetic trees in `test_golden_prod.py`, the boot-stage refusals are the guest's own behaviour in C/D/E); the real ICS code (PostgreSQL, `bootsecrets`) is not in the loop (the older `bootproof.sh` is), the simulator's protocol is pinned to the real functions by a unit test instead; and the suite ran in the same machine the builds ran in.

## 6. Signed manifest v2, rollback floor, attestor and signer contracts

**Manifest** (`manifest.json`, canonical JSON, signed as exact bytes by ECDSA P-256 / SHA-256 in `manifest.json.sig`; schema in `manifest.py`): `schema` `ou-golden-manifest-v2`; `name`; `os`; `version` (integer, strictly monotonic per OS); `created_at` (= source epoch); `image{file,sha256,size}`; `packages{file,sha256,count}` (the exact `name=version` list = the package-list hash); `sbom{file,sha256}` (CycloneDX); `provenance{file,sha256,source_date_epoch,recipe_sha256,package_lock_sha256}` (the full provenance file carries the archive InRelease hashes and tool versions); `boot_test{attestation,sig,attestation_sha256}` = the `ou-test-attest` v2 attestation (kind `image-first-boot`, name `first-boot`, sha256 of the **image**, result `pass`, `log_sha256` of the runner-captured log, `at`, `run_id`) verbatim.

**ICS `verify_release`** (`ics/guest/golden.py`) refuses unless: key is ECDSA P-256 and matches the operator pin; signature over the exact manifest bytes verifies; manifest is canonical, closed-schema, without duplicate keys; name/os/version/created_at valid and not future; image, SBOM, package list and provenance files are regular, non-symlink files matching their hashes; SBOM is CycloneDX with an inventory; package list is sorted/well-formed with the signed count; provenance agrees with the manifest (os, epoch, package-list hash, recipe hash); the attestation is **signed by the configured test-runner Ed25519 key** (so a self-made attestation of the builder is refused), is exactly the closed v2 shape, is for this image's sha256, kind `image-first-boot`, `pass`, newer than the build, not in the future and not older than 90 days, and its hash is bound; and **version is not below the floor** (equal version only for the same image bytes).
**Rollback floor (review 7 M-4):** table `golden_image_floor` (migration `0012`, down-revision `0011`): written only by `golden.advance_floor` (`INSERT ... ON CONFLICT DO UPDATE ... WHERE version < excluded`), a trigger refuses any UPDATE that does not raise the version, the application role has no DELETE; Proxmox tags are no longer a source of the floor. **Trust only from Settings** (`ICS_GUEST_GOLDEN_RELEASE_PUBKEY_FILE`, `ICS_GUEST_GOLDEN_RELEASE_PIN_SHA256`, `ICS_GUEST_GOLDEN_ATTESTOR_PUBKEY`); `golden.verify_for_import(rt, dir)` builds the `Trust`+`Floor` that `ImageImportSpec` now carries instead of caller-supplied key/pin; the provider re-verifies. Limit: there is still **no non-test caller** of `image.import` in a plan; `verify_for_import` + `advance_floor` are the two calls that step must make (advance only after a successful import).

**Integration with the attestor (read from `fixes-r7` `ou-test-attest`, attestation v2; consumed by `oci-signing` `testrunner/image-first-boot` + `image-boot-root`, commit 639c0b4).** `ou-test-attest run image-first-boot <path>` copies and hashes the image and runs `<lib>/image-first-boot <copy>`; exit 0/1 = pass/fail, anything else = no attestation; the runner hashes the program output as the evidence log. oci-signing's wrapper asks root helper `image-boot-root` to boot the copy in `ou-img1` with `bootproof.sh` and judges `evidence.json`. **This branch provides the test that helper should run instead** (`bootproof.sh`'s real-ICS/PostgreSQL enrollment proof remains valid and is a superset only for the real enrollment call; the suite adds all negative and hardening checks). Suggested change for the owner of `image-boot-root` (not made here, per instructions): after copying the image to the machine, run

```
systemd-run -M "$M" --wait --pipe -q /bin/bash -c 'cd /var/tmp/ou-guest-image/tests && OU_TEST_WORK=/var/tmp ./image-boot-suite /var/tmp/under-test.qcow2' | tee "$LOG"
```
and take the verdict from `${PIPESTATUS[0]}` (0 pass, 1 fail, other infra) **and** require the final `SUMMARY ... 0 failed ... complete=True` line and the first line's `sha256=` to equal the runner's hash of the copy. Install the suite root-owned into the machine with `tests/install-testsuite.sh` (from a reviewed checkout, not from builder output). The runner's `image-first-boot` timeout is 1800 s in `ou-test-attest` (`KINDS`): the suite needs 14-22 minutes (24 min if loaded) under TCG, so that constant must be raised (suggest 3600). Merge notes: `oci-signing` also rewrote `ics/tests/test_golden_image.py` (v1 `verify_release`); this branch replaced the v1 verification tests there with v2 and moved the helpers `make_release`/`verify` (conflict to resolve in favour of v2). Migration `0012` here follows `0011`; `fixes-r7` renamed its own to `0012r7/0013r7`, so the chain must be re-ordered at merge.

**Signer contract (for `ou-image-sign`, not implemented here).** New command `sign-manifest` (stdin: tar of `manifest.json`-less inputs: image, SBOM, package list, provenance, `<image>.attestation.json`): the signer must (1) re-hash every file itself; (2) verify the attestation signature with its root-owned `trust/test-runner.pub`, `sha256` == image hash, kind `image-first-boot`, `pass`; (3) build the manifest **itself** with `manifest.py build` semantics (never accept a builder-made `manifest.json`), taking `version` from its own state and refusing `version <= last signed version for that OS`; (4) sign the canonical bytes; print `manifest.json` + `manifest.json.sig`. Until then `recipe.sh ... sign` falls back to `manifest.py lab-sign` with a throw-away lab key (evidence in s7; not a release key).

## 7. End-to-end lab evidence of the manifest chain

Lab-only chain executed for both images with **throw-away keys generated by me** (the Ed25519 "test runner" key stands in for `ou-test-attest`, which is not installed on this host; the P-256 signer key stands in for `ou-image-sign`; script kept as `docs/status/golden-image-prod-evidence/lab-attest-LAB-ONLY.py`, it must never be used for a release): `recipe.sh <os> manifest` (`manifest.py build`, refuses an attestation that is not a passing image-first-boot for this image hash) -> `recipe.sh <os> sign` (`manifest.py lab-sign`) -> copy the six files to the ICS host -> `ics.guest.golden.verify_release` with the signer's SPKI pin and the lab attestor key: **accepted for both** (`ou-golden-debian-12-20261116.qcow2` version 1, `ou-golden-ubuntu-24.04-20261116.qcow2` version 1); the same Debian release with a floor of 2 is **refused** ("below the rollback floor 2"). Manifests, signatures and provenance are in `docs/status/golden-image-prod-evidence/`. The attestation's `log_sha256` is the SHA-256 of the suite log of that run.

## 8. Tests

* New `ics/tests/test_golden_prod.py` (56 tests): v2 acceptance, 26 parametrised tamper/bad-field refusals, wrong keys/pins, self-attested boot test refused, floor rules, DB floor monotonic + trigger + no DELETE + `verify_for_import` from Settings, manifest tool output verified by the ICS, simulator == real `ics.guest.callback`/`ou_agent.firstboot` (real guest client against the simulator: right pin once, replay refused, wrong pin sends nothing, wrong secret rejected), static checks on a clean tree and 17 single-regression trees, symlink escape, runner program contract.
* Adapted: `test_golden_image.py` (v2 `make_release`/`verify`, Ubuntu upstream checks now `verify-upstream`, key pins incl. the 2018 archive key), `test_image_import.py` (Trust/Floor in the spec, floor from the caller), `test_migration_chain.py` (head `0012`), `test_review5.py` (`fetch-upstream`).
* Targeted run after the last change: `test_review5 test_golden_prod test_golden_image test_image_import` = **82 passed**.
* Full suite (`ICS_TEST_ENV_FILE=/etc/office-unbound/ics-test-g.env pytest -q -p no:cacheprovider`, DB `ics_test_g`, log only): first run **925 passed, 2 failed** (a race in my own test and the old `fetch` step name in `test_review5`, both fixed); final run: @@FULL@@

## 9. Requirement-by-requirement

Columns follow ADR-0000 evidence levels: **Unit tested** (pytest/offline), **Integrated** (components wired together in code), **Lab tested** (executed in the nspawn lab/qemu TCG), **Real infrastructure** (Proxmox or real hardware; none of this work reached it, so every cell is "no").

| Owner requirement | Unit tested | Integrated | Lab tested | Real infrastructure |
|---|---|---|---|---|
| Reproducible Debian 12 and Ubuntu 24.04 guest images | recipe closed-shape + key-pin tests; SBOM normaliser | recipe -> manifest -> ICS verifier | **yes**: 2 builds per OS byte-identical (one builder) | no |
| Pinned and verified upstream signing keys | pins vs shipped key files (`test_golden_image`), refusals exit 4 | recipe `pinned_keyring` -> apt `signed-by` | **yes**: Debian (3 keys) and Ubuntu (2018 key) builds verified against pins; 3 sources for Ubuntu | no (wiki.ubuntu.com unavailable, noted) |
| Independent image boot testing | static checks on good/bad trees, simulator drift test (56+ tests in `test_golden_prod.py`) | program fits the `ou-test-attest` v2 contract (read from `fixes-r7`); `image-boot-root` change is a suggestion only | **yes**: run on both images (s5) inside the builder machine; **not yet** run through the real `ou-test-attest` -> signer chain (neither branch is merged/installed) | no |
| Signed image manifests | v2 verify: 26 refusal cases, key/pin, canonical form | `manifest.py` output verified by `golden.verify_release`; provider consumes `Trust`/`Floor` | **yes** (lab key, s7) ; production signer **not** implemented here | no |
| Immutable image checksums | image/SBOM/package/provenance hashes bound in the signed manifest; floor refuses same version with other bytes | provider re-hashes before upload (existing) + Proxmox `checksum` | yes (s7) | no |
| Secure initial enrollment | simulator protocol == real `ics.guest.callback` (drift test) | firstboot <-> callback <-> agent enroll in code | **yes**: suite stage A (+ earlier real-ICS boot proof) | no |
| One-time enrollment tokens | agent unit tests (existing) | guest generates token, hash only on disk | **yes**: wrong token refused, enrolls once, second use refused, `enroll.json` consumed (A/T01-T03, Z04) | no |
| HMAC-authenticated bootstrap callbacks | proof/ack/config MAC equal the real functions; wrong secret rejected | guest verifies ack + config MAC | **yes**: valid report accepted once (A), impostor ack refused by the guest (D), wrong-secret report rejected (E) | no |
| TLS certificate pinning | existing `test_guest_callback`; sim end-to-end with the real guest client (wrong pin sends nothing) | pin delivered via SMBIOS | **yes**: wrong pin -> 0 requests (C); agent certificate equals the reported pin (A02) | no |
| Secrets removed after enrollment | - | ICS `delete_secrets` (existing) | **yes** for the guest side: secret and token absent from disk, journal, console (L01-L04), token file consumed. **Limit:** the SMBIOS values stay in firmware tables until the VM is power-cycled with the Proxmox config cleared (ICS action, not exercised: no Proxmox) | no |
| Bootstrap access automatically sealed | static checks on unit/seal script | `ou-seal` as `ExecStartPost` | **yes**: `sealed`+`done`, unit disabled itself, reboot with SMBIOS present makes no second callback (B) | no |
| No permanent SSH dependency | S02-S06 on good/bad trees | - | **yes**: no sshd package/unit/keys, no banner on 22 before/after enrollment, default-deny drops (A,B,C) | no |
| No unrestricted guest command execution | - | agent allowlist (existing) | **yes**: no qemu-guest-agent, no exec endpoint, signed non-allowlisted action refused, unsigned refused (A/X01-X04) | no |
| Builder cannot fabricate boot-test evidence | self-attested / wrong-key attestation refused by `verify_release`; builder-made manifest never trusted by ICS without the runner's key | verifier trusts only the runner public key from Settings | **partial**: the lab attestation in s7 was made with a throw-away lab key by me (NOT the independent runner); the independent chain (`ou-test-attest` -> `ou-image-sign`) was **not** run end to end because fixes-r7/oci-signing are not merged or installed | no |
| Rollback protection | floor rules (equal/lower/higher/other bytes), DB trigger monotonic, app role cannot delete | `verify_for_import` + provider uses spec floor | yes (DB tests on `ics_test_g`) | no |

## 10. Not done / limits (honest list)

* No Proxmox import, no VM on real infrastructure; SeaBIOS/UEFI behaviour on pve06, PVE's SMBIOS rendering, DHCP and virtio on real hardware remain unproven (as in `golden-image-results.md` s6).
* The independent-tester guarantees hold only if the suite runs where the builder cannot change it (root-owned install in the boot-test machine) **and** the builder cannot edit the machine; in the lab the builder machine and the test machine are the same container `ou-img1` (that is how it was executed here), so the lab run demonstrates the suite, not the separation.
* `ou-image-sign`, `ou-test-attest` and `image-boot-root` were not modified (other agents' branches); see s6 for the exact integration changes.
* Reproducibility is per-builder; the lock needs the archive to still serve those versions; `libfaketime` is a new builder tool (recorded in the provenance).
* Same-day versions: `version` is an integer chosen by the signer; the image file name carries only the date.
* The suite parses a hostile journal with the host's `journalctl` (best effort, `timeout 60`); the authoritative leak check is the raw byte scan. A memory-corruption bug in `journalctl` or `debugfs` would be a host risk: run it in the throw-away machine only.
* 154 (Debian) / 144 (Ubuntu) licence "review" items and vulnerability triage of the images are still open.
