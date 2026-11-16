# Artifact distribution results (ADR-0015, agent CC, 2026-11-16)

Status vocabulary: ADR-0000. Branch `artifact-dist` (from `fullstack-plan`). Design: [ADR-0015](../adr/0015-artifact-distribution.md). Evidence: `docs/status/artifact-dist-evidence/` (`negative-matrix.log`, `source-restriction.log`, `server-and-client-state.txt`). Lab drivers: `ics/scripts/lab_artifact_client.py`, `lab_artifact_apply.py`, `lab_artifact_proof.sh`.

## 1. Status summary

| Part | Where | Status |
|---|---|---|
| Artifact service: nginx TLS front end (GET/HEAD only, no listings, rate limits, logs), Distribution registry reader (read-only) + unix-socket push instance, nftables allow-list, private CA | `ics/ics/artifacts.py` (rendering), `ics/deploy/artifacts/` (installer, units, publisher) | **VERIFIED-IN-LAB** on nspawn `ou-dist1` (Ubuntu 24.04, MemoryMax 1G) |
| Verifying publisher `ou-artifact-publish` (apt trees per channel, OCI image + signature) | `ics/deploy/artifacts/ou-artifact-publish` | VERIFIED-IN-LAB; unit-tested (gpg + ECDSA) |
| Guest bootstrap metadata: per-channel apt keys, CA scoped to the artifact hosts, per-repository signed identity | `ics/ics/guest/cloudinit.py`, `ics/agent/ou_agent/firstboot.py` (`validate_artifacts`, `apply_trust`), `guesthelper._apt_opts`, `render_image_policy.py` | VERIFIED-IN-LAB with the golden-image first-boot code path on `ou-dist-client1`; **not** booted on a real VM or golden image |
| `OU_ARTIFACT_*` configuration replaces `registry.ou.invalid` in plans; `plan["artifacts"]` in the hash; guest metadata injected by the executor (`agentport._artifact_fields`) | `ics/ics/artifacts.py`, `deploy/ops.py`, `deploy/plan.py`, `deploy/agentport.py` | Implemented and unit-tested; the executor path `_artifact_fields` is covered only indirectly (`callback_config` tests), **not** run in a deployment |
| `bootstrap.sh --artifacts-*` integration | `ics/deploy/bootstrap.sh` | Syntax checked, early argument validation executed (2 refusals); the artifact block inside a full bootstrap was **not** run (needs a fresh ICS install). The script it calls (`ou-artifacts-setup.sh`) was run and re-run |
| Backup coverage | `ics/deploy/backup/ics-backup.sh`, `ics-restore-inner.sh` | Implemented (config, CA key, units always; data with `OU_ICS_BACKUP_ARTIFACT_DATA=1`); backup/restore **not executed** |
| Health in the ICS | `/api/v1/system` -> `artifacts`, `python -m ics.artifacts health` | Implemented and unit-tested against an unreachable server; **not** run against the live lab service |
| Placement (b) platform VM | ADR-0015 | Documented only |

## 2. What was built and how it was run

* **Server `ou-dist1`** (clone of `ou-base-noble`, zone oulab, `MemoryMax=1G`, 192.168.186.120; free memory on the host was 8 GiB available before start): `ou-artifacts-setup.sh --listen-ip 192.168.186.120 --allow-cidr 192.168.186.0/24` (lab stand-in for 10.64.0.0/16) with the three channel release keys and the three channel image keys (public). Installed packages: nginx, `docker-registry` 2.8.2+ds1 (Distribution, Ubuntu archive, Apache-2.0), nftables, python3-cryptography. Re-run prints `changes this run: none`.
* **Seed content**: `ou-artifact-publish apt --src /root/build-repo` (a copy of the lab repo: dev 60 files, staging 59, stable 59, all verified against the pinned channel key; 30 s) and `ou-artifact-publish oci` for `ou/ou-softphone` 0.1.0-ou1 (sha256:efc5d8b4...b33941, 150 MB), `ou/meet-token-service`, `ou/synapse` from the lab registry on ou-build1 (signatures by the lab dev image key `cd28d8bc...`). `ou/office` (Collabora, large) was not copied; softphone is the signed image used for the proof.
* **Client `ou-dist-client1`** (clone of `ou-guest1`: Ubuntu 24.04, rootless Podman 4.9.3 as `ou-svc`, nspawn accommodations from guest-bootstrap-results): its trust configuration was produced by `lab_artifact_client.py render` (same `ArtifactMap` -> `GuestSpec` -> `callback_config` code as the ICS) and applied by the **real** `ou_agent.firstboot.validate_config` + `apply_trust` (the golden image's first-boot code): `sources.list` with `deb [signed-by=/etc/ou-agent/apt/keyrings/ou-dev.asc] https://192.168.186.120:8444/apt dev main` and the stable line, per-channel keyrings, `pinned-fingerprints`, `Acquire::https::192.168.186.120::CaInfo` (CA scoped to the host, not in the system store), `/etc/containers/certs.d/<host:port>/ca.crt`, `registries.d` with `use-sigstore-attachments`, `image-policy.json` (sigstoreSigned, one pinned key, per-repository `exactRepository`). See `server-and-client-state.txt`.

## 3. Positive results (executed)

| Test | Result |
|---|---|
| `pkg.install_pinned` (agent code, `guesthelper.install_pinned`) `ou-libhx=4.28-ou1` from the dev channel over TLS with the pinned CA, `Signed-By` per channel | `installed: 4.28-ou1, ok: true` (also the control run in the matrix, N8, from a clean apt state) |
| `podman pull --signature-policy /etc/ou-agent/image-policy.json 192.168.186.120:8444/ou/ou-softphone@sha256:efc5d8b4...` as `ou-svc` | rc=0, image id `c4f28a831b6b` (matrix P1, repeated after each tamper test was reverted) |
| Source restriction: nftables allow-list and nginx allow-list | allowed /24: 200 for `/healthz`, `/v2/`, `/apt/dists/dev/InRelease`; allow-list changed to 10.64.0.0/16 only: client connection **times out** (nftables); table removed: **403** from nginx on all three; restored: 200; re-run `changes this run: none` (`source-restriction.log`) |

## 4. Negative matrix (executed, `negative-matrix.log`)

| # | Attack | Result |
|---|---|---|
| N1 | signed image of a repository that is not in the VM's plan | `rejected by policy` (registry-wide scope is `reject`) |
| N2 | unsigned image (signature attachment removed from the registry store) | `A signature was required, but no signature exists`; after restoring, pull rc=0 |
| N3 | wrong channel key: image signed by dev, guest pinned the stable image key | `cryptographic signature verification failed` |
| N4 | tampered manifest bytes on the server | `Manifest does not match provided manifest digest` |
| N5 | tampered layer on the server | `flate: corrupt input` (blob rejected); after restore rc=0 |
| N6 | push from the client: PUT/POST/PATCH/DELETE on `/v2/...`, PUT/DELETE on `/apt/...`, `podman push` | all **405**; podman: `initiating layer upload ... StatusCode: 405`; the push registry is inactive and has no network listener (`ss`: only 127.0.0.1:5001 and nginx); direct POST on the loopback reader: 405 (registry-level read-only) |
| N7 | listings | `/apt/` 404, `/apt/dists/` 403, `/apt/pool/` 404, `/apt/dists/dev/` 403, `/v2/_catalog` 403, `tags/list` 403, `referrers` 403, `..` traversal 404; `InRelease`, `/v2/`, `/healthz` 200 |
| N8a | `.deb` modified after signing (clean apt state) | apt `Hash Sum mismatch`, `installed: null, ok: false` |
| N8b | `Packages.gz` modified after signing | `apt update failed ... Hashes of expected file`, nothing installed |
| N8c | `InRelease` text modified | `BADSIG`, `The repository ... is not signed`, nothing installed |
| N9 | wrong channel key for apt: stable keyring holds the dev key, VM installs from stable only | `NO_PUBKEY CE58A8B691F84C1B`, `not signed`, nothing installed |
| N9b | keyring key not in `pinned-fingerprints` | `repo_key_mismatch` before any download |
| N10 | publisher: tampered InRelease; a stable tree offered as dev; the same image with the wrong channel key | `REFUSED` (exit 3), `status` unchanged (release `20261116T020123Z`) |
| N11 | 400 requests in a burst from one client address | 154 x 200, 246 x 429 |
| logs | dedicated access log | 405, 403, 429, 404 lines with address, request, status, timing, user agent |

## 5. Findings

1. **Signed identity binds the image to the registry host the signer used.** The lab signatures name `192.168.186.235:5000`; with the stock `matchRepository` policy a pull from the artifact service is refused ("Signature for identity 192.168.186.235:5000/ou/ou-softphone is not accepted"). `remapIdentity` did **not** help (it does not match repository-only identities; tried with podman 4.9.3). Fix implemented: when `OU_ARTIFACT_SIGNED_REGISTRY` is set, the guest policy pins every repository of the plan with `exactRepository <signed>/<repo>` and rejects the rest (verified: rc=0 for a planned repository, rejected for another). The cleaner production setup is to run the signer with the artifact service as its registry host so no remap is needed (ADR-0015).
2. **`return` bypasses `allow/deny` in nginx** (rewrite phase before the access phase): the first `/healthz` implementation answered clients outside the allow-list. Found by the source-restriction test, fixed (static file) and unit-tested.
3. The installer did not reload the nft table when the unit was active but the table had been removed; fixed (checks `nft list table`).
4. Go services die with SIGSYS under `SystemCallFilter=~@resources` (prlimit): units use `~@privileged` only.
5. A good cached `.deb`/index masked refusals in the first matrix runs (the tests passed vacuously); every apt case now starts from a clean apt state and asserts "not installed" before and after.
6. The 400-request burst limit (30 r/s, burst 120 per source) is aggressive for a NAT'd customer site where many guests share one source address; guests normally have their own VNet address. Tune `req_rate`/`req_burst` in `server.json` if a site NATs.
7. Ubuntu/Debian archive packages (`repo: ubuntu-noble` in the catalog: slapd, postgresql, nginx, postfix, mariadb) are **not** served by this service; guests still need an archive mirror or reachable archive (ADR-0015, placement (b) scale item). This is the next blocker for a fully isolated VNet.

## 6. Tests

New `ics/tests/test_artifacts.py`: 37 tests (configuration pins, catalog rewrite and plan injection, nginx/registry/nft rendering and fail-closed validation, cloud-init files, first-boot validation and apply, per-repository policy, agent apt `-c`, publisher gpg and ECDSA verification, system health block). Full suite: `ICS_TEST_ENV_FILE=/etc/office-unbound/ics-test-h.env .../pytest -q -p no:cacheprovider` (database h: g was in use by another agent's full run when this one started, so g was not used): **925 passed, 1 failed, 3 errors in 20 min 53 s**. The 3 errors (`test_security_review.py` L4/M4) are database-fixture errors that did not recur: that file passed in isolation (66 passed together with test_golden_image.py). The 1 failure, `test_golden_image.py::test_the_ubuntu_profile_refuses_a_wrong_pin...`, fails in isolation too with `os/ubuntu-24.04.env: UPSTREAM_SERIAL is not pinned`: a recipe-pin assertion in the golden-image blueprint on `fullstack-plan`, unrelated to this change (no file it uses was touched; fixed on another branch per the readiness document). The suite started before the last two small fixes (nginx `/healthz` static file, installer nft check, `signed_registry` needs a CA); `test_artifacts.py` was re-run afterwards: 37 passed.

## 7. Not done / open

* Real VMs on a customer VNet, golden image boot with the new metadata (the golden image must carry a first-boot with `apply_artifacts`; the older closed schema refuses the new fields), `bootstrap.sh --artifacts-*` end to end, backup/restore of the artifact config, an alert/check in the monitoring engine (the status is in `/api/v1/system` only), console page.
* Production keys, certificate and host address; key rotation/revocation; mirror of the Ubuntu/Debian archives; `ou/office` and the other images copied through the publisher (only softphone, meet-token-service and synapse were published); OCI signing identity set to the artifact host in the signer.
* The lab ran the client in the same /24 as the server; the customer subnet 10.64.0.0/16 was exercised only as a rendered allow-list (and by moving the allow-list so the client was outside it).
