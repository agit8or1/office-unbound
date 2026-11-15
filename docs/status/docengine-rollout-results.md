# Document engine rollout: Office Unbound Docs replaces the vendor CODE install (lab)

Date: 2026-11-15. Agent AF. Follows `docengine-build-results.md` (our own Collabora Online cp-26.04.6-1 build) and
`identity-files-lab-results.md` (OpenCloud <-> Collabora WOPI wiring). Lab only. ADR-0000 status words: PASS means executed, quoted below.

## 1. Replacement on `ou-office1` (task 1)

| Item | Before (vendor CODE) | After (Office Unbound Docs) |
|---|---|---|
| Engine | `coolwsd 26.04.6.1-1` + `collaboraoffice 26.04.6-1` (vendor apt repo), `/opt/collaboraoffice` | artifact `ou-docs-cp-26.04.6-1.tar` (sha256 `814c402e...868392bd`, re-verified on the builder before the copy), engine in `/opt/officeunbound-office`; `/hosting/capabilities` productName `Office Unbound Docs` |
| Unit | vendor `/usr/lib/systemd/system/coolwsd.service` | `/etc/systemd/system/coolwsd.service` (same unit name on purpose: t03 restarts `coolwsd`, ICS health checks use it; shadows the vendor unit). Source: `blueprints/build/collabora/deploy/coolwsd.service` |
| Run user | `cool` | `cool` (coolforkit hard-requires this user name: "Security: coolforkit incorrect user-name, other than 'cool'" with a different name - found by trying `oudocs`). Not root. `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, work dir `/opt/ou-docs` (own systemplate/child-roots/cache; the vendor `/opt/cool` tree is untouched) |
| Config | vendor `coolwsd.xml` hand-edited | patched-default `/etc/coolwsd/coolwsd.xml` from the artifact + `deploy/ou-docs-configure.py` (every edit must match exactly once): `ssl.enable=false`, `ssl.termination=true` (TLS stays in nginx with the lab cert `office.crt`/`office.key` for office.ou-lab.internal), `net.listen=loopback`, `ssl.ca_file_path=/etc/ou-lab/tls/ca.crt` + `ssl.ssl_verification=true`, WOPI allowlist mode `groups` with the single host `https://cloud.ou-lab.internal:443`, `fetch_update_check=0`, `allow_update_popup=false`, admin console off, `mount_jail_tree=false` + `security.capabilities=false` (nspawn only) |
| Memory | machine MemoryMax 3G | unchanged (3G on `systemd-nspawn@ou-office1`; peak with 30 documents open: 2.07 GB, see 2.3) |
| Vendor recoverable | - | `systemctl stop+disable` done before the swap; **not purged**: dpkg still lists `coolwsd` and `collaboraoffice*` (state `hi`/`ii`), `/opt/collaboraoffice` and `/opt/cool` untouched. Because the artifact is a DESTDIR tree, extracting it overwrote the vendor *package-owned files* (`/usr/bin/cool*`, `/usr/share/coolwsd`, `/etc/coolwsd/coolwsd.xml`); a tar of every file `dpkg -L coolwsd` lists plus the configured `coolwsd.xml` is in `/var/backups/vendor-code/` (`coolwsd-vendor.tar` 303 MB, `coolwsd.files`, `coolwsd.xml.vendor-configured`). Rollback (written, **not executed**): `systemctl disable --now coolwsd; rm /etc/systemd/system/coolwsd.service; tar -xpf /var/backups/vendor-code/coolwsd-vendor.tar -C /; cp /var/backups/vendor-code/coolwsd.xml.vendor-configured /etc/coolwsd/coolwsd.xml; systemctl daemon-reload; systemctl enable --now coolwsd`. Do the purge (`apt purge coolwsd code-brand collaboraoffice*`) only after sign-off |

Runtime facts observed after the swap (executed): `ss -ltnp` shows only `[::1]:9980` (coolwsd); no established TCP connection of coolwsd/forkit/kit processes while idle;
`grep -c home_mode /etc/coolwsd/coolwsd.xml` = 0; processes run as `cool`. Not packet-captured: "no outbound telemetry" rests on config (`fetch_update_check=0`,
no infobar/welcome/feedback/support-key URLs, AI disabled by default, empty remote_config/remote_font_config/indirection URLs) plus that idle `ss` snapshot.
WOPI allowlist, negative proof (journal, real websocket `load`): `ERR No authorized hosts found matching the target host [evil.ou-lab.internal] in config`; for the allowed
host the request reaches OpenCloud (`WOPI::CheckFileInfo returned 401 Unauthorized` for a bogus token, i.e. the host passed the allowlist).
Jails: not available in nspawn (as in the build results); coolwsd runs with `mount_jail_tree=false`, `security.capabilities=false`. A VM/bare-metal deployment must leave both at their defaults (not tested here).

## 2. Test results, before (CODE) vs after (Office Unbound Docs) (task 2)

Run from the ICS host with the documented env: `OU_CA_FILE` = copy of `ou-id1:/root/ou-lab-ca/ca.crt`, passwords `eval`'d from `ou-id1:/root/ou-lab-secrets/test-users.env`
(not printed), `OU_RESTART_CMD='sudo systemctl -M {machine} restart {unit}'`, `OU_MACHINE_FILES/OFFICE/KC`, venv from `requirements.txt`. Tests were run one by one
(`python -I tNN.py`), not through `run_all.sh`, so that each result line is read directly (SKIP exits 0 - evidence is the PASS/FAIL counts).

| Test | before: vendor CODE (same day, same stack) | after: Office Unbound Docs |
|---|---|---|
| t01_oidc | 36 PASS / 0 FAIL | 36 PASS / 0 FAIL |
| t02_files_webdav | 11 / 0 | 11 / 0 |
| t03_office_roundtrip (incl. Collabora edit fidelity DOCX/XLSX/PPTX) | 28 / 0 | 28 / 0 (two runs: right after the unit swap and in the full sequence) |
| t04_wopi (real session -> PutFile, version created) | 13 / 0 | 13 / 0 on the second run; the very first run right after the swap failed 1 check: `app/open HTTP 425 TOO_EARLY` (OpenCloud "file not yet available", its post-processing of the just-uploaded file; not a Collabora error). Re-run and the later full sequence: 13/0 |
| t05_versions | 9 / 0 | 9 / 0 |
| t07_desktop_sync | not re-run before (lead's earlier result: 11/0) | 11 / 0 (no Collabora involvement) |
| t06_disable_user | not in scope, not run | not run |

After t03 details (our engine): `PASS test.docx edited+saved in Collabora - PutFile ok`, `PASS test.xlsx content after Collabora save - formulas=('=SUM(A1:A3)', '=AVERAGE(A1:A3)', '=Data!B1*2', ...) cached=(60, 20, 120)`,
`PASS test.pptx content after Collabora save - slides=2 ... notes=... pics=1`. t04: `PASS Collabora save (PutFile)`, `PASS stored DOCX contains Collabora edit`, `PASS Collabora save created a version`.
Honest limits: the sequence was not run through `run_all.sh` in one pass; t04's 425 flake shows the app/open path is timing sensitive right after upload (a test-side retry would be a reasonable fix, not done).

### 2.3 More than 20 concurrent sessions, end to end through OpenCloud

New test `blueprints/lab/tests/t08_office_concurrency.py`: N=30 distinct DOCX files uploaded by user bob; 30 threads each `POST /app/open` (OpenCloud WOPI) -> `wss://office.../cool/.../ws` -> `load`,
all held open simultaneously (barrier + 10 s), then each types a unique marker and saves (Collabora PutFile into OpenCloud); the stored DOCX of every session is read back.
```
PASS uploaded 30 docs
PASS all 30 sessions opened via /app/open - 30/30
PASS all 30 sessions loaded concurrently (perm: edit) - 30/30 in 24s
PASS all 30 saved (PutFile) - 30/30
PASS stored DOCX of every session contains its own marker - 30/30
-- T08 Collabora 30 concurrent sessions via OpenCloud: 5 PASS, 0 FAIL, 0 SKIP
```
Memory of the 3G machine sampled every 4 s from the host: peak `MemoryCurrent` 2.07 GB (page cache included). This exceeds the vendor CODE caps (20 connections / 10 documents) end to end.
Not proven: more than 30 documents (the 3G cap, not a software limit, is the expected ceiling), many users on ONE document, browser rendering, CODE before-numbers for t08 (the caps are documented, not re-measured here).

## 3. OCI image (task 3)

Built inside `ou-build1` by `blueprints/build/collabora/oci/{Containerfile,entrypoint.sh,healthcheck.sh,build-image.sh}`.

| Item | Value |
|---|---|
| Tooling | apt-installed in the builder (host change logged): podman 4.9.3, buildah 1.33.7, skopeo 1.13.3 (same versions as agent C's guests), `docker-registry` (loopback `127.0.0.1:5000`, lab only) |
| Rootless | yes: build runs as user `imgbuild` (subuid/gid 20000:40000, vfs storage). `--isolation chroot` was required: the default runtime (`crun`) cannot mount `proc` in nspawn ("mount `proc` to `proc`: Operation not permitted"), and `apt` needs `APT::Sandbox::User=root` (`setgroups` EINVAL). `podman run` also fails here (kernel keyring EPERM): smoke tests ran with `buildah run --isolation chroot` |
| Base | `docker.io/library/ubuntu@sha256:2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5` (index digest of `ubuntu:24.04`, 2026-11-10) |
| Content | 14 runtime apt packages (no recommends; 132 packages in the image, list in `/root/ou-docs-image-dpkg.txt` of the builder) + the DESTDIR tree of the artifact; systemplate pre-built at image build; image size 1.41 GB (534 MB compressed in the registry) |
| User / FS | `USER 10001:10001` (`cool`); all writes go to `/opt/ou-docs/work` (VOLUME) and `/tmp`, so `--read-only` with those two as tmpfs/volumes is the intended run mode. Smoke test: files created outside `/opt/ou-docs/work` and `/tmp` during a run: only buildah's own `/run/.containerenv`. `--read-only` itself was **not run** (no working `podman run` in nspawn) |
| Config | environment only: `OU_WOPI_HOST` (required, single WOPI host), `OU_CA_FILE`, `OU_SERVER_NAME`; TLS terminated in front; no secrets in the image; no outbound update/telemetry settings |
| Healthcheck | `HEALTHCHECK` (docker manifest format) `curl -fsS http://127.0.0.1:9980/hosting/discovery`; the catalog health check (`wopi-discovery`) is unchanged |
| Smoke test (executed, chroot run as uid 10001) | coolwsd/forkit/kit processes as the unprivileged uid; `/hosting/discovery` 200; `/hosting/capabilities` `"productName":"Office Unbound Docs","productVersion":"26.04.6.1"`; `convert-to/pdf` of a text file: HTTP 200, `%PDF-1.7`. In chroot-in-nspawn coolwsd logs `enterMountingNS, CLONE_NEWUSER unshare failed (EPERM)` and falls back to forkit-built jails (expected here) |
| Signed digest | **`sha256:da2488739aa20766d5479db806f9287edc98f561d70a2be8075a11f4213ae097`** (`127.0.0.1:5000/ou/office:26.04.6-ou1`, docker v2 manifest) |
| Signature | sigstore key signature (ECDSA P-256, cosign-format attachment tag `sha256-da24....sig`) made by `skopeo copy --sign-by-sigstore-private-key`, the same mechanism as `ics/scripts/lab_guest/labprep.sh`. Public key SPKI-DER sha256 fingerprint `d5227d3d5300405ee4333bcea4e3e70c5447b0bb59d801099acfe1dfdf317de4`. Private key + passphrase: `ou-build1:/home/imgbuild/ou-lab-image-key/` (mode 700), never in the repo. The public key PEM is in `blueprints/build/collabora/oci/lab-image-signing.pub` |
| Policy check (executed) | `skopeo --registries.d ... copy --policy <sigstoreSigned/keyPath/matchRepository, default reject>` of `.../ou/office@sha256:da24...` with the lab public key: accepted. Same with a different public key: `Source image rejected: cryptographic signature verification failed`. The agent's policy shape was copied from `ics/agent/deploy/render_image_policy.py`; **the ICS agent itself did not pull this image** (guests pin their own `image-signing.pub`; to pull it in ou-guest1 that guest's pinned key would have to be replaced by this lab key, not done) |
| Catalog | `blueprints/catalog/components/office.yaml`: `digest` set to the value above, image repo `registry.ou.invalid/ou/office` (registry host still a placeholder; the digest is registry independent), fingerprint and "lab-signed, not production" recorded as comments (the catalog schema rejects unknown keys; a `signature:` field would be an `ics/ics/deploy/catalog.py` change). `office` is now **pinned**, so plans no longer refuse it as a placeholder: `ics/tests/test_deploy_plan.py::test_real_catalog_loads_and_is_complete` was updated accordingly (office pinned, files still a placeholder) |
| Reproducibility | NOT reproducible bit for bit: apt layer pulls the archive state of the build day (versions recorded), image config contains the build time, vfs/tar mtimes only clamped (`--timestamp`, `touch`). Pinned: base digest, artifact sha256, source commit. A rebuild gives a different digest. Needs an apt snapshot mirror (ADR-0008 follow-up) |
| Published | nowhere: loopback registry inside the builder only |

## 4. Engine product-name rebuild (task 4)

Host check at start: `free -g` available 7 GiB (>= 6), builder idle (no make/cc1plus), so it was started: unit `ou-engine-pn.service` inside `ou-build1`
(`MemoryMax=8G MemoryHigh=7G Nice=10 JOBS=6 NINJA_JOBS=4`, the recipe's ninja wrapper cap), started 2026-11-15 ~20:59 UTC, log `/root/build/engine-pn.log`, markers `/root/build/engine-pn.start|end`.
It runs `recipe.sh engine` in place on the existing tree (`blueprints/build/collabora/recipe.sh` now passes `--with-product-name="Office Unbound Docs"` unless `PRODUCT_NAME=""`). After reconfigure
`config_host.mk` shows `export PRODUCTNAME=Office Unbound Docs` (executed check); the earlier artifact tar and `out/instdir` stay untouched.
**Status at the time of this write-up: running, not finished, result unknown.** The previous full engine build took ~2.5 h at -j10; after the flag change the share of targets that recompile is not known yet.
Next steps when it ends (`cat /root/build/engine-pn.end`): `recipe.sh online install` (new tar), verify PDF `Producer`, `bootstraprc ProductKey`, registry `ooName`, the test suite, then rebuild the image and re-sign (new digest -> update the catalog).
If the build failed, the old tar is still the deployed artifact.

## 5. Not done / unproven

- Rollback to the vendor package was written down but not executed. The vendor `.deb` files are in the machine's apt cache as a second recovery path.
- No browser test (UI rendering, CSP/iframe, absence of popups), no packet capture, no co-editing of one document by several users, `--read-only` run, real jails.
- The image was not pulled/run through the ICS agent (`podman.pull_verified`); only the policy mechanism was reproduced with skopeo.
- Remaining engine strings ("Collabora Office" in PDF producer etc.) stay until section 4 finishes.
- The shipped `build-image.sh` was assembled from the commands that actually ran (the first complete one-shot run of the final script has not been done; the first run stopped at the push step, the rest was executed by hand with the same commands).
- `t08_office_concurrency.py` was added to the files list in `run_all.sh` (after t07); it needs ~2 GB of the 3G office machine.
- The recipe `deps` phase still has not been run as one clean `all` pass.
