# ADR-0015: Artifact distribution (signed apt repository + OCI registry for guests)

Status: implemented-lab-verified for placement (a) on an nspawn machine (see [artifact-dist-results.md](../status/artifact-dist-results.md)); production keys, a production host address and the customer VNets are not available yet. Date: 2026-11-16. Builds on ADR-0008 (build/release), ADR-0009 section 5 (guests), ADR-0007 (zero cost), security review 7 (separate channel keys).

## Context
Guests on customer VNets (10.64.0.0/16, `docs/admin/proxmox-sdn-isolation.md`) have no internet access, and no registry or apt repository was reachable from them (`docs/status/fullstack-readiness.md` row 17): the lab repo lives in a builder, the lab registry is a loopback HTTP process, and the catalog used the placeholder host `registry.ou.invalid`. A plan could therefore never execute. Signatures already exist (release key per channel, OCI image key per channel, podman `sigstoreSigned` policy), but nothing serves the signed content.

## Decision
A **read-only artifact service**, one TLS endpoint `https://<OU_ARTIFACT_BASE>`:

| Path | Content | Server |
|---|---|---|
| `/apt/dists/<channel>/InRelease`, `/apt/pool/<channel>/...` | the signed apt repository (channels `dev`, `staging`, `stable`; ADR-0008 layout) | nginx, static, `autoindex off` |
| `/v2/...` | OCI images by digest, with the sigstore signature as a registry attachment (tag `sha256-<hex>.sig`, cosign layout) | nginx -> Distribution `registry` 2.8.2 (Debian/Ubuntu archive package `docker-registry`, Apache-2.0, pinned by the archive) |
| `/healthz` | liveness | nginx |

Signatures are stored as registry attachments, not in a lookaside tree, because that is what the guest policy already reads (`use-sigstore-attachments: true`, ADR-0009 section 5 and `guest-bootstrap-results.md`); a lookaside server would be a second thing to run and to replicate.

### Read-only by construction
* nginx routes GET and HEAD only (405 otherwise), `client_max_body_size 1k`.
* The registry behind nginx is a **separate read-only process** (`maintenance.readonly.enabled`, `delete.enabled: false`, loopback only, systemd `ReadOnlyPaths`).
* The **only write path** is `ou-artifact-publish` (root, on the artifact host), which starts a second registry instance listening on a **unix socket** (no network listener, `ProtectSystem=strict`, `IPAddressDeny=any`) for the duration of a publication and stops it afterwards. The apt tree is replaced by an atomic symlink flip of a new release directory (3 releases kept for rollback).
* `ou-artifact-publish` verifies before it serves: apt: each channel's `InRelease` against that channel's **pinned** key fingerprint (`server.json`) in a throw-away keyring, `Valid-Until`, suite name, and every hash and size down to each `.deb`/`.dsc`, checked **in the copied tree that will be served** (the builder cannot change bytes after the check); OCI: manifest, config and layers re-hashed, and the signature attachment must verify (ECDSA P-256) with that channel's pinned image key and name exactly this manifest digest. Unsigned or wrongly signed images are never published.

### No listings, rate limits, logs
Directory requests return 403/404, `/v2/_catalog`, `.../tags/list` and `.../referrers/` are 403 (guests pull by digest and need none of them), dotfiles 404. `limit_req` 30 requests/s (burst 120) and 24 connections per source address (429). Dedicated access and error logs (`/var/log/nginx/ou-artifacts.*.log`, rotated with the other nginx logs), registry logs in the journal. Per-customer access control is not needed: everything served is signed, public-ish content; the allow-list is by network.

### TLS and what the guest pins
A private, name-constrained CA (`/etc/office-unbound/artifacts/tls`, permitted: the listen IP and the configured names) issues the server certificate. The CA certificate and its **sha256 pin** are injected into every guest through the bootstrap metadata (`artifact_ca_pem`, `artifact_ca_sha256`, `artifact_tls_hosts`): the guest recomputes the hash, writes the CA for **those hosts only** (`Acquire::https::<host>::CaInfo` in the agent's private apt configuration, `/etc/containers/certs.d/<host>/ca.crt`) and never adds it to the system trust store. TLS gives confidentiality and prevents trivial redirection. It is **not** what protects guests: apt verifies the signed `InRelease` against the per-channel key the guest pinned; podman verifies the sigstore signature against the pinned image key and pulls by digest. A compromised artifact host can withhold content or replay older signed content (bounded by `Valid-Until`, 14 days), but cannot make a guest accept unsigned or wrongly signed content (lab negative matrix).

### Per-channel keys in the guest
`GuestSpec.ou_repos` (new) carries one apt line per release channel the VM installs from, each with its own key file `ou-<channel>.asc`; the agent's `pkg.install_pinned` already refuses any key whose fingerprint is not in `pinned-fingerprints`. The ICS derives the channels from the plan (`ob-apt-<channel>` repo values) and refuses to render a VM whose channel has no configured key pin (`OU_ARTIFACT_CHANNEL_FPRS`). The OCI side keeps one pinned image key per guest (security review 7: pin the channel the VM runs).

### Signed identity (finding)
A cosign payload binds an image to the `docker-reference` it was signed for, and `ou-oci-sign` writes the registry host recorded in its root-owned trust file. If guests pull from another host than the signer addressed (the lab: signatures name `192.168.186.235:5000`, guests pull from the artifact service), the stock `matchRepository` policy refuses the image, and `remapIdentity` does not match repository-only identities (verified with podman 4.9.3). Two supported setups:
1. Preferred: set the signer's registry to the artifact service address, so the signed identity equals the pull address (`OU_ARTIFACT_SIGNED_REGISTRY` unset).
2. Otherwise `OU_ARTIFACT_SIGNED_REGISTRY=<host the signer used>`: the guest policy then pins **every repository of the plan explicitly** (`<serving>/<repo>` = `sigstoreSigned` + `exactRepository <signed>/<repo>`) and rejects the registry-wide scope, so a validly signed image that is not in the plan is refused as well. The repository list comes from the plan (`image_repos`).

### Configuration injected into plans and guests
`OU_ARTIFACT_BASE` (host[:port]; or `OU_ARTIFACT_APT_HOST` and `OU_ARTIFACT_REGISTRY_HOST` separately), `OU_ARTIFACT_CA_FILE` + `OU_ARTIFACT_CA_SHA256`, `OU_ARTIFACT_KEYS_DIR` + `OU_ARTIFACT_CHANNEL_FPRS` (`dev=<40 hex>,stable=...`: the key files must match their pins), optional `OU_ARTIFACT_SIGNED_REGISTRY`. A set-but-broken configuration raises (same rule as `OU_NETWORK_MODEL`); unset leaves the catalog placeholder and the plan carries the warning `artifact_base_unset`. `ics.deploy.ops.get_catalog()` rewrites the OCI images of the reviewed catalog (`registry.ou.invalid/...`) to the configured registry, the plan gets an `artifacts` section (inside the plan hash) and the guest configuration (`cloudinit.callback_config`, `ou_agent.firstboot.validate_config`/`apply_trust`) carries repos, CA, hosts and identity. The golden-image first boot validates every field again (closed schema; the key block must hash to its declared fingerprint, the CA to its sha256).

### Placement
**(a) on the ICS host, separate unit and port** (chosen for the alpha): `bootstrap.sh --artifacts-listen-ip ...` or `deploy/artifacts/ou-artifacts-setup.sh` installs nginx site + two registry units + nftables table `inet ou_artifacts` (customer subnets only; same pattern as `ics-admin-fw`) + the publisher. Why: the release host already holds the build outputs and the signers' public side, there is no extra VM to patch, secure, back up and monitor, `REPO_IPS` in the SDN owner commands is one existing address, and the service is read-only static content plus one Go binary. Cost: the ICS host's nginx now also faces the customer VNets (separate server block, port, allow-list in nginx and nftables, no access to ICS data: the registry user owns only its tree). Health: `/api/v1/system` -> `artifacts` (TLS with the pinned CA, `InRelease` validity per channel, `/v2/`), `python -m ics.artifacts health`. Backup: `ics-backup.sh` includes configuration, the CA key and units; the published data on request (`OU_ICS_BACKUP_ARTIFACT_DATA=1`), because it is rebuildable from the pipeline.

**(b) an ICS-deployed platform VM** (for scale, not built): the same three pieces (`ou-artifacts-setup.sh` is host-independent) on a VM in a platform pool, deployed by the ICS like a customer component, behind its own VNet address. Choose it when (1) more than one customer site or node needs mirrors, (2) the ICS host's CPU/disk must not serve image blobs, (3) the apt Ubuntu/Debian archive should also be mirrored for guests (not part of (a): guests still need `archive.ubuntu.com` reachable or an archive mirror for `ubuntu-noble` packages; flagged in the results), or (4) HA is wanted (two VMs behind the same name, `rsync` of the signed tree is already idempotent and verifying).

## Consequences
* A plan with a configured `OU_ARTIFACT_BASE` points every OCI image and apt channel at one reachable, verifiable source; the `.invalid` placeholder disappears from executable plans.
* The golden image / cloud-init guest gains the per-channel keys and the CA; an old golden image without `apply_artifacts` refuses the new metadata fields (closed schema), so image and ICS must be upgraded together (the image `floor` mechanism of the image-import path applies).
* Not done: mirror of the Ubuntu/Debian archives for guests, production keys and certificates, real guests on a customer VNet, key rotation/revocation process for the channel keys, reproducing the lab matrix against a server on the ICS host itself, a console page for the artifact service (the status is in `/api/v1/system`).
