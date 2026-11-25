# Office Unbound Desktop for Windows: download from our own UI

Owner requirement (2026-11-25): "the app needs to be able to be directly downloaded from the ui". Users download the installer from
their **portal** (`/devices`, card "Office Unbound Desktop for Windows", file at `GET /download/windows`). Operators download it from the **ICS
console** (a tenant's Overview tab, `GET /api/v1/downloads/desktop/windows`). The installer is never fetched from GitHub. A GitHub
prerelease may exist as well, but no UI links to it.

Status (ADR-0000): **Implementing**. The portal, ICS and package code are tested with a dummy installer only. No real installer has been
published, and no deployment carries the package yet.

## How it reaches a deployment

The installer travels as the apt package **`ou-desktop-windows`** (`blueprints/build/desktop-windows-deb/build-deb.sh`). This reuses
everything the stack already trusts: the dev channel signer (`publish-dev.sh`, `ou-release-sign`), the artifact service (ADR-0015:
`InRelease` is checked against the pinned channel key on the guest), and the exact version pin in the catalog (`pkg.install_pinned`). No new
artifact kind, no new trust path.

| Where | Path | Who reads it |
|---|---|---|
| Portal VM (package) | `/usr/share/ou-desktop/windows/{manifest.json, OfficeUnbound-Desktop-<ver>-x64-setup.exe}` | `ou-portal` (`PORTAL_DESKTOP_DIR`, default this path; the unit's `ProtectSystem=strict` leaves `/usr` readable) |
| ICS host (extracted automatically from the same signed deb, see below) | `/var/lib/office-unbound/desktop/windows` (a symlink to `releases/<version>-<deb sha256[:12]>/`) | `ics` (`ICS_DESKTOP_WINDOWS_DIR`, default this path) |

`manifest.json` (schema 1, at most 4 KiB): `{"schema":1, "product", "platform":"windows-x64", "version", "file", "sha256", "size",
"unsigned", "stage"}`. Both servers (`portal/app/desktop_download.py`, `ics/ics/desktop_download.py`, identical code, enforced by a test)
serve **only** the file the manifest names (`[A-Za-z0-9._-]+.exe|.msi`, no path, no symlink, regular file). They serve it only after the
bytes hash to the manifest's sha256 and the size matches. The result is cached per file identity (device, inode, size, mtime, sha256).
The bytes sent come from the same open file that was hashed. On a mismatch the server returns 500 without sending any bytes and logs
the error. With no or a malformed manifest it returns 404, and the card says "Not available yet". Headers:
`Content-Disposition: attachment`, `Content-Type: application/vnd.microsoft.portable-executable`, `X-Content-Type-Options: nosniff`,
`Cache-Control: private, no-cache`, `ETag: "<sha256>"`, `Content-Length`.

Access: the portal requires a signed-in user (otherwise 303 to `/login`). The ICS route requires `viewer` or higher, in any customer scope
(otherwise 401/403), because the file is the same for every tenant and holds no tenant data.

## Publish steps (controller)

Prerequisites: the installer and its sha256 come from the winci GitHub Actions run (artifact + the printed `sha256`). Run as the operator on
the ICS host, from a clean checkout of the gated commit. Back up first (`ics/deploy/backup/ics-backup.sh`).

1. **Fetch and check the installer** into a new, empty directory (it is untrusted data until checked):
   ```sh
   D=$(mktemp -d) && gh run download <run-id> -R agit8or1/office-unbound -n <artifact-name> -D "$D"
   sha256sum "$D"/*.exe      # must equal the sha256 the winci run printed
   ```
2. **Build the deb.** It refuses a wrong sha256 or version:
   ```sh
   OU_REVISION=ou1 blueprints/build/desktop-windows-deb/build-deb.sh "$D/<installer>.exe" <sha256> <app-version> /var/lib/office-unbound/pkgbuild/desktop
   # -> ou-desktop-windows_<app-version with - as ~>-ou1_all.deb   (0.1.0-alpha.1 -> 0.1.0~alpha.1-ou1)
   ```
3. **Admit, sign and publish to dev.** The ou-portal debs go the same way: `publish-dev.sh` into a scratch tree, then copy into the
   served pool without pruning:
   ```sh
   S=$(mktemp -d); OU_COMPONENT=ou-desktop-windows blueprints/build/guest-image/agent-deb/publish-dev.sh /var/lib/office-unbound/pkgbuild/desktop/ou-desktop-windows_<ver>_all.deb "$S"
   install -d /var/lib/office-unbound/pkgbuild/repo/pool/dev/ou-desktop-windows
   cp "$S"/pool/dev/ou-desktop-windows/*.deb /var/lib/office-unbound/pkgbuild/repo/pool/dev/ou-desktop-windows/
   blueprints/build/repo/repo.sh index dev
   sudo ou-artifact-publish apt --src /var/lib/office-unbound/pkgbuild/repo --channels dev
   ```
   Verify that the published dev `Packages` lists `ou-desktop-windows <ver>` and still lists every version the deployed release pins. Do
   not use `repo.sh publish` for this package, because it prunes older versions.
4. **Pin it in the catalog**, in `blueprints/catalog/components/portal.yaml` under `artifacts:`:
   ```yaml
   - {name: desktop-windows, kind: package, package: ou-desktop-windows, version: "<ver>", repo: ob-apt-dev}
   ```
   Add the pin only after step 3: a pin to an unpublished version makes `pkg.install_pinned` fail on every portal VM. Commit, bump the
   release version and name (versioning rule), then update `ROADMAP.md`/`progress.json`. The ICS copy needs no manual step: once the ICS
   runs a catalog with this pin, it extracts the package itself (next section). To do it at once after a publish, run
   `sudo -u ics env ICS_ENV_FILE=/etc/office-unbound/ics.env /opt/office-unbound/ics/.venv/bin/python -m ics.desktop_sync`. It prints the
   result as JSON and exits 0 on `extracted`, `current` or `no_pin`.
5. **Gate, then ship.** Run the full release gate on the commit (pytest with your own test env, vitest, typecheck, build,
   static-drift 0, portal pytest, doc links). Deploy the ICS from a clean checkout. The portal code that serves the file ships in a new
   `ou-portal` build (PORTAL_VERSION bump, `portal-deb/build-deb.sh`, same step 3), pinned in the same `portal.yaml`.
6. **Roll out in place** with an approved `deployment.change` of the tenant's deployment (never destroy and recreate). Because the plan
   adds a new package to the portal VM, the change gets `agent.update:<vm>` with `allow` (the agent's allowlist grows; needs agent
   0.10.1 or later) and then `comp.upgrade:<vm>:portal` (`pkg.install_pinned`, about 5 s portal downtime).
7. **Verify, with evidence.** Signed in on `https://app.<domain>/devices`, the card shows the version, size and sha256.
   `curl -sI` with a session shows the headers listed above. Download the file and compare its sha256 with the manifest. In the console,
   open the tenant's Overview and use the same link. Close the GitHub issue with this evidence.

Rollback: pin the previous `ou-desktop-windows` version (it stays in the dev pool, because step 3 does not prune), then `deployment.change`.
The ICS follows the pin on its next pass and flips back (or uses the kept previous release). Removing the pin leaves the VMs' package
installed, because a change removes nothing from a VM, and leaves the ICS copy as it is.

## The ICS copy: extracted automatically (`ics/ics/desktop_sync.py`)

Owner, 2026-11-25: "yes, have the ICS extract it automatically".

**When it runs.** The worker leader runs it in its own thread at start, then every 5 minutes (`SYNC_SECONDS`). Only the active primary
runs it, never a standby or a fenced controller. `ou-artifact-publish apt` publishes by flipping the `apt/current` symlink, and the next
pass sees the changed `InRelease` (inode, mtime, size). An unchanged tree and pin cost two `stat` calls and never hash again. The CLI
above runs the same pass at once. Why not a hook inside the root publisher: the publisher has no database or audit key, and running ICS
code as root would widen it. Why not a typed action: there is nothing to choose, because the catalog pin fixes the version. Neither
path has an API or parameters, so no caller decides what is read, run or written. `ICS_DESKTOP_SYNC=false` turns the worker pass off.

**What it trusts.** It uses the guests' own path (ADR-0015):
1. The version is the **catalog pin** of the portal component (`portal.yaml`), never "latest", and only from our `ob-apt-*` channels.
   With no pin it does nothing, and the console says "Not available yet".
2. `dists/<suite>/InRelease` of the **published** tree (`<data_dir>/apt/current`, from the publisher's `server.json`) must verify with
   `gpgv` against the channel key pinned there (`channel_fprs`, `keys/ou-release-<suite>.pub.asc`). The key file must hash to that
   fingerprint. The `InRelease` must be for that suite and not expired.
3. `main/binary-amd64/Packages` must match the signed `InRelease` (size and sha256). Its stanza for exactly the pinned version names
   the deb, with a safe `pool/<suite>/` path.
4. The deb is copied while it is hashed, and must match that stanza's size and sha256. The copy is what gets parsed.
5. Each `data.tar.xz|gz` member must be a directory or regular file: no symlink, hard link, device or fifo, no absolute path and no
   `..`. Members are only allowed under `usr/share/ou-desktop/windows/` (extracted) and `usr/share/doc/ou-desktop-windows/` (ignored).
   The payload must be exactly `manifest.json` plus the installer it names.
6. The installer must hash to the manifest's sha256.

**Replacement.** It extracts into `releases/.tmp-*`, renames that to `releases/<version>-<deb sha256[:12]>`, then flips the `windows`
symlink with `os.replace`. The previous release stays until the flip succeeded, and one release is kept for rollback. A copy placed by
hand earlier is kept as `releases/manual-*`. Any refusal leaves the current copy untouched. Audit: `desktop.installer.extracted`
(version, sha256, size, package version, deb sha256, release, previous) on each flip, and `desktop.installer.refused` (reason) once per
input.

**Host.** `ics.service` gets `ReadWritePaths=-/var/lib/office-unbound/desktop`, the only path the ICS writes outside the database. The
directory is created `ics:ics 0755` by `install.sh` and by the ou-ics package's tmpfiles. `gpgv` comes with Ubuntu's `gpgv` package,
which is already on the ICS host.

## Open points

- The installer is **not code-signed** (zero cost, no certificate). Windows SmartScreen warns, and the card says so and shows the sha256 with
  the `Get-FileHash` command to check it.
- One Windows x64 installer. Other platforms would get their own `platform` value and package.
