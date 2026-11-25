# Building `opencloudcmd.exe` (OpenCloud Desktop sync engine) for Windows: investigation

Status: **approved by the owner on 2026-11-25; workflow `.github/workflows/desktop-engine-windows.yml`.** It runs on
push to `desktop-*` when the workflow or `desktop/ci/engine/**` changes, or by hand. Pins: OpenCloud Desktop `v4.0.0` @
`9f701e6db2e101cb3247d3331647a60266e83b0f`, CraftMaster `8a19d8fc`, craft-core `b80e8f8c` and both blueprint
repositories at the revisions in upstream's `.craft.shelf`, runner `windows-2022` (that Craft does not
detect VS 2026 on `windows-latest`) (`desktop/ci/engine/craft-pin.ini` + a pinned shelf copy).
Output artifact `opencloudcmd-windows-x64-v4.0.0-<run>`: `opencloudcmd/` (the exe, its DLL import closure, Qt tls and
networkinformation plugins, OpenSSL, checked by starting it with a clean PATH), `source/` (desktop tree archive,
Craft repo archives, shelf, recipe, installed-package list, SOURCES.md) and `SHA256SUMS`.
Facts below come from upstream's public repo and Actions runs (read 2026-11-25); the time figures are upstream's,
not ours.

## First green build (2026-11-25)

Run https://github.com/agit8or1/office-unbound/actions/runs/45698384557 (windows-2022) took 17 min with a cold cache:
6 min for unshelve, which brings Qt 6.11.1 and the other deps from KDE's binary cache; 7 min to build; 3 min for upstream's
34 tests, all of which passed.
- `opencloudcmd.exe --version` prints `opencloudcmd OpenCloud 4.0.0.4` for commit `9f701e6d...`. It ran from the
  collected folder with PATH limited to the Windows system dirs.
- Collected: 45 files, 102.8 MB. These are the exe; OpenCloudLibSync and the Qt 6 Core/Network/Gui/Qml/Quick/Widgets
  DLLs that LibSync imports; ICU; OpenSSL 3; SQLite; the VC++ runtime; the TLS backends (schannel, openssl, certonly);
  and networkinformation.
- `source/` is 7.6 MB in 14 files: the desktop tree, craft-core, CraftMaster, both blueprint repos, the shelf and the recipe.
- The artifact is 48.4 MB zipped. sha256 of `opencloudcmd.exe` is
  `a55e3d6ead5c6c49841fa92e8e742cd03a3b39e861302e13f2c58a92b402051c` (full list in the artifact's `SHA256SUMS`).
- Not proven yet: a real sync over HTTPS. That is the files agent's live test against the test stack, on a Windows host.

## What upstream does

- Repo `opencloud-eu/desktop`, licence GPL-2.0 (or later). Releases ship only Linux AppImages and macOS pkgs:
  v4.0.0 (2026-09-03) and v5.0.0-rc.1 (2026-11-23) have **no Windows assets**.
- Upstream CI (`.github/workflows/main.yml`) **does build Windows x64 on GitHub-hosted runners** using
  **KDE Craft** (CraftMaster + upstream's own `.github/workflows/.craft.ps1` and `craft_override.ini`):
  - tag v4.0.0 / branch `stable-4.0`: target `windows-cl-msvc2022-x86_64` on `windows-2022`;
  - `main` (5.0 line): `windows-cl-msvc2026-x86_64` on `windows-2025-vs2026`, plus arm64.
- Windows packaging: release builds make an MSIX that is signed through SignPath (upstream secrets). PR builds
  run "Package for testing" with `[Packager]PackageType=PortablePackager`, a portable zip that holds
  `opencloud.exe`, `opencloudcmd.exe` and the Qt 6 DLLs. Normal pushes upload no Windows binary
  (the artifact is about 1 KB).
- Measured on upstream's run 45663663783 (main, 2026-11-25, warm caches), Windows x64 job: about 17 min.
  That was Craft unshelve plus prebuilt dependencies 4m37s, build 8m16s, tests 3m01s.

## Plan (now implemented as the workflow above)

A separate `desktop-opencloudcmd.yml` workflow, started by hand (`workflow_dispatch`):
1. Check out `opencloud-eu/desktop` at the tag (`v4.0.0`, matching the brief), pinned by commit SHA.
2. Run upstream's own recipe: CraftMaster, `.craft.ps1 --setup`, `--unshelve .craft.shelf`, `--install-deps`, build,
   `--test`, then `--package --options "[Packager]PackageType=PortablePackager"`.
3. Take `opencloudcmd.exe` and the DLLs it needs from the portable zip. Write sha256 and an SBOM for the Craft
   image dir. Upload as a workflow artifact. The `windows` job of `desktop-windows.yml` would then bundle it.

Estimate: **medium complexity, 1-2 days** to get green and stable. A cold run is about **30-50 min**, a warm one
about 20 min; GitHub-hosted runners are free for this public repo.

## Risks and open points for the owner

- **Supply chain.** Craft downloads prebuilt Qt and other dependencies from KDE's binary cache and from upstream's
  S3 craft-cache, then CraftMaster `main`, unpinned. Pinning means fixing a CraftMaster/blueprints commit and keeping
  the shelf file. A from-source Qt build would take hours per run.
- **Runner images.** v4.0.0 expects `windows-2022` with MSVC 2022. When that image is retired, use 5.x
  (`windows-2025-vs2026`) or patch the recipe.
- **Licences.** Shipping `opencloudcmd.exe` (GPL-2.0+) and Qt (LGPL-3.0, dynamically linked) next to our AGPL app
  needs a written source offer: upstream tag + Craft blueprint revisions + our workflow. Qt DLLs must stay
  replaceable. We need cargo-deny-like licence review for the Craft dependency set; no tool covers it yet.
- **Signing.** Ours would be unsigned like the rest of the alpha. Upstream's SignPath signing is not available to us.
- **Alternative.** Ask upstream whether they would attach the portable Windows zip to releases. That costs nothing
  and avoids running our own build.
