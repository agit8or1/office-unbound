# Office Unbound Desktop: Windows build, installer and CI evidence

Workflow: `.github/workflows/desktop-windows.yml` (GitHub-hosted `windows-latest`, free for this public repo).
Triggers: every push to a `desktop-*` branch, PRs touching `desktop/**`, manual `workflow_dispatch`.

## What it does

| Job | Runner | Steps |
|---|---|---|
| `supply-chain` | ubuntu-24.04 | `cargo audit` (RustSec, warnings fail), `cargo deny check` with `desktop/ci/deny.toml` (advisories, licence allowlist, bans, sources; Windows + Linux targets), CycloneDX SBOM for `x86_64-pc-windows-msvc` |
| `windows` | windows-latest | pinned Rust toolchain, `cargo test --workspace --locked`, release build, installer, smoke test (`desktop/ci/smoke-windows.ps1`) |
| (same job) | windows-latest | `ou-files` unit tests only (`--lib`; its live tests need credentials, which never go into CI) and `desktop/ci/winprobe`: junction, symlink and junction-loop classification, NTFS name round-trips against `name_problem()`, drive letters |
| `bundle` | ubuntu-24.04 | one artifact `ou-desktop-windows-<version>-<sha7>`: installer, MSI if any, `sbom/*.cdx.json`, `smoke-report.md`, `SHA256SUMS` |

Installer path:

- **Tauri GUI crate present** (`desktop/crates/*/tauri.conf.json`): `cargo tauri build --bundles nsis,msi`. Set
  `bundle.windows.nsis.installMode = "currentUser"` in `tauri.conf.json` (the job warns otherwise). The Tauri MSI is per-machine.
- **No GUI crate yet**: `ou-agent.exe` packaged by `desktop/ci/installer.nsi` (NSIS, `RequestExecutionLevel user`).

Per-user layout: program `%LOCALAPPDATA%\Programs\Office Unbound Desktop` (removed on uninstall), user data
`%LOCALAPPDATA%\OfficeUnbound` and Credential Manager entries (kept on uninstall), uninstall entry in HKCU.

## Download and verify

```
gh run list -R agit8or1/office-unbound --workflow desktop-windows.yml --branch desktop-winci
gh run download <run-id> -R agit8or1/office-unbound --pattern 'ou-desktop-windows-*'
sha256sum -c SHA256SUMS          # PowerShell: Get-FileHash <file> -Algorithm SHA256
```

Install: `OfficeUnboundDesktop-<version>-<sha7>-x64-setup.exe` (add `/S` for silent; silent uninstall:
`"%LOCALAPPDATA%\Programs\Office Unbound Desktop\uninstall.exe" /S`).

**The installer is UNSIGNED ALPHA.** SmartScreen shows "Windows protected your PC / unknown publisher";
use "More info, Run anyway" only for artifacts whose sha256 matches the run's `SHA256SUMS`. Artifacts expire after 30 days.

## What the runner proves, and what it cannot

Proven on real Windows each run (see `smoke-report.md` and the job summary): workspace tests pass on Windows
(including the Credential Manager code paths), silent per-user install without elevation, files, Start-menu
entries and HKCU uninstall entry, the installed agent starts, no token/password-like strings in plain files under
the install dir and the data root, silent uninstall removes the program and keeps user data, upgrade from the
previous successful run's installer keeps user data and leaves a single install entry.

Agent checks: `--version`, background start, second start is a no-op (single instance), `--status` over the per-user
IPC endpoint, idle CPU and RAM over 20 s, `--quit`, and the uninstaller and upgrade stopping a running agent.

Not provable on a headless runner (needs the owner's Windows 10/11 workstation): tray icon and menu, toasts,
interactive Keycloak sign-in and MFA, SmartScreen behaviour, start at login and after reboot, Explorer
integration, Windows 10 (runners are Windows Server 2025), high-DPI and real WebView2 rendering.
