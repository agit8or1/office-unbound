# WinFsp bundling (mapped drive)

Status: **Planned** (owner decision 2026-11-25: bundle WinFsp, notice in About and the docs). Nothing is installed or tested on Windows yet.

## 1. Licence basis

WinFsp is GPLv3 with a FLOSS exception (`License.txt` in winfsp/winfsp). We use exception permission 2, "distribute unmodified binary
releases of the WinFsp installer". Our own code does not link the WinFsp DLL: rclone does, and rclone (MIT) is FLOSS, so permission 1
covers it. The conditions:

1. The product is FLOSS: Office Unbound Desktop is AGPL-3.0-only. Yes.
2. The notice and a repository link appear in the UI and in user-facing documentation. Texts are in section 2.
3. It is not linked or distributed with proprietary software. The installer must stay all-FLOSS. Release review: any new bundled binary
   gets a licence row in `docs/status/third-party-inventory.md` before it ships.
   **Open risk (owner/legal decision):** the WebView2 loader is under Microsoft's WebView2 SDK licence, not a FLOSS licence (inventory row,
   status REVIEW). MSVC builds link it statically into the app, and the GNU-ABI dev installer ships `WebView2Loader.dll`. Whether that
   counts as "linked or distributed with proprietary software" under the WinFsp exception, or as a system component like the MSVC
   runtime and the WebView2 runtime itself, is not settled here. Options: (a) get confirmation from the WinFsp author (the exception text
   invites contact), (b) ship WinFsp as a separate optional download that is not inside our installer, or (c) treat the loader as a
   system-library exception. Until this is decided, the release build must not embed the WinFsp MSI. Use option (b): the mapped-drive
   setup downloads the pinned, verified MSI on demand.

## 2. Notice texts (exact)

**About dialog** (Settings → About → "Third-party components", always visible, not behind a toggle):

> **WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos**
> Used for the mapped drive. Licensed under GPLv3 with the FLOSS exception. Source: https://github.com/winfsp/winfsp

**User documentation** (the "Mapped drive" page, and `THIRD-PARTY-NOTICES.txt` installed next to the executable):

> The Office Unbound mapped drive uses **WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos**
> (https://github.com/winfsp/winfsp), distributed unmodified under the GPLv3 with its FLOSS exception, and **rclone**
> (https://github.com/rclone/rclone, MIT licence). The WinFsp installer is the official release from the WinFsp project. Its licence
> text is installed in `C:\Program Files (x86)\WinFsp\License.txt`.

The same two lines go into the installer's licence page (after the AGPL text).

## 3. Version pin

| Field | Value |
|---|---|
| Release | **WinFsp 2.1** (tag `v2.1`, published 2025-06-05), installer `winfsp-2.1.25156.msi` |
| SHA-256 | `073a70e00f77423e34bed98b86e600def93393ba5822204fac57a29324db9f7a` (GitHub release asset digest, read 2026-11-25) |
| Source URL | `https://github.com/winfsp/winfsp/releases/download/v2.1/winfsp-2.1.25156.msi` |
| Next candidate | WinFsp 2.2 (`winfsp-2.2.26323.msi`, published 2026-11-19, sha256 `36ce01f9eedbbe6842b7fb4bedc79d7d4f71983e8aceb6877b46a07b331c7e19`). Move to it after a soak test on Windows, not before. |

The pin (version, URL, sha256) lives in one file, `desktop/installer/thirdparty.lock` (the lead owns the installer directory; proposed
content below). Updates are pull requests that change all three fields together.

```
winfsp  2.1.25156  https://github.com/winfsp/winfsp/releases/download/v2.1/winfsp-2.1.25156.msi  073a70e00f77423e34bed98b86e600def93393ba5822204fac57a29324db9f7a
```

## 4. Build-time fetch (winci, GitHub Actions `windows-latest`)

1. Download from the GitHub release URL only (github.com is an authorized endpoint). No mirrors, no other CDN.
2. Verify the SHA-256 against the lock file and fail the build on a mismatch.
3. Verify the Authenticode signature with `Get-AuthenticodeSignature`. It must be `Valid`, chain to a trusted root, and the signer subject
   must equal the value recorded in the lock file on the first verified build. If the subject changes, the build fails and a human reviews.
4. Cache the verified MSI keyed by its sha256 (actions/cache). Do not commit it to the repo.
5. Once the open risk in section 1 is cleared, embed the MSI unmodified in our installer payload. It is never repacked, so the
   exception's "unmodified binary release" holds and the original signature stays valid. Until then, the agent fetches the same pinned
   URL on demand and verifies it the same way (sha256 + signature) before running it.

## 5. Install integration

- **When:** only if the user (or a policy) enables the mapped drive. The sync folder does not need WinFsp, so a default install does not
  add a kernel-mode driver. The option "Install mapped-drive support" is in the installer and also in Settings later. Enabling it there
  needs one UAC elevation.
- **Detect first:** read the MSI UpgradeCode `5466A3D8-3AA1-4240-B6A0-3A051940A3EC` (from WinFsp's `Product.wxs`) through
  `MsiEnumRelatedProducts`. If a WinFsp of the pinned major version or newer is installed (for example by the user for another tool),
  use it and do not install or downgrade.
- **Silent install**, elevated (the WinFsp driver needs admin rights; it is the only elevated step):
  `msiexec /i winfsp-2.1.25156.msi /qn /norestart ADDLOCAL=F.Main,F.User /l*v "%ProgramData%\Office Unbound\logs\winfsp-install.log"`.
  The feature IDs come from WinFsp `Product.wxs` v2.1: `F.Main` and `F.User` (Core). `F.Developer` and `F.Net` are not installed.
- **Exit codes:** 0 = done. 3010 = done, reboot required: the UI says "Restart to finish setting up the mapped drive" and never forces a
  restart. 1618 = another install is running: retry later. Anything else: the mapped-drive option stays off and the log path is shown.
- **Uninstall:** our uninstaller does **not** remove WinFsp, because other software may depend on it. Settings shows how to remove it
  through Windows "Installed apps". Exception: if our installer installed it and the user ticks "also remove mapped-drive support", run
  `msiexec /x {ProductCode} /qn /norestart`.
- **Upgrades:** WinFsp's MSI has a MajorUpgrade, so installing a newer pinned MSI upgrades in place. We only upgrade when our lock file's
  version is newer than the installed one.
- **Enterprise/MSP:** the silent install of our MSI takes `OU_MAPPED_DRIVE=1` and installs WinFsp the same way. Intune/GPO packages can
  also deploy the WinFsp MSI themselves first.

## 6. To verify on Windows (not done)

The signer subject value; silent install on Windows 10 22H2 and 11 24H2 (with and without a pre-installed WinFsp); the 3010 path; rclone
mount on `O:`, then unmount and remount after a reboot; uninstall leaves other WinFsp users working.
