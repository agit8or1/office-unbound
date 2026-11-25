<#
  Corresponding source for the GPL-2.0-or-later engine build: the OpenCloud Desktop tree at the pinned commit, the exact
  Craft core and blueprint revisions from upstream's .craft.shelf, CraftMaster, our workflow and scripts, and a manifest of
  every Craft package installed (name, version, how it was obtained). Third-party library sources that Craft took as
  prebuilt binaries (e.g. Qt, LGPL-3.0) are listed with their versions in packages.txt; see SOURCES.md.
#>
param(
  [Parameter(Mandatory = $true)][string]$OcDir, [Parameter(Mandatory = $true)][string]$CraftRoot,
  [Parameter(Mandatory = $true)][string]$OutDir, [string]$Tag = "", [string]$Commit = "",
  [string]$CraftMasterUrl = "", [string]$CraftMasterCommit = ""
)
$ErrorActionPreference = "Stop"
$src = Join-Path $OutDir "source"
New-Item -ItemType Directory -Force -Path $src | Out-Null

git -C $OcDir archive --format=tar.gz --prefix="opencloud-desktop-$Tag/" -o (Join-Path $src "opencloud-desktop-$Tag-$($Commit.Substring(0,12)).tar.gz") $Commit
if ($LASTEXITCODE) { throw "git archive (desktop) failed" }

# Craft core + blueprint repositories exactly as unshelved (CraftMaster checks them out under the Craft root).
$repos = @()
foreach ($g in Get-ChildItem $CraftRoot -Recurse -Directory -Filter ".git" -Depth 5 -Force -ErrorAction SilentlyContinue) {
  $d = $g.Parent.FullName
  if ($d -like "*\downloads\*" -or $d -like "*\build\*") { continue }
  $name = ($d.Substring($CraftRoot.Length).Trim('\', '/') -replace '[\\/]', '_')
  $rev = git -C $d rev-parse HEAD
  $url = git -C $d config --get remote.origin.url
  git -C $d archive --format=tar.gz --prefix="$name/" -o (Join-Path $src "$name-$($rev.Substring(0,12)).tar.gz") HEAD
  $repos += "| $name | $url | $rev |"
}

# Our build recipe.
Copy-Item (Join-Path $OcDir ".craft.shelf") $src
Copy-Item "$env:GITHUB_WORKSPACE/ou/.github/workflows/desktop-engine-windows.yml" $src
Copy-Item "$env:GITHUB_WORKSPACE/ou/desktop/ci/engine/*" $src
Copy-Item "$env:RUNNER_TEMP/pinned.shelf" $src

# Installed Craft packages.
$list = & $env:CRAFT -c --list-installed 2>&1 | Out-String
Set-Content -Path (Join-Path $src "packages.txt") -Value $list

$md = @("# Corresponding source: opencloudcmd $Tag for Windows x64", "",
  "- OpenCloud Desktop: https://github.com/opencloud-eu/desktop tag $Tag, commit $Commit (archive in this folder).",
  "- CraftMaster: $CraftMasterUrl commit $CraftMasterCommit.",
  "- Build recipe: desktop-engine-windows.yml + collect-*.ps1 (this folder), upstream .craft.ps1/.craft.ini/craft_override.ini (inside the desktop archive), .craft.shelf (pins every package version).",
  "", "## Craft repositories (archived here)", "", "| Repo | URL | Commit |", "|---|---|---|") + $repos + @(
  "", "## Third-party libraries", "",
  "packages.txt lists every Craft package with its version. Libraries Craft installed from KDE's binary cache (Qt 6 and others)",
  "are not re-archived here; their sources are the upstream releases of those exact versions, and the Craft blueprints archived",
  "above give the download URLs and patches. Before redistributing the engine outside CI, add those source archives",
  "(or a written offer) next to the binaries.")
Set-Content -Path (Join-Path $src "SOURCES.md") -Value $md
Get-ChildItem $src | Format-Table Name, Length
