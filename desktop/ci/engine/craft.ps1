<#
  Runs KDE CraftMaster with upstream's own configuration (opencloud-eu/desktop .craft.ini + .github/workflows/craft_override.ini
  at the pinned tag) plus craft-pin.ini, which pins craft-core to the revision recorded in upstream's .craft.shelf and stops
  Craft from updating its repositories, so a rebuild months later uses the same recipe as upstream's v4.0.0 build.
  Usage (env OC_DIR = desktop checkout, CRAFT_PYTHON, CRAFT_TARGET): craft.ps1 --setup | craft.ps1 -c <craft args>
  Plain $args on purpose (no param block), so "-c" and craft options pass through untouched.
#>
$OcDir = $env:OC_DIR
if (-not $OcDir) { throw "OC_DIR not set" }
$PSNativeCommandUseErrorActionPreference = $true
$ErrorActionPreference = "Stop"
$python = $env:CRAFT_PYTHON
if (-not $python) { throw "CRAFT_PYTHON not set" }
$env:HOME = $HOME
$env:ANDROID_NDK = $null   # upstream's workaround: keeps CraftMaster from detecting Android
$cmd = @("$HOME/craft/CraftMaster/CraftMaster/CraftMaster.py",
         "--config", "$OcDir/.craft.ini",
         "--config-override", "$OcDir/.github/workflows/craft_override.ini",
         "--config-override", "$PSScriptRoot/craft-pin.ini",
         "--target", $env:CRAFT_TARGET,
         "--variables", "WORKSPACE=$HOME/craft") + $args
Write-Host "Exec: $python $($cmd -join ' ')"
& $python @cmd
if ($LASTEXITCODE -ne 0) { exit 1 }
