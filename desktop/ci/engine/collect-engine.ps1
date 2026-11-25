<#
  Extracts opencloudcmd.exe from upstream's portable package and copies exactly the files it needs:
  its import closure (dumpbin /dependents, recursive, only files shipped in the package), the Qt plugins Qt loads at run time
  for networking (tls, networkinformation), OpenSSL DLLs that the TLS backend loads dynamically, and qt.conf.
  Then runs the collected engine in isolation (--version / --help) to prove it loads on Windows.
#>
param(
  [Parameter(Mandatory = $true)][string]$PackageDir,
  [Parameter(Mandatory = $true)][string]$OutDir,
  [string]$Tag = "", [string]$Commit = ""
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$pkg = Get-ChildItem $PackageDir -File | Where-Object { $_.Extension -in ".zip", ".7z" } | Sort-Object Length -Descending | Select-Object -First 1
if (-not $pkg) { throw "no portable package (.zip/.7z) in $PackageDir" }
Write-Host "portable package: $($pkg.Name) ($($pkg.Length) bytes)"
$x = Join-Path $env:RUNNER_TEMP "portable"
Remove-Item -Recurse -Force $x -ErrorAction SilentlyContinue
& 7z x -y "-o$x" $pkg.FullName | Out-Null
if ($LASTEXITCODE) { throw "7z failed" }

$cmd = Get-ChildItem $x -Recurse -Filter "opencloudcmd.exe" | Select-Object -First 1
if (-not $cmd) { throw "opencloudcmd.exe not in the package" }
$root = $cmd.DirectoryName
Write-Host "package root: $root"

$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
$dumpbin = & $vswhere -latest -products * -find "VC\Tools\MSVC\**\bin\Hostx64\x64\dumpbin.exe" | Select-Object -First 1
if (-not $dumpbin) { throw "dumpbin not found" }

# All DLLs shipped in the package, by lower-case file name.
$shipped = @{}
Get-ChildItem $x -Recurse -Filter "*.dll" | ForEach-Object { if (-not $shipped.ContainsKey($_.Name.ToLower())) { $shipped[$_.Name.ToLower()] = $_.FullName } }

function Get-Deps([string]$file) {
  $out = & $dumpbin /nologo /dependents $file
  $out | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^[A-Za-z0-9_.+-]+\.dll$' }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$seen = @{}
$queue = New-Object System.Collections.Generic.Queue[string]
$queue.Enqueue($cmd.FullName)

# Run-time loaded pieces: Qt network plugins, OpenSSL (dynamically loaded by the TLS backend), qt.conf.
$extra = @()
$pluginDirs = @(Get-ChildItem $x -Recurse -Directory | Where-Object { $_.Name -in @("tls", "networkinformation") })
Write-Host "plugin dirs: $(($pluginDirs | ForEach-Object { [IO.Path]::GetRelativePath($x, $_.FullName) }) -join ', ')"
foreach ($pd in $pluginDirs) { Get-ChildItem $pd.FullName -Filter "*.dll" | ForEach-Object { $extra += $_.FullName } }
if (-not $pluginDirs) { Write-Host "::warning::no Qt tls/networkinformation plugin dirs in the package" }
$extra += @(Get-ChildItem $root -Filter "lib*ssl*.dll") + @(Get-ChildItem $root -Filter "lib*crypto*.dll") | ForEach-Object { $_.FullName }
foreach ($e in $extra) { $queue.Enqueue($e) }

$system = 0
while ($queue.Count) {
  $f = $queue.Dequeue()
  $key = $f.ToLower()
  if ($seen.ContainsKey($key)) { continue }
  $seen[$key] = $true
  $rel = [IO.Path]::GetRelativePath($root, $f)
  # Plugins live outside bin/ in the portable layout: put them in plugins/<type>/ next to the exe (qt.conf below).
  if ($rel.StartsWith("..") -or (Split-Path $f -Parent | Split-Path -Leaf) -in @("tls", "networkinformation")) {
    $rel = Join-Path "plugins" ([IO.Path]::GetRelativePath((Split-Path (Split-Path $f)), $f))
  }
  $dest = Join-Path $OutDir $rel
  New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
  Copy-Item $f $dest -Force
  foreach ($d in Get-Deps $f) {
    $n = $d.ToLower()
    if ($shipped.ContainsKey($n)) { $queue.Enqueue($shipped[$n]) } else { $system++ }
  }
}
# Our own qt.conf: the upstream one points at the portable layout (bin/ + ../plugins), ours is flat.
Set-Content -Path (Join-Path $OutDir "qt.conf") -Value "[Paths]`nPrefix = .`nPlugins = plugins"

$files = Get-ChildItem $OutDir -Recurse -File
Write-Host "collected $($files.Count) files, $((($files | Measure-Object Length -Sum).Sum)) bytes; $system import(s) resolved by Windows itself"
$files | ForEach-Object { Write-Host ("  {0,10}  {1}" -f $_.Length, [IO.Path]::GetRelativePath($OutDir, $_.FullName)) }

# Isolation check: a clean PATH (Windows only), so nothing from Craft's image can satisfy a missing DLL.
$env:PATH = "$env:SystemRoot\system32;$env:SystemRoot"
$exe = Join-Path $OutDir "opencloudcmd.exe"
$ok = $false
foreach ($a in @("--version", "--help")) {
  $o = & $exe $a 2>&1 | Out-String
  $code = $LASTEXITCODE
  Write-Host "opencloudcmd $a -> exit $code"
  Write-Host ($o.Trim() -split "`n" | Select-Object -First 15 | Out-String)
  if ($code -ne -1073741515 -and $o.Trim().Length -gt 0) { $ok = $true }   # 0xC0000135 = DLL not found
}
if (-not $ok) { throw "collected opencloudcmd.exe does not start in isolation" }
$tls = @(Get-ChildItem (Join-Path $OutDir "plugins\tls") -Filter "*.dll" -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
Write-Host "TLS backends shipped: $($tls -join ', ')"
if (-not $tls) { throw "no Qt TLS backend collected: HTTPS would fail at run time" }
@("opencloudcmd $Tag ($Commit) for Windows x64, built by .github/workflows/desktop-engine-windows.yml (unsigned).",
  "Collected from upstream's PortablePackager output $($pkg.Name).") | Set-Content (Join-Path $OutDir "BUILDINFO.txt")
