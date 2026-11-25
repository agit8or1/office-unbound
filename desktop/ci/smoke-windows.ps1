<#
  Office Unbound Desktop - installer smoke test on a real Windows runner (windows-latest).

  Usage: smoke-windows.ps1 -Installer <setup.exe> [-Previous <older setup.exe>] [-Msi <file.msi>] [-Report <file.md>]

  Proves on real Windows: silent per-user install (/S), installed files, Start-menu entry, uninstall
  registry entry, launch of the installed agent (and GUI if present), no secret-looking strings in
  config/data files, silent uninstall that removes the program but keeps user data, and (with -Previous)
  an upgrade from the previous CI artifact that keeps user data.
  Cannot prove headless: tray icon visibility/menu, toasts, interactive sign-in, SmartScreen prompts.
#>
param(
  [Parameter(Mandatory = $true)][string]$Installer,
  [string]$Previous = "",
  [string]$Msi = "",
  [string]$Report = "smoke-report.md"
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Matches both the Tauri build ("Office Unbound") and the ou-agent-only fallback ("Office Unbound Desktop").
$Product = "Office Unbound"
$Identifier = "com.officeunbound.desktop"   # Tauri identifier: WebView2 and app data folders
$DataRoot = Join-Path $env:LOCALAPPDATA "OfficeUnbound"
$StartMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
$script:Results = New-Object System.Collections.Generic.List[string]
$script:Failed = 0

function Note([string]$status, [string]$what) {
  $line = "| $status | $what |"
  $script:Results.Add($line)
  Write-Host "[$status] $what"
  if ($status -eq "FAIL") { $script:Failed++ }
}
function Check([bool]$ok, [string]$what) { if ($ok) { Note "PASS" $what } else { Note "FAIL" $what } }

function Get-UninstallEntry {
  $roots = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
             "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall")
  foreach ($r in $roots) {
    if (-not (Test-Path $r)) { continue }
    foreach ($k in @(Get-ChildItem $r -ErrorAction SilentlyContinue)) {
      $p = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
      if ($null -eq $p) { continue }
      if (($p.PSObject.Properties.Name -contains "DisplayName") -and ($p.DisplayName -like "$Product*")) {
        return [pscustomobject]@{ Hive = $r; Key = $k.PSPath; Props = $p }
      }
    }
  }
  return $null
}

function Get-InstallDir($entry) {
  if ($entry -and ($entry.Props.PSObject.Properties.Name -contains "InstallLocation") -and $entry.Props.InstallLocation) {
    return $entry.Props.InstallLocation.Trim('"')
  }
  if ($entry -and ($entry.Props.PSObject.Properties.Name -contains "UninstallString")) {
    return Split-Path -Parent ($entry.Props.UninstallString.Trim('"'))
  }
  return $null
}

function Stop-OurProcesses([string]$dir) {
  if (-not $dir) { return }
  Get-Process -ErrorAction SilentlyContinue | Where-Object {
    try { $_.Path -and $_.Path.StartsWith($dir, [System.StringComparison]::OrdinalIgnoreCase) } catch { $false }
  } | ForEach-Object { Write-Host "stopping $($_.ProcessName) ($($_.Id))"; Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Seconds 1
}

function Install-Silent([string]$exe, [string]$label) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $p = Start-Process -FilePath $exe -ArgumentList "/S" -Wait -PassThru
  $sw.Stop()
  Check ($p.ExitCode -eq 0) "$label silent install (/S) exit code $($p.ExitCode) in $([int]$sw.Elapsed.TotalSeconds)s"
  $entry = $null
  for ($i = 0; $i -lt 30 -and -not $entry; $i++) { $entry = Get-UninstallEntry; if (-not $entry) { Start-Sleep 1 } }
  Check ($null -ne $entry) "$label uninstall registry entry present"
  return $entry
}

function Uninstall-Silent($entry, [string]$label) {
  $dir = Get-InstallDir $entry
  $u = $entry.Props.UninstallString.Trim('"')
  if ($entry.Props.PSObject.Properties.Name -contains "QuietUninstallString" -and $entry.Props.QuietUninstallString) {
    Write-Host "QuietUninstallString: $($entry.Props.QuietUninstallString)"
  }
  $p = Start-Process -FilePath $u -ArgumentList "/S" -Wait -PassThru
  # NSIS uninstallers copy themselves to %TEMP% and return early: poll for the result.
  $gone = $false
  for ($i = 0; $i -lt 60; $i++) {
    if (-not (Get-UninstallEntry) -and -not (Test-Path (Join-Path $dir "*.exe"))) { $gone = $true; break }
    Start-Sleep 1
  }
  Check ($p.ExitCode -eq 0) "$label silent uninstall exit code $($p.ExitCode)"
  Check (@(Get-AgentProcs).Count -eq 0) "$label no ou-agent process left after uninstall"
  Check $gone "$label uninstall removed the program files and the registry entry ($dir)"
  $lnk = @(Get-ChildItem -Path $StartMenu -Recurse -Filter "*.lnk" -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*Office Unbound*" })
  Check ($lnk.Count -eq 0) "$label uninstall removed the Start-menu entries"
  $run = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
  $left = @()
  if ($run) { $left = @($run.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" -and "$($_.Value)" -like "*$dir*" } | ForEach-Object { $_.Name }) }
  Check ($left.Count -eq 0) "$label no start-at-login entry left pointing into the removed program dir ($($left -join ', '))"
}

function Seed-UserData([string]$tag) {
  New-Item -ItemType Directory -Force -Path $DataRoot | Out-Null
  $f = Join-Path $DataRoot "ci-user-data-marker.txt"
  Set-Content -Path $f -Value "kept-across-$tag $(Get-Date -Format o)"
  return $f
}

function Count-SecretHits([string[]]$dirs) {
  # Look for token/credential material in plain files. Credential Manager is the only allowed store.
  $patterns = @('eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', '"?(access|refresh|id)_token"?\s*[:=]\s*"?[A-Za-z0-9._-]{8,}',
                'client_secret', '(?i)password\s*[:=]\s*\S+', '-----BEGIN [A-Z ]*PRIVATE KEY-----')
  $hits = 0; $files = 0
  foreach ($d in $dirs) {
    if (-not $d -or -not (Test-Path $d)) { continue }
    foreach ($f in Get-ChildItem -Path $d -Recurse -File -ErrorAction SilentlyContinue) {
      if ($f.Extension -in @(".exe", ".dll", ".msi", ".pdb")) { continue }
      if ($f.Length -gt 10MB) { continue }
      if ($f.FullName -like "*\EBWebView\*") { continue }   # WebView2 browser cache
      $files++
      foreach ($pat in $patterns) {
        if (Select-String -Path $f.FullName -Pattern $pat -Quiet -ErrorAction SilentlyContinue) {
          Write-Host "secret-like pattern in $($f.FullName) (content not printed)"
          $hits++
        }
      }
    }
  }
  return @($hits, $files)
}

function Scan-Secrets([string[]]$dirs) {
  # Self-test first: the scanner must flag a planted fake token, or a clean result means nothing.
  $canary = Join-Path $env:RUNNER_TEMP "secret-scan-canary"
  New-Item -ItemType Directory -Force -Path $canary | Out-Null
  Set-Content -Path (Join-Path $canary "settings.json") -Value ('{"refresh_token": "' + ("ci" * 8) + '"}')
  $c = Count-SecretHits @($canary)
  Remove-Item -Recurse -Force $canary
  Check ($c[0] -ge 1) "secret scanner self-test flags a planted fake token"
  $r = Count-SecretHits $dirs
  Check ($r[0] -eq 0) "no secret-like strings in $($r[1]) config/data/log file(s) under install dir and $DataRoot (no sign-in happens in CI)"
}

function Invoke-Exe([string]$exe, [string]$argline, [int]$seconds) {
  $tag = [guid]::NewGuid().ToString("N").Substring(0, 8)
  $out = Join-Path $env:RUNNER_TEMP "run-$tag.out.txt"; $err = Join-Path $env:RUNNER_TEMP "run-$tag.err.txt"
  $sp = @{ FilePath = $exe; PassThru = $true; RedirectStandardOutput = $out; RedirectStandardError = $err; WindowStyle = "Hidden" }
  if ($argline) { $sp.ArgumentList = $argline }
  $p = Start-Process @sp
  $done = $p.WaitForExit($seconds * 1000)
  $txt = (Get-Content $out -Raw -ErrorAction SilentlyContinue); if ($null -eq $txt) { $txt = "" }
  $etxt = (Get-Content $err -Raw -ErrorAction SilentlyContinue); if ($null -eq $etxt) { $etxt = "" }
  return [pscustomobject]@{ Process = $p; Exited = $done; Code = $(if ($done) { $p.ExitCode } else { $null }); Out = $txt.Trim(); Err = $etxt.Trim() }
}

function Get-AgentProcs { @(Get-Process -Name "ou-agent" -ErrorAction SilentlyContinue) }

# Background agent lifecycle: --version, start, single instance, --status over IPC, idle CPU/RAM, --quit.
function Agent-Lifecycle([string]$exe, [string]$label) {
  if (-not (Test-Path $exe)) { Note "FAIL" "${label}: $exe missing"; return }
  $v = Invoke-Exe $exe "--version" 10
  Check ($v.Exited -and $v.Code -eq 0 -and $v.Out -like "ou-agent *") "$label --version exit $($v.Code): '$($v.Out)'"
  $a = Invoke-Exe $exe "" 8
  if ($a.Exited) {
    Note "FAIL" "$label background start exited at once (code $($a.Code), stderr '$($a.Err)')"
    return
  }
  $agentProc = $a.Process
  Note "PASS" "$label background process running (pid $($agentProc.Id))"
  $second = Invoke-Exe $exe "" 10
  Check ($second.Exited -and $second.Code -eq 0) "$label second start is a no-op (exit $($second.Code))"
  Check (@(Get-AgentProcs).Count -eq 1) "$label single instance: $(@(Get-AgentProcs).Count) ou-agent process(es)"
  $st = Invoke-Exe $exe "--status" 15
  Check ($st.Exited -and $st.Code -eq 0 -and $st.Out.StartsWith("{")) "$label --status over the per-user IPC endpoint: exit $($st.Code), $($st.Out.Length) bytes JSON"
  $pp = Get-Process -Id $agentProc.Id
  $cpu0 = $pp.TotalProcessorTime.TotalMilliseconds
  Start-Sleep -Seconds 20
  $pp.Refresh()
  $cpuMs = [int]($pp.TotalProcessorTime.TotalMilliseconds - $cpu0)
  $wsMb = [math]::Round($pp.WorkingSet64 / 1MB, 1)
  $thr = $pp.Threads.Count
  Check ($cpuMs -lt 1000) "$label idle: ${cpuMs} ms CPU in 20 s, working set $wsMb MB, $thr threads"
  $q = Invoke-Exe $exe "--quit" 15
  $gone = $agentProc.WaitForExit(15000)
  Check ($q.Code -eq 0 -and $gone) "$label --quit: exit $($q.Code), agent stopped: $gone"
}

function Launch-Check([string]$exe, [string]$label, [int]$seconds) {
  if (-not (Test-Path $exe)) { Note "SKIP" "$label not installed ($exe)"; return }
  $out = Join-Path $env:RUNNER_TEMP "$label.out.txt"; $err = Join-Path $env:RUNNER_TEMP "$label.err.txt"
  $p = Start-Process -FilePath $exe -PassThru -RedirectStandardOutput $out -RedirectStandardError $err -WindowStyle Hidden
  $exited = $p.WaitForExit($seconds * 1000)
  if ($exited) {
    $txt = (Get-Content $out -Raw -ErrorAction SilentlyContinue)
    if ($null -eq $txt) { $txt = "" }
    Check ($p.ExitCode -eq 0) "$label launched and exited with code $($p.ExitCode); stdout: '$($txt.Trim())'"
  } else {
    $alive = Get-Process -Id $p.Id -ErrorAction SilentlyContinue
    $ws = if ($alive) { [int]($alive.WorkingSet64 / 1MB) } else { 0 }
    $kids = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($p.Id)" -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    Check ($null -ne $alive) "$label still running after ${seconds}s (pid $($p.Id), working set ${ws} MB, children: $($kids -join ', '))"
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
  }
}

trap {
  Write-Host "::error::smoke test aborted: $($_.Exception.Message) at $($_.InvocationInfo.PositionMessage)"
  exit 2
}

Write-Host "== OS: $((Get-CimInstance Win32_OperatingSystem).Caption) $([Environment]::OSVersion.Version) user=$env:USERNAME"
$Installer = (Resolve-Path $Installer).Path
Note "INFO" "installer $(Split-Path -Leaf $Installer), $((Get-Item $Installer).Length) bytes, sha256 $((Get-FileHash $Installer -Algorithm SHA256).Hash.ToLower())"
$sig = Get-AuthenticodeSignature $Installer
Note "INFO" "Authenticode status: $($sig.Status) (expected NotSigned: unsigned alpha)"

if (Get-UninstallEntry) { throw "a previous '$Product' install exists on this runner; refusing to continue" }

# --- 1. fresh install ---
$entry = Install-Silent $Installer "fresh"
$dir = Get-InstallDir $entry
Note "INFO" "install dir: $dir; registry: $($entry.Hive); DisplayVersion $($entry.Props.DisplayVersion)"
Check ($dir -and $dir.StartsWith($env:LOCALAPPDATA, [System.StringComparison]::OrdinalIgnoreCase)) "per-user install location under %LOCALAPPDATA%"
Check ($entry.Hive -like "HKCU:*") "uninstall entry is per-user (HKCU), no elevation needed"
Check (-not $dir.TrimEnd('\').Equals($DataRoot, [System.StringComparison]::OrdinalIgnoreCase)) "program dir is separate from the user data root $DataRoot"
$exes = @(Get-ChildItem -Path $dir -Filter "*.exe" -File | ForEach-Object { $_.Name })
Note "INFO" "installed executables: $($exes -join ', ')"
foreach ($x in @(Get-ChildItem -Path $dir -Filter "*.exe" -File | Where-Object { $_.Name -ne "uninstall.exe" })) {
  $txt = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($x.FullName))
  $leaks = @(@($env:USERPROFILE, "$env:GITHUB_WORKSPACE", ".cargo\registry") | Where-Object { $_ -and $txt.IndexOf($_, [StringComparison]::OrdinalIgnoreCase) -ge 0 })
  Check ($leaks.Count -eq 0) "$($x.Name) embeds no build-machine paths (checked user profile, workspace, cargo registry)$(if ($leaks.Count) { ': found ' + ($leaks -join ', ') })"
}
$agent = Join-Path $dir "ou-agent.exe"
Check (Test-Path $agent) "ou-agent.exe installed"
$lnk = @(Get-ChildItem -Path $StartMenu -Recurse -Filter "*.lnk" -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*Office Unbound*" })
Check ($lnk.Count -ge 1) "Start-menu entry present: $(($lnk | ForEach-Object { $_.FullName.Substring($StartMenu.Length) }) -join ', ')"

# --- 2. launch ---
Agent-Lifecycle $agent "ou-agent"
$logs = @(Get-ChildItem -Path $DataRoot -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName.Substring($DataRoot.Length) })
Note "INFO" "files the agent wrote under the data root: $($logs -join ', ')"
$gui = @(Get-ChildItem -Path $dir -Filter "*.exe" -File | Where-Object { $_.Name -notin @("ou-agent.exe", "uninstall.exe") })
if ($gui.Count -gt 0) {
  foreach ($g in $gui) { Launch-Check $g.FullName $g.BaseName 15 }
  Note "INFO" "ou-agent processes after the GUI ran: $(@(Get-AgentProcs).Count)"
  Note "INFO" "tray icon/menu cannot be verified headless; the process check above only proves the GUI process starts and stays up"
} else {
  Note "SKIP" "no GUI executable in this build yet: tray and window cannot be tested"
}

# --- 3. secrets ---
$marker = Seed-UserData "uninstall"
Scan-Secrets @($dir, $DataRoot, (Join-Path $env:APPDATA $Identifier), (Join-Path $env:LOCALAPPDATA $Identifier))

# --- 4. uninstall (with the agent running) keeps user data ---
$bg = Invoke-Exe $agent "" 5
Note "INFO" "agent started before uninstall: running=$(-not $bg.Exited)"
Uninstall-Silent $entry "fresh"
Check (Test-Path $marker) "user data kept after uninstall ($marker)"

# --- 5. upgrade from the previous CI artifact ---
if ($Previous -and (Test-Path $Previous)) {
  $Previous = (Resolve-Path $Previous).Path
  Note "INFO" "previous installer $(Split-Path -Leaf $Previous), sha256 $((Get-FileHash $Previous -Algorithm SHA256).Hash.ToLower())"
  $old = Install-Silent $Previous "previous"
  $oldBuild = if ($old.Props.PSObject.Properties.Name -contains "BuildId") { $old.Props.BuildId } else { "" }
  $marker = Seed-UserData "upgrade"
  $bg = Invoke-Exe (Join-Path (Get-InstallDir $old) "ou-agent.exe") "" 5
  Note "INFO" "previous agent started before the upgrade: running=$(-not $bg.Exited)"
  $new = Install-Silent $Installer "upgrade"
  if (-not $bg.Exited) { Check (@(Get-AgentProcs).Count -eq 0) "upgrade stopped the running previous agent" }
  else { Note "SKIP" "previous build's agent does not stay running (code $($bg.Code)): stop-on-upgrade not exercised" }
  $newBuild = if ($new.Props.PSObject.Properties.Name -contains "BuildId") { $new.Props.BuildId } else { "" }
  Note "INFO" "upgrade: $($old.Props.DisplayVersion) ($oldBuild) -> $($new.Props.DisplayVersion) ($newBuild)"
  $entries = @(Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall" | ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue } | Where-Object { $_ -and ($_.PSObject.Properties.Name -contains "DisplayName") -and $_.DisplayName -like "$Product*" })
  Check ($entries.Count -eq 1) "exactly one installed entry after the upgrade (found $($entries.Count))"
  if ($oldBuild -and $newBuild) { Check ($newBuild -ne $oldBuild -or $oldBuild -eq $env:GITHUB_SHA) "upgrade replaced the build id" }
  Check (Test-Path $marker) "user data kept across the upgrade"
  Agent-Lifecycle (Join-Path (Get-InstallDir $new) "ou-agent.exe") "after-upgrade"
  Uninstall-Silent $new "upgrade"
} else {
  Note "SKIP" "no previous CI installer artifact found: upgrade path not tested in this run"
}

# --- 6. MSI (if built) ---
if ($Msi -and (Test-Path $Msi)) {
  $log = Join-Path $env:RUNNER_TEMP "msi-install.log"
  $p = Start-Process msiexec.exe -ArgumentList @("/i", "`"$((Resolve-Path $Msi).Path)`"", "/qn", "/norestart", "/l*v", "`"$log`"") -Wait -PassThru
  Check ($p.ExitCode -eq 0) "MSI silent install (msiexec /qn) exit code $($p.ExitCode)"
  $m = Get-UninstallEntry
  Check ($null -ne $m) "MSI uninstall entry present ($(if ($m) { $m.Hive }))"
  if ($m) {
    Stop-OurProcesses (Get-InstallDir $m)
    $code = Split-Path -Leaf $m.Key
    $p = Start-Process msiexec.exe -ArgumentList @("/x", $code, "/qn", "/norestart") -Wait -PassThru
    Check ($p.ExitCode -eq 0) "MSI silent uninstall exit code $($p.ExitCode)"
  }
} else {
  Note "SKIP" "no MSI in this build"
}

Remove-Item -Force (Join-Path $DataRoot "ci-user-data-marker.txt") -ErrorAction SilentlyContinue

$md = @("## Windows smoke test", "", "Runner: $((Get-CimInstance Win32_OperatingSystem).Caption) $([Environment]::OSVersion.Version)", "",
        "| Result | Check |", "|---|---|") + $script:Results +
      @("", "Not testable on a headless runner: tray icon and menu, toasts, interactive Keycloak sign-in, SmartScreen, reboot/login autostart.")
Set-Content -Path $Report -Value $md
if ($env:GITHUB_STEP_SUMMARY) { Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value $md }
if ($script:Failed -gt 0) { Write-Host "::error::$($script:Failed) smoke check(s) failed"; exit 1 }
Write-Host "all smoke checks passed"
