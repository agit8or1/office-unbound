; Office Unbound Desktop - per-user NSIS installer (CI fallback, UNSIGNED ALPHA).
; Used by .github/workflows/desktop-windows.yml while no Tauri GUI crate exists in desktop/crates/.
; Once a crate with tauri.conf.json exists, the workflow builds with the Tauri bundler instead.
;
; makensis /DVERSION=0.1.0-alpha.1 /DVERSION4=0.1.0.123 /DBUILDID=<git sha> /DSRCDIR=<dir with exes> /DOUTFILE=<path> installer.nsi
;
; Layout (per user, no elevation):
;   program files : %LOCALAPPDATA%\Programs\Office Unbound Desktop   (removed by the uninstaller)
;   user data     : %LOCALAPPDATA%\OfficeUnbound                      (KEPT by the uninstaller: accounts, settings, sync state)
;   credentials   : Windows Credential Manager                         (KEPT; signing out in the app removes them)

Unicode true
!include "MUI2.nsh"

!ifndef VERSION | VERSION4 | BUILDID | SRCDIR | OUTFILE
  !error "VERSION, VERSION4, BUILDID, SRCDIR and OUTFILE must be defined"
!endif

!define PRODUCT "Office Unbound Desktop"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\OfficeUnboundDesktop"

Name "${PRODUCT}"
OutFile "${OUTFILE}"
RequestExecutionLevel user
InstallDir "$LOCALAPPDATA\Programs\${PRODUCT}"
InstallDirRegKey HKCU "${UNINST_KEY}" "InstallLocation"
SetCompressor /SOLID lzma
ShowInstDetails show
ShowUninstDetails show

VIProductVersion "${VERSION4}"
VIAddVersionKey "ProductName" "${PRODUCT}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "FileVersion" "${VERSION4}"
VIAddVersionKey "FileDescription" "${PRODUCT} installer (unsigned alpha)"
VIAddVersionKey "LegalCopyright" "AGPL-3.0-only"
VIAddVersionKey "CompanyName" "Office Unbound"

!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TEXT "This installs ${PRODUCT} ${VERSION} for the current user only.$\r$\n$\r$\nThis is an UNSIGNED ALPHA build: Windows SmartScreen will warn about an unknown publisher."
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

; Stop this user's running agent so its exe can be replaced (upgrade) or removed (uninstall).
!macro StopAgent
  ReadEnvStr $0 USERNAME
  nsExec::Exec '"$SYSDIR\taskkill.exe" /F /IM ou-agent.exe /FI "USERNAME eq $0"'
  Pop $1
  Sleep 500
!macroend

Section "Install"
  SetShellVarContext current
  !insertmacro StopAgent
  SetOutPath "$INSTDIR"
  File "${SRCDIR}\ou-agent.exe"
  File "${SRCDIR}\LICENSE"
  WriteUninstaller "$INSTDIR\uninstall.exe"

  CreateDirectory "$SMPROGRAMS\${PRODUCT}"
  CreateShortcut "$SMPROGRAMS\${PRODUCT}\${PRODUCT}.lnk" "$INSTDIR\ou-agent.exe"
  CreateShortcut "$SMPROGRAMS\${PRODUCT}\Uninstall ${PRODUCT}.lnk" "$INSTDIR\uninstall.exe"

  WriteRegStr HKCU "${UNINST_KEY}" "DisplayName" "${PRODUCT}"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINST_KEY}" "Publisher" "Office Unbound"
  WriteRegStr HKCU "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\ou-agent.exe"
  WriteRegStr HKCU "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKCU "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegStr HKCU "${UNINST_KEY}" "BuildId" "${BUILDID}"
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  SetShellVarContext current
  !insertmacro StopAgent
  Delete "$INSTDIR\ou-agent.exe"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\${PRODUCT}\${PRODUCT}.lnk"
  Delete "$SMPROGRAMS\${PRODUCT}\Uninstall ${PRODUCT}.lnk"
  RMDir "$SMPROGRAMS\${PRODUCT}"
  DeleteRegKey HKCU "${UNINST_KEY}"
  ; User data (%LOCALAPPDATA%\OfficeUnbound) and Credential Manager entries are intentionally kept.
SectionEnd
