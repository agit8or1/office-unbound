; Office Unbound Desktop NSIS hooks (tauri bundle.windows.nsis.installerHooks).
; The background agent (ou-agent.exe) keeps running when the window is closed; stop it before files are replaced or removed,
; otherwise an upgrade or uninstall would fail on a locked file. "--quit" asks the running agent of this user to exit over its
; own endpoint; nothing else is executed.
!macro OU_STOP_AGENT
  IfFileExists "$INSTDIR\ou-agent.exe" 0 +3
    nsExec::Exec '"$INSTDIR\ou-agent.exe" --quit'
    Sleep 1500
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro OU_STOP_AGENT
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro OU_STOP_AGENT
!macroend
