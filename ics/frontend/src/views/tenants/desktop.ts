// Office Unbound Desktop for Windows, downloaded from the ICS itself (owner 2026-11-25: "directly downloaded from the ui", not from GitHub).
import { API_BASE, get } from '../../api'

export interface DesktopWindows {
  product: string; platform: string; version: string; file: string; sha256: string; size: number; unsigned: boolean
  stage: 'alpha' | 'beta' | 'stable'; url: string
}

export const desktopApi = { info: () => get<{ windows: DesktopWindows | null }>('downloads/desktop') }

/** The download link: only the console's own API path (never an absolute or foreign URL from the response). */
export const DESKTOP_WINDOWS_HREF = `${API_BASE}/downloads/desktop/windows`

export function humanSize(n: number): string {
  return n >= 1024 ** 2 ? `${(n / 1024 ** 2).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`
}

/** The warning shown next to the link; null when the installer is code-signed and released. */
export function desktopWarning(w: DesktopWindows): string | null {
  if (w.unsigned) return `${w.stage === 'beta' ? 'Beta' : 'Alpha'}, not code-signed: Windows SmartScreen will warn`
  return w.stage === 'stable' ? null : `${w.stage === 'beta' ? 'Beta' : 'Alpha'} release`
}
