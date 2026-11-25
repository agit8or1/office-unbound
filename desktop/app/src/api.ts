// Typed bridge to the Rust side. Mirrors ou_core::ipc (Request/Response); the webview never sees tokens.
import { invoke } from '@tauri-apps/api/core'

export type Service = 'portal' | 'files' | 'chat' | 'mail' | 'calendar' | 'contacts'
export type SessionState = 'signed_in' | 'signing_in' | 'signed_out' | 'offline' | 'error'

export interface Deployment {
  domain: string; name: string; issuer: string; client_id: string; files_url: string
  portal_url: string | null; matrix_url: string | null; chat_web_url: string | null; mail_web_url: string | null
  source: 'client_document' | 'web_finger'; login_hint: string | null; foreign_hosts: string[]
}
export interface AccountStatus {
  id: string; label: string; deployment: string; domain: string; state: SessionState
  detail: string | null; services: Service[]; files_url: string
}
export type Request =
  | { type: 'status' }
  | { type: 'discover'; input: string }
  | { type: 'sign_in'; discovery_id: string }
  | { type: 'sign_out'; account_id: string }
  | { type: 'remove_account'; account_id: string }
  | { type: 'open_service'; account_id: string; service: Service }
  | { type: 'set_paused'; paused: boolean }
export type Response =
  | { type: 'status'; accounts: AccountStatus[]; paused: boolean; agent: string }
  | { type: 'discovered'; discovery_id: string; deployment: Deployment }
  | { type: 'sign_in_started' }
  | { type: 'ok' }
  | { type: 'error'; message: string }
  | { type: 'hello'; protocol: number; agent: string }
  | { type: 'signed_in'; account: AccountStatus }

export interface AppInfo { version: string; data_dir: string; log_file: string; autostart: boolean }

export interface Backend {
  agent(req: Request): Promise<Response>
  appInfo(): Promise<AppInfo>
  setAutostart(enabled: boolean): Promise<boolean>
}

export const tauriBackend: Backend = {
  agent: (req) => invoke<Response>('agent', { req }),
  appInfo: () => invoke<AppInfo>('app_info'),
  setAutostart: (enabled) => invoke<boolean>('set_autostart', { enabled }),
}

export function errorText(e: unknown): string {
  if (typeof e === 'string') return e
  if (e && typeof e === 'object' && 'message' in e) return String((e as { message: unknown }).message)
  return 'Something went wrong'
}

export const STATE_LABEL: Record<SessionState, string> = {
  signed_in: 'Connected', signing_in: 'Signing in…', signed_out: 'Signed out', offline: 'Offline, retrying', error: 'Problem',
}
