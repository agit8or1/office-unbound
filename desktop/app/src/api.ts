// Typed bridge to the Rust side. Mirrors ou_core::ipc (Request/Response); the webview never sees tokens.
import { invoke } from '@tauri-apps/api/core'
import type { ChatMessage, ChatNotification, RoomSummary, SearchResult } from './chat/types'

export type Service = 'portal' | 'files' | 'chat' | 'mail' | 'calendar' | 'contacts'
export type SessionState = 'signed_in' | 'signing_in' | 'signed_out' | 'offline' | 'error'

export interface Deployment {
  domain: string; name: string; issuer: string; client_id: string; files_url: string
  portal_url: string | null; matrix_url: string | null; chat_web_url: string | null; mail_web_url: string | null
  source: 'client_document' | 'web_finger'; login_hint: string | null; foreign_hosts: string[]
}
export interface AccountStatus {
  id: string; label: string; deployment: string; domain: string; state: SessionState
  detail: string | null; services: Service[]; files_url: string; chat?: SessionState | null
}
export type Request =
  | { type: 'status' }
  | { type: 'discover'; input: string }
  | { type: 'sign_in'; discovery_id: string }
  | { type: 'sign_out'; account_id: string }
  | { type: 'remove_account'; account_id: string }
  | { type: 'open_service'; account_id: string; service: Service }
  | { type: 'set_paused'; paused: boolean }
  | { type: 'chat_sign_in'; account_id: string }
  | { type: 'chat_sign_out'; account_id: string }
  | { type: 'chat_rooms'; account_id: string }
  | { type: 'chat_history'; account_id: string; room_id: string; limit: number }
  | { type: 'chat_send'; account_id: string; room_id: string; body: string }
  | { type: 'chat_mark_read'; account_id: string; room_id: string; event_id: string }
  | { type: 'chat_search'; account_id: string; query: string }
  | { type: 'chat_download'; account_id: string; room_id: string; event_id: string }
  | { type: 'chat_start_meeting'; account_id: string; room_id: string }
  | { type: 'poll_events'; since: number; wait_ms: number }
export type AgentEvent =
  | { event: 'chat_notification'; account_id: string; notification: ChatNotification }
  | { event: 'chat_badge'; account_id: string; count: number }
  | { event: 'chat_signed_in'; account_id: string }
  | { event: 'chat_signed_out'; account_id: string }
  | { event: 'account_changed'; account_id: string }
export type Response =
  | { type: 'status'; accounts: AccountStatus[]; paused: boolean; agent: string }
  | { type: 'discovered'; discovery_id: string; deployment: Deployment }
  | { type: 'sign_in_started' }
  | { type: 'ok' }
  | { type: 'error'; message: string }
  | { type: 'hello'; protocol: number; agent: string }
  | { type: 'signed_in'; account: AccountStatus }
  | { type: 'chat_rooms'; rooms: RoomSummary[]; badge: number }
  | { type: 'chat_history'; messages: ChatMessage[] }
  | { type: 'chat_sent'; event_id: string }
  | { type: 'chat_downloaded'; path: string }
  | { type: 'chat_search'; result: SearchResult }
  | { type: 'chat_meeting'; url: string }
  | { type: 'events'; next: number; events: [number, AgentEvent][] }

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
