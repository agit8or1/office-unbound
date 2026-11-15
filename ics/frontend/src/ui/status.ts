// One mapping from raw status strings (jobs, plans, checks, infra, deployments) to a display tone.
// ADR-0009 section 8 labels (Implemented / Planned / Blocked) are included so they render the same everywhere.
export type Tone = 'ok' | 'warn' | 'bad' | 'info' | 'idle' | 'planned'

const MAP: Record<string, Tone> = {
  ok: 'ok', online: 'ok', running: 'ok', active: 'ok', available: 'ok', up: 'ok', healthy: 'ok', succeeded: 'ok', recovered: 'ok', verified: 'ok', approved: 'ok', ready: 'ok', sent: 'ok', implemented: 'ok',
  warning: 'warn', degraded: 'warn', pending_approval: 'warn', pending: 'warn', high: 'warn', maintenance: 'warn', queued: 'warn', draining: 'warn', paused: 'warn', planning: 'warn', applying: 'warn', in_progress: 'warn', awaiting_integration_test: 'warn',
  critical: 'bad', offline: 'bad', down: 'bad', failed: 'bad', rejected: 'bad', open: 'bad', error: 'bad', blocked: 'bad', destroyed: 'bad', unreachable: 'bad',
  acked: 'info', info: 'info', low: 'info', unknown: 'idle', stopped: 'idle', shutdown: 'idle', disabled: 'idle', inactive: 'idle', template: 'idle', cancelled: 'idle',
  planned: 'planned',
}
export function tone(s: string | null | undefined): Tone {
  return MAP[String(s ?? '').toLowerCase().replace(/[\s-]+/g, '_')] ?? 'idle'
}
export const label = (s: string | null | undefined) => String(s ?? 'unknown').replace(/_/g, ' ')
/** Worst of a list of tones, for roll-ups (bad > warn > idle/info > ok). */
export function worst(ts: Tone[]): Tone {
  if (ts.includes('bad')) return 'bad'
  if (ts.includes('warn')) return 'warn'
  if (!ts.length) return 'idle'
  return ts.every((t) => t === 'ok') ? 'ok' : ts.includes('ok') ? 'ok' : 'idle'
}
