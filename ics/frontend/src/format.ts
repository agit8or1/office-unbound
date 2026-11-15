import { ref } from 'vue'

export function fmtDuration(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000))
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m`
  const h = Math.floor(m / 60)
  if (h < 48) return `${h}h ${m % 60}m`
  return `${Math.floor(h / 24)}d ${h % 24}h`
}
export function ago(s: string | null | undefined, now = Date.now()): string {
  if (!s) return '-'
  const t = +new Date(s)
  return isNaN(t) ? '-' : `${fmtDuration(now - t)} ago`
}
export const fmtPct = (v: number | null | undefined) => (v === null || v === undefined ? '-' : `${Math.round(v)}%`)
export function fmtRate(bytesPerSec: number): string {
  const u = ['B/s', 'KiB/s', 'MiB/s', 'GiB/s']
  let i = 0, x = bytesPerSec
  while (x >= 1024 && i < u.length - 1) { x /= 1024; i++ }
  return `${x.toFixed(x >= 100 || i === 0 ? 0 : 1)} ${u[i]}`
}

/** Breadcrumb detail label, set by detail views once the resource name is known. */
export const crumbLabel = ref('')

/** Console footer text, e.g. "Office Unbound ICS v0.1.0 (abc1234)"; the version always comes from the API, never a constant. */
export function buildLabel(b: { version: string; commit?: string | null; dirty?: boolean | null } | null | undefined): string {
  if (!b) return 'Office Unbound ICS'
  return `Office Unbound ICS v${b.version}` + (b.commit ? ` (${b.commit.slice(0, 7)}${b.dirty ? ', modified' : ''})` : '')
}

export const COMPONENT_LABELS: Record<string, string> = {
  ics: 'ICS core', node_agent: 'Node agent', portal: 'User portal', migration_toolkit: 'Migration toolkit', docs_engine: 'Office Unbound Docs engine',
}
