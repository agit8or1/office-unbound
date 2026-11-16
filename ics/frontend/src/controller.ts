// Controller role banner and System card state. The role, epoch and replication numbers all come from /readyz and /system.
import type { ControllerInfo, Ready, Replication } from './api'

export const RUNBOOK_URL = 'https://github.com/agit8or1/office-unbound/blob/main/docs/runbooks/ics-recovery.md'

export interface BannerView {
  show: boolean; kind: 'warn' | 'bad'; title: string; text: string; facts: string[]; lag: 'ok' | 'behind' | 'unknown' | null
}
const none: BannerView = { show: false, kind: 'warn', title: '', text: '', facts: [], lag: null }

export function fmtSeconds(s: number | null | undefined): string {
  if (s === null || s === undefined || !isFinite(s)) return 'unknown'
  if (s < 90) return `${Math.round(s)} seconds`
  if (s < 5400) return `${Math.round(s / 60)} minutes`
  return `${Math.round(s / 3600)} hours`
}

export function replicationOf(r: Ready | null): Replication | null {
  const c = r?.checks?.replication
  return c ? (c as unknown as Replication) : null
}

/** Lag in plain terms: how old the newest change copied from the primary is. */
export function lagState(rep: Replication | null): 'ok' | 'behind' | 'unknown' {
  if (!rep || rep.heartbeat_age_seconds === null || rep.heartbeat_age_seconds === undefined) return 'unknown'
  return rep.ok ? 'ok' : 'behind'
}

export function bannerView(r: Ready | null): BannerView {
  if (!r) return none
  const epoch = r.epoch !== undefined ? [`Controller epoch ${r.epoch}`] : []
  if (r.role === 'standby') {
    const rep = replicationOf(r), lag = lagState(rep)
    const facts = [...epoch]
    if (rep) {
      facts.push(`Newest copied change is ${fmtSeconds(rep.heartbeat_age_seconds)} old (limit ${fmtSeconds(rep.max_lag_seconds)})`)
      if (rep.replay_backlog_bytes) facts.push(`${rep.replay_backlog_bytes} bytes received but not applied yet`)
    }
    return { show: true, kind: lag === 'behind' ? 'bad' : 'warn', lag,
      title: 'This is the standby controller (read-only)',
      text: 'It mirrors the primary controller and refuses every change. Monitoring, jobs and agent requests run on the primary only. '
        + (lag === 'behind' ? 'The copy is behind or the primary may be down: do not take over until you have read the recovery runbook.' : 'Use the primary controller for normal work. An operator takes this one over only through the documented, fenced promotion.'),
      facts }
  }
  if (r.fenced) {
    return { show: true, kind: 'bad', lag: null, title: 'This controller has been replaced (fenced)',
      text: 'Another controller took over. This one no longer sends requests to agents and must not be used. Sign in to the current primary controller instead.', facts: epoch }
  }
  return none
}

export function roleLabel(c: Pick<ControllerInfo, 'role' | 'fenced'>): { text: string; tone: 'ok' | 'warn' | 'bad' } {
  if (c.fenced) return { text: 'Fenced (replaced)', tone: 'bad' }
  return c.role === 'standby' ? { text: 'Standby (read-only)', tone: 'warn' } : { text: 'Primary', tone: 'ok' }
}
