// State logic for the Releases page, the release.promote diff in Approvals, and the promote flow. Pure functions: tested in releases.test.ts.
// Everything that decides (what may be promoted, which hashes, how many approvers) comes from GET /releases; nothing is computed here.
import type { PromoteParams, PromotionCandidate, ReleaseChannel, ReleasePackage, Releases } from './api'

export const CHANNEL_LABEL: Record<string, string> = { dev: 'Development', staging: 'Staging', stable: 'Stable' }
export const CHANNEL_BLURB: Record<string, string> = {
  dev: 'Freshly built packages. Used for lab testing only.',
  staging: 'Packages that passed testing and are ready for a final check.',
  stable: 'Packages that customer installations may use.',
}

export type PageState = 'not_configured' | 'empty' | 'ready'
export function pageState(r: Releases | null): PageState | 'loading' {
  if (!r) return 'loading'
  if (!r.configured) return 'not_configured'
  return r.channels.some((c) => c.available && c.components.length) ? 'ready' : 'empty'
}

export type EvidenceTone = 'ok' | 'bad' | 'warn' | 'idle'
export function evidenceView(p: Pick<ReleasePackage, 'file' | 'evidence'>, recordsReadable = true): { tone: EvidenceTone; text: string } {
  if (!p.file.endsWith('.deb')) return { tone: 'idle', text: 'Not tested (source file)' }
  if (!recordsReadable) return { tone: 'idle', text: 'Test records are not readable here' }
  const e = p.evidence
  if (!e || e.result === null) return { tone: 'warn', text: 'No install test recorded' }
  return e.result === 'pass' ? { tone: 'ok', text: 'Install test passed' } : { tone: 'bad', text: 'Install test failed' }
}

export const shortHash = (h: string | null | undefined, n = 12) => (h ? h.slice(0, n) : '-')

/** Versions of one component in a channel, e.g. "ou-agent 1.2.0, ou-cli 1.2.0". */
export function componentSummary(ch: ReleaseChannel | undefined, component: string): string {
  const c = ch?.components.find((x) => x.component === component)
  if (!c) return 'not present'
  return c.packages.filter((p) => p.file.endsWith('.deb')).map((p) => `${p.name} ${p.version}`).join(', ') || 'source files only'
}

export function approverText(n: number): string {
  return n === 1 ? 'one approver' : `${n} different approvers`
}

export function promoteTitle(c: Pick<PromotionCandidate, 'component' | 'from_channel' | 'to_channel'>): string {
  return `Promote ${c.component} from ${CHANNEL_LABEL[c.from_channel]} to ${CHANNEL_LABEL[c.to_channel]}`
}

/** The plan body for POST /plans: exactly what the backend proposed, plus the operator's optional reason. */
export function promotePlanParams(c: PromotionCandidate, reason: string): PromoteParams {
  const r = reason.trim()
  return { ...c.params, ...(r ? { reason: r.slice(0, 500) } : {}) }
}

export function canPromote(c: PromotionCandidate, r: Releases, role: string): { ok: boolean; why: string } {
  if (role !== 'admin') return { ok: false, why: 'Blocked: only administrators can propose a promotion.' }
  if (!r.promote_enabled) return { ok: false, why: 'Blocked: this server is not connected to the release pipeline yet.' }
  if (!c.ready) return { ok: false, why: 'Blocked: every package needs a passing install test first.' }
  return { ok: true, why: '' }
}

export interface DiffRow { file: string; name: string; sha256: string; kind: 'new' | 'replaces' | 'unchanged'; was: string | null; evidence: string | null }
/** Release diff for an approver: each package of a release.promote plan against what the target channel holds right now. */
export function releaseDiff(p: PromoteParams, channels: ReleaseChannel[]): DiffRow[] {
  const target = channels.find((c) => c.name === p.to_channel)
  const have = target?.components.find((c) => c.component === p.component)?.packages ?? []
  const ev = new Map(p.evidence.map((e) => [e.sha256, e.attestation_sha256]))
  return p.packages.map((x) => {
    const same = have.find((h) => h.sha256 === x.sha256)
    const prev = same ? null : have.find((h) => !!x.name && h.name === x.name)
    return { file: x.file, name: x.name ? `${x.name} ${x.version ?? ''}`.trim() : x.file, sha256: x.sha256, kind: same ? 'unchanged' : prev ? 'replaces' : 'new',
      was: prev ? prev.version : null, evidence: ev.get(x.sha256) ?? null }
  })
}

export function isReleasePlan(action: string): boolean { return action === 'release.promote' }

/** Parse the stored plan params defensively (they are untrusted JSON until proven otherwise). */
export function asPromoteParams(raw: unknown): PromoteParams | null {
  const o = raw as Partial<PromoteParams> | null
  if (!o || typeof o !== 'object' || typeof o.component !== 'string' || !Array.isArray(o.packages) || !o.from_channel || !o.to_channel) return null
  return { component: o.component, from_channel: o.from_channel, to_channel: o.to_channel, packages: o.packages, evidence: Array.isArray(o.evidence) ? o.evidence : [], reason: o.reason }
}
