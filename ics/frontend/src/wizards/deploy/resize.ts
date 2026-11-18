// "Re-run sizing" on a deployment (POST /deployments/{slug}/resize-plan). PURE shaping; the request itself writes nothing.
// The proposed ChangeSet is submitted only through POST /plans (deployment.change) and the normal approval flow.
import { post } from '../../api'

/* eslint-disable @typescript-eslint/no-explicit-any */
type Raw = Record<string, any>
export type ResizeWindow = '24h' | '7d' | '30d'

export interface ResizeResponse {
  deployment_id: string; window: ResizeWindow; applied_revision?: number; writes: 'none'; note?: string
  usage?: Record<string, Raw>
  recommendations: Raw[]
  model_drift?: { differs: boolean; changed: unknown[]; note?: string }
  proposed_change: null | {
    changes: Raw; plan_hash: string; executable: boolean; errors: unknown[]; diff?: Raw
    requires_downtime: boolean; requires_data_migration: boolean; moved_vms?: string[]
    submit_as: { action: 'deployment.change'; params: { deployment_id: string; changes: Raw; plan_hash: string } }
  }
}

export const resizeApi = {
  resizePlan: (slug: string, window: ResizeWindow) => post<ResizeResponse>(`deployments/${encodeURIComponent(slug)}/resize-plan`, { window }),
}

const KIND_TITLE: Record<string, string> = {
  increase_resources: 'Increase resources', decrease_resources: 'Decrease resources', expand_storage: 'Expand storage',
  no_data: 'Not enough data', upgrade_ha: 'High availability', add_capacity: 'Add capacity',
}
const fmt = (v: unknown) => (v === null || v === undefined ? '' : typeof v === 'object' ? Object.entries(v as Raw).map(([k, x]) => `${k} ${x}`).join(', ') : String(v))

export interface RecRow { title: string; vm: string; from: string; to: string; message: string; downtime: boolean; migration: boolean; automatic: boolean }
export function recommendationRows(r: ResizeResponse | null): RecRow[] {
  return (r?.recommendations ?? []).map((x) => ({
    title: KIND_TITLE[x.kind] ?? String(x.kind ?? ''), vm: x.vm ?? '', from: fmt(x.from), to: fmt(x.to),
    message: String(x.message ?? '') + (x.kind === 'upgrade_ha' && x.available === false && x.why_not ? ` (${x.why_not})` : ''),
    downtime: !!x.requires_downtime, migration: !!x.requires_data_migration, automatic: x.automatic === true,
  }))
}

/** A disruptive proposal needs `maintenance` on deployment.change (window or explicit override). */
export function needsMaintenance(r: ResizeResponse | null): boolean {
  const p = r?.proposed_change
  if (!p) return false
  return !!(p.requires_downtime || p.diff?.requires_maintenance || (p.diff?.disruptive_steps ?? []).length)
}

/** Exact params for POST /plans {action: 'deployment.change'}: the API's submit_as params, plus the maintenance choice when disruptive. */
export function changeParams(r: ResizeResponse, override: boolean): Record<string, unknown> {
  const p: Record<string, unknown> = { ...r.proposed_change!.submit_as.params }
  if (needsMaintenance(r) && override) p.maintenance = 'override'
  return p
}

export function canSubmitChange(r: ResizeResponse | null, override: boolean): boolean {
  const p = r?.proposed_change
  if (!p || !p.executable || (p.errors ?? []).length) return false
  return !needsMaintenance(r) || override
}
