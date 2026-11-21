// Read-only diagnostics of a deployment VM (POST deployments/{slug}/diagnostics/logs; agent runbook guest.journal). Pure helpers for the panel.
export interface DiagVm { name: string; components: string[]; enrolled: boolean; available: boolean; suggested_units: string[]; suggested_files: string[] }
export interface DiagSources { deployment: string; vms: DiagVm[]; units: string[]; files: string[]; greps: string[]; max_lines: number }
export interface DiagForm { vm: string; kind: 'unit' | 'file'; name: string; lines: number; since: number | null; grep: string }
export interface DiagResult { vm: string; unit?: string | null; file?: string | null; target: string | null; exists: boolean | null; error: string | null;
  lines_returned: number; truncated: boolean; redacted: boolean; log: string[] }

/** Suggested names for this VM first, then every other allowlisted one. */
export function choices(src: DiagSources, vm: string, kind: 'unit' | 'file'): { suggested: string[]; other: string[] } {
  const v = src.vms.find((x) => x.name === vm)
  const all = kind === 'unit' ? src.units : src.files
  const suggested = (kind === 'unit' ? v?.suggested_units : v?.suggested_files)?.filter((n) => all.includes(n)) ?? []
  return { suggested, other: all.filter((n) => !suggested.includes(n)) }
}

/** The request body: exactly the closed schema the ICS and the agent accept (since only for a unit's journal). */
export function body(f: DiagForm, max = 300): Record<string, unknown> {
  const lines = Math.min(Math.max(Math.trunc(f.lines) || 1, 1), max)
  const b: Record<string, unknown> = { vm: f.vm, [f.kind]: f.name, lines }
  if (f.kind === 'unit' && f.since) b.since_minutes = Math.min(Math.max(Math.trunc(f.since), 1), 1440)
  if (f.grep) b.grep = f.grep
  return b
}
