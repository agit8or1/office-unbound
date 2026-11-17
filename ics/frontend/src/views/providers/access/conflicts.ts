// Conflict choices and leftover cleanup for the dry run (ADR-0016 amendment). The server lists, per conflicting pre-existing object,
// which actions are possible and why the others are not; the wizard only lets the admin pick an available one and sends the picks as
// the typed `choices` parameter of provider.provision.plan_preview. The server re-checks everything and binds the choices into the plan hash.

export type ChoiceAction = 'use_existing' | 'overwrite' | 'recreate' | 'create_new'
export type ChoiceKind = 'role' | 'user' | 'token'
export interface ConflictOption { action: ChoiceAction; available: boolean; why_not: string | null }
export interface ConflictEntry {
  kind: ChoiceKind; target: string; default: ChoiceAction | null; chosen: ChoiceAction | null
  existing: Record<string, unknown>; options: ConflictOption[]
}
export interface Leftover { id: string; kind: string; target: string; why: string; removable: boolean; kept_because: string | null; removes: string[] }
export interface ChoiceItem { kind: ChoiceKind; target: string; action: ChoiceAction; acknowledge_shared?: boolean }
export interface ChoicesParam { items: ChoiceItem[]; cleanup: string[] }
/** The admin's picks: key `${kind}|${target}` -> action, plus acknowledgements and the selected leftover ids. */
export interface ChoiceState { pick: Record<string, ChoiceAction | ''>; ack: Record<string, boolean>; cleanup: string[] }

export const ACTION_LABEL: Record<ChoiceAction, string> = {
  use_existing: 'Use it as is',
  overwrite: 'Overwrite it with what Office Unbound needs',
  recreate: 'Remove it and create it again',
  create_new: 'Leave it alone and create a new one alongside',
}
export const KIND_NOUN: Record<string, string> = { role: 'Role', user: 'Service account', token: 'API token', pool: 'Pool', acl: 'Permission' }

export const emptyChoices = (): ChoiceState => ({ pick: {}, ack: {}, cleanup: [] })
export const choiceKey = (e: Pick<ConflictEntry, 'kind' | 'target'>) => `${e.kind}|${e.target}`

export function conflictsOf(facts: Record<string, unknown> | undefined): ConflictEntry[] {
  return Array.isArray(facts?.conflict_options) ? (facts!.conflict_options as ConflictEntry[]) : []
}
export function leftoversOf(facts: Record<string, unknown> | undefined): Leftover[] {
  return Array.isArray(facts?.leftovers) ? (facts!.leftovers as Leftover[]) : []
}

/** Start from what the server applied (its default or the previous pick), so the radio buttons show the truth. */
export function seedChoices(st: ChoiceState, conflicts: ConflictEntry[], previous: ChoicesParam | null): void {
  for (const c of conflicts) {
    const k = choiceKey(c)
    if (!(k in st.pick)) st.pick[k] = c.chosen ?? ''
  }
  for (const it of previous?.items ?? []) if (it.acknowledge_shared) st.ack[`${it.kind}|${it.target}`] = true
  if (previous) st.cleanup = [...previous.cleanup]
}

/** Only explicit decisions that differ from the server default are sent; an unavailable pick is never sent (the server would refuse it). */
export function toChoicesParam(st: ChoiceState, conflicts: ConflictEntry[]): ChoicesParam | null {
  const items: ChoiceItem[] = []
  for (const c of conflicts) {
    const a = st.pick[choiceKey(c)]
    if (!a || a === c.default) continue
    if (!c.options.find((o) => o.action === a)?.available) continue
    const it: ChoiceItem = { kind: c.kind, target: c.target, action: a }
    if (a === 'overwrite' && st.ack[choiceKey(c)]) it.acknowledge_shared = true
    items.push(it)
  }
  items.sort((x, y) => (x.kind + x.target).localeCompare(y.kind + y.target))
  const cleanup = [...new Set(st.cleanup)].sort()
  return items.length || cleanup.length ? { items, cleanup } : null
}

export const choicesKey = (p: ChoicesParam | null | undefined) => JSON.stringify(p && (p.items.length || p.cleanup.length) ? { items: p.items.map((i) => ({ ...i, acknowledge_shared: !!i.acknowledge_shared })), cleanup: p.cleanup } : null)

/** The plan on screen was computed with exactly these choices (otherwise Apply must wait for a recalculation). */
export function choicesMatch(planChoices: Partial<ChoicesParam> | null | undefined, wanted: ChoicesParam | null): boolean {
  const have = planChoices && (planChoices.items?.length || planChoices.cleanup?.length) ? { items: planChoices.items ?? [], cleanup: planChoices.cleanup ?? [] } : null
  return choicesKey(have) === choicesKey(wanted)
}

export function needsAck(c: ConflictEntry, st: ChoiceState): boolean {
  return st.pick[choiceKey(c)] === 'overwrite' && ((c.existing.used_by_others as string[] | undefined)?.length ?? 0) > 0
}

/** One-line description of what the existing object is, for the conflict card. */
export function describeExisting(c: ConflictEntry): string {
  const e = c.existing
  if (c.kind === 'role') {
    const p = (e.privileges as string[] | undefined) ?? []
    return `${e.builtin ? 'Built-in Proxmox role' : 'Existing role'} with ${p.length ? p.join(', ') : 'no privileges'}.`
  }
  if (c.kind === 'user') return `${e.created_by_office_unbound ? 'Created by Office Unbound earlier' : 'Not created by Office Unbound'}; tokens: ${((e.tokens as string[]) ?? []).join(', ') || 'none'}.`
  return e.created_by_office_unbound ? 'Created by Office Unbound earlier (its secret cannot be read again).' : 'Not created by Office Unbound.'
}
