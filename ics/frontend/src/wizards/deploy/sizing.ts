// New-deployment wizard (sizing engine front end, docs/status/sizing-api.md). PURE: request building, response shaping and validation.
// The backend is authoritative for every number: VM counts, totals, headroom, availability and the recommendation are read from the
// POST /deployments/size response, never computed or invented here. Nothing in this module provisions; the only mutation path is
// deployment.create through POST /plans (RunPanel / useRun), after an explicit approval.
import { post } from '../../api'
import type { Errors, StepDef } from '../kit'
import { DOMAIN_RE, intIn } from '../kit'

export type DeploymentType = 'evaluation' | 'production' | 'msp' | 'custom'
export type Arch = 'consolidated' | 'balanced' | 'isolated' | 'ha' | 'dedicated'
export const ARCH_ORDER: Arch[] = ['consolidated', 'balanced', 'isolated', 'ha', 'dedicated']

export const DEPLOYMENT_TYPES: { id: DeploymentType; title: string; blurb: string }[] = [
  { id: 'evaluation', title: 'Evaluation or lab', blurb: 'Try Office Unbound with a few people. Kept small and simple; not meant for real business data.' },
  { id: 'production', title: 'Production, one organization', blurb: 'The everyday system for one company, sized for your people, with backups and room to grow.' },
  { id: 'msp', title: 'MSP, several customers', blurb: 'Host several customers, each kept separate from the others, behind one shared entry point.' },
  { id: 'custom', title: 'Custom or advanced', blurb: 'Start from production defaults and adjust every sizing parameter yourself.' },
]

export const ARCH_INFO: Record<Arch, { title: string; blurb: string }> = {
  consolidated: { title: 'Consolidated', blurb: 'Services share as few machines as possible. Uses the least resources; one machine problem affects everything.' },
  balanced: { title: 'Balanced', blurb: 'Related services are grouped together. A good default for most organizations.' },
  isolated: { title: 'Isolated', blurb: 'Each service gets its own machine, so services can be scaled and updated independently. Uses more resources.' },
  ha: { title: 'High availability', blurb: 'Services run as copies on separate nodes, so one node can fail without an outage.' },
  dedicated: { title: 'Dedicated physical placement', blurb: 'Runs only on nodes that host nothing else.' },
}

/** Plain-language names for the catalog's service ids; ids the catalog adds later are shown as-is. */
export const SERVICE_INFO: Record<string, { label: string; blurb: string }> = {
  mail: { label: 'Email', blurb: 'Mailboxes for every user.' },
  calendar: { label: 'Calendars', blurb: 'Shared and personal calendars.' },
  contacts: { label: 'Contacts', blurb: 'Address books.' },
  files: { label: 'Files', blurb: 'File storage and sharing.' },
  office: { label: 'Office editing', blurb: 'Edit documents in the browser (needs Files).' },
  chat: { label: 'Chat', blurb: 'Team chat.' },
  meetings: { label: 'Video meetings', blurb: 'Browser video meetings.' },
  telephony: { label: 'Telephony', blurb: 'Internal phone system with a browser softphone; no outside line.' },
}
export const KNOWN_SERVICES = Object.keys(SERVICE_INFO)
export const serviceLabel = (id: string) => SERVICE_INFO[id]?.label ?? id
const DEFAULT_SERVICES = ['mail', 'calendar', 'contacts', 'files', 'office']

/** Backend slug rule for customer_id / deployment_id. */
export const DEPLOY_SLUG_RE = /^[a-z0-9][a-z0-9-]{1,30}$/

// ---------------------------------------------------------------- model

export interface VmOverride { cores?: number; memory_mb?: number }
export interface WizardModel {
  type: DeploymentType | ''
  customerId: string; name: string; domain: string
  /** Endpoint NAME (the API resolves inventory by name). */
  endpoint: string
  users: number; tenants: number
  /** '' = derive from concurrentPct. */
  concurrentUsers: string
  concurrentPct: number; mailboxGb: number; fileGb: number; growthPct: number
  officeEditorPct: number; meetingPct: number; callPct: number
  /** Checked services only. */
  services: string[]
  /** null = take the recommendation. */
  architecture: Arch | null
  /** [] = every approved node. */
  allowedNodes: string[]
  storage: string; bridge: string; vlan: string; pool: string
  backupDestination: string; retentionDays: number; rpoHours: number; rtoHours: string; offsite: boolean
  updatesMode: 'manual' | 'maintenance_window'; updatesWindow: string
  marginPct: string; tier: '' | 'minimum' | 'recommended'
  vmOverrides: Record<string, VmOverride>
  /** Service address overrides: catalog host label -> '' (default <label>.<domain>), a word (files) or a full name (files.example.com). */
  hosts: Record<string, string>
  /** Multi-tenant: own domain per customer (index 0 = t01); '' = <tNN>.<domain>. */
  tenantDomains: string[]
}

/** The service addresses a deployment can rename (catalog DNS host labels; the planner refuses unknown ones). */
export const HOST_FIELDS = [
  { id: 'portal', label: 'User portal' }, { id: 'auth', label: 'Sign-in' }, { id: 'cloud', label: 'Files' },
  { id: 'office', label: 'Documents' }, { id: 'mail', label: 'Mail' },
] as const
export const HOST_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
export const tenantId = (i: number) => 't' + String(i + 1).padStart(2, '0')

/** PlanInput.names from the wizard (undefined = catalog defaults, so plans without settings keep their exact input). */
export function nameSettings(m: WizardModel): Raw | undefined {
  const hosts = Object.fromEntries(Object.entries(m.hosts).map(([k, v]) => [k, v.trim().toLowerCase()]).filter(([, v]) => v))
  const tenants: Raw = {}
  if (m.type === 'msp') m.tenantDomains.slice(0, m.tenants).forEach((d, i) => { if (d.trim()) tenants[tenantId(i)] = { domain: d.trim().toLowerCase() } })
  if (!Object.keys(hosts).length && !Object.keys(tenants).length) return undefined
  return { hosts, tenants }
}
/** The plan input the reviewed size response produced, with the address settings. */
export function withNames(planInput: Raw, m: WizardModel): Raw {
  const n = nameSettings(m)
  return n ? { ...planInput, names: n } : planInput
}
/** Full name of a service address as it will be used (for hints in the form). */
export function hostPreview(m: WizardModel, id: string): string {
  const v = (m.hosts[id] ?? '').trim().toLowerCase() || id
  return v.includes('.') ? v : `${v}.${m.domain.trim().toLowerCase() || 'your-company.tld'}`
}

export function newModel(): WizardModel {
  return {
    type: '', customerId: '', name: '', domain: '', endpoint: '',
    users: 100, tenants: 1, concurrentUsers: '', concurrentPct: 30, mailboxGb: 2, fileGb: 5, growthPct: 0,
    officeEditorPct: 20, meetingPct: 20, callPct: 10,
    services: [...DEFAULT_SERVICES], architecture: null, allowedNodes: [],
    storage: '', bridge: '', vlan: '', pool: '',
    backupDestination: '', retentionDays: 14, rpoHours: 24, rtoHours: '', offsite: false,
    updatesMode: 'manual', updatesWindow: '', marginPct: '', tier: '', vmOverrides: {},
    hosts: Object.fromEntries(HOST_FIELDS.map((h) => [h.id, ''])), tenantDomains: [],
  }
}

/** Editable starting values per deployment type (the operator can change all of them in step 2). */
export function applyType(m: WizardModel, t: DeploymentType): void {
  m.type = t
  m.architecture = null
  m.vmOverrides = {}
  if (t === 'evaluation') { m.users = 10; m.tenants = 1; m.growthPct = 0 }
  else if (t === 'msp') { m.users = 25; m.tenants = Math.max(m.tenants, 2) }
  else { m.users = 100; m.tenants = 1; if (m.growthPct === 0) m.growthPct = 20 }
}

// ---------------------------------------------------------------- request

export interface SizeRequest {
  deployment_type: DeploymentType
  customer_id: string; deployment_id: string; domain: string; endpoint: string
  workload: {
    users: number; tenants: number; concurrent_users: number | null; concurrent_pct: number; mailbox_gb_per_user: number; file_gb_per_user: number
    growth_pct: number; office_editor_pct: number; meeting_participant_pct: number; concurrent_call_pct: number
  }
  services: string[]
  architecture: Arch | null
  placement: { allowed_nodes: string[] | null; storage: string | null; bridge: string | null; vlan: number | null; pool: string | null }
  backup: { destination: string | null; retention_days: number; rpo_hours: number; rto_hours: number | null; offsite: boolean }
  updates: { mode: 'manual' | 'maintenance_window'; window: string | null }
  overrides: { estimate_margin_pct: number | null; tier: 'minimum' | 'recommended' | null; vm: Record<string, VmOverride> }
}

/** Identity values that let the live summary size before step 1's names are filled in. Such a draft is never planned or submitted. */
export const DRAFT_IDENTITY = { customer_id: 'draft', deployment_id: 'draft', domain: 'draft.example' }

export const identityValid = (m: WizardModel) => DEPLOY_SLUG_RE.test(m.customerId.trim()) && DEPLOY_SLUG_RE.test(m.name.trim()) && DOMAIN_RE.test(m.domain.trim())
const num = (s: string): number | null => (s.trim() && /^\d+$/.test(s.trim()) ? Number(s.trim()) : null)

/**
 * Body of POST /deployments/size. `catalog` = service ids the API offers (service_catalog); when known, anything else is dropped.
 * Unchecked services are never sent. `draft` substitutes placeholder identity values for the live summary only.
 */
export function buildSizeRequest(m: WizardModel, catalog: string[] | null, draft = false): SizeRequest {
  const useDraft = draft && !identityValid(m)
  const services = [...new Set(m.services)].filter((s) => !catalog || catalog.includes(s)).sort()
  const vm: Record<string, VmOverride> = {}
  for (const [k, o] of Object.entries(m.vmOverrides).sort(([a], [b]) => a.localeCompare(b))) {
    const c: VmOverride = {}
    if (o.cores && o.cores > 0) c.cores = o.cores
    if (o.memory_mb && o.memory_mb > 0) c.memory_mb = o.memory_mb
    if (Object.keys(c).length) vm[k] = c
  }
  return {
    deployment_type: m.type || 'production',
    customer_id: useDraft ? DRAFT_IDENTITY.customer_id : m.customerId.trim(),
    deployment_id: useDraft ? DRAFT_IDENTITY.deployment_id : m.name.trim(),
    domain: useDraft ? DRAFT_IDENTITY.domain : m.domain.trim().toLowerCase(),
    endpoint: m.endpoint,
    workload: {
      users: m.users, tenants: m.type === 'msp' ? m.tenants : 1, concurrent_users: num(m.concurrentUsers), concurrent_pct: m.concurrentPct,
      mailbox_gb_per_user: m.mailboxGb, file_gb_per_user: m.fileGb, growth_pct: m.growthPct,
      office_editor_pct: m.officeEditorPct, meeting_participant_pct: m.meetingPct, concurrent_call_pct: m.callPct,
    },
    services,
    architecture: m.architecture,
    placement: {
      allowed_nodes: m.allowedNodes.length ? [...m.allowedNodes].sort() : null,
      storage: m.storage || null, bridge: m.bridge || null, vlan: num(m.vlan), pool: m.pool || null,
    },
    backup: { destination: m.backupDestination || null, retention_days: m.retentionDays, rpo_hours: m.rpoHours, rto_hours: num(m.rtoHours), offsite: m.offsite },
    updates: { mode: m.updatesMode, window: m.updatesMode === 'maintenance_window' ? m.updatesWindow.trim() || null : null },
    overrides: { estimate_margin_pct: num(m.marginPct), tier: m.tier || null, vm },
  }
}
export const requestKey = (r: SizeRequest) => JSON.stringify(r)
/** A request is sizable once a cluster and at least one service are chosen and the numbers are in range. */
export function sizable(m: WizardModel): boolean {
  return !!m.endpoint && m.services.length > 0 && isEmpty(validateWorkload(m))
}

// ---------------------------------------------------------------- response

/* eslint-disable @typescript-eslint/no-explicit-any */
type Raw = Record<string, any>
export interface Issue { code?: string; severity?: string; message: string }
export interface SizeVm {
  name: string; logical: string; tenant?: string | null; replica?: number | null; services: string[]; components: string[]
  cores: number; memory_mb: number; disk_gb: number; disks: { name: string; size_gb: number; storage?: string; purpose?: string }[]
  node: string | null; anti_affinity?: unknown; depends_on: string[]; sizing?: Raw | null
}
export interface ArchEntry { id: Arch; available: boolean; why_not: string | null; vms?: number; cores?: number; memory_mb?: number; disk_gb?: number; fits?: boolean; capacity_errors?: unknown[]; why_not_fit?: string }
export interface SizeResponse {
  deployment_type: DeploymentType; services: string[]; components: string[]
  service_catalog: { id: string; components: string[] }[]
  architectures: ArchEntry[]
  recommended: { architecture: Arch; vms: number; text: string } | null
  selected: Arch | null
  alternatives?: { architecture: Arch; vms: number; fits: boolean }[]
  errors: Issue[]
  writes: 'none'
  plan_input?: Raw; plan_hash?: string; plan_executable?: boolean; plan_blocking?: Issue[]
  vms?: SizeVm[]
  totals?: { vms: number; cores: number; memory_mb: number; disk_gb: number }
  fits?: boolean; production_ready?: boolean; production_ready_blockers?: string[]
  capacity?: Raw
  validated?: boolean; evidence?: Raw[]
  estimated_supported_workload?: { capacity_bound_users: number | null; estimate: boolean; basis: string }
  backup?: Raw; backup_destinations?: { name: string; avail_gb: number; shared?: boolean; type?: string }[]
  updates?: Raw; recovery?: Raw
  scaling_recommendations?: { kind: string; message: string }[]
  risks?: Issue[]; assumptions?: string[]; estimates_flags?: string[]
  shortfall?: { message: string; alternatives: Raw[] }
}

/** Any issue shape (string, {message}, {code}) -> text. */
export function issueText(x: unknown): string {
  if (typeof x === 'string') return x
  if (x && typeof x === 'object') { const o = x as Raw; return String(o.message ?? o.detail ?? o.code ?? JSON.stringify(o)) }
  return String(x)
}

export interface ArchCard {
  id: Arch; title: string; blurb: string
  /** True only when the API says so; anything missing or unclear is unavailable. */
  available: boolean
  whyNot: string | null
  recommended: boolean; selected: boolean
  vms: number | null; fits: boolean | null
  /** Available but does not fit the approved capacity. */
  fitNote: string | null
}
export function architectureCards(r: SizeResponse | null): ArchCard[] {
  return ARCH_ORDER.map((id) => {
    const a = r?.architectures.find((x) => x.id === id)
    const available = a?.available === true
    const fits = a && available ? a.fits === true : null
    return {
      id, ...ARCH_INFO[id], available,
      whyNot: available ? null : (a?.why_not || (r ? 'Not offered for this deployment.' : 'Waiting for the sizing result.')),
      recommended: !!r?.recommended && r.recommended.architecture === id,
      selected: r?.selected === id,
      vms: a && available && typeof a.vms === 'number' ? a.vms : null,
      fits,
      fitNote: available && fits === false ? (a?.why_not_fit || (a?.capacity_errors ?? []).map(issueText).join('; ') || 'Does not fit the approved capacity.') : null,
    }
  })
}

export interface Summary {
  ready: boolean
  vms: number; vcpu: number; memoryMb: number; storageGb: number
  headroom: { vcpu: number; memoryMb: number; storageGb: number; memoryPct: number | null } | null
  available: { vcpu: number; memoryMb: number; storageGb: number } | null
  fits: boolean | null
  architecture: Arch | null
}
/** Live summary: VM count = vms[].length (the generated plan), resources summed from the same VMs. */
export function summarize(r: SizeResponse | null): Summary {
  const vms = r?.vms ?? []
  const h = r?.capacity?.headroom, av = r?.capacity?.available
  return {
    ready: !!r && !!r.selected && vms.length > 0,
    vms: vms.length,
    vcpu: vms.reduce((s, v) => s + (v.cores || 0), 0),
    memoryMb: vms.reduce((s, v) => s + (v.memory_mb || 0), 0),
    storageGb: vms.reduce((s, v) => s + (v.disk_gb || 0), 0),
    headroom: h ? { vcpu: h.vcpu ?? 0, memoryMb: h.memory_mb ?? 0, storageGb: h.storage_gb ?? 0, memoryPct: h.memory_pct ?? null } : null,
    available: av ? { vcpu: av.vcpu ?? 0, memoryMb: av.memory_mb ?? 0, storageGb: av.storage_gb ?? 0 } : null,
    fits: r && r.selected ? r.fits === true : null,
    architecture: r?.selected ?? null,
  }
}

/** "Recommended: N VMs ..." with N exactly as the API reports it; null when the API recommends nothing. */
export function recommendationText(r: SizeResponse | null): string | null {
  if (!r?.recommended) return null
  const n = r.recommended.vms
  return `Recommended: ${n} VM${n === 1 ? '' : 's'} based on your selected services and available infrastructure`
}

/** "estimate" when any resource of the VM's components is sized from an estimate, else "measured". */
export function vmEvidence(vm: SizeVm, flags: string[]): 'estimate' | 'measured' {
  const fromFlags = vm.components.some((c) => flags.some((f) => f === c || f.startsWith(c + '.')))
  const comps = (vm.sizing?.components ?? {}) as Record<string, Raw>
  const fromSizing = Object.values(comps).some((c) => Array.isArray(c?.estimated) && c.estimated.length > 0)
  return fromFlags || fromSizing ? 'estimate' : 'measured'
}

/** Approved nodes with what is available on each (from capacity.nodes). */
export function nodeRows(r: SizeResponse | null): { name: string; vcpu: number; memoryMb: number; vmsHere: number }[] {
  const nodes = (r?.capacity?.nodes ?? []) as Raw[]
  return nodes.map((n) => ({ name: String(n.name), vcpu: n.available?.vcpu ?? 0, memoryMb: n.available?.memory_mb ?? 0, vmsHere: (r?.vms ?? []).filter((v) => v.node === n.name).length }))
}

/** Messages relevant to backup/updates (step 4): request errors, backup issues and backup-related risks. */
const BACKUP_CODES = ['no_backup_destination', 'backup_destination_unknown', 'backup_space_insufficient', 'backup_on_vm_storage', 'rpo_not_achievable', 'offsite_not_configured', 'rto_unverified']
export function backupMessages(r: SizeResponse | null): { kind: 'bad' | 'warn' | 'info'; text: string }[] {
  if (!r) return []
  const out: { kind: 'bad' | 'warn' | 'info'; text: string }[] = []
  for (const i of (r.backup?.issues ?? []) as unknown[]) {
    const sev = typeof i === 'object' && i ? (i as Raw).severity : undefined
    out.push({ kind: sev === 'error' ? 'bad' : sev === 'info' ? 'info' : 'warn', text: issueText(i) })
  }
  for (const k of r.risks ?? []) {
    if (!k.code || !BACKUP_CODES.includes(k.code) || out.some((o) => o.text === k.message)) continue
    out.push({ kind: k.severity === 'error' ? 'bad' : k.severity === 'info' ? 'info' : 'warn', text: k.message })
  }
  return out
}

/** Params of deployment.create: exactly the plan_input the reviewed size response produced, and the hash of the generated plan. */
export function createParams(planInput: Raw, planHash: string): { spec: Raw; plan_hash: string } {
  return { spec: planInput, plan_hash: planHash }
}

// ---------------------------------------------------------------- validation

const isEmpty = (e: Errors) => Object.keys(e).length === 0
export function validateType(m: WizardModel): Errors {
  const e: Errors = {}
  if (!m.type) e.type = 'Choose a deployment type to continue.'
  if (!DEPLOY_SLUG_RE.test(m.customerId.trim())) e.customerId = 'Lower-case letters, digits and "-" (2-31 characters), starting with a letter or digit.'
  if (!DEPLOY_SLUG_RE.test(m.name.trim())) e.name = 'Lower-case letters, digits and "-" (2-31 characters), starting with a letter or digit.'
  if (!DOMAIN_RE.test(m.domain.trim())) e.domain = 'Enter the customer domain, for example your-company.tld.'
  const seen = new Map<string, string>()
  for (const h of HOST_FIELDS) {
    const v = (m.hosts[h.id] ?? '').trim().toLowerCase()
    if (v && !(HOST_LABEL_RE.test(v) || DOMAIN_RE.test(v))) { e['host_' + h.id] = 'A single word (for example files) or a full name (files.example.com).'; continue }
    const full = hostPreview(m, h.id)
    if (seen.has(full)) e['host_' + h.id] = `Same address as ${seen.get(full)}; each service needs its own.`
    seen.set(full, h.label)
  }
  return e
}
export function validateWorkload(m: WizardModel): Errors {
  const e: Errors = {}
  if (!intIn(m.users, 1, 100000)) e.users = 'Whole number of users, 1-100000.'
  if (m.type === 'msp' && !intIn(m.tenants, 1, 50)) e.tenants = 'Whole number of customers, 1-50.'
  if (m.type === 'msp') {
    const ds = m.tenantDomains.slice(0, m.tenants).map((d) => d.trim().toLowerCase())
    ds.forEach((d, i) => {
      if (d && !DOMAIN_RE.test(d)) e['tenant_' + i] = 'Enter a domain, for example customer.tld, or leave empty.'
      else if (d && (ds.indexOf(d) !== i || d === m.domain.trim().toLowerCase())) e['tenant_' + i] = 'Each customer needs its own domain.'
    })
  }
  if (m.concurrentUsers.trim() && !(num(m.concurrentUsers) !== null && num(m.concurrentUsers)! <= m.users)) e.concurrentUsers = 'A whole number no larger than the number of users, or empty.'
  if (!intIn(m.concurrentPct, 1, 100)) e.concurrentPct = 'Percent, 1-100.'
  if (!(m.mailboxGb >= 0 && m.mailboxGb <= 1000)) e.mailboxGb = 'GB per user, 0-1000.'
  if (!(m.fileGb >= 0 && m.fileGb <= 10000)) e.fileGb = 'GB per user, 0-10000.'
  if (!intIn(m.growthPct, 0, 500)) e.growthPct = 'Percent, 0-500.'
  for (const k of ['officeEditorPct', 'meetingPct', 'callPct'] as const) if (!intIn(m[k], 0, 100)) e[k] = 'Percent, 0-100.'
  if (m.marginPct.trim() && !(num(m.marginPct) !== null && num(m.marginPct)! <= 200)) e.marginPct = 'Percent, 0-200, or empty for the catalog default.'
  if (!m.services.length) e.services = 'Choose at least one service.'
  return e
}
export function validatePlacement(m: WizardModel, r: SizeResponse | null): Errors {
  const e: Errors = {}
  if (!m.endpoint) e.endpoint = 'Choose the cluster to deploy onto.'
  if (m.vlan.trim() && !(num(m.vlan) !== null && intIn(num(m.vlan)!, 1, 4094))) e.vlan = 'VLAN tag 1-4094, or empty.'
  if (m.architecture && r && !architectureCards(r).find((a) => a.id === m.architecture)?.available) e.architecture = 'That architecture is not available. Choose another one.'
  return e
}
export function validateBackup(m: WizardModel): Errors {
  const e: Errors = {}
  if (!intIn(m.retentionDays, 1, 3650)) e.retentionDays = 'Days, 1-3650.'
  if (!intIn(m.rpoHours, 1, 720)) e.rpoHours = 'Hours, 1-720.'
  if (m.rtoHours.trim() && !(num(m.rtoHours) !== null && intIn(num(m.rtoHours)!, 1, 720))) e.rtoHours = 'Hours, 1-720, or empty.'
  if (m.updatesMode === 'maintenance_window' && !/^[A-Za-z0-9 :,-]{1,60}$/.test(m.updatesWindow.trim())) e.updatesWindow = 'Describe the window, for example "sun 02:00-04:00".'
  return e
}

export function wizardSteps(getResponse: () => SizeResponse | null): StepDef<WizardModel>[] {
  return [
    { id: 'type', title: 'Deployment type', validate: validateType },
    { id: 'workload', title: 'Workload and capacity', validate: validateWorkload },
    { id: 'placement', title: 'Infrastructure', validate: (m) => validatePlacement(m, getResponse()) },
    { id: 'backup', title: 'Backup and options', validate: validateBackup },
    { id: 'review', title: 'Plan review' },
  ]
}

// ---------------------------------------------------------------- API (dry runs only)

export const sizingApi = {
  /** Dry run: writes nothing on the server. */
  size: (r: SizeRequest) => post<SizeResponse>('deployments/size', r),
  /** Dry run: computes the plan (and plan_hash) for a plan_input; writes nothing. */
  plan: (planInput: Raw) => post<Raw>('deployments/plan', planInput),
}

/**
 * Debounced sizing: the latest request wins, older responses are discarded. `regenerate` sizes immediately.
 * Only POST /deployments/size is ever called from here (dry run).
 */
export function createSizer(onResult: (r: SizeResponse | null, err: string, key: string) => void, opts: { delay?: number; size?: (r: SizeRequest) => Promise<SizeResponse> } = {}) {
  const size = opts.size ?? sizingApi.size
  const delay = opts.delay ?? 400
  let timer: ReturnType<typeof setTimeout> | undefined
  let seq = 0
  async function run(r: SizeRequest): Promise<void> {
    const mine = ++seq
    const key = requestKey(r)
    try {
      const res = await size(r)
      if (mine === seq) onResult(res, '', key)
    } catch (e) {
      if (mine === seq) onResult(null, e instanceof Error ? e.message : String(e), key)
    }
  }
  return {
    schedule(r: SizeRequest) { clearTimeout(timer); timer = setTimeout(() => { void run(r) }, delay) },
    regenerate(r: SizeRequest) { clearTimeout(timer); return run(r) },
    cancel() { clearTimeout(timer); seq++ },
  }
}
