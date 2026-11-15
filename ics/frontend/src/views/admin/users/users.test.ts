import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, nextTick, type App } from 'vue'
import { route, session } from '../../../store'
import { setCsrf } from '../../../api'
import UsersPage from './UsersPage.vue'
import { ago, cliCommand, duration, outcomeText } from './users'
import routes from './routes'

const USERS = [
  { id: 'u1', username: 'alice', role: 'admin', privileged: true, status: 'active', created_by: null, created_at: '2026-01-01T00:00:00Z', role_set_by: null,
    role_set_at: null, last_login_at: new Date().toISOString(), last_login_ip: '10.0.0.5', mfa_enrolled: true, active_sessions: 1, pending_plans: 0 },
  { id: 'u2', username: 'bob', role: 'operator', privileged: false, status: 'active', created_by: 'alice', created_at: '2026-01-02T00:00:00Z', role_set_by: 'alice',
    role_set_at: null, last_login_at: null, mfa_enrolled: true, active_sessions: 2, pending_plans: 1 },
  { id: 'u3', username: 'carol', role: 'viewer', privileged: false, status: 'invited', created_by: 'alice', created_at: '2026-01-03T00:00:00Z', role_set_by: 'alice',
    role_set_at: null, last_login_at: null, mfa_enrolled: false, active_sessions: 0, pending_plans: 0 },
]
const INV = [{ id: 'u3', username: 'carol', role: 'viewer', privileged: false, status: 'pending', token: 'not_issued', invited_by: 'alice', invited_at: '2026-01-03T00:00:00Z', token_expires_at: null }]
const POLICY = {
  approvals: [{ risk: 'low', required: 0, text: 'auto' }, { risk: 'normal', required: 1, text: 'one' }, { risk: 'high', required: 2, text: 'two' }],
  sessions: { absolute_seconds: 43200, idle_seconds: 3600, max_per_user: 10 },
  lockout: { max_failures: 5, window_seconds: 900, backoff_base_seconds: 15, backoff_cap_seconds: 900, per_ip_max_failures: 100 },
  mfa: { mandatory: true, method: 'TOTP' }, enrollment: { token_ttl_seconds: 86400, token_channel: 'host CLI only', password_min_length: 12 },
  plan_expiry_seconds: 604800, rules: [{ id: 'provenance', title: 'Provenance rule', text: 'x' }],
  roles: ['viewer', 'operator', 'approver', 'admin'].map((role) => ({ role, summary: role + ' summary' })),
  capabilities: [{ capability: 'See last sign-in address', min_role: 'admin', roles: { viewer: false, operator: false, approver: false, admin: true } }],
}
const DETAIL = { ...USERS[1], enrollment_expires_at: null, recent_events: [{ at: new Date().toISOString(), action: 'auth.login', ip: '10.0.0.9' }],
  role_history: [{ at: '2026-01-02T00:00:00Z', kind: 'invited', role: 'operator', previous_role: null, by: 'alice', plan_id: null, justification: null }],
  sessions: [{ created_at: new Date().toISOString(), last_seen: new Date().toISOString(), expires_at: new Date().toISOString() }], pending_plans_detail: [] }

let calls: { url: string; method: string; body: unknown }[] = []
function mockApi() {
  calls = []
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, method: init?.method ?? 'GET', body: init?.body ? JSON.parse(String(init.body)) : undefined })
    let data: unknown = []
    if (url.endsWith('/users')) data = USERS
    else if (url.endsWith('/invitations')) data = INV
    else if (url.endsWith('/access-policy')) data = POLICY
    else if (url.includes('/users/u2')) data = DETAIL
    else if (url.endsWith('/plans') && init?.method === 'POST') data = { plan_id: 'abcdef12-0000', status: 'pending_approval', risk: 'high', job_id: null, params_hash: 'h', approvals_required: 2 }
    return { ok: true, status: 200, statusText: 'OK', headers: new Headers(), text: async () => JSON.stringify(data) } as unknown as Response
  }))
}
let app: App | null = null
let host: HTMLElement
async function mount(arg = '') {
  route.value = { page: 'users', arg }
  host = document.createElement('div'); document.body.appendChild(host)
  app = createApp(UsersPage); app.mount(host)
  for (let i = 0; i < 8; i++) { await Promise.resolve(); await nextTick() }
  await new Promise((r) => setTimeout(r, 0)); await nextTick()
}
const as = (role: string) => { session.user = { username: role === 'admin' ? 'alice' : 'vera', role: role as never, csrf_token: 't' }; setCsrf('t') }
beforeEach(() => mockApi())
afterEach(() => { app?.unmount(); host?.remove(); app = null; vi.unstubAllGlobals() })

describe('Users & roles', () => {
  it('shows a real directory, never development copy', async () => {
    as('admin'); await mount()
    const t = host.textContent ?? ''
    expect(t).not.toMatch(/API has no user list/i)
    expect(host.querySelectorAll('tbody tr').length).toBe(3)
    expect(t).toContain('bob'); expect(t).toContain('10.0.0.5'); expect(t).toContain('1 pending')
    expect(host.querySelectorAll('.ux-tabs a').length).toBe(5)
  })
  it('hides account actions from non-admins', async () => {
    as('viewer'); await mount()
    expect(host.textContent).not.toContain('Disable')
    expect(host.textContent).toContain('Account changes can be requested by administrators')
  })
  it('admins get row actions and the dialog submits a typed plan', async () => {
    as('admin'); await mount()
    const rowBob = [...host.querySelectorAll('tbody tr')].find((r) => r.textContent?.includes('bob'))!
    const dis = [...rowBob.querySelectorAll('button')].find((b) => b.textContent === 'Disable')!
    dis.click(); await nextTick()
    expect(document.body.textContent ?? host.textContent).toContain('Disable bob')
    const confirm = [...host.querySelectorAll('.ux-dialog button')].find((b) => b.textContent?.includes('Request disable')) as HTMLButtonElement
    confirm.click(); await new Promise((r) => setTimeout(r, 0)); await nextTick()
    const post = calls.find((c) => c.method === 'POST')!
    expect(post.url).toBe('/api/v1/plans'); expect(post.body).toEqual({ action: 'user.disable', params: { username: 'bob' } })
    expect(host.textContent).toContain('Waiting for approval')
  })
  it('opens the detail drawer from the route', async () => {
    as('admin'); await mount('directory/u2')
    expect(host.querySelector('.ux-drawer')).not.toBeNull()
    expect(host.textContent).toContain('Role history'); expect(host.textContent).toContain('10.0.0.9')
  })
  it('invitations explain the out-of-band token flow and never show a token', async () => {
    as('admin'); await mount('invitations')
    const t = host.textContent ?? ''
    expect(t).toContain('never shown in this console'); expect(t).toContain('ics.cli issue-enrollment --username USERNAME')
    expect(t).toContain('Not issued yet')
  })
  it('privileged workflow requires justification + acknowledgement and submits user.set_role with it', async () => {
    as('admin'); await mount('privileged/change/bob')
    const click = async (txt: string) => { ([...host.querySelectorAll('button')].find((b) => b.textContent?.trim() === txt) as HTMLButtonElement).click(); await nextTick() }
    await click('Continue')
    const next = () => [...host.querySelectorAll('button')].find((b) => b.textContent?.trim() === 'Review') as HTMLButtonElement
    expect(next().disabled).toBe(true)
    const ta = host.querySelector('textarea')!; ta.value = 'Covering the on-call rota for November'; ta.dispatchEvent(new Event('input')); await nextTick()
    const radio = [...host.querySelectorAll('input[type=radio]')].find((r) => (r as HTMLInputElement).value === 'approver') as HTMLInputElement
    radio.click(); await nextTick()
    await click('Review')
    expect(host.textContent).toContain('Provenance rule'); expect(host.textContent).toContain('2 approvers')
    const submit = () => [...host.querySelectorAll('button')].find((b) => b.textContent?.includes('Submit for approval')) as HTMLButtonElement
    expect(submit().disabled).toBe(true)
    const cb = host.querySelector('input[type=checkbox]') as HTMLInputElement; cb.click(); await nextTick()
    submit().click(); await new Promise((r) => setTimeout(r, 0)); await nextTick()
    const post = calls.find((c) => c.method === 'POST')!
    expect(post.body).toEqual({ action: 'user.set_role', params: { username: 'bob', role: 'approver', justification: 'Covering the on-call rota for November' } })
    expect(host.querySelector('a[href="#/plans/abcdef12-0000"]')).not.toBeNull()
  })
  it('create-account workflow uses user.invite', async () => {
    as('admin'); await mount('privileged/create')
    const inp = host.querySelector('input[type=text], input:not([type])') as HTMLInputElement
    inp.value = 'dave'; inp.dispatchEvent(new Event('input')); await nextTick()
    ;([...host.querySelectorAll('button')].find((b) => b.textContent?.trim() === 'Continue') as HTMLButtonElement).click(); await nextTick()
    const ta = host.querySelector('textarea')!; ta.value = 'Second administrator for DR cover'; ta.dispatchEvent(new Event('input')); await nextTick()
    ;([...host.querySelectorAll('button')].find((b) => b.textContent?.trim() === 'Review') as HTMLButtonElement).click(); await nextTick()
    expect(host.textContent).toContain('without credentials')
    ;(host.querySelector('input[type=checkbox]') as HTMLInputElement).click(); await nextTick()
    ;([...host.querySelectorAll('button')].find((b) => b.textContent?.includes('Submit for approval')) as HTMLButtonElement).click()
    await new Promise((r) => setTimeout(r, 0)); await nextTick()
    expect(calls.find((c) => c.method === 'POST')!.body).toEqual({ action: 'user.invite', params: { username: 'dave', role: 'approver', justification: 'Second administrator for DR cover' } })
  })
  it('roles tab renders the permission matrix and policies tab the effective policy', async () => {
    as('viewer'); await mount('roles')
    expect(host.querySelector('table.ux-matrix')).not.toBeNull()
    app?.unmount(); host.remove()
    await mount('policies')
    expect(host.textContent).toContain('Approvals by risk'); expect(host.textContent).toContain('mandatory')
  })
})

describe('helpers', () => {
  it('formats', () => {
    expect(ago(null)).toBe('Never'); expect(ago(new Date(Date.now() - 7200_000).toISOString())).toBe('2 h ago')
    expect(duration(43200)).toBe('12 h'); expect(duration(900)).toBe('15 min')
    expect(cliCommand('x')).toContain('issue-enrollment --username x')
    expect(outcomeText({ status: 'pending_approval', approvals_required: 2 } as never)).toContain('2 approvers')
    expect(routes[0].id).toBe('users')
  })
})
