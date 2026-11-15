import { afterEach, describe, expect, it, vi } from 'vitest'
import { createApp, nextTick } from 'vue'
import { api, load } from './api'
import { setCsrf } from '../api'
import DeployWizard from './deploy/DeployWizard.vue'

function stubFetch(routes: Record<string, { status?: number; body: unknown }>) {
  const calls: { method: string; url: string; body: string | undefined }[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit) => {
    calls.push({ method: init.method ?? 'GET', url, body: init.body as string | undefined })
    const r = routes[`${init.method} ${url}`] ?? { status: 404, body: { detail: 'Not Found' } }
    return new Response(JSON.stringify(r.body), { status: r.status ?? 200 })
  }))
  return calls
}
afterEach(() => vi.unstubAllGlobals())

describe('wizard api client', () => {
  it('submitPlan posts the exact {action, params} JSON to /plans with CSRF', async () => {
    setCsrf('csrf1')
    const calls = stubFetch({ 'POST /api/v1/plans': { status: 201, body: { plan_id: 'p', status: 'pending_approval', risk: 'high', job_id: null, params_hash: 'h', approvals_required: 2 } } })
    await api.submitPlan('deployment.change', { deployment_id: 'e', change: { type: 'scale', params: { replicas: 2 } } })
    expect(calls).toHaveLength(1)
    expect(JSON.parse(calls[0].body!)).toEqual({ action: 'deployment.change', params: { deployment_id: 'e', change: { type: 'scale', params: { replicas: 2 } } } })
    setCsrf(null)
  })
  it('maps 404 to an "unavailable" state, other errors to error, never to data', async () => {
    stubFetch({ 'GET /api/v1/catalog/profiles': { status: 404, body: { detail: 'Not Found' } }, 'GET /api/v1/catalog/components': { status: 500, body: { detail: 'boom' } } })
    expect(await load(() => api.profiles())).toEqual({ state: 'unavailable', status: 404 })
    expect(await load(() => api.components())).toMatchObject({ state: 'error', message: 'boom' })
  })
})

describe('DeployWizard component', () => {
  it('on a backend without the catalog shows the unavailable state, offers no submit, and sends no plan', async () => {
    const calls = stubFetch({})
    const el = document.createElement('div'); document.body.appendChild(el)
    const app = createApp(DeployWizard); app.mount(el)
    await new Promise((r) => setTimeout(r, 20)); await nextTick()
    expect(el.textContent).toMatch(/not available|catalog/i)
    const submit = [...el.querySelectorAll('button')].find((b) => /Submit deployment plan/.test(b.textContent ?? '')) as HTMLButtonElement | undefined
    expect(submit === undefined || submit.disabled).toBe(true)
    expect(calls.some((c) => c.method === 'POST')).toBe(false)
    app.unmount()
  })
})
