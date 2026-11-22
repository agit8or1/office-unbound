import { afterEach, describe, expect, it, vi } from 'vitest'
import { createApp, nextTick, type App } from 'vue'
import { buildLabel } from './format'
import System from './views/System.vue'

const SYS = {
  product: 'Office Unbound', version: '0.1.0', commit: 'abc1234def5678', dirty: false, built_at: '2026-11-15T10:00:00Z', api: 'v1',
  schema: { build_head: '0007', database: '0007' },
  components: { ics: '0.1.0', node_agent: '0.1.0', portal: '0.1.0', migration_toolkit: '0.1.0', docs_engine: 'cp-26.04.6-1+ou1' },
  interfaces: { api: 'v1' },
  updates: { current: '0.1.0', latest_known: '0.2.0', latest_date: '2027-01-01', notes_url: 'https://example.invalid/notes', update_available: true, checked: 'local release list; no network check is performed' },
}
let app: App | null = null
afterEach(() => { app?.unmount(); app = null; vi.unstubAllGlobals() })

describe('build label', () => {
  it('formats the console footer from API data', () => {
    expect(buildLabel({ version: '0.1.0', commit: 'abc1234def5678' })).toBe('Office Unbound ICS v0.1.0 (abc1234)')
    expect(buildLabel({ version: '0.2.0-dev', codename: 'Beacon', commit: 'abc1234def5678' })).toBe('Office Unbound ICS v0.2.0-dev “Beacon” (abc1234)')
    expect(buildLabel({ version: '0.1.0', commit: 'abc1234def', dirty: true })).toBe('Office Unbound ICS v0.1.0 (abc1234, modified)')
    expect(buildLabel({ version: '0.1.0' })).toBe('Office Unbound ICS v0.1.0')
    expect(buildLabel(null)).toBe('Office Unbound ICS')
    expect(buildLabel({ version: '' })).toBe('Office Unbound ICS')
  })
})

describe('Administration -> System', () => {
  it('shows every component version and the pending-update comparison from /system', async () => {
    const urls: string[] = []
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      urls.push(url)
      return { ok: true, status: 200, statusText: 'OK', headers: new Headers(), text: async () => JSON.stringify(SYS) } as unknown as Response
    }))
    const host = document.createElement('div'); document.body.appendChild(host)
    app = createApp(System); app.mount(host)
    for (let i = 0; i < 8; i++) { await Promise.resolve(); await nextTick() }
    expect(urls.some((u) => u.endsWith('/api/v1/system'))).toBe(true)
    const t = host.textContent ?? ''
    for (const s of ['0.1.0', 'abc1234def5678', 'Node agent', 'User portal', 'Migration toolkit', 'cp-26.04.6-1+ou1', 'Update available', '0.2.0', 'No network check']) expect(t).toContain(s)
    host.remove()
  })
})
