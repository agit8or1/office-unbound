import { describe, expect, it } from 'vitest'
import { createApp, h } from 'vue'
import { friendly } from './friendly'
import { hasPath } from './router'
import { NAV, isActive } from './nav'
import TechText from './ui/TechText.vue'

const mount = (comp: object, props: Record<string, unknown>) => { const el = document.createElement('div'); createApp({ render: () => h(comp, props) }).mount(el); return el }

describe('plain-language errors', () => {
  it('maps known technical failures and leaves readable text alone', () => {
    expect(friendly('SSLError: [SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1010)')).toMatch(/secure \(TLS\) connection/)
    expect(friendly('ConnectionRefusedError: [Errno 111] Connection refused')).toMatch(/refused/)
    expect(friendly('IMAP login rejected by the server')).toMatch(/sign-in/)
    expect(friendly('HTTP 200 in 12 ms')).toBeNull()
  })
  it('TechText keeps the raw text only inside the Technical details expander', () => {
    const raw = 'SSLError: [SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1010)'
    const el = mount(TechText, { text: raw })
    expect(el.querySelector('details summary')?.textContent).toBe('Technical details')
    expect(el.querySelector('details code')?.textContent).toBe(raw)
    expect(el.textContent?.replace(el.querySelector('details')!.textContent!, '')).not.toContain('WRONG_VERSION')
    expect(mount(TechText, { text: 'login ok' }).querySelector('details')).toBeNull()
  })
})

describe('routes and navigation', () => {
  it('/deployments/new and /deployments/history are real routes, not the :id detail route', () => {
    expect(hasPath('/deployments/new')).toBe(true)
    expect(hasPath('/deployments/history')).toBe(true)
    expect(hasPath('/deployments/abc')).toBe(false)
    expect(hasPath('/nope')).toBe(false)
  })
  it('every nav item without a page is Planned, and Environments is not active on History', () => {
    for (const g of NAV) for (const i of g.items) expect(!!i.to || !!i.planned).toBe(true)
    const env = NAV.flatMap((g) => g.items).find((i) => i.label === 'Environments')!
    expect(isActive(env, '/deployments/history')).toBe(false)
    expect(isActive(env, '/deployments/acme')).toBe(true)
  })
})
