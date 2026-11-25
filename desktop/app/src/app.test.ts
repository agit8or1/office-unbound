import { describe, expect, it } from 'vitest'
import { createApp, nextTick } from 'vue'
import App from './App.vue'
import type { AccountStatus, Backend, Request, Response } from './api'

const dep = {
  domain: 'company.com', name: 'Company', issuer: 'https://auth.company.com/realms/ou', client_id: 'OpenCloudDesktop',
  files_url: 'https://cloud.company.com/', portal_url: 'https://app.company.com/', matrix_url: 'https://matrix.company.com/',
  chat_web_url: 'https://chat.company.com/', mail_web_url: 'https://mail.company.com/', source: 'web_finger' as const,
  login_hint: 'doc@company.com', foreign_hosts: [] as string[],
}
const acct = (state: AccountStatus['state']): AccountStatus => ({
  id: 'aa11', label: 'doc@company.com', deployment: 'Company', domain: 'company.com', state, detail: null,
  services: ['portal', 'files', 'chat', 'mail', 'calendar', 'contacts'], files_url: dep.files_url,
})

function fake() {
  const sent: Request[] = []
  let accounts: AccountStatus[] = []
  let foreign: string[] = []
  const api: Backend = {
    async agent(req: Request): Promise<Response> {
      sent.push(req)
      switch (req.type) {
        case 'status': return { type: 'status', accounts, paused: false, agent: '0.1.0-alpha.1' }
        case 'discover': return req.input.includes('@') ? { type: 'discovered', discovery_id: 'd1', deployment: { ...dep, foreign_hosts: foreign } }
          : { type: 'error', message: 'no Office Unbound deployment was found for nowhere.example' }
        case 'sign_in': accounts = [{ ...acct('signing_in'), id: '' }]; return { type: 'sign_in_started' }
        case 'remove_account': accounts = []; return { type: 'ok' }
        default: return { type: 'ok' }
      }
    },
    appInfo: async () => ({ version: '0.1.0-alpha.1', data_dir: 'C:\\Users\\u\\AppData\\Local\\OfficeUnbound', log_file: 'x', autostart: false }),
    setAutostart: async (e) => e,
  }
  return { api, sent, setAccounts: (a: AccountStatus[]) => { accounts = a }, setForeign: (f: string[]) => { foreign = f } }
}

async function flush() { for (let i = 0; i < 6; i++) { await Promise.resolve(); await nextTick() } }

function mount(api: Backend, pollMs = 1_000_000) {
  const el = document.createElement('div')
  document.body.innerHTML = ''
  document.body.appendChild(el)
  const app = createApp(App, { api, pollMs })
  app.mount(el)
  return { el, app }
}

function type(el: HTMLElement, value: string) {
  const i = el.querySelector('input#addr') as HTMLInputElement
  i.value = value
  i.dispatchEvent(new Event('input'))
}
function click(el: HTMLElement, text: string) {
  const b = [...el.querySelectorAll('button')].find((b) => b.textContent?.trim().startsWith(text))
  if (!b) throw new Error(`no button ${text}: ${el.innerHTML}`)
  b.click()
}

describe('first run', () => {
  it('goes from e-mail to confirmation to waiting to signed in', async () => {
    const f = fake()
    const { el } = mount(f.api, 40)
    await flush()
    expect(el.textContent).toContain('Sign in to Office Unbound')
    type(el, 'doc@company.com')
    await flush()
    ;(el.querySelector('form') as HTMLFormElement).dispatchEvent(new Event('submit'))
    await flush()
    expect(el.textContent).toContain('Sign in to Company?')
    expect(el.textContent).toContain('auth.company.com')
    expect(el.textContent).toContain('never in this app')
    expect(el.querySelector('[role=alert]')).toBeNull()
    click(el, 'Open sign-in page')
    await flush()
    expect(el.textContent).toContain('Finish signing in in your browser')
    expect(f.sent).toContainEqual({ type: 'sign_in', discovery_id: 'd1' })
    f.setAccounts([acct('signed_in')])
    await new Promise((r) => setTimeout(r, 120))
    await flush()
    expect(el.querySelector('h1')?.textContent).toBe('Home')
    expect(el.textContent).toContain('doc@company.com')
  })

  it('reports discovery errors and warns about foreign hosts', async () => {
    const f = fake()
    const { el } = mount(f.api)
    await flush()
    type(el, 'nowhere.example')
    await flush()
    ;(el.querySelector('form') as HTMLFormElement).dispatchEvent(new Event('submit'))
    await flush()
    expect(el.querySelector('[role=alert]')?.textContent).toContain('no Office Unbound deployment')
    f.setForeign(['matrix.elsewhere.example'])
    type(el, 'doc@company.com')
    await flush()
    ;(el.querySelector('form') as HTMLFormElement).dispatchEvent(new Event('submit'))
    await flush()
    expect(el.querySelector('[role=alert]')?.textContent).toContain('matrix.elsewhere.example')
  })
})

describe('signed-in shell', () => {
  it('shows the account, opens services through the agent and needs confirmation to remove', async () => {
    const f = fake()
    f.setAccounts([acct('signed_in')])
    const { el } = mount(f.api)
    await flush()
    expect(el.querySelector('[role=status]')?.textContent).toContain('Connected')
    expect(el.textContent).toContain('doc@company.com')
    click(el, 'Files')  // nav button
    await flush()
    click(el, 'Home')
    await flush()
    const filesQuick = [...el.querySelectorAll('.quick button')].find((b) => b.textContent?.includes('Files')) as HTMLButtonElement
    filesQuick.click()
    await flush()
    expect(f.sent).toContainEqual({ type: 'open_service', account_id: 'aa11', service: 'files' })
    click(el, 'Settings')
    await flush()
    expect(el.textContent).toContain('alpha, not code-signed')
    click(el, 'Remove')
    await flush()
    expect(f.sent.some((r) => r.type === 'remove_account')).toBe(false)
    click(el, 'Confirm remove')
    await flush()
    expect(f.sent).toContainEqual({ type: 'remove_account', account_id: 'aa11' })
  })

  it('signed-out account disables its actions and shows action needed', async () => {
    const f = fake()
    f.setAccounts([acct('signed_out')])
    const { el } = mount(f.api)
    await flush()
    expect(el.querySelector('[role=status]')?.textContent).toContain('Action needed')
    const btns = [...el.querySelectorAll('.quick button')] as HTMLButtonElement[]
    expect(btns.length).toBeGreaterThan(0)
    expect(btns.every((b) => b.disabled)).toBe(true)
  })

  it('meetings page is honest when the deployment has none', async () => {
    const f = fake()
    f.setAccounts([acct('signed_in')])
    const { el } = mount(f.api)
    await flush()
    click(el, 'Meetings')
    await flush()
    expect(el.textContent).toContain('not available')
  })
})
