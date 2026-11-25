// App state: polls the agent only while the window is visible (no background polling from the GUI).
import { reactive } from 'vue'
import type { AccountStatus, Backend, Deployment, Response } from './api'
import { errorText } from './api'

export type Phase = 'loading' | 'welcome' | 'confirm' | 'waiting' | 'ready'

export function createStore(api: Backend) {
  const s = reactive({
    phase: 'loading' as Phase,
    accounts: [] as AccountStatus[],
    paused: false,
    agentVersion: '',
    error: '' as string,
    pending: null as null | { id: string; deployment: Deployment },
    busy: false,
  })

  function apply(r: Response) {
    if (r.type === 'status') {
      s.accounts = r.accounts.filter((a) => a.id !== '')
      s.paused = r.paused
      s.agentVersion = r.agent
      const signing = r.accounts.some((a) => a.state === 'signing_in')
      if (s.phase === 'waiting' && !signing) {
        s.phase = s.accounts.some((a) => a.state === 'signed_in') ? 'ready' : 'welcome'
        if (s.phase === 'welcome') s.error = 'Sign-in was not completed. Try again.'
      } else if (s.phase === 'loading') {
        s.phase = s.accounts.length ? 'ready' : 'welcome'
      }
    }
  }

  async function refresh() {
    try {
      apply(await api.agent({ type: 'status' }))
    } catch (e) {
      s.error = errorText(e)
      if (s.phase === 'loading') s.phase = 'welcome'
    }
  }

  async function discover(input: string) {
    s.error = ''
    s.busy = true
    try {
      const r = await api.agent({ type: 'discover', input })
      if (r.type === 'discovered') {
        s.pending = { id: r.discovery_id, deployment: r.deployment }
        s.phase = 'confirm'
      } else if (r.type === 'error') s.error = r.message
    } catch (e) {
      s.error = errorText(e)
    } finally {
      s.busy = false
    }
  }

  async function signIn() {
    if (!s.pending) return
    s.error = ''
    const r = await api.agent({ type: 'sign_in', discovery_id: s.pending.id })
    if (r.type === 'sign_in_started') {
      s.phase = 'waiting'
      s.pending = null
    } else if (r.type === 'error') {
      s.error = r.message
      s.phase = 'welcome'
    }
  }

  function cancel() {
    s.pending = null
    s.phase = s.accounts.length ? 'ready' : 'welcome'
  }

  async function simple(req: Parameters<Backend['agent']>[0]) {
    const r = await api.agent(req)
    if (r.type === 'error') s.error = r.message
    await refresh()
    return r
  }

  return { s, refresh, discover, signIn, cancel, simple, addAccount: () => { s.phase = 'welcome'; s.error = '' } }
}
export type Store = ReturnType<typeof createStore>
