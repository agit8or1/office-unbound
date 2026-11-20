import { reactive, ref, onMounted, onUnmounted } from 'vue'
import { ApiError, get, post, rank, setCsrf, setUnauthorizedHandler, type Me, type Role } from './api'

export const session = reactive<{ user: Me | null; ready: boolean; expired: boolean }>({ user: null, ready: false, expired: false })

export function hasRole(min: Role) { return !!session.user && rank(session.user.role) >= rank(min) }

export async function loadSession() {
  try {
    const me = await get<Me>('auth/me')
    setCsrf(me.csrf_token)
    session.user = me
  } catch {
    session.user = null
    setCsrf(null)
  }
  session.ready = true
}

export function setLoggedIn(u: { username: string; role: Role }, csrf: string) {
  setCsrf(csrf)
  session.user = { ...u, csrf_token: csrf }
  session.expired = false
}

export async function logout() {
  try { await post('auth/logout') } catch { /* cookie may already be gone */ }
  setCsrf(null)
  session.user = null
  go('login')
}

setUnauthorizedHandler(() => {
  if (session.user) { session.user = null; session.expired = true; setCsrf(null); go('login') }
})

// ---- hash router: #/page or #/page/arg ----
export const route = ref(parse())
function parse() {
  const [page = '', ...rest] = location.hash.replace(/^#\/?/, '').split('/')
  return { page, arg: rest.join('/') }
}
window.addEventListener('hashchange', () => { route.value = parse() })
/** Called by the router after every navigation: router links change the URL with pushState, which fires no 'hashchange',
 *  so without this the legacy route kept the previous page's argument (e.g. "directory" from #/users/directory became a job id). */
export function syncRoute() { route.value = parse() }
export function go(page: string, arg = '') { location.hash = `#/${page}${arg ? '/' + arg : ''}` }

// ---- data loading helper ----
export function errText(e: unknown) {
  if (e instanceof ApiError) return e.message
  return e instanceof Error ? e.message : String(e)
}

export function useLoad<T>(fn: () => Promise<T>, pollMs = 0) {
  const data = ref<T | null>(null) as { value: T | null }
  const error = ref<ApiError | null>(null)
  const loading = ref(false)
  let timer: number | undefined
  async function reload() {
    loading.value = true
    try { data.value = await fn(); error.value = null }
    catch (e) { error.value = e instanceof ApiError ? e : new ApiError(0, errText(e)) }
    finally { loading.value = false }
  }
  onMounted(() => { void reload(); if (pollMs) timer = window.setInterval(() => { if (!document.hidden) void reload() }, pollMs) })
  onUnmounted(() => clearInterval(timer))
  return { data: data as import('vue').Ref<T | null>, error, loading, reload }
}

// ---- formatting ----
export function fmtTime(s: string | null | undefined) {
  if (!s) return '-'
  const d = new Date(s)
  return isNaN(+d) ? s : d.toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'medium' })
}
export const short = (s: string | null | undefined, n = 8) => (s ? s.slice(0, n) : '-')
export function fmtBytes(n: unknown) {
  const v = Number(n)
  if (!isFinite(v) || v <= 0) return '-'
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let i = 0, x = v
  while (x >= 1024 && i < u.length - 1) { x /= 1024; i++ }
  return `${x.toFixed(x >= 100 || i === 0 ? 0 : 1)} ${u[i]}`
}
export const pretty = (v: unknown) => JSON.stringify(v, null, 2)
