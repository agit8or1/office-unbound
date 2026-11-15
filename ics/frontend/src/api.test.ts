import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, formatDetail, get, post, setCsrf, setUnauthorizedHandler } from './api'

function mockFetch(status: number, body: unknown, headers: Record<string, string> = {}) {
  const f = vi.fn(async (..._a: unknown[]) => new Response(body === null ? '' : JSON.stringify(body), { status, headers }))
  vi.stubGlobal('fetch', f)
  return f
}

describe('api client', () => {
  beforeEach(() => { setCsrf(null); setUnauthorizedHandler(null) })
  afterEach(() => vi.unstubAllGlobals())

  it('sends the CSRF header on POST but not GET', async () => {
    setCsrf('tok123')
    const f = mockFetch(200, { ok: true })
    await post('plans', { a: 1 })
    await get('plans')
    const [, postInit] = f.mock.calls[0] as unknown as [string, RequestInit]
    const [, getInit] = f.mock.calls[1] as unknown as [string, RequestInit]
    expect((postInit.headers as Record<string, string>)['X-CSRF-Token']).toBe('tok123')
    expect((getInit.headers as Record<string, string>)['X-CSRF-Token']).toBeUndefined()
    expect(postInit.credentials).toBe('same-origin')
    expect(postInit.body).toBe('{"a":1}')
  })

  it('maps relative paths under /api/v1', async () => {
    const f = mockFetch(200, [])
    await get('endpoints')
    expect(f.mock.calls[0][0]).toBe('/api/v1/endpoints')
  })

  it('surfaces the server error text and status', async () => {
    mockFetch(403, { detail: 'requester cannot approve or reject their own plan' })
    await expect(post('plans/x/approve')).rejects.toMatchObject({
      status: 403, message: 'requester cannot approve or reject their own plan',
    })
  })

  it('formats validation error lists', () => {
    expect(formatDetail([{ loc: ['body', 'params', 'name'], msg: 'bad' }], 'x')).toBe('params.name: bad')
    expect(formatDetail(undefined, 'fallback')).toBe('fallback')
  })

  it('429 carries Retry-After', async () => {
    mockFetch(429, { detail: 'too many attempts' }, { 'Retry-After': '31' })
    const e = (await post("auth/login", {}).catch((x) => x)) as ApiError
    expect(e).toBeInstanceOf(ApiError)
    expect(e.status).toBe(429)
    expect(e.retryAfter).toBe(31)
    expect(e.message).toContain('retry in 31s')
  })

  it('401 triggers the unauthorized handler except for login itself', async () => {
    const h = vi.fn()
    setUnauthorizedHandler(h)
    mockFetch(401, { detail: 'not authenticated' })
    await get('auth/me').catch(() => {})
    expect(h).toHaveBeenCalledTimes(1)
    await post('auth/login', {}).catch(() => {})
    expect(h).toHaveBeenCalledTimes(1)
  })

  it('network failure becomes ApiError status 0', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('x') }))
    await expect(get('x')).rejects.toMatchObject({ status: 0 })
  })
})
