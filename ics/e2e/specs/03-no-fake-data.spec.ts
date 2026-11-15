import { test, expect, type Page } from '@playwright/test'
import { api, finding, gotoRoute } from '../lib/helpers'
import { authFile } from '../lib/state'

test.use({ storageState: authFile('admin') })
test.beforeEach(({ browserName }, info) => { test.skip(info.project.name !== 'desktop', 'desktop only') })

const rows = (page: Page) => page.locator('main table tbody tr')

function check(info: any, route: string, what: string, actual: unknown, expected: unknown) {
  const same = JSON.stringify(actual) === JSON.stringify(expected)
  if (!same) finding('data mismatch', route, `${what}: UI=${JSON.stringify(actual)} API=${JSON.stringify(expected)}`, info)
  expect.soft(actual, `${route}: ${what}`).toEqual(expected)
}

test('overview status cards equal the API', async ({ page }, info) => {
  await gotoRoute(page, 'overview')
  await page.waitForTimeout(1500)
  const [plans, jobs, checks, inc] = [await api(page, 'plans'), await api(page, 'jobs'), await api(page, 'checks'), await api(page, 'incidents?status=active&limit=100')]
  const cards: Record<string, string> = {}
  for (const d of await page.locator('.statgrid .stat').all()) cards[(await d.locator('.lbl').innerText()).trim()] = (await d.locator('.val').innerText()).replace(/\s+/g, '').trim()
  const pend = plans.filter((p: any) => p.status === 'pending_approval').length
  const run = jobs.filter((j: any) => ['running', 'queued'].includes(j.status)).length
  check(info, 'overview', 'Pending operations', cards['Pending operations'], String(pend + run))
  check(info, 'overview', 'Active incidents', cards['Active incidents'], String(inc.length))
  // infra-derived cards: compare with /infra/* when that API exists, else they must show zero / none
  for (const [label, path] of [['Clusters', 'infra/clusters'], ['Nodes', 'infra/nodes']] as const) {
    const r = await page.request.get(`/api/v1/${path}`)
    const n = r.ok() ? (await r.json()).length ?? 0 : 0
    const shown = cards[label]?.split('/')[0]
    if (label === 'Nodes') check(info, 'overview', `${label} (online part <= API total)`, Number(shown) <= n, true)
    else check(info, 'overview', label, shown, String(n))
  }
  const sub = (await page.locator('.statgrid').innerText()).replace(/\s+/g, ' ')
  const crit = inc.filter((x: any) => x.severity === 'critical').length
  check(info, 'overview', 'incident subtitle', crit ? sub.includes(`${crit} critical`) : sub.includes('All clear'), true)
  // the active-incident list names the real incidents
  for (const i of inc.slice(0, 5)) {
    const has = (await page.locator('main').innerText()).includes(i.check_name) || (await page.locator('main').innerText()).includes(i.title)
    check(info, 'overview', `incident ${i.check_name} listed`, has, true)
  }
  // no readiness warning while /readyz says ready
  const rd = await (await page.request.get('/readyz')).json()
  check(info, 'overview', 'not-ready banner matches /readyz', (await page.locator('.alert.warn').count()) > 0, !rd.ready)
})

test('checks list = API', async ({ page }, info) => {
  await gotoRoute(page, 'checks')
  const api_ = await api(page, 'checks')
  check(info, 'checks', 'row count', await rows(page).count(), api_.length)
  for (const c of api_) {
    const row = rows(page).filter({ hasText: c.name })
    await expect(row, `check ${c.name} listed`).toHaveCount(1)
    check(info, 'checks', `${c.name} state`, (await row.innerText()).toLowerCase().includes(c.state), true)
  }
  const cards: Record<string, string> = {}
  for (const d of await page.locator('.statgrid .stat').all()) cards[(await d.locator('.lbl').innerText()).trim()] = (await d.locator('.val').innerText()).trim()
  for (const [label, s] of [['Healthy', 'ok'], ['Warning', 'warning'], ['Critical', 'critical'], ['Unknown', 'unknown']] as const)
    check(info, 'checks', `summary ${label}`, cards[label], String(api_.filter((c: any) => c.state === s).length))
})

test('incidents list = API', async ({ page }, info) => {
  await gotoRoute(page, 'incidents')
  await page.getByRole('button', { name: 'All' }).click()
  await page.waitForTimeout(800)
  const inc = await api(page, 'incidents')
  expect(inc.length, 'seed has an incident').toBeGreaterThan(0)
  check(info, 'incidents', 'row count', await rows(page).count(), inc.length)
  await page.getByRole('button', { name: 'Active' }).click()
  await page.waitForTimeout(800)
  const act = await api(page, 'incidents?status=active')
  check(info, 'incidents', 'active row count', await rows(page).count(), act.length)
})

test('plans list = API', async ({ page }, info) => {
  await gotoRoute(page, 'plans')
  const pend = (await api(page, 'plans')).filter((p: any) => p.status === 'pending_approval')
  check(info, 'plans', 'pending rows', await rows(page).count(), pend.length)
  await page.getByRole('button', { name: 'All' }).click()
  check(info, 'plans', 'all rows', await rows(page).count(), (await api(page, 'plans')).length)
})

test('jobs list = API', async ({ page }, info) => {
  await gotoRoute(page, 'jobs')
  const jobs = await api(page, 'jobs')
  check(info, 'jobs', 'row count', await rows(page).count(), jobs.length)
})

test('endpoints list = API', async ({ page }, info) => {
  await gotoRoute(page, 'endpoints')
  const eps = await api(page, 'endpoints')
  check(info, 'endpoints', 'row count', await rows(page).count(), eps.length)
})

test('users page shows the accounts the API has', async ({ page }, info) => {
  await gotoRoute(page, 'users')
  const users = await api(page, 'users')
  expect(users.length).toBeGreaterThan(3)
  for (const u of users) {
    const shown = (await page.locator('main').innerText()).includes(u.username)
    if (!shown) finding('data missing', 'users', `account ${u.username} (${u.role}) exists in GET /users but is not shown`, info)
    expect.soft(shown, `account ${u.username} visible on Users page`).toBe(true)
  }
})

test('audit rows and chain verification equal the API', async ({ page }, info) => {
  await gotoRoute(page, 'audit')
  const log = await api(page, 'audit?limit=500')
  expect(log.length).toBeGreaterThan(5)
  const verify = await api(page, 'audit/verify')
  await page.getByRole('button', { name: 'Verify chain' }).click()
  await page.waitForTimeout(1500)
  const txt = (await page.locator('main').innerText()).toLowerCase()
  check(info, 'audit', 'chain result text reflects API ok=' + verify.ok, verify.ok ? /intact|ok|verified/.test(txt) : /broken|problem/.test(txt), true)
})
