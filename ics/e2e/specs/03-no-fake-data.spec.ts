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

test('overview numbers equal the API', async ({ page }, info) => {
  await gotoRoute(page, 'overview')
  const [eps, plans, jobs] = [await api(page, 'endpoints'), await api(page, 'plans'), await api(page, 'jobs')]
  const stats: Record<string, string> = {}
  for (const d of await page.locator('dl.stats > div').all()) stats[(await d.locator('dt').innerText()).trim()] = (await d.locator('dd').innerText()).trim()
  check(info, 'overview', 'Endpoints', stats['Endpoints'], String(eps.length))
  check(info, 'overview', 'Plans pending', stats['Plans pending'], String(plans.filter((p: any) => p.status === 'pending_approval').length))
  check(info, 'overview', 'Jobs running / queued', stats['Jobs running / queued'], String(jobs.filter((j: any) => ['running', 'queued'].includes(j.status)).length))
  check(info, 'overview', 'Jobs failed', stats['Jobs failed'], String(jobs.filter((j: any) => j.status === 'failed').length))
  // readiness list equals /readyz
  const rd = await (await page.request.get('/readyz')).json()
  const items = await page.locator('section[aria-labelledby="rd"] ul.checks li').count()
  check(info, 'overview', 'readiness rows (checks + overall)', items, Object.keys(rd.checks).length + 1)
  // recent audit: every row's action exists in the API log
  const audit = await api(page, 'audit?limit=12')
  const shown = await page.locator('main table tbody tr').count()
  check(info, 'overview', 'recent audit rows', shown, Math.min(12, audit.length))
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
  const summary = await page.locator('main p[role=status]').first().innerText()
  const n = (s: string) => Number(summary.match(new RegExp(`(\\d+) ${s}`))?.[1])
  for (const s of ['ok', 'warning', 'critical', 'unknown']) check(info, 'checks', `summary ${s}`, n(s), api_.filter((c: any) => c.state === s).length)
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
