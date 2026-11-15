import { test, expect } from '@playwright/test'
import { IA_GROUPS } from '../lib/routes'
import { finding, gotoRoute } from '../lib/helpers'
import { authFile } from '../lib/state'

// ADR-0009 section 6: the navigation must expose the target IA. Items not built yet must be visible and labelled "Planned" (or hidden).
test.use({ storageState: authFile('admin') })
test.beforeEach(({ browserName }, info) => { test.skip(info.project.name !== 'desktop', 'desktop only') })

test('navigation groups from ADR-0009 section 6 exist', async ({ page }, info) => {
  await gotoRoute(page, 'overview')
  const nav = (await page.locator('nav[aria-label="Main"]').innerText()).replace(/\s+/g, ' ')
  const missing = Object.keys(IA_GROUPS).filter((g) => !nav.includes(g))
  for (const g of missing) finding('IA gap', 'navigation', `group "${g}" missing from navigation`, info)
  expect.soft(missing, 'IA groups missing').toEqual([])
})

// ADR-0009 section 6: "Audit is never on the dashboard"; dashboard = status cards for the listed resources.
test('dashboard: no audit log, status cards from ADR-0009', async ({ page }, info) => {
  await gotoRoute(page, 'overview')
  const main = (await page.locator('main').innerText()).replace(/\s+/g, ' ')
  const audit = /latest audit|audit entries|audit log/i.test(main)
  if (audit) finding('IA gap', 'overview', 'audit entries are shown on the dashboard (ADR-0009 section 6: never on the dashboard)', info)
  expect.soft(audit, 'audit on dashboard').toBe(false)
  const cards = ['infra health', 'clusters', 'nodes', 'vms|virtual machines', 'containers', 'deployments', 'pending operations|pending approvals|plans pending', 'incidents']
  const missing = cards.filter((c) => !new RegExp(c, 'i').test(main))
  for (const m of missing) finding('IA gap', 'overview', `dashboard status card missing: ${m}`, info)
  expect.soft(missing, 'dashboard status cards missing').toEqual([])
})

test('every shown nav item is real or labelled Planned', async ({ page }, info) => {
  await gotoRoute(page, 'overview')
  const items = await page.locator('nav[aria-label="Main"] a').evaluateAll((as) => as.map((a) => ({ t: a.textContent!.trim(), h: a.getAttribute('href') })))
  for (const it of items) {
    if (/planned/i.test(it.t)) continue
    await page.evaluate((h) => { location.hash = h }, it.h!)
    await expect(page.locator('main h1').first()).toBeVisible()
    const txt = await page.locator('main').innerText()
    const stub = /^\s*$/.test(txt) || /unknown page/i.test(txt)
    if (stub) finding('IA gap', it.t, 'nav item opens an empty/unknown page', info)
    expect.soft(stub, `${it.t} opens a real page`).toBe(false)
  }
})
