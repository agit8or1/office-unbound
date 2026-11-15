import { test, expect } from '@playwright/test'
import { IA_GROUPS } from '../lib/routes'
import { finding, gotoRoute } from '../lib/helpers'
import { authFile } from '../lib/state'

// ADR-0009 section 6: the navigation must expose the target IA. Items not built yet must be visible and labelled "Planned".
test.use({ storageState: authFile('admin') })
test.beforeEach(({ browserName }, info) => { test.skip(info.project.name !== 'desktop', 'desktop only') })

// ADR label -> accepted labels in the console
const ALIASES: Record<string, string[]> = {
  Alerts: ['Incidents', 'Alerts'], Users: ['Users & roles', 'Users'], Audit: ['Audit log', 'Audit'],
}

test('navigation groups from ADR-0009 section 6 exist and every child is real or labelled Planned', async ({ page }, info) => {
  await gotoRoute(page, 'overview')
  const nav = page.locator('nav[aria-label="Main"]')
  const text = (await nav.innerText()).replace(/\s+/g, ' ').toLowerCase()
  const missing: string[] = []
  for (const [group, children] of Object.entries(IA_GROUPS)) {
    if (group !== 'Overview' && !text.includes(group.toLowerCase())) { missing.push(`group ${group}`); continue }
    for (const c of children) {
      const names = ALIASES[c] ?? [c]
      if (!names.some((n) => text.includes(n.toLowerCase()))) missing.push(`${group} > ${c}`)
    }
  }
  for (const m of missing) finding('IA gap', 'navigation', `ADR-0009 item missing from navigation: ${m} (neither built nor labelled Planned)`, info)
  expect.soft(missing, 'IA items missing').toEqual([])
  // planned items carry the label, never a link that leads to an error
  for (const p of await nav.locator('.navitem.planned').all()) {
    const t = await p.innerText()
    if (!/planned/i.test(t)) finding('IA gap', 'navigation', `inert nav item without Planned label: ${t}`, info)
    expect.soft(t).toMatch(/planned/i)
  }
})

test('every linked nav item opens a real page', async ({ page }, info) => {
  await gotoRoute(page, 'overview')
  const items = await page.locator('nav[aria-label="Main"] a').evaluateAll((as) => as.map((a) => ({ t: a.textContent!.trim(), h: a.getAttribute('href') })))
  for (const it of items) {
    await page.goto(`/ui/${it.h}`)
    const h1 = await page.locator('main h1').first().waitFor({ timeout: 8000 }).then(() => true, () => false)
    const txt = await page.locator('main').innerText().catch(() => '')
    const bad = !h1 || /^\s*$/.test(txt) || /not found|unknown page/i.test(txt)
    if (bad) finding('IA gap', it.t, 'nav item opens an empty/not-found page', info)
    expect.soft(bad, `${it.t} opens a real page`).toBe(false)
  }
})

// ADR-0009 section 6: "Audit is never on the dashboard"; dashboard = status cards for the listed resources.
test('dashboard: no audit log, status cards from ADR-0009', async ({ page }, info) => {
  await gotoRoute(page, 'overview')
  const main = (await page.locator('main').innerText()).replace(/\s+/g, ' ')
  const audit = /latest audit|audit entries/i.test(main)
  if (audit) finding('IA gap', 'overview', 'audit entries are shown on the dashboard (ADR-0009 section 6: never on the dashboard)', info)
  expect.soft(audit, 'audit on dashboard').toBe(false)
  const cards = ['infrastructure health', 'clusters', 'nodes', 'virtual machines', 'containers', 'deployments', 'pending operations', 'incidents']
  const missing = cards.filter((c) => !new RegExp(c, 'i').test(main))
  for (const m of missing) finding('IA gap', 'overview', `dashboard status card missing: ${m}`, info)
  expect.soft(missing, 'dashboard status cards missing').toEqual([])
})

test('first-run setup wizard route (when merged) renders', async ({ page }) => {
  await page.goto('/ui/#/setup')
  await page.waitForTimeout(1000)
  const t = (await page.locator('body').innerText()).replace(/\s+/g, ' ')
  test.skip(/not found/i.test(t), 'setup wizard not merged yet')
  expect(t.length).toBeGreaterThan(50)
})

// Owner decision: login lands on the dashboard; the setup wizard is only offered there, never opened automatically.
test('no endpoint: dashboard stays open and offers the guided setup as one primary button', async ({ page }) => {
  await page.goto('/ui/#/overview')
  await expect(page.getByRole('heading', { name: 'Connect your first Proxmox cluster' })).toBeVisible()
  await expect(page).toHaveURL(/#\/overview/)
  await expect(page.getByRole('link', { name: 'Start guided setup' })).toHaveCount(1)
})
