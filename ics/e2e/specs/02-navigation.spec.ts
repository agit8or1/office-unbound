import { test, expect } from '@playwright/test'
import { ROUTES } from '../lib/routes'
import { api, bodyText, FORBIDDEN, finding, gotoRoute, watch } from '../lib/helpers'
import { authFile } from '../lib/state'

test.use({ storageState: authFile('admin') })

// Every route: renders, no console errors / CSP violations / failed requests, no leaked internal copy or raw errors.
for (const r of ROUTES) {
  test(`route ${r.id}: clean render`, async ({ page }, info) => {
    const issues = watch(page)
    await gotoRoute(page, r.id)
    await page.waitForTimeout(1200)
    for (const i of issues) finding('console/network', r.id, i, info)
    expect.soft(issues, `console/CSP/network issues on ${r.id}`).toEqual([])
    const text = await bodyText(page)
    for (const f of FORBIDDEN) {
      const m = text.match(f.re)
      if (m) finding('user-facing copy', r.id, `${f.name}: "...${text.slice(Math.max(0, m.index! - 20), m.index! + m[0].length + 60)}..."`, info)
      expect.soft(m, `${f.name} on ${r.id}`).toBeNull()
    }
    const errs = await page.locator('.alert.bad').allInnerTexts()
    for (const e of errs) finding('raw error shown', r.id, e.replace(/\s+/g, ' '), info)
    expect.soft(errs, `error banners on ${r.id}`).toEqual([])
  })
}

test('detail routes (checks/plans/incidents) render', async ({ page }, info) => {
  const issues = watch(page)
  const ids = {
    checks: (await api(page, 'checks'))[0]?.id,
    plans: (await api(page, 'plans'))[0]?.id,
    incidents: (await api(page, 'incidents'))[0]?.id,
  }
  for (const [route, id] of Object.entries(ids)) {
    expect(id, `seed provides a ${route} entry`).toBeTruthy()
    await gotoRoute(page, `${route}/${id}`)
    await page.waitForTimeout(800)
    const text = await bodyText(page)
    for (const f of FORBIDDEN) {
      const m = text.match(f.re)
      if (m) finding('user-facing copy', `${route}/<id>`, `${f.name}: "...${text.slice(Math.max(0, m.index! - 20), m.index! + m[0].length + 60)}..."`, info)
      expect.soft(m, `${f.name} on ${route}/<id>`).toBeNull()
    }
  }
  for (const i of issues) finding('console/network', 'detail routes', i, info)
  expect.soft(issues).toEqual([])
})

test('every sidebar link opens its page', async ({ page }) => {
  await gotoRoute(page, 'overview')
  if (page.viewportSize()!.width < 900) await page.getByRole('button', { name: 'Open navigation' }).click()
  const links = await page.locator('nav[aria-label="Main"] a').evaluateAll((as) => as.map((a) => ({ t: a.textContent!.trim(), h: a.getAttribute('href') })))
  expect(links.length).toBeGreaterThanOrEqual(12)
  for (const l of links) {
    await page.evaluate((h) => { location.hash = h }, l.h!)
    await expect(page.locator('main h1').first()).toBeVisible()
    await expect(page.locator('main')).not.toContainText('Unknown page')
  }
})
