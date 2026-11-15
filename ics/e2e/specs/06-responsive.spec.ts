import { test, expect } from '@playwright/test'
import { ROUTES } from '../lib/routes'
import { finding, gotoRoute, layoutProblems, setTheme } from '../lib/helpers'
import { authFile } from '../lib/state'

// Runs in each viewport project: desktop 1440x900, tablet 1024x768, mobile 400x860.
test.describe('layout', () => {
  test.use({ storageState: authFile('admin') })
  for (const r of ROUTES) {
    test(`${r.id}: no horizontal page scroll, no overlap`, async ({ page }, info) => {
      await setTheme(page, 'light')
      await gotoRoute(page, r.id)
      const p = await layoutProblems(page)
      for (const x of p) finding('layout', r.id, x, info)
      expect.soft(p, `layout problems on ${r.id} at ${info.project.name}`).toEqual([])
    })
  }

  test('detail panels (checks/plans/incidents)', async ({ page }, info) => {
    await setTheme(page, 'light')
    for (const route of ['checks', 'plans', 'incidents']) {
      await gotoRoute(page, route)
      const first = page.locator('main table tbody tr a').first()
      await expect(first).toBeVisible({ timeout: 30000 })
      await first.click()
      await expect(page.locator('section.detail')).toBeVisible()
      await page.waitForTimeout(600)
      const p = await layoutProblems(page)
      for (const x of p) finding('layout', `${route}/<id>`, x, info)
      expect.soft(p, `layout problems on ${route}/<id> at ${info.project.name}`).toEqual([])
    }
  })

  test('navigation is reachable (menu button on narrow screens)', async ({ page }, info) => {
    await gotoRoute(page, 'overview')
    const w = page.viewportSize()!.width
    const nav = page.locator('nav[aria-label="Main"]')
    const menu = page.getByRole('button', { name: 'Open navigation' })
    if (await menu.isVisible()) {
      await menu.click()
      await expect(menu).toHaveAttribute('aria-expanded', 'true')
    }
    await expect(nav.getByRole('link', { name: 'Health checks' })).toBeVisible()
    const p = await layoutProblems(page)
    for (const x of p) finding('layout', `nav@${w}`, x, info)
    expect.soft(p).toEqual([])
    await nav.getByRole('link', { name: 'Health checks' }).click()
    await expect(page.getByRole('heading', { name: 'Health checks' })).toBeVisible()
  })
})

test('login page layout', async ({ page }, info) => {
  await page.goto('/ui/')
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible()
  const p = await layoutProblems(page)
  for (const x of p) finding('layout', 'login', x, info)
  expect.soft(p).toEqual([])
})
