import { test, expect } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import { ROUTES } from '../lib/routes'
import { finding, gotoRoute, setTheme, type Theme } from '../lib/helpers'
import { authFile } from '../lib/state'

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice']

async function scan(page: any, route: string, theme: Theme, info: any) {
  const res = await new AxeBuilder({ page }).withTags(TAGS).analyze()
  const blocking = res.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')
  for (const v of res.violations) {
    const sev = v.impact === 'serious' || v.impact === 'critical' ? 'defect' : 'minor'
    finding(`a11y ${v.impact}`, `${route} [${theme}]`, `${v.id}: ${v.help} (${v.nodes.length} nodes, e.g. ${v.nodes[0]?.target?.join(' ')})`, info, sev)
  }
  expect.soft(blocking.map((v) => `${v.id} (${v.impact}, ${v.nodes.length} nodes)`), `serious/critical axe violations on ${route} [${theme}]`).toEqual([])
}

for (const theme of ['light', 'dark'] as Theme[]) {
  test.describe(`axe ${theme}`, () => {
    test.use({ storageState: authFile('admin') })
    for (const r of ROUTES) {
      test(`${r.id}`, async ({ page }, info) => {
        await setTheme(page, theme)
        await gotoRoute(page, r.id)
        await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
        await scan(page, r.id, theme, info)
      })
    }
  })
  test.describe(`axe ${theme} unauthenticated`, () => {
    test(`login + enroll`, async ({ page }, info) => {
      await setTheme(page, theme)
      await page.goto('/ui/')
      await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible()
      await scan(page, 'login', theme, info)
      await page.evaluate(() => { location.hash = '#/enroll' })
      await expect(page.getByRole('heading', { name: 'Enroll account' })).toBeVisible()
      await scan(page, 'enroll', theme, info)
    })
  })
}

test.describe('axe detail panels', () => {
  test.use({ storageState: authFile('approver') })
  test('plan detail with approve/reject (light)', async ({ page }, info) => {
    await setTheme(page, 'light')
    await gotoRoute(page, 'plans')
    const first = page.locator('main table tbody tr a').first()
    await expect(first).toBeVisible({ timeout: 30000 })
    await first.click()
    await expect(page.getByRole('heading', { name: /^Plan / })).toBeVisible()
    await scan(page, 'plans/<id>', 'light', info)
  })
})
