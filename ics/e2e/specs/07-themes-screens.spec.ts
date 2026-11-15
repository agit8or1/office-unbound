import { test, expect } from '@playwright/test'
import { ROUTES } from '../lib/routes'
import { finding, gotoRoute, layoutProblems, setTheme, shotPath, type Theme } from '../lib/helpers'
import { authFile } from '../lib/state'

// Key pages in both themes at every viewport -> docs/screenshots/e2e/<viewport>-<theme>-<page>.png (+ layout check in dark too).
for (const theme of ['light', 'dark'] as Theme[]) {
  test.describe(`screens ${theme}`, () => {
    test.use({ storageState: authFile('admin') })
    for (const r of ROUTES.filter((x) => x.key)) {
      test(`${r.id}`, async ({ page }, info) => {
        await setTheme(page, theme)
        await gotoRoute(page, r.id)
        await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
        const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor)
        const lum = bg.match(/\d+/g)!.slice(0, 3).map(Number).reduce((a, b) => a + b, 0) / 3
        expect(theme === 'dark' ? lum < 100 : lum > 150, `${theme} body background ${bg}`).toBe(true)
        const p = await layoutProblems(page)
        for (const x of p) finding('layout', `${r.id} [${theme}]`, x, info)
        expect.soft(p).toEqual([])
        await page.screenshot({ path: shotPath(info.project.name, theme, r.id), fullPage: false })
      })
    }
  })
  test(`screens ${theme}: login`, async ({ page }, info) => {
    await setTheme(page, theme)
    await page.goto('/ui/')
    await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible()
    await page.screenshot({ path: shotPath(info.project.name, theme, 'login') })
  })
}

test.describe('theme toggle', () => {
  test.use({ storageState: authFile('admin') })
  test('cycles auto -> light -> dark and persists', async ({ page }, info) => {
    test.skip(info.project.name !== 'desktop')
    await gotoRoute(page, 'overview')
    const btn = page.getByRole('button', { name: /^Theme:/ })
    await expect(btn).toContainText('auto')
    await btn.click()
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
    await btn.click()
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
    await page.reload()
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
    await btn.click()
    await expect(page.locator('html')).not.toHaveAttribute('data-theme', /.+/)
  })
})
