import { test, expect } from '@playwright/test'
import { finding, gotoRoute, layoutProblems, setTheme } from '../lib/helpers'
import { authFile } from '../lib/state'

// UI audit 2026-11-25: the console at every width the owner listed (320 ... 2560 px), both themes: no page-level horizontal scroll,
// no control outside the viewport, the menu button only where the navigation is off-canvas, and a closed drawer is not reachable by Tab.
// Runs once (desktop project); the width is set per step.
test.use({ storageState: authFile('admin') })
test.beforeEach(({}, info) => { test.skip(info.project.name !== 'desktop', 'widths are set per step') })

const WIDTHS = [320, 390, 768, 1024, 1366, 1600, 1920, 2560]
const PAGES = ['overview', 'deployments', 'releases', 'checks', 'incidents', 'system', 'users', 'infrastructure/nodes']

for (const theme of ['light', 'dark'] as const) {
  test(`no horizontal page scroll at any width (${theme})`, async ({ page }, info) => {
    await setTheme(page, theme)
    for (const route of PAGES) {
      await page.setViewportSize({ width: 1366, height: 900 })
      await gotoRoute(page, route)
      for (const w of WIDTHS) {
        await page.setViewportSize({ width: w, height: w < 600 ? 844 : 900 })
        await page.waitForTimeout(150)
        const p = (await layoutProblems(page)).filter((x) => /scrolls horizontally|outside viewport/.test(x))
        for (const x of p) finding('layout', `${route}@${w} [${theme}]`, x, info)
        expect.soft(p, `${route} at ${w}px (${theme})`).toEqual([])
      }
    }
  })
}

test('menu button only where the navigation is off-canvas; a closed drawer is skipped by Tab', async ({ page }) => {
  await setTheme(page, 'light')
  await gotoRoute(page, 'overview')
  const menu = page.getByRole('button', { name: 'Open navigation' })
  for (const w of [1366, 1024, 900]) { await page.setViewportSize({ width: w, height: 900 }); await expect(menu, `${w}px`).toBeHidden() }
  await page.setViewportSize({ width: 390, height: 844 })
  await expect(menu).toBeVisible()
  await page.waitForTimeout(400) // the drawer hides after its 0.2 s slide-out
  // closed: nothing inside the drawer takes focus
  const inNav = async () => page.evaluate(() => !!document.activeElement?.closest('aside.side'))
  await page.locator('body').focus()
  for (let i = 0; i < 6; i++) { await page.keyboard.press('Tab'); expect(await inNav(), `tab ${i + 1} landed in the closed drawer`).toBe(false) }
  // open with the keyboard: focus moves in; Escape closes and returns focus to the menu button
  await menu.focus(); await page.keyboard.press('Enter')
  await expect(menu).toHaveAttribute('aria-expanded', 'true')
  await expect.poll(inNav).toBe(true)
  await page.keyboard.press('Escape')
  await expect(menu).toHaveAttribute('aria-expanded', 'false')
  await expect(menu).toBeFocused()
})
