import { test, expect } from '@playwright/test'
import path from 'node:path'
import fs from 'node:fs'
import { api, gotoRoute, setTheme, type Theme } from '../lib/helpers'
import { authFile } from '../lib/state'

// Documentation screenshots of the polished console (dashboard, users, integrations, a failing check with its plain-language error),
// light and dark, written to $CONSOLE_SHOT_DIR (default docs/screenshots/console-v2). Desktop only.
test.use({ storageState: authFile('admin') })
test.beforeEach(({}, info) => { test.skip(info.project.name !== 'desktop', 'desktop only') })
const dir = process.env.CONSOLE_SHOT_DIR ?? path.resolve('../../docs/screenshots/console-v2')

for (const theme of ['light', 'dark'] as Theme[]) {
  test(`console screenshots ${theme}`, async ({ page }) => {
    fs.mkdirSync(dir, { recursive: true })
    await setTheme(page, theme)
    const shot = async (name: string) => page.screenshot({ path: path.join(dir, `${name}-${theme}.png`) })
    await gotoRoute(page, 'overview'); await shot('dashboard')
    await gotoRoute(page, 'users'); await shot('users')
    await gotoRoute(page, 'endpoints'); await shot('integrations')
    const checks = await api<{ id: string; state: string; last_message: string | null }[]>(page, 'checks')
    const bad = checks.find((c) => c.state === 'critical' && c.last_message) ?? checks[0]
    expect(bad, 'seed has a check').toBeTruthy()
    await gotoRoute(page, `checks/${bad.id}`)
    await page.locator('details.techd summary').first().click({ timeout: 3000 }).catch(() => undefined)
    await shot('check-detail-error')
    await gotoRoute(page, 'system'); await shot('system')
  })
}
