import { test, expect, type Page } from '@playwright/test'
import { ROUTES } from '../lib/routes'
import { api, finding, gotoRoute } from '../lib/helpers'
import { authFile, state } from '../lib/state'

test.beforeEach(({ browserName }, info) => { test.skip(info.project.name !== 'desktop', 'desktop only') })

// ---- 1. Dead-control scan: every visible button/link either reacts (request, DOM change, hash change, aria state) or is disabled/Planned.
const MUTATING = /approve|reject|acknowledge|create|register|invite|request refresh|verify|sign out|theme|menu|preview/i
test.describe('dead control scan', () => {
  test.use({ storageState: authFile('admin') })
  for (const r of ROUTES) {
    test(`controls on ${r.id}`, async ({ page, context }, info) => {
      await context.grantPermissions(['clipboard-read', 'clipboard-write'])
      await gotoRoute(page, r.id)
      const dead: string[] = []
      const href = await page.locator('main a').evaluateAll((as) => as.map((a) => [a.textContent!.trim(), a.getAttribute('href')]))
      for (const [t, h] of href) if (!h || h === '#' || h.startsWith('javascript:')) dead.push(`link "${t}" has href=${h}`)
      const btns = page.locator('main button')
      const n = await btns.count()
      for (let i = 0; i < n; i++) {
        const b = btns.nth(i)
        if (!(await b.isVisible())) continue
        const label = ((await b.innerText()) || (await b.getAttribute('aria-label')) || '').trim()
        if (await b.isDisabled()) {
          const explained = /planned|blocked/i.test(label + (await b.getAttribute("title") ?? "") + (await b.getAttribute('aria-label') ?? ''))
          if (!explained && !/newer|older|sign|checking|submitting|verifying|\n\s*0$|create|request|submit/i.test(label)) finding('disabled control unexplained', r.id, `"${label}" is disabled with no Planned/Blocked label`, info, 'review')
          continue
        }
        if (MUTATING.test(label) || (await b.getAttribute('aria-pressed')) === 'true') continue // covered by the real-flow tests below
        let reqs = 0
        const onReq = () => reqs++
        page.on('request', onReq)
        const before = await page.evaluate(() => String(document.body!.innerHTML.length) + location.hash + [...document.querySelectorAll("[aria-expanded],[aria-pressed]")].map((e) => `${e.getAttribute("aria-expanded")}${e.getAttribute("aria-pressed")}`).join())
        let clickErr = ''
        await b.click({ timeout: 5000 }).catch((e) => { clickErr = String(e).split('\n')[0] })
        await page.waitForTimeout(500)
        page.off('request', onReq)
        const after = await page.evaluate(() => String(document.body!.innerHTML.length) + location.hash + [...document.querySelectorAll("[aria-expanded],[aria-pressed]")].map((e) => `${e.getAttribute("aria-expanded")}${e.getAttribute("aria-pressed")}`).join())
        if (clickErr) dead.push(`button "${label}" could not be clicked: ${clickErr}`)
        else if (reqs === 0 && before === after && !(await page.locator('[role=dialog]').count())) dead.push(`button "${label}" did nothing (no request, no DOM/hash/aria change)`)
        await page.goto(`/ui/#/${r.id}`)
        await page.reload()
        await expect(page.locator('main h1').first()).toBeVisible()
        await page.waitForTimeout(400)
      }
      for (const d of dead) finding('dead control', r.id, d, info)
      expect.soft(dead, `dead controls on ${r.id}`).toEqual([])
    })
  }
})

