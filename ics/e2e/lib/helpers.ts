import { expect, type Page, type TestInfo } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'

export type Theme = 'light' | 'dark'

/** Append a finding (deduplicated later by scripts/findings-summary.mjs). Failing assertions use the same ids. */
export function finding(category: string, route: string, detail: string, info?: TestInfo, severity = 'defect') {
  fs.mkdirSync('results', { recursive: true })
  const rec = { category, route, detail: detail.slice(0, 400), project: info?.project.name ?? '', severity }
  fs.appendFileSync('results/findings.jsonl', JSON.stringify(rec) + '\n')
}

/** Collect console errors, page errors, CSP violations and failed/4xx/5xx requests for the lifetime of the page. */
export function watch(page: Page, allow: RegExp[] = []) {
  const issues: string[] = []
  const ok = (s: string) => allow.some((r) => r.test(s))
  const add = (s: string) => { if (!ok(s)) issues.push(s) }
  page.on('console', (m) => {
    const t = m.text()
    if (m.type() === 'error' || /Content Security Policy|Refused to/.test(t)) add(`console.${m.type()}: ${t}`)
  })
  page.on('pageerror', (e) => add(`pageerror: ${e.message}`))
  page.on('requestfailed', (r) => add(`requestfailed: ${r.method()} ${r.url()} ${r.failure()?.errorText}`))
  page.on('response', (r) => { if (r.status() >= 400) add(`http ${r.status()} ${r.request().method()} ${new URL(r.url()).pathname}`) })
  void page.addInitScript(() => {
    document.addEventListener('securitypolicyviolation', (e) => {
      console.error(`CSP violation: ${e.violatedDirective} ${e.blockedURI}`)
    })
  })
  return issues
}

/** Copy that must never reach an operator: internal gaps, raw API/server errors, template leaks. */
export const FORBIDDEN: { name: string; re: RegExp }[] = [
  { name: 'internal-gap copy', re: /not implemented|no api\b|api gap|api (has no|does not|doesn't|only supports|lacks)|endpoint (is )?missing|todo\b|tbd\b|lorem ipsum|coming soon|not yet (wired|available in the api)/i },
  { name: 'raw exception text', re: /SSLError|Errno \d+|ConnectionRefused|socket\.\w+|ssl\.\w+Error|\bException\b|\bat 0x[0-9a-f]+/ },
  { name: 'template leak', re: /\bundefined\b|\bNaN\b|\[object Object\]|\{\{|\}\}/ },
  { name: 'raw server error', re: /traceback|internal server error|unprocessable (entity|content)|"detail"|\b(500|502|503|504) (internal|bad|service|gateway)|Cannot reach the ICS server/i },
]

export async function bodyText(page: Page) {
  return (await page.locator('body').innerText()).replace(/\s+/g, ' ')
}

export async function gotoRoute(page: Page, hash: string) {
  await page.goto(`/ui/#/${hash}`)  // direct: setting the hash after load races the app's own login/overview redirect
  await expect(page.locator('main h1, .center h1').first()).toBeVisible()
  await page.waitForLoadState('networkidle')
}

export async function setTheme(page: Page, theme: Theme) {
  await page.addInitScript((t) => { try { localStorage.setItem('ics-theme', t) } catch { /* */ } }, theme)
  await page.emulateMedia({ colorScheme: theme })
}

export function shotPath(project: string, theme: string, id: string) {
  const dir = process.env.SHOT_DIR ?? path.resolve('../../docs/screenshots/e2e')
  fs.mkdirSync(dir, { recursive: true })
  return path.join(dir, `${project}-${theme}-${id}.png`)
}

/** Runs in the page: horizontal overflow and overlapping controls. */
export async function layoutProblems(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const out: string[] = []
    const de = document.documentElement
    if (de.scrollWidth > de.clientWidth + 1) out.push(`page scrolls horizontally (scrollWidth ${de.scrollWidth} > ${de.clientWidth})`)
    const vis = (e: Element) => {
      const r = e.getBoundingClientRect(), s = getComputedStyle(e)
      return r.width > 1 && r.height > 1 && s.visibility !== 'hidden' && s.display !== 'none' && Number(s.opacity) > 0
    }
    const scrollParent = (e: Element) => {
      for (let p = e.parentElement; p && p !== document.body; p = p.parentElement) {
        const o = getComputedStyle(p).overflowX
        if ((o === 'auto' || o === 'scroll') && p.scrollWidth > p.clientWidth) return true
      }
      return false
    }
    const label = (e: Element) => `${e.tagName.toLowerCase()}${e.className && typeof e.className === 'string' ? '.' + e.className.split(' ')[0] : ''} "${(e.textContent || '').trim().slice(0, 30)}"`
    const els = [...document.querySelectorAll('button, a[href], input, select, textarea, h1, h2, h3, .chip, dt, dd')].filter(vis)
    for (const e of els) {
      const r = e.getBoundingClientRect()
      if (r.right > innerWidth + 1 && !scrollParent(e)) out.push(`outside viewport: ${label(e)} right=${Math.round(r.right)}`)
    }
    for (let i = 0; i < els.length; i++) {
      for (let j = i + 1; j < els.length; j++) {
        const a = els[i], b = els[j]
        if (a.contains(b) || b.contains(a)) continue
        const x = a.getBoundingClientRect(), y = b.getBoundingClientRect()
        const w = Math.min(x.right, y.right) - Math.max(x.left, y.left), h = Math.min(x.bottom, y.bottom) - Math.max(x.top, y.top)
        if (w > 3 && h > 3) out.push(`overlap: ${label(a)} x ${label(b)} (${Math.round(w)}x${Math.round(h)}px)`)
      }
    }
    for (const e of document.querySelectorAll('main *')) {
      const s = getComputedStyle(e)
      if ((s.overflowX === 'hidden' || s.overflowX === 'clip') && e.scrollWidth > e.clientWidth + 2 && vis(e) && s.textOverflow !== 'ellipsis' && (e.textContent || '').trim())
        out.push(`clipped text: ${label(e)} (${e.scrollWidth}px content in ${e.clientWidth}px box)`)
    }
    return out.slice(0, 15)
  })
}

export async function api<T = any>(page: Page, p: string): Promise<T> {
  const r = await page.request.get(`/api/v1/${p}`)
  expect(r.ok(), `GET ${p} -> ${r.status()}`).toBeTruthy()
  return r.json()
}
