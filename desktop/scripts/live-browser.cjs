// Test "system browser" for live_check: drives the real Keycloak sign-in page with Playwright (from the ICS e2e toolchain),
// reading the password from a 0600 file. Never prints the password or the redirect URL.
const NM = process.env.OU_PLAYWRIGHT_NODE_MODULES || '/home/administrator/office-unbound/ics/e2e/node_modules'
const { chromium } = require(NM + '/playwright')
;(async () => {
  const b = await chromium.launch()
  const p = await b.newPage()
  await p.goto(process.env.U)
  if (await p.locator('#password').count()) {
    if (!(await p.inputValue('#username'))) await p.fill('#username', process.env.OU_LIVE_USER || 'doctest')
    await p.fill('#password', require('fs').readFileSync(process.env.F, 'utf8').trim())
    await Promise.all([p.waitForURL(/^http:\/\/127\.0\.0\.1/, { timeout: 60000 }), p.click('#kc-login')])
  } else if (!p.url().startsWith('http://127.0.0.1')) {
    // Not a sign-in form and not redirected: report the IdP's visible message (no secrets on that page).
    const msg = (await p.locator('#kc-error-message, .kc-feedback-text, .alert-error, h1').allInnerTexts()).join(' | ')
    console.error('IdP page without sign-in form:', (await p.title()), '-', msg.slice(0, 200))
    process.exit(2)
  }
  await b.close()
})().catch((e) => { console.error('browser step failed:', String(e.message || e).split('\n')[0].replace(/code=[^&\s]+/g, 'code=[REDACTED]')); process.exit(1) })
