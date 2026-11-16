import { test, expect, type Page } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'
import { api, bodyText, FORBIDDEN, gotoRoute, setTheme, watch, type Theme } from '../lib/helpers'
import { authFile, state } from '../lib/state'

// Console v3: Releases (channels, promote flow, approval diff), controller role banner + System card, guest bootstrap health.
// Runs in the `flows` project (it creates a release.promote plan). Data: the real GET /releases reads a fixture repo tree written by the
// launcher; bootstrap rows are in the test database. The standby/fenced banner cannot be produced by a primary-only test backend, so those two
// cases answer /readyz in the browser with the exact body shape a standby / fenced primary returns (api.Ready); the banner logic itself is unit-tested.
test.use({ storageState: authFile('admin') })
const dir = process.env.CONSOLE_SHOT_DIR ?? path.resolve('../../docs/screenshots/console-v3')

const STANDBY = { ready: true, version: '1', role: 'standby', epoch: 4, fenced: false, checks: { database: { ok: true }, audit_chain: { ok: true },
  replication: { ok: true, in_recovery: true, heartbeat_age_seconds: 6.2, replay_delay_seconds: 0.8, replay_backlog_bytes: 0, max_lag_seconds: 60 } } }
const LAGGING = { ...STANDBY, ready: false, checks: { ...STANDBY.checks, replication: { ...STANDBY.checks.replication, ok: false, heartbeat_age_seconds: 410, replay_backlog_bytes: 4096 } } }
const FENCED = { ready: false, version: '1', role: 'primary', epoch: 5, fenced: true, checks: { database: { ok: true }, worker: { ok: false }, audit_chain: { ok: true } } }

async function readyAs(page: Page, body: object, status: number) {
  await page.route('**/readyz', (r) => r.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) }))
}
async function clean(page: Page, label: string) {
  const t = await bodyText(page)
  for (const f of FORBIDDEN) expect(t, `${label}: ${f.name}`).not.toMatch(f.re)
}
const shot = async (page: Page, theme: Theme, name: string) => { fs.mkdirSync(dir, { recursive: true }); await page.screenshot({ path: path.join(dir, `${name}-${theme}.png`), fullPage: false }) }

test.describe('releases', () => {
  test('channels, evidence and promotable sets come from the real API and render', async ({ page }) => {
    const issues = watch(page)
    await gotoRoute(page, 'releases')
    const r = await api(page, 'releases')
    expect(r.configured).toBe(true)
    expect(r.channels.map((c: any) => c.name)).toEqual(['dev', 'staging', 'stable'])
    await expect(page.getByTestId('candidates')).toBeVisible()
    const stable = page.getByTestId('cand-ou-agent-stable')
    await expect(stable).toContainText('Promote ou-agent from Staging to Stable')
    await expect(stable).toContainText('Needs 2 different approvers')
    await expect(stable).toContainText('High risk')
    // an untested component is offered with the reason it cannot move, and its button is disabled
    const mail = page.getByTestId('cand-ou-mail-staging')
    await expect(mail).toContainText('no install-smoke test record')
    await expect(mail.getByRole('button', { name: 'Review and promote' })).toBeDisabled()
    await expect(page.locator('main')).toContainText('Install test passed')
    await expect(page.locator('main')).toContainText('No install test recorded')
    await clean(page, 'releases')
    expect(issues).toEqual([])
  })

  test('a viewer cannot propose a promotion', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: authFile('viewer'), baseURL: 'http://127.0.0.1:8108' })
    const page = await ctx.newPage()
    await gotoRoute(page, 'releases')
    await expect(page.getByTestId('cand-ou-agent-stable').getByRole('button', { name: 'Review and promote' })).toBeDisabled()
    await ctx.close()
  })

  test('promote flow: exact set shown -> plan created -> approval shows a diff and the approver count', async ({ page }) => {
    await gotoRoute(page, 'releases')
    await page.getByTestId('cand-ou-agent-stable').getByRole('button', { name: 'Review and promote' }).click()
    const set = page.getByTestId('promote-set')
    await expect(set).toContainText('ou-agent_1.1.0_amd64.deb')
    await expect(set).toContainText('b'.repeat(20))
    await page.getByLabel(/Reason/).fill('e2e promotion check')
    const [resp] = await Promise.all([page.waitForResponse((x) => /\/api\/v1\/plans$/.test(x.url()) && x.request().method() === 'POST'), page.getByRole('button', { name: 'Propose promotion' }).click()])
    expect(resp.status()).toBe(201)
    const created = await resp.json()
    expect(created.approvals_required).toBe(2)
    await expect(page.locator('.drawer, .modal').getByText(/2 different approvers must now review/)).toBeVisible()
    await page.getByRole('link', { name: 'Open the approval' }).click()
    const diff = page.getByTestId('release-diff')
    await expect(diff).toBeVisible()
    await expect(diff.locator('tr[data-kind="replaces"]')).toContainText('was 1.0.0')
    await expect(page.locator('main')).toContainText('needs 2 distinct approvers')
    await expect(page.locator('main')).toContainText('e2e promotion check')
    const plan = (await api(page, 'plans')).find((p: any) => p.id === created.plan_id)
    expect(plan.action).toBe('release.promote')
    expect(plan.risk).toBe('high')
    expect(plan.approvals_required).toBe(2)
  })

  for (const theme of ['light', 'dark'] as Theme[]) {
    test(`screenshots ${theme}`, async ({ page }, info) => {
      test.skip(info.project.name !== 'flows', 'desktop flows only')
      await setTheme(page, theme)
      await gotoRoute(page, 'releases'); await shot(page, theme, 'releases')
      await page.getByTestId('cand-ou-agent-stable').getByRole('button', { name: 'Review and promote' }).click()
      await expect(page.getByTestId('promote-set')).toBeVisible(); await shot(page, theme, 'releases-promote')
      const plans = (await api(page, 'plans')).filter((p: any) => p.action === 'release.promote')
      expect(plans.length).toBeGreaterThan(0)
      await gotoRoute(page, `plans/${plans[0].id}`); await expect(page.getByTestId('release-diff')).toBeVisible(); await shot(page, theme, 'approval-release-diff')
    })
  }
})

test.describe('controller role', () => {
  test('a normal primary shows no banner and the System page has the controller card', async ({ page }) => {
    await gotoRoute(page, 'system')
    await expect(page.getByTestId('controller-banner')).toHaveCount(0)
    const card = page.getByTestId('controller-card')
    await expect(card).toContainText('Primary')
    await expect(card).toContainText('Epoch')
    await expect(card).toContainText('never been promoted')
    const sys = await api(page, 'system')
    expect(sys.controller.role).toBe('primary')
    await expect(card).toContainText(String(sys.controller.epoch))
  })

  test('standby: banner explains read-only mode, shows lag and the runbook link on every page', async ({ page }) => {
    await readyAs(page, STANDBY, 200)
    for (const route of ['overview', 'plans']) {
      await gotoRoute(page, route)
      const b = page.getByTestId('controller-banner')
      await expect(b).toContainText('standby controller (read-only)')
      await expect(b).toContainText('Controller epoch 4')
      await expect(b).toContainText('6 seconds old (limit 60 seconds)')
      await expect(b.getByRole('link', { name: 'Open the recovery runbook' })).toHaveAttribute('href', /docs\/runbooks\/ics-recovery\.md$/)
    }
    await clean(page, 'standby banner')
  })

  test('a standby that fell behind is red and warns against taking over', async ({ page }) => {
    await readyAs(page, LAGGING, 503)
    await gotoRoute(page, 'overview')
    await expect(page.getByTestId('controller-banner')).toContainText('7 minutes old')
    await expect(page.getByTestId('controller-banner')).toContainText('do not take over')
    await expect(page.getByTestId('controller-banner')).toHaveClass(/bad/)
  })

  test('a fenced primary says it was replaced', async ({ page }) => {
    await readyAs(page, FENCED, 503)
    await gotoRoute(page, 'overview')
    await expect(page.getByTestId('controller-banner')).toContainText('has been replaced')
  })

  for (const theme of ['light', 'dark'] as Theme[]) {
    test(`screenshots ${theme}`, async ({ page }, info) => {
      test.skip(info.project.name !== 'flows', 'desktop flows only')
      await setTheme(page, theme)
      await readyAs(page, STANDBY, 200)
      await gotoRoute(page, 'system'); await shot(page, theme, 'controller-standby-banner')
      await page.unroute('**/readyz')
      await gotoRoute(page, 'system'); await shot(page, theme, 'system-controller')
    })
  }
})

test.describe('guest bootstrap health', () => {
  test('every state is explained in plain language with a next step', async ({ page }) => {
    const slug = state().boot_slug!
    const issues = watch(page)
    await gotoRoute(page, `deployments/${slug}`)
    const panel = page.getByTestId('bootstrap-panel')
    await expect(panel).toBeVisible()
    await expect(panel.locator('[data-state="enrolled"]').first()).toContainText('Enrolled')
    await expect(panel.locator('[data-state="pending"]')).toContainText('Waiting for the VM to call in')
    await expect(panel.locator('[data-state="pending"]')).toContainText('2 attempts were rejected')
    await expect(panel.locator('[data-state="expired"]')).toContainText('Start-up window expired')
    await expect(panel.locator('[data-state="expired"]')).toContainText('Next step')
    await expect(panel).toContainText('1 VM needs attention')
    const api_ = await api(page, `deployments/${slug}/bootstrap`)
    expect(api_.vms.map((v: any) => v.state).sort()).toEqual(['enrolled', 'enrolled', 'expired', 'pending'])
    await clean(page, 'bootstrap panel')
    expect(issues).toEqual([])
  })

  for (const theme of ['light', 'dark'] as Theme[]) {
    test(`screenshots ${theme}`, async ({ page }, info) => {
      test.skip(info.project.name !== 'flows', 'desktop flows only')
      await setTheme(page, theme)
      await gotoRoute(page, `deployments/${state().boot_slug}`); await shot(page, theme, 'deployment-bootstrap')
    })
  }
})

test('scope-change approver counts come from the backend policy endpoint', async ({ page }) => {
  await gotoRoute(page, 'overview')
  expect(await api(page, 'approvals/policy')).toMatchObject({ normal: 1, high: 2, mode: 'two_person', self_approval: false })
})
