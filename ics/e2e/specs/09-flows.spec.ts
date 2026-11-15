import { test, expect } from '@playwright/test'
import { api, finding, gotoRoute } from '../lib/helpers'
import { authFile, state } from '../lib/state'

// Mutating flows: run in the `flows` project AFTER all read-only projects (they change plans/users/incidents), desktop viewport.
// ---- 2. Real flows: the UI action must end in the corresponding server state.
test.describe('approval flow', () => {
  test('two approvers approve a high-risk plan in the UI -> approved + job in API', async ({ browser }, info) => {
    const id = state().pending_plan_ids[0]
    const doApprove = async (role: 'approver' | 'approver2') => {
      const ctx = await browser.newContext({ storageState: authFile(role), baseURL: 'http://127.0.0.1:8108' })
      const page = await ctx.newPage()
      await gotoRoute(page, `plans/${id}`)
      const [resp] = await Promise.all([page.waitForResponse(/\/approve$/), page.getByRole('button', { name: 'Approve' }).click()])
      expect(resp.status()).toBe(200)
      // the operator must see the outcome of the click (the server state is verified below)
      await page.waitForTimeout(1500)
      const shown = await page.locator('main .alert.ok, main .alert.bad').first().isVisible()
      if (!shown) finding('feedback lost', 'plans/<id>', `after the ${role} approval no confirmation is shown (result block is rendered only while the plan is pending)`, info)
      await ctx.close()
    }
    await doApprove('approver')
    await doApprove('approver2')
    const ctx = await browser.newContext({ storageState: authFile('admin'), baseURL: 'http://127.0.0.1:8108' })
    const page = await ctx.newPage()
    const plan = (await api(page, 'plans')).find((p: any) => p.id === id)
    expect(plan.status).toBe('approved')
    expect(plan.approval_count).toBe(2)
    const jobs = await api(page, 'jobs')
    const hit = jobs.some((j: any) => j.plan_id === id)
    if (!hit) finding('action without effect', 'plans', 'approved plan has no job', info)
    expect(hit, 'approved plan has a job').toBe(true)
    await ctx.close()
  })

  test('reject in the UI -> rejected in API', async ({ browser }, info) => {
    const id = state().pending_plan_ids[1]
    const ctx = await browser.newContext({ storageState: authFile('approver'), baseURL: 'http://127.0.0.1:8108' })
    const page = await ctx.newPage()
    await gotoRoute(page, `plans/${id}`)
    const [resp] = await Promise.all([page.waitForResponse(/\/reject$/), page.getByRole('button', { name: 'Reject' }).click()])
    expect(resp.status()).toBe(200)
    await page.waitForTimeout(1500)
    const shown = await page.getByText('Plan rejected.').isVisible()
    if (!shown) finding('feedback lost', 'plans/<id>', 'after Reject no confirmation is shown (result block is rendered only while the plan is pending)', info)
    expect((await api(page, 'plans')).find((p: any) => p.id === id).status).toBe('rejected')
    await ctx.close()
  })

  test('requester cannot approve own plan: friendly message, not raw error', async ({ browser }, info) => {
    const id = state().pending_plan_ids[2]
    const ctx = await browser.newContext({ storageState: authFile('admin'), baseURL: 'http://127.0.0.1:8108' })
    const page = await ctx.newPage()
    await gotoRoute(page, `plans/${id}`)
    const approve = page.getByRole('button', { name: 'Approve' })
    if (await approve.count()) {
      await approve.click()
      const err = (await page.locator('main .alert.bad').first().innerText()).replace(/\s+/g, ' ')
      if (/^\d{3}\b|detail|\{/.test(err)) finding('raw error shown', 'plans', err, info)
    } // admins lack the approver role in this model -> button absent is acceptable
    await ctx.close()
  })
})

test.describe('forms', () => {
  test.use({ storageState: authFile('admin') })
  test('Users: invitation creates the account', async ({ page }) => {
    await gotoRoute(page, 'users/invitations')
    await page.locator('.ux-inline-form input').fill('e2e-ui-invite')
    await page.getByRole('button', { name: 'Create invitation' }).click()
    const note = page.locator('main .alert.ok')
    await expect(note).toBeVisible()
    const t = await note.innerText()
    if (/Applied/.test(t)) {
      await expect.poll(async () => (await api(page, 'users')).some((u: any) => u.username === 'e2e-ui-invite'), { timeout: 30000 }).toBe(true)
    } else {  // approval needed: the plan must exist and name the user
      expect((await api(page, 'plans')).some((p: any) => JSON.stringify(p.params).includes('e2e-ui-invite'))).toBe(true)
    }
  })
  test('Users: disable (directory action) creates an approval plan', async ({ page }, info) => {
    await gotoRoute(page, 'users')
    const row = page.locator('main table tbody tr').filter({ hasText: 'e2e-viewer' })
    await row.getByRole('button', { name: 'Disable' }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'Request disable' }).click()
    await expect(page.getByRole('dialog').locator('.alert')).toBeVisible()
    const plans = await api(page, 'plans')
    const hit = plans.some((p: any) => p.action === 'user.disable' && p.params.username === 'e2e-viewer')
    if (!hit) finding('action without effect', 'users', 'Disable did not create a user.disable plan', info)
    expect(hit).toBe(true)
  })
  test('Users: privileged-account workflow submits a high-risk plan', async ({ page }, info) => {
    await gotoRoute(page, 'users/privileged/create')
    await page.getByLabel(/Username for the new account/).fill('e2e-ui-plan')
    await page.getByRole('button', { name: 'Continue' }).click()
    await page.locator('input[type=radio][value=approver]').check()
    await page.getByLabel(/Justification/).fill('e2e verification of the privileged workflow')
    await page.getByRole('button', { name: 'Review' }).click()
    await page.getByLabel(/I understand/).check()
    await page.getByRole('button', { name: 'Submit for approval' }).click()
    await expect(page.getByText('Submitted.')).toBeVisible()
    const plans = await api(page, 'plans')
    const plan = plans.find((p: any) => JSON.stringify(p.params).includes('e2e-ui-plan'))
    expect(plan, 'a plan names the new privileged account').toBeTruthy()
    expect(plan.risk).toBe('high')
  })
  test('Audit: verify chain performs a request', async ({ page }) => {
    await gotoRoute(page, 'audit')
    const [resp] = await Promise.all([page.waitForResponse(/audit\/verify/), page.getByRole('button', { name: 'Verify chain' }).click()])
    expect(resp.status()).toBe(200)
  })
  test('Preview: invalid blueprint yields a readable validation result', async ({ page }, info) => {
    await gotoRoute(page, 'preview')
    await page.getByLabel('Blueprint YAML').fill('not: a blueprint')
    const [resp] = await Promise.all([page.waitForResponse(/plans\/preview/), page.getByRole('button', { name: 'Preview' }).click()])
    expect(resp.status()).toBe(200)
    await expect(page.getByText(/not valid/)).toBeVisible()
  })
  test('Endpoints: Register endpoint opens the form', async ({ page }) => {
    await gotoRoute(page, 'endpoints')
    await page.locator('button, a.btn').filter({ hasText: /Add endpoint|Start setup wizard/ }).first().click()
    await expect(page.locator('[role=dialog], h1').filter({ hasText: /endpoint|setup|connect/i }).first()).toBeVisible()
  })
})

test.describe('operator flows', () => {
  test.use({ storageState: authFile('operator') })
  test('Incident acknowledge -> incident acked in API', async ({ page }, info) => {
    const inc = (await api(page, 'incidents?status=active'))[0]
    expect(inc, 'seed has an active incident').toBeTruthy()
    await gotoRoute(page, `incidents/${inc.id}`)
    await page.getByRole('button', { name: 'Acknowledge' }).click()
    await expect.poll(async () => (await api<any>(page, `incidents/${inc.id}`)).status, { timeout: 30000 }).toBe('acked')
  })
  test('Inventory refresh without an endpoint is explained, not a raw error', async ({ page }, info) => {
    await gotoRoute(page, 'inventory')
    const t = (await page.locator('main').innerText()).replace(/\s+/g, ' ')
    expect(t).toMatch(/endpoint|connect|setup/i)
    expect(t).not.toMatch(/\b(4|5)\d\d\b/)
  })
})
