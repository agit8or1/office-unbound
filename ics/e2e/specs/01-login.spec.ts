import { test, expect } from '@playwright/test'
import { finding, watch } from '../lib/helpers'
import { nextTotp, state, totp } from '../lib/state'

test.describe.configure({ mode: 'serial' })

test('invite enrollment (password + TOTP) then login through the UI', async ({ page }, info) => {
  const issues = watch(page, [/http 401 /, /Failed to load resource.*(401|429)/])
  const u = state().users['e2e-invitee']
  await page.goto('/ui/')
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible()
  await page.getByRole('link', { name: 'Set up your account' }).click()
  await expect(page.getByRole('heading', { name: 'Enroll account' })).toBeVisible()

  // step 1: wrong token is refused with a human message (no raw JSON / status text only)
  await page.getByLabel('Username').fill('e2e-invitee')
  await page.getByLabel('Enrollment token').fill('wrong-token')
  await page.getByLabel('New password').fill(u.password)
  await page.getByLabel('Repeat password').fill(u.password)
  await page.getByRole('button', { name: 'Set password' }).click()
  await expect(page.locator('.alert.bad')).toBeVisible()
  const bad = (await page.locator('.alert.bad').innerText()).replace(/\s+/g, ' ')
  if (/[{}"]/.test(bad)) finding('raw error shown', 'enroll', bad, info)
  expect.soft(bad).not.toMatch(/[{}"]/)

  await page.getByLabel('Enrollment token').fill(u.enrollment_token!)
  await page.getByRole('button', { name: 'Set password' }).click()
  await expect(page.getByRole('heading', { name: 'Enroll account' })).toBeVisible()
  await expect(page.getByAltText('QR code for the authenticator app')).toBeVisible()
  const secret = await page.getByLabel('Secret (manual entry)').inputValue()
  expect(secret).toMatch(/^[A-Z2-7]{16,}$/)
  const step = Math.floor(Date.now() / 30000)
  await page.getByLabel('Code from the app').fill(totp(secret, step))
  await page.getByRole('button', { name: 'Verify and finish' }).click()
  await expect(page.getByText('Account enrolled')).toBeVisible()
  await page.getByRole('button', { name: 'Go to sign in' }).click()

  // login with a fresh TOTP step; a wrong code first
  await page.getByLabel('Username').fill('e2e-invitee')
  await page.getByLabel('Password').fill(u.password)
  await page.getByLabel('Authenticator code').fill('000000')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.locator('.alert.bad')).toBeVisible()
  const next = await nextTotp(secret, step)
  await page.getByLabel('Password').fill(u.password)
  await page.getByLabel('Authenticator code').fill(next.code)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible()
  await expect(page.locator('.userchip')).toContainText('e2e-invitee')
  await expect(page.locator('.userchip')).toContainText('viewer')

  // a viewer must not see admin/approver pages in the navigation
  const nav = (await page.locator('nav[aria-label="Main"]').innerText()).toLowerCase()
  expect(nav).not.toContain('users')
  expect(nav).not.toContain('audit')

  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible()
  for (const i of issues) finding('console/network', 'login/enroll', i, info)
  expect.soft(issues).toEqual([])
})
