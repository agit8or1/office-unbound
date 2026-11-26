import { test, expect, type Page } from '@playwright/test'
import { api, bodyText, FORBIDDEN, finding, gotoRoute, watch } from '../lib/helpers'
import { authFile } from '../lib/state'

// ADR-0021 step 1: Administration > Tenants and one tenant's page (Overview, Domains with the DNS checker, Users, Policy).
// Seed: the only tenant is the default "MSP (internal)" customer (migration 0007m) with no deployments, and the tenancy mode is not set,
// so /tenants lists it instead of redirecting. The DNS checker needs a deployment with an applied plan and a public domain, which the
// seed does not have and which must never query real DNS from a test: the Domains test answers the tenant and its /dns call in the
// browser (page.route) with rows shaped like tenants_api.dns_rows (tests/test_tenants_api.py), so no request reaches the server.
// Runs once (desktop project); widths are set per step.
test.use({ storageState: authFile('admin') })
test.beforeEach(({}, info) => { test.skip(info.project.name !== 'desktop', 'runs once; widths are set per step') })

const WIDTHS = [320, 768, 1366, 2560]
const TABS = ['overview', 'domains', 'users', 'policy'] as const
const LABEL: Record<(typeof TABS)[number], string> = { overview: 'Overview', domains: 'Domains', users: 'Users', policy: 'Policy' }

async function onlyTenant(page: Page) {
  const r = await api(page, 'tenants')
  expect(r.tenants.length, 'seed provides at least one tenant').toBeGreaterThan(0)
  return r as { mode: string | null; tenants: { id: string; name: string }[] }
}
async function clean(page: Page, label: string, info: Parameters<typeof finding>[3]) {
  const t = await bodyText(page)
  for (const f of FORBIDDEN) {
    const m = t.match(f.re)
    if (m) finding('user-facing copy', label, `${f.name}: "${m[0]}"`, info)
    expect.soft(m, `${f.name} on ${label}`).toBeNull()
  }
}

test('navigation: Tenants and Platform admins, no Users & roles', async ({ page }) => {
  await gotoRoute(page, 'overview')
  const nav = page.locator('nav[aria-label="Main"]')
  await expect(nav.getByRole('link', { name: 'Tenants', exact: true })).toHaveAttribute('href', '#/tenants')
  await expect(nav.getByRole('link', { name: 'Platform admins', exact: true })).toBeVisible()
  await expect(nav).not.toContainText('Users & roles')
  await nav.getByRole('link', { name: 'Tenants', exact: true }).click()
  await expect(page.locator('main h1').first()).toBeVisible()
})

test('/tenants lists the tenants, or opens the only one in single-tenant mode', async ({ page }, info) => {
  const issues = watch(page)
  const r = await onlyTenant(page)
  await gotoRoute(page, 'tenants')
  if (r.mode === 'single' && r.tenants.length === 1) {
    await expect(page).toHaveURL(new RegExp(`#/tenants/${r.tenants[0].id}`))
    await expect(page.locator('main h1')).toHaveText(r.tenants[0].name)
  } else {
    await expect(page.locator('main h1')).toHaveText('Tenants')
    const table = page.getByRole('region', { name: 'Tenants' })
    for (const t of r.tenants) await expect(table.getByRole('link', { name: t.name })).toHaveAttribute('href', `#/tenants/${t.id}`)
    await table.getByRole('link', { name: r.tenants[0].name }).click()
    await expect(page).toHaveURL(new RegExp(`#/tenants/${r.tenants[0].id}`))
    await expect(page.locator('main h1')).toHaveText(r.tenants[0].name)
  }
  await clean(page, 'tenants', info)
  expect(issues).toEqual([])
})

test('tenant page: every tab renders cleanly with no horizontal page scroll at 320-2560 px', async ({ page }, info) => {
  const issues = watch(page)
  const { tenants } = await onlyTenant(page)
  const id = tenants[0].id
  for (const tab of TABS) {
    await page.setViewportSize({ width: 1366, height: 900 })
    await gotoRoute(page, `tenants/${id}/${tab}`)
    await expect(page.getByRole('tab', { name: LABEL[tab] })).toHaveAttribute('aria-selected', 'true')
    await expect(page.locator('main .alert.bad')).toHaveCount(0)
    await clean(page, `tenants/<id>/${tab}`, info)
    for (const w of WIDTHS) {
      await page.setViewportSize({ width: w, height: w < 600 ? 844 : 900 })
      await page.waitForTimeout(150)
      const sw = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, iw: innerWidth }))
      if (sw.sw > sw.iw) finding('layout', `tenants/<id>/${tab}@${w}`, `page scrolls horizontally (${sw.sw} > ${sw.iw})`, info)
      expect.soft(sw.sw, `${tab} at ${w}px`).toBeLessThanOrEqual(sw.iw)
    }
  }
  // switching tabs by click keeps the URL in step
  await page.setViewportSize({ width: 1366, height: 900 })
  await gotoRoute(page, `tenants/${id}`)
  await page.getByRole('tab', { name: 'Policy' }).click()
  await expect(page).toHaveURL(new RegExp(`#/tenants/${id}/policy$`))
  await expect(page.locator('main')).toContainText('How changes are approved')
  for (const i of issues) finding('console/network', 'tenants/<id>', i, info)
  expect(issues).toEqual([])
})

// ---- Domains: DNS checker against a browser-side answer (never real DNS)
const DOM = 'e2e-tenant.com', IP = '203.0.113.10', MAILHOST = `mail.${DOM}`
const row = (group: string, name: string, type: string, expected: string, status: string, found: string[], why: string, required = true, how = '') =>
  ({ group, name, type, expected, status, found, why, how, required })
const ROWS = [
  row('Web names', DOM, 'A', IP, 'ok', [IP], 'the portal at the domain itself'),
  row('Web names', `cloud.${DOM}`, 'CNAME', DOM, 'missing', [], 'Files', true),
  row('Mail', MAILHOST, 'A', IP, 'ok', [IP], 'the mail server'),
  row('Mail', DOM, 'MX', `10 ${MAILHOST}`, 'differs', ['10 mx.other.example'], 'delivers mail for the domain to this deployment'),
  row('Mail', DOM, 'TXT', 'v=spf1 mx -all', 'ok', ['v=spf1 mx -all'], 'SPF: says which servers may send mail for the domain'),
  row('Mail', `_dmarc.${DOM}`, 'TXT', `v=DMARC1; p=quarantine; rua=mailto:postmaster@${DOM}`, 'missing', [], 'DMARC: tells receivers what to do with mail that fails SPF (start with p=none to observe)', false),
  row('Mail', `<selector>._domainkey.${DOM}`, 'TXT', '-', 'not_available', [], 'DKIM: this deployment does not sign outgoing mail yet, so there is no key to publish (planned with internet mail)', false),
  row('Mail', IP, 'PTR', MAILHOST, 'missing', [], 'reverse DNS of the public address: receivers trust mail more when it names the mail server', false),
  row('Client setup', `autodiscover.${DOM}`, 'CNAME', DOM, 'missing', [], 'Outlook setup'),
  row('Client setup', `_imaps._tcp.${DOM}`, 'SRV', `0 1 993 ${MAILHOST}`, 'missing', [], 'mail apps find incoming mail (IMAP) (optional)', false),
  row('Certificates', DOM, 'CAA', 'none, or one that allows letsencrypt.org', 'ok', [], "Let's Encrypt may issue the public certificate only if CAA allows it"),
]

test('domains: Check DNS groups the records, marks optional ones and copies a value (browser-side answer, no DNS query)', async ({ page, context }, info) => {
  const issues = watch(page)
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  const { tenants } = await onlyTenant(page)
  const real = await api(page, `tenants/${tenants[0].id}`)
  const id = real.id as string
  const dnsCalls: string[] = []
  await page.route((u) => u.pathname === `/api/v1/tenants/${id}`, (r) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
    ...real, domains: [DOM], deployments: [{ slug: 'e2e-dns', status: 'active', domain: DOM, components: ['groupware', 'files'] }] }) }))
  await page.route((u) => u.pathname === `/api/v1/tenants/${id}/dns`, (r) => {
    dnsCalls.push(r.request().url())
    return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
      deployment: 'e2e-dns', domain: DOM, public_ipv4: IP, available: true, rows: ROWS, checked_at: '2026-11-25T09:00:00Z', cached: false,
      summary: { ok: 4, missing: 5, differs: 1, unknown: 0, not_available: 1 },
      note: 'Checked from this server with its own resolver. A record you just changed can take up to its TTL to show.' }) })
  })
  await gotoRoute(page, `tenants/${id}/domains`)
  const card = page.locator('main').filter({ hasText: `Deployment e2e-dns` })
  await expect(card).toContainText(DOM)
  expect(dnsCalls, 'the page does not check DNS before the button is pressed').toEqual([])
  await page.getByTestId('dns-check').click()
  await expect(page.getByTestId('dns-check')).toHaveText('Check again')
  expect(dnsCalls.length).toBe(1)
  expect(new URL(dnsCalls[0]).searchParams.get('deployment')).toBe('e2e-dns')
  await expect(page.locator('main')).toContainText('3 required records need attention.')

  // one table per group, in the fixed order, each with its own rows
  await expect(page.locator('.dnsgroup h3')).toHaveText(['Web names', 'Mail', 'Client setup', 'Certificates'])
  const group = (g: string) => page.getByRole('region', { name: `${g} records` })
  await expect(group('Web names').locator('tbody tr')).toHaveCount(2)
  await expect(group('Mail').locator('tbody tr')).toHaveCount(6)
  await expect(group('Client setup').locator('tbody tr')).toHaveCount(2)
  await expect(group('Certificates').locator('tbody tr')).toHaveCount(1)
  const rowOf = (g: string, name: string, type: string) => group(g).locator('tbody tr').filter({ has: page.getByRole('rowheader', { name: new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`) }) }).filter({ has: page.getByRole('cell', { name: type, exact: true }) })

  // badges: required missing/different are failures, optional ones say so, DKIM is not available, ok is OK
  await expect(rowOf('Web names', `cloud.${DOM}`, 'CNAME').locator('.badge')).toHaveText('Missing')
  await expect(rowOf('Mail', DOM, 'MX').locator('.badge')).toHaveText('Different')
  await expect(rowOf('Mail', `_dmarc.${DOM}`, 'TXT').locator('.badge')).toHaveText('Missing (optional)')
  await expect(rowOf('Client setup', `_imaps._tcp.${DOM}`, 'SRV').locator('.badge')).toHaveText('Missing (optional)')
  await expect(rowOf('Mail', `<selector>._domainkey.${DOM}`, 'TXT').locator('.badge')).toHaveText('Not available')
  await expect(rowOf('Web names', DOM, 'A').locator('.badge')).toHaveText('OK')
  await expect(rowOf('Mail', DOM, 'MX')).toContainText('10 mx.other.example')

  // copy: offered only where something has to be published
  await expect(rowOf('Web names', DOM, 'A').getByRole('button', { name: /^Copy/ })).toHaveCount(0)
  await expect(rowOf('Mail', `<selector>._domainkey.${DOM}`, 'TXT').getByRole('button', { name: /^Copy/ })).toHaveCount(0)
  const copy = page.getByRole('button', { name: `Copy the value for _dmarc.${DOM}` })
  await expect(copy).toHaveText('Copy')
  await copy.click()
  await expect(copy).toHaveText('Copied')
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(`v=DMARC1; p=quarantine; rua=mailto:postmaster@${DOM}`)

  // "Check again" asks for a fresh check
  await page.getByTestId('dns-check').click()
  await expect.poll(() => dnsCalls.length).toBe(2)
  expect(new URL(dnsCalls[1]).searchParams.get('refresh')).toBe('true')

  for (const w of WIDTHS) {
    await page.setViewportSize({ width: w, height: w < 600 ? 844 : 900 })
    await page.waitForTimeout(150)
    const sw = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, iw: innerWidth }))
    if (sw.sw > sw.iw) finding('layout', `tenants/<id>/domains (DNS results)@${w}`, `page scrolls horizontally (${sw.sw} > ${sw.iw})`, info)
    expect.soft(sw.sw, `DNS results at ${w}px`).toBeLessThanOrEqual(sw.iw)
  }
  await clean(page, 'tenants/<id>/domains (DNS results)', info)
  expect(issues).toEqual([])
})

test('a viewer opens the tenant page; Users says Admins only', async ({ browser }, info) => {
  const ctx = await browser.newContext({ storageState: authFile('viewer'), baseURL: 'http://127.0.0.1:8108', viewport: { width: 1366, height: 900 } })
  const page = await ctx.newPage()
  const issues = watch(page)
  const r = await api(page, 'tenants')
  expect(r.tenants.length, 'the e2e viewer has every tenant in scope').toBeGreaterThan(0)
  const id = r.tenants[0].id
  await gotoRoute(page, `tenants/${id}`)
  await expect(page.locator('main h1')).toHaveText(r.tenants[0].name)
  await page.getByRole('tab', { name: 'Users' }).click()
  await expect(page.locator('main')).toContainText('Admins only')
  await expect(page.locator('main')).toContainText('Reading a tenant\'s people needs the admin role.')
  await page.getByRole('tab', { name: 'Policy' }).click()
  await expect(page.locator('main')).not.toContainText('Edit approval policy and contact')
  await clean(page, 'tenants/<id> (viewer)', info)
  expect(issues).toEqual([])
  await ctx.close()
})

test('overview: each deployment lists its VMs (location, size, agent, health) and its DNS records, without sideways scrolling', async ({ page }, info) => {
  const issues = watch(page)
  const { tenants } = await onlyTenant(page)
  const real = await api(page, `tenants/${tenants[0].id}`)
  const id = real.id as string
  const vm = (name: string, comps: string[], vmid: number, health: string, failing: string[] = []) => ({
    name, role: null, components: comps, cores: 4, memory_mb: 8192, disk_gb: 81, storage: ['local-lvm'], endpoint: 'lab', node: 'pve1', vmid,
    state: 'present', agent: { status: 'online', version: '0.10.2', address: '10.0.0.' + vmid % 100, last_seen_at: new Date().toISOString() },
    health: { status: health, checks: 3, failing } })
  await page.route((u) => u.pathname === `/api/v1/tenants/${id}`, (r) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
    ...real, domains: ['acme.example.com'], deployments: [{ slug: 'e2e-vms', status: 'active', domain: 'acme.example.com', components: ['groupware', 'files'],
      vms: [vm('e2e-vms-gateway', ['identity', 'edge', 'portal'], 137, 'ok'), vm('e2e-vms-files-with-a-rather-long-name', ['files', 'office', 'chat'], 136, 'ok'),
            vm('e2e-vms-mail', ['groupware'], 138, 'critical', ['e2e-vms-mail-groupware-imaps-tls'])] }] }) }))
  const dns: string[] = []
  await page.route((u) => u.pathname === `/api/v1/tenants/${id}/dns`, (r) => { dns.push(r.request().url()); return r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ deployment: 'e2e-vms', domain: 'acme.example.com', available: true, checked_at: new Date().toISOString(), cached: false, summary: {}, note: 'n',
      rows: [{ group: 'Mail', name: 'acme.example.com', type: 'MX', expected: '10 mail.acme.example.com', status: 'missing', found: [], why: 'w', how: '', required: true }] }) }) })
  await gotoRoute(page, `tenants/${id}/overview`)
  const card = page.locator('section.card', { hasText: 'Deployment e2e-vms' })
  await expect(card.getByRole('region', { name: 'Virtual machines of e2e-vms' })).toBeVisible()
  const rows = card.locator('tbody tr')
  await expect(rows).toHaveCount(3)
  await expect(rows.nth(0)).toContainText('pve1')
  await expect(rows.nth(0)).toContainText('VM 137')
  await expect(rows.nth(0)).toContainText('4 vCPU · 8 GB')
  await expect(rows.nth(2)).toContainText('1 failing')
  expect(dns, 'no DNS check before it is asked for').toEqual([])
  await card.getByRole('button', { name: 'Show the DNS records this deployment needs' }).click()
  await card.getByTestId('dns-check').click()
  await expect(card.getByText('1 required record needs attention.')).toBeVisible()
  expect(dns.length).toBe(1)
  for (const w of WIDTHS) {
    await page.setViewportSize({ width: w, height: 900 })
    await page.waitForTimeout(150)
    const sw = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
    expect.soft(sw, `no page-level horizontal scroll at ${w}px`).toBeLessThanOrEqual(0)
  }
  for (const i of issues) finding('console/network', 'tenants/<id>/overview', i, info)
  expect(issues).toEqual([])
})

test('deployment page: the DNS records card shows the DKIM record to publish, copyable, without sideways scrolling', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  const KEY = 'v=DKIM1; k=rsa; p=' + 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA'.repeat(9) + 'IDAQAB'
  const rows = [ROWS[0], row('Mail', `ou1._domainkey.${DOM}`, 'TXT', KEY, 'differs', ['v=DKIM1; p='], 'DKIM: receivers check the signature', false)]
  const calls: string[] = []
  await page.route((u) => u.pathname === '/api/v1/deployments/e2e-dns', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ slug: 'e2e-dns', status: 'active', profile: 'small', desired_spec: {}, revisions: [], resource_summary: [] }) }))
  await page.route((u) => u.pathname === '/api/v1/deployments/e2e-dns/dns', (r) => {
    calls.push(r.request().url())
    return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ deployment: 'e2e-dns', domain: DOM, public_ipv4: IP,
      available: true, rows, checked_at: '2026-11-26T09:00:00Z', cached: false, summary: { ok: 1, missing: 0, differs: 1, unknown: 0, not_available: 0 }, note: '' }) })
  })
  await gotoRoute(page, 'deployments/e2e-dns')
  const card = page.getByTestId('deployment-dns')
  await expect(card).toContainText('DNS records')
  await card.getByTestId('dns-check').click()
  await expect(card.getByTestId('dns-check')).toHaveText('Check again')
  await expect(card).toContainText(DOM)
  const copy = card.getByRole('button', { name: `Copy the value for ou1._domainkey.${DOM}` })
  await copy.click()
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(KEY)
  expect(calls.length).toBe(1)
  for (const w of [320, 1366]) {
    await page.setViewportSize({ width: w, height: 900 })
    await page.waitForTimeout(150)
    const sw = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, iw: innerWidth }))
    expect.soft(sw.sw, `deployment DNS card at ${w}px`).toBeLessThanOrEqual(sw.iw)
  }
})
