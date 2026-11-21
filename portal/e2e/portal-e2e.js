// End-to-end test of the user portal against the REAL lab services (Keycloak, OpenCloud, grommunio-web, Collabora).
// Headless Chromium (Playwright). Test user + password come from the lab secret store on ou-id1 and are never printed.
//
//   NODE_EXTRA_CA_CERTS=<lab ca.crt> HOME=<dir with NSS db trusting the lab CAs> node portal-e2e.js
// env: PORTAL=https://portal.ou-lab.internal  OU_E2E_USER=bob  SHOTS=<dir for screenshots>  OU_E2E_PASSWORD_CMD (default: read from ou-id1)
const { chromium } = require('playwright');
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const PORTAL = process.env.PORTAL || 'https://portal.ou-lab.internal';
const USER = process.env.OU_E2E_USER || 'bob';
const SHOTS = process.env.SHOTS || path.join(__dirname, 'shots');
const FILES = 'https://cloud.ou-lab.internal';
const MAIL_HOST = 'gw1.ou-lab.internal';
fs.mkdirSync(SHOTS, { recursive: true });

function password() {
  const out = execFileSync('sudo', ['systemd-run', '-M', 'ou-id1', '-P', '--wait', '-q', '/bin/cat', '/root/ou-lab-secrets/test-users.env']).toString();
  const line = out.split('\n').find(l => l.startsWith('OU_PASSWORD_' + USER.toUpperCase() + '='));
  if (!line) throw new Error('no password for ' + USER);
  return line.split('=')[1].trim();
}
const PW = password();

let pass = 0, fail = 0;
function check(name, ok, detail) {
  if (ok) { pass++; console.log('PASS ' + name + (detail ? ' - ' + detail : '')); }
  else { fail++; console.log('FAIL ' + name + (detail ? ' - ' + detail : '')); }
}

async function lab_token() {            // lab-only direct grant client, used ONLY to cross-check what OpenCloud really holds
  const r = await fetch('https://auth.ou-lab.internal/realms/ou-lab/protocol/openid-connect/token', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'password', client_id: 'ou-lab-test', username: USER, password: PW, scope: 'openid' }) });
  return (await r.json()).access_token;
}

(async () => {
  const browser = await chromium.launch({ env: { ...process.env, HOME: process.env.E2E_HOME || process.env.HOME } });
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 }, colorScheme: 'light', acceptDownloads: true });
  const page = await ctx.newPage();
  const consoleErrors = [];
  page.on('console', m => { if (m.type() === 'error' && /Content Security Policy|CSP/i.test(m.text())) consoleErrors.push(m.text()); });

  // 1. signed out, the portal address goes straight to the sign-in service (no landing page) -----------------------
  await page.goto(PORTAL + '/');
  await page.waitForURL(/auth\.ou-lab\.internal/);
  check('redirected to Keycloak with code+PKCE', /code_challenge_method=S256/.test(page.url()) && /response_type=code/.test(page.url()) && /client_id=ou-portal/.test(page.url()));
  await page.fill('#username', USER);
  await page.fill('#password', PW);
  await page.click('#kc-login');
  await page.waitForURL(PORTAL + '/', { timeout: 30000 });
  check('signed in, back on the portal', (await page.locator('h1.greet').innerText()).startsWith('Hello,'), await page.locator('h1.greet').innerText());

  // 2. session is a BFF cookie, tokens never reach the browser -------------------------------------------------------
  const cookies = (await ctx.cookies(PORTAL)).filter(c => c.name.startsWith('__Host-'));
  const sc = cookies.find(c => c.name === '__Host-ou_portal');
  check('session cookie __Host- httpOnly+Secure+Lax, path=/', !!sc && sc.httpOnly && sc.secure && sc.sameSite === 'Lax' && sc.path === '/' && !sc.domain.startsWith('.'));
  check('session cookie is opaque (no JWT)', !!sc && !sc.value.includes('.') && !sc.value.startsWith('eyJ'));
  check('flow cookie removed after login', !cookies.some(c => c.name === '__Host-ou_portal_flow'));
  const html = await page.content();
  check('no token / secret in page HTML', !/eyJ[A-Za-z0-9_-]{20,}/.test(html) && !html.includes(PW));
  check('document.cookie cannot see the session', !(await page.evaluate(() => document.cookie)).includes('ou_portal'));
  check('no inline script/style (CSP strict)', (await page.locator('script').count()) === 0 && (await page.locator('[style]').count()) === 0);

  // 3. launcher -----------------------------------------------------------------------------------------------------
  const hrefs = {};
  for (const a of ['mail', 'calendar', 'contacts', 'files']) hrefs[a] = await page.locator(`a.tile[data-app=${a}]`).getAttribute('href');
  check('launcher has Mail/Calendar/Contacts/Files', Object.values(hrefs).every(Boolean), JSON.stringify(hrefs));
  check('three create buttons', (await page.locator('button[data-new]').count()) === 3);

  // 4. recent files == what OpenCloud really holds ------------------------------------------------------------------
  const tok = await lab_token();
  const gr = await (await fetch(FILES + '/graph/v1.0/me/drive/root/children?$top=500', { headers: { authorization: 'Bearer ' + tok } })).json();
  const real = gr.value.filter(x => x.file).sort((a, b) => b.lastModifiedDateTime.localeCompare(a.lastModifiedDateTime));
  const shown = await page.locator('a.row').evaluateAll(es => es.map(e => e.dataset.file));
  check('recent files listed', shown.length >= 3, shown.length + ' shown');
  check('every listed file really exists in OpenCloud (Graph, bob token)', shown.every(n => real.some(r => r.name === n)), shown.join(', '));
  check('newest file in OpenCloud is first in the list', shown[0] === real[0].name, `${shown[0]} == ${real[0].name}`);
  await page.screenshot({ path: path.join(SHOTS, '_home-check.png') });

  // 5. a recent-file link opens the real file in OpenCloud ----------------------------------------------------------
  const firstHref = await page.locator('a.row').first().getAttribute('href');
  const p2 = await ctx.newPage();
  await p2.goto(firstHref);
  await p2.waitForURL(/cloud\.ou-lab\.internal\/(external|files)/, { timeout: 30000 });
  await p2.waitForTimeout(2500);
  check('recent-file link resolves inside OpenCloud (SSO, no second login)', /cloud\.ou-lab\.internal/.test(p2.url()) && !/auth\.ou-lab/.test(p2.url()), decodeURIComponent(p2.url()).slice(0, 110));
  await p2.close();

  // 6. Files tile ---------------------------------------------------------------------------------------------------
  const p3 = await ctx.newPage();
  await p3.goto(PORTAL + '/'); await p3.click('a.tile[data-app=files]');
  await p3.waitForURL(/cloud\.ou-lab\.internal\/files\/spaces/, { timeout: 30000 });
  await p3.waitForSelector('#files-view, .oc-tile, tr, .resource-table', { timeout: 20000 }).catch(() => {});
  check('Files tile opens OpenCloud files view with SSO', /files\/spaces\/personal\/bob/.test(decodeURIComponent(p3.url())), p3.url().split('?')[0]);
  await p3.close();

  // 7. Mail / Calendar / Contacts tiles: grommunio-web with Keycloak SSO (no second password prompt) and the deep link opens the right view ------------
  const WANT = { mail: 'mail', calendar: 'calendar', contacts: 'contact' };
  for (const app of ['mail', 'calendar', 'contacts']) {
    const p = await ctx.newPage();
    const posts = []; p.on('request', r => { if (r.method() === 'POST' && /login-actions\/authenticate/.test(r.url())) posts.push(r.url()); });
    const resp = await p.goto(hrefs[app]);
    let ctxName = '';
    try {
      await p.waitForFunction(() => typeof container !== 'undefined' && container.getCurrentContext && container.getCurrentContext(), null, { timeout: 60000 });
      await p.waitForTimeout(1500);
      ctxName = await p.evaluate(() => container.getCurrentContext().getName());
    } catch (_) { /* first-run wizard or no SSO: reported below */ }
    const pwForm = (await p.locator('input[type=password]').count()) > 0;
    check(`${app} tile opens the real webmail without a password prompt, in the ${WANT[app]} view (HTTP ${resp.status()}, TLS verified)`,
      resp.ok() && p.url().includes(MAIL_HOST) && !pwForm && posts.length === 0 && ctxName === WANT[app], p.url() + ' | context=' + ctxName + ' | auth POSTs=' + posts.length);
    await p.close();
  }

  // 8. New document -> created in OpenCloud and opened in the editor -------------------------------------------------
  const before = new Set(real.map(r => r.name));
  const created = [];
  for (const kind of ['document', 'spreadsheet', 'presentation']) {
    const p = await ctx.newPage();
    await p.goto(PORTAL + '/');
    await p.click(`button[data-new=${kind}]`);
    await p.waitForURL(/external-(documents|collaboraonline)\//, { timeout: 30000 });
    const fr = await p.waitForSelector('iframe', { timeout: 30000 }).catch(() => null);
    await p.waitForTimeout(3000);
    const frames = p.frames().map(f => f.url());
    const name = decodeURIComponent(new URL(p.url()).pathname.split('/').pop());
    created.push(name);
    check(`new ${kind}: file created + editor opened (Collabora frame)`, !!fr && frames.some(u => u.startsWith('https://office.ou-lab.internal/browser/') && u.includes('cool.html')), name);
    if (kind === 'document') await p.screenshot({ path: path.join(SHOTS, '_editor-check.png') });
    await p.close();
  }
  const after = await (await fetch(FILES + '/graph/v1.0/me/drive/root/children?$top=500', { headers: { authorization: 'Bearer ' + (await lab_token()) } })).json();
  check('created files really exist in bob\'s OpenCloud (Graph)', created.every(n => after.value.some(x => x.name === n)), created.join(', '));
  await page.goto(PORTAL + '/');
  const shown2 = await page.locator('a.row').evaluateAll(es => es.map(e => e.dataset.file));
  check('new files appear in Recent files', created.every(n => shown2.includes(n)), shown2.slice(0, 4).join(', '));
  // cleanup the test files (WebDAV DELETE with bob's own token)
  const t2 = await lab_token();
  for (const n of created) {                 // Collabora keeps a WOPI lock for a few seconds after the editor tab closes
    let st = 0;
    for (let i = 0; i < 20 && st !== 204; i++) {
      const r = await fetch(`${FILES}/remote.php/dav/files/${USER}/${encodeURIComponent(n)}`, { method: 'DELETE', headers: { authorization: 'Bearer ' + await lab_token() } });
      st = r.status; if (st !== 204) await new Promise(res => setTimeout(res, 3000));
    }
    check('cleanup ' + n, st === 204, 'HTTP ' + st);
  }

  // 9. Account ------------------------------------------------------------------------------------------------------
  await page.goto(PORTAL + '/account');
  const acct = await page.locator('main').innerText();
  check('account shows profile from OIDC claims', acct.includes(USER + '@ou-lab.internal') && acct.includes('Bob Lab'), 'name+email present');
  check('account shows MFA status and this device', /Two-step verification/.test(acct) && (await page.locator('.pill:has-text("This device")').count()) === 1);
  const pwLink = await page.locator('a.act').first().getAttribute('href');
  const p4 = await ctx.newPage();
  await p4.goto(pwLink);
  await p4.waitForTimeout(3500);
  check('password link opens the Keycloak account console (SSO)', /auth\.ou-lab\.internal\/realms\/ou-lab\/account/.test(p4.url()), p4.url().split('?')[0]);
  await p4.screenshot({ path: path.join(SHOTS, '_kc-account-check.png') });
  await p4.close();

  // 10. Devices: generated files carry no password ---------------------------------------------------------------
  await page.goto(PORTAL + '/devices');
  const dl = page.waitForEvent('download');
  await page.locator('#ios a.btn, details a[href="/devices/apple.mobileconfig"]').first().evaluate(a => a.closest('details').open = true).catch(() => {});
  await page.locator('a[href="/devices/apple.mobileconfig"]').first().click();
  const d = await dl;
  const file = await d.path();
  const txt = fs.readFileSync(file, 'utf8');
  check('.mobileconfig downloaded', d.suggestedFilename() === 'office-unbound.mobileconfig' && txt.includes('com.apple.mail.managed') && txt.includes('com.apple.caldav.account') && txt.includes('com.apple.carddav.account'));
  check('.mobileconfig has the user\'s address, never the password', txt.includes(USER + '@ou-lab.internal') && !txt.includes(PW));
  const ac = await (await ctx.request.get(PORTAL + '/.well-known/autoconfig/mail/config-v1.1.xml')).text();
  check('Thunderbird autoconfig served (public)', ac.includes('<clientConfig version="1.1">') && ac.includes(MAIL_HOST) && !ac.includes(PW));
  const sums = await page.locator('code.hash').evaluateAll(es => es.map(e => e.textContent));
  check('desktop client checksums listed', sums.length >= 3 && sums.every(s => /^[0-9a-f]{64}$/.test(s)), sums.length + ' sha256 values');

  // 11. screenshots light/dark x desktop/mobile ---------------------------------------------------------------------
  const state = await ctx.storageState();
  for (const scheme of ['light', 'dark']) {
    for (const [dev, vp, dsf] of [['desktop', { width: 1280, height: 800 }, 1], ['mobile', { width: 390, height: 844 }, 2]]) {
      const c = await browser.newContext({ viewport: vp, colorScheme: scheme, storageState: state, deviceScaleFactor: dsf, isMobile: dev === 'mobile' });
      const p = await c.newPage();
      for (const [name, url] of [['home', '/'], ['devices', '/devices'], ['account', '/account']]) {
        await p.goto(PORTAL + url);
        await p.waitForLoadState('networkidle');
        if (name === 'devices') await p.evaluate(() => document.querySelectorAll('details.plat').forEach((d, i) => { d.open = i === 0; }));
        await p.screenshot({ path: path.join(SHOTS, `${name}-${scheme}-${dev}.png`), fullPage: true });
      }
      if (dev === 'mobile') { const w = await p.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1); check(`no horizontal scroll on mobile (${scheme})`, w); }
      await c.close();
    }
  }
  const landing = await browser.newContext({ viewport: { width: 1280, height: 800 }, colorScheme: 'light' });
  const lp = await landing.newPage(); await lp.goto(PORTAL + '/'); await lp.screenshot({ path: path.join(SHOTS, 'landing-light-desktop.png') }); await landing.close();
  check('no CSP violations reported in the browser console', consoleErrors.length === 0, consoleErrors.slice(0, 2).join(' | '));

  // 12. sign out ----------------------------------------------------------------------------------------------------
  await page.goto(PORTAL + '/');
  await page.click('form.signout button');
  await page.waitForURL(url => url.href.startsWith(PORTAL), { timeout: 20000 });
  check('sign out returns to the signed-out portal', (await page.locator('a:has-text("Sign in")').count()) > 0, page.url());
  const r = await page.goto(PORTAL + '/account');
  check('after sign out, /account requires login again (Keycloak SSO ended)', /auth\.ou-lab\.internal/.test(page.url()) && (await page.locator('#username').count()) === 1, page.url().split('?')[0]);

  await browser.close();
  console.log(`\nSUMMARY: ${pass} PASS, ${fail} FAIL`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.log('FATAL ' + String(e.stack || e).replace(new RegExp(PW.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '***')); process.exit(2); });
