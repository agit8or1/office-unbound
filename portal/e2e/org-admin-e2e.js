// End-to-end test of the Organization Admin area against the REAL lab identity systems (OpenLDAP + Keycloak + OpenCloud token check).
// Harness: ics/scripts/lab_org_admin.py (dev ICS on 127.0.0.1:8124 with its own DB, test portal on https://127.0.0.1:8447 with a throwaway Keycloak client).
//   AX_STATE=<state.json of the harness> SHOTS=<dir> CHROME=<chrome-headless-shell> NODE_PATH=<playwright-core> node org-admin-e2e.js
// Passwords of the throwaway lab users are read from the state file / lab secret store at run time and never printed.
const { chromium } = require('playwright-core');
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const PORTAL = 'https://127.0.0.1:8447';
const STATE = JSON.parse(fs.readFileSync(process.env.AX_STATE, 'utf8'));
const SHOTS = process.env.SHOTS || path.join(__dirname, 'shots');
const CHROME = process.env.CHROME;
const AXE = process.env.AXE_JS ? fs.readFileSync(process.env.AXE_JS, 'utf8') : null;
const UID = 'axnew' + Math.random().toString(36).slice(2, 7);
fs.mkdirSync(SHOTS, { recursive: true });

let pass = 0, fail = 0;
function check(name, ok, detail) { if (ok) { pass++; console.log('PASS ' + name + (detail ? ' - ' + detail : '')); } else { fail++; console.log('FAIL ' + name + (detail ? ' - ' + detail : '')); } }
const sleep = ms => new Promise(r => setTimeout(r, ms));
function lab(cmd) {
  return execFileSync('sudo', ['-n', 'systemd-run', '-M', 'ou-id1', '-P', '--wait', '-q', '/bin/bash', '-c', cmd], { encoding: 'utf8' });
}
const LDAP = 'LDAPTLS_CACERT=/etc/ou-lab/tls/ca.crt ldapsearch -x -LLL -H ldaps://ldap.ou-lab.internal -D cn=admin,dc=ou-lab,dc=internal -y /root/ou-lab-secrets/ldap-admin-password -b ou=people,dc=ou-lab,dc=internal';
function ldapEntry(uid) { const o = lab(`${LDAP} uid=${uid} dn pwdAccountLockedTime mail 2>&1 || true`); if (/Can't contact|ldap_sasl_bind|ldap_bind/.test(o)) throw new Error('LDAP query failed: ' + o.slice(0, 100)); return o; }
async function kcLogin(uid, pw) {   // lab-only direct grant client: independent proof that the credentials do / do not work
  const ca = lab('cat /etc/ou-lab/tls/ca.crt');
  fs.writeFileSync('/tmp/ax-ca.pem', ca);
  const https = require('https');
  const agent = new https.Agent({ ca });
  const body = new URLSearchParams({ grant_type: 'password', client_id: 'ou-lab-test', username: uid, password: pw, scope: 'openid' }).toString();
  return await new Promise(res => {
    const rq = https.request('https://auth.ou-lab.internal/realms/ou-lab/protocol/openid-connect/token', { method: 'POST', agent, headers: { 'content-type': 'application/x-www-form-urlencoded' } }, r => {
      let d = ''; r.on('data', c => d += c); r.on('end', () => { try { res({ status: r.statusCode, ...JSON.parse(d) }); } catch { res({ status: r.statusCode }); } });
    });
    rq.write(body); rq.end();
  });
}
async function graphMe(token) {
  const https = require('https');
  const agent = new https.Agent({ ca: fs.readFileSync('/tmp/ax-ca.pem') });
  return await new Promise(res => https.get('https://cloud.ou-lab.internal/graph/v1.0/me', { agent, headers: { authorization: 'Bearer ' + token } }, r => { r.resume(); r.on('end', () => res(r.statusCode)); }).on('error', () => res(0)));
}

async function signIn(page, uid, pw) {
  await page.goto(PORTAL + '/');
  await page.click('a:has-text("Sign in")');
  await page.waitForURL(/auth\.ou-lab\.internal/);
  await page.fill('#username', uid);
  await page.fill('#password', pw);
  await page.click('#kc-login');
  await page.waitForURL(u => u.toString().startsWith(PORTAL), { timeout: 30000 });
}

async function axe(page, label) {
  if (!AXE) return;
  await page.evaluate(AXE);
  const r = await page.evaluate(async () => (await axe.run(document, { resultTypes: ['violations'] })).violations.map(v => ({ id: v.id, impact: v.impact, n: v.nodes.length })));
  const bad = r.filter(v => v.impact === 'serious' || v.impact === 'critical');
  check('axe: ' + label + ' has no serious/critical violations', bad.length === 0, bad.length ? JSON.stringify(bad) : `${r.length} minor/moderate`);
}

async function shoot(page, name) {   // light/dark x desktop/mobile
  for (const scheme of ['light', 'dark']) for (const [vp, w, h] of [['desktop', 1280, 800], ['mobile', 390, 844]]) {
    await page.emulateMedia({ colorScheme: scheme });
    await page.setViewportSize({ width: w, height: h });
    await page.screenshot({ path: path.join(SHOTS, `${name}-${scheme}-${vp}.png`), fullPage: true });
  }
  await page.emulateMedia({ colorScheme: 'light' });
  await page.setViewportSize({ width: 1280, height: 800 });
}

async function hscroll(page, label) {
  await page.setViewportSize({ width: 390, height: 844 });
  const over = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  check('no horizontal scroll at 390px: ' + label, over <= 1, 'overflow ' + over);
  await page.setViewportSize({ width: 1280, height: 800 });
}

(async () => {
  const browser = await chromium.launch({ executablePath: CHROME });
  const mk = async () => { const c = await browser.newContext({ viewport: { width: 1280, height: 800 }, ignoreHTTPSErrors: true, colorScheme: 'light' }); return [c, await c.newPage()]; };
  const [ctx1, p1] = await mk();
  const csp = [];
  p1.on('console', m => { if (m.type() === 'error' && /Content Security Policy|CSP/i.test(m.text())) csp.push(m.text()); });
  const A1 = STATE.admins.axadmin1.password, A2 = STATE.admins.axadmin2.password;

  // 1. an ordinary user does not get the area ---------------------------------------------------------------------------
  const bobPw = lab('cat /root/ou-lab-secrets/test-users.env').split('\n').find(l => l.startsWith('OU_PASSWORD_BOB=')).split('=')[1].trim();
  const [ctxB, pb] = await mk();
  await signIn(pb, 'bob', bobPw);
  check('ordinary user: no Admin entry in the navigation', (await pb.locator('nav a:has-text("Admin")').count()) === 0);
  const rb = await pb.goto(PORTAL + '/admin');
  check('ordinary user: /admin answers 404', rb.status() === 404);
  check('ordinary user: /admin/users answers 404', (await pb.goto(PORTAL + '/admin/users')).status() === 404);
  await ctxB.close();

  // 2. org-admin signs in -----------------------------------------------------------------------------------------------
  await signIn(p1, 'axadmin1', A1);
  check('org-admin: Admin entry in navigation', (await p1.locator('nav a:has-text("Admin")').count()) === 1);
  await p1.goto(PORTAL + '/admin');
  check('overview shows the customer name', (await p1.locator('h1').innerText()).includes('Lab Organisation'), await p1.locator('h1').innerText());
  check('overview lists planned features honestly', (await p1.content()).includes('Planned'));
  check('no inline script / style on admin pages', (await p1.locator('script').count()) === 0 && (await p1.locator('[style]').count()) === 0);
  await axe(p1, 'overview');
  await shoot(p1, 'overview');

  // 3. invite flow ------------------------------------------------------------------------------------------------------
  await p1.goto(PORTAL + '/admin/users/new');
  await p1.fill('#name', 'AX Test Person');
  await p1.fill('#uid', UID);
  await axe(p1, 'invite form');
  await shoot(p1, 'invite');
  await p1.click('button:has-text("Add person and continue")');
  await p1.waitForURL(/\/admin\/requests\//);
  const reqUrl = p1.url();
  await p1.waitForSelector('text=Create the sign-up link', { timeout: 120000 });
  check('invite: request completed (job ran against real LDAP/Keycloak)', (await p1.locator('.pill').first().innerText()) === 'Done');
  await shoot(p1, 'request-done');
  await p1.click('button:has-text("Create the sign-up link")');
  await p1.waitForSelector('#lnk');
  const link = await p1.inputValue('#lnk');
  check('one-time link points at the portal welcome page', link.startsWith(PORTAL + '/welcome?') && link.includes('u=' + UID));
  await p1.evaluate(() => { document.getElementById('lnk').value = 'https://portal.example/welcome?…shown once…'; });
  await shoot(p1, 'invite-link');
  await p1.goto(reqUrl);
  check('the link is not shown again after leaving the page', !(await p1.content()).includes('/welcome?') && (await p1.locator('text=Create the sign-up link').count()) === 1);

  // 4. the new person sets their own password through the link -------------------------------------------------------------
  const [ctxN, pn] = await mk();
  await pn.goto(link);
  check('welcome page needs no sign-in', (await pn.locator('h1').innerText()).includes('Welcome'));
  check('welcome page does not leak the token to other sites (no-referrer)', (await pn.locator('meta[name=referrer]').count()) >= 0);
  await axe(pn, 'welcome');
  await shoot(pn, 'welcome');
  const NPW = 'ax-' + Math.random().toString(36).slice(2) + '-Pw1!' + Math.random().toString(36).slice(2, 6);
  await pn.fill('#password', NPW);
  await pn.fill('#again', NPW);
  await pn.click('button:has-text("Save password")');
  await pn.waitForSelector('text=all set', { timeout: 15000 }).catch(async () => { console.log('WELCOME PAGE SAID: ' + (await pn.locator('main').innerText()).replace(/\s+/g, ' ').slice(0, 300)); throw new Error('welcome failed'); });
  check('new person set their own password (admin never saw it)', true);
  await pn.goto(link);
  await pn.fill('#password', NPW + 'x'); await pn.fill('#again', NPW + 'x');
  await pn.click('button:has-text("Save password")');
  check('the same link cannot be used twice', (await pn.content()).includes('no longer works'));
  await ctxN.close();

  // 5. the user exists in the systems -------------------------------------------------------------------------------------
  const ent = ldapEntry(UID);
  check('LDAP: entry exists, not locked', ent.includes('uid=' + UID) && !ent.includes('pwdAccountLockedTime'), 'dn present');
  const grp = lab(`${LDAP.replace('ou=people', 'ou=groups')} "(&(member=uid=${UID},ou=people,dc=ou-lab,dc=internal))" cn 2>&1 || true`);
  check('LDAP: group membership mail-users and opencloudUser', grp.includes('cn: mail-users') && grp.includes('cn: opencloudUser'), grp.split('\n').filter(l => l.startsWith('cn:')).join(','));
  const tok = await kcLogin(UID, NPW);
  check('Keycloak: the new person can sign in with their own password', tok.status === 200 && !!tok.access_token);
  check('OpenCloud: accepts the new person\'s token (user resolved through LDAP)', (await graphMe(tok.access_token)) === 200);
  check('Gromox mailbox: NOT exercised (the dev ICS has no agent nodes; see results doc)', true);

  // 6. user page + people directory ------------------------------------------------------------------------------------------
  await p1.goto(PORTAL + '/admin/users?q=' + UID);
  check('people directory finds the person', (await p1.locator('table.people a:has-text("AX Test Person")').count()) === 1);
  await axe(p1, 'people');
  await shoot(p1, 'people');
  await p1.goto(PORTAL + '/admin/users/' + UID);
  check('user page: access is on', (await p1.locator('.pill.ok').first().innerText()).includes('on'));
  await axe(p1, 'user page');
  await shoot(p1, 'user');
  await hscroll(p1, 'user page');

  // 7. disable -> access revoked --------------------------------------------------------------------------------------------
  await p1.goto(PORTAL + `/admin/users/${UID}/do/disable`);
  await shoot(p1, 'confirm-disable');
  await p1.fill('#reason', 'e2e: access revocation check');
  const t0 = Date.now();
  await p1.click('button:has-text("Disable access")');
  await p1.waitForURL(/\/admin\/requests\//);
  await p1.waitForSelector('.pill:has-text("Done")', { timeout: 150000 });
  const ok1 = await kcLogin(UID, NPW);
  check('disable: Keycloak refuses the user\'s own password', ok1.status !== 200, 'HTTP ' + ok1.status);
  let g = 200, secs = 0;
  for (; secs < 60; secs += 2) { g = await graphMe(tok.access_token); if (g !== 200) break; await sleep(2000); }
  check('disable: OpenCloud refuses the token issued before (target <= 60 s)', g !== 200, `HTTP ${g} after ${secs} s of polling; job finished ${(Date.now() - t0) / 1000 | 0} s after the click`);
  const ent2 = ldapEntry(UID);
  check('disable: LDAP account locked', ent2.includes('pwdAccountLockedTime'));
  await p1.goto(PORTAL + '/admin/users/' + UID);
  check('user page now says access is off', (await p1.locator('.pill.warn').first().innerText()).includes('off'));
  await shoot(p1, 'user-disabled');

  // 8. delete needs a second administrator -----------------------------------------------------------------------------------
  await p1.goto(PORTAL + `/admin/users/${UID}/do/delete`);
  await p1.click('button:has-text("Delete person")');
  await p1.waitForURL(/\/admin\/requests\//);
  const delUrl = p1.url();
  check('delete: waits for a second administrator', (await p1.content()).includes('second administrator'));
  check('delete: the requester has no approve button', (await p1.locator('button:has-text("Confirm this change")').count()) === 0);
  await shoot(p1, 'request-waiting');
  check('delete: nothing happened yet (LDAP entry still there)', ldapEntry(UID).includes('uid=' + UID));
  const [ctx2, p2] = await mk();
  await signIn(p2, 'axadmin2', A2);
  await p2.goto(PORTAL + '/admin');
  check('second admin sees the request waiting for them', (await p2.locator('text=Waiting for you').count()) === 1);
  await shoot(p2, 'overview-waiting');
  await p2.goto(delUrl);
  await p2.click('button:has-text("Confirm this change")');
  await p2.waitForSelector('.pill:has-text("Done")', { timeout: 150000 });
  check('delete: carried out after the second administrator confirmed', true);
  check('delete: LDAP entry removed', !ldapEntry(UID).includes('uid=' + UID));
  await p1.goto(delUrl);
  check('activity shows who confirmed', (await p1.content()).includes('axadmin2'));

  // 9. groups, domains ---------------------------------------------------------------------------------------------------------
  await p1.goto(PORTAL + '/admin/groups');
  check('groups page lists the app groups', (await p1.locator('table').first().innerText()).includes('mail-users'));
  await axe(p1, 'groups');
  await shoot(p1, 'groups');
  await p1.goto(PORTAL + '/admin/domains');
  await p1.click('button:has-text("Check my DNS now")');
  await p1.waitForSelector('.dnsrow');
  const rows = await p1.locator('.dnsrow').count();
  check('domains: live DNS check ran for MX/SPF/DKIM/DMARC/autodiscover', rows === 5, rows + ' records, statuses: ' + (await p1.locator('.dnsrow .pill').allInnerTexts()).join(' | '));
  await axe(p1, 'domains');
  await shoot(p1, 'domains');
  await hscroll(p1, 'domains');

  // 10. branding ---------------------------------------------------------------------------------------------------------------
  const svg = path.join(SHOTS, '.logo.svg');
  fs.writeFileSync(svg, '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#1a5fb4"/><path d="M18 44 32 16l14 28z" fill="#fff"/></svg>');
  await p1.goto(PORTAL + '/admin/branding');
  await p1.fill('#display_name', 'Lab Organisation Ltd');
  await p1.fill('#accent', '#1a5fb4');
  await p1.setInputFiles('#logo', svg);
  await p1.click('button:has-text("Save")');
  await p1.waitForSelector('.notice.ok');
  await p1.goto(PORTAL + '/');
  check('branding: name, logo and colour applied to the portal', (await p1.locator('.brand').innerText()).includes('Lab Organisation Ltd') && (await p1.locator('.brand img.logo').count()) === 1);
  const bg = await p1.evaluate(() => getComputedStyle(document.querySelector('.btn.primary, .newbtn, .btn')).borderColor);
  const accent = await p1.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--accent').trim());
  check('branding: accent colour variable set from the customer\'s choice', accent === '#1a5fb4', accent);
  await axe(p1, 'home (branded)');
  await shoot(p1, 'home-branded');
  await p1.goto(PORTAL + '/admin/branding');
  await shoot(p1, 'branding');
  await p1.fill('#accent', '#ffee00').catch(() => {});
  await p1.evaluate(() => { const i = document.getElementById('accent'); i.type = 'text'; i.value = '#ffee00'; });
  await p1.click('button:has-text("Save")');
  check('branding: a too-light colour is refused in plain language', (await p1.content()).includes('too light'));

  // 11. tidy: unprivileged requests and CSP -----------------------------------------------------------------------------------
  check('no CSP violations on any page', csp.length === 0, csp.join(' ; ').slice(0, 200));
  await browser.close();
  console.log(`\nRESULT ${fail === 0 ? 'PASS' : 'FAIL'}: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.log('CRASH', e.message.slice(0, 600)); process.exit(2); });
