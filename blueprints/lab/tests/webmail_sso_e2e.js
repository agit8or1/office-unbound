// SSO e2e: bob signs in to Keycloak once -> webmail without 2nd password prompt -> mailbox/name -> deep links -> logout.
// usage: NODE_PATH=<playwright node_modules> SSO_IP=<node ip> E2E_HOME=<HOME with NSS db trusting the lab CA and the node CA> SHOTS=<dir> [LOGOUT_WAIT=420] node webmail_sso_e2e.js
// env: SSO_IP, E2E_HOME (NSS db trusting both lab CAs), SHOTS
const { chromium } = require('playwright');
const { execFileSync } = require('child_process');
const fs = require('fs');
const IP = process.env.SSO_IP, SHOTS = process.env.SHOTS;
const WEB = 'https://sso.ou-lab.internal', KC = 'https://auth.ou-lab.internal';
fs.mkdirSync(SHOTS, { recursive: true });
const out = execFileSync('sudo', ['systemd-run', '-M', 'ou-id1', '-P', '--wait', '-q', '/bin/cat', '/root/ou-lab-secrets/test-users.env']).toString();
const PW = out.split('\n').find(l => l.startsWith('OU_PASSWORD_BOB=')).split('=')[1].trim();
let pass = 0, fail = 0;
const check = (n, ok, d) => { ok ? pass++ : fail++; console.log((ok ? 'PASS ' : 'FAIL ') + n + (d ? ' - ' + d : '')); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
(async () => {
  const browser = await chromium.launch({ args: [`--host-resolver-rules=MAP sso.ou-lab.internal ${IP}`], env: { ...process.env, HOME: process.env.E2E_HOME } });
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } });
  const page = await ctx.newPage(); globalThis.__page = page;
  const authPosts = [];
  page.on('request', r => { if (r.method() === 'POST' && /login-actions\/authenticate/.test(r.url())) authPosts.push(r.url()); });
  const ready = async () => { try { const b = await page.locator('text=Get Started').first().boundingBox({ timeout: 10000 }); if (b) await page.mouse.click(b.x + b.width / 2, b.y + b.height / 2); } catch (_) {} await page.waitForFunction(() => typeof container !== 'undefined' && container.getHierarchyStore && container.getHierarchyStore().getDefaultStore && container.getHierarchyStore().getDefaultStore(), null, { timeout: 60000 }); await sleep(2000); };
  const ctxName = () => page.evaluate(() => container.getCurrentContext().getName());

  // 1. one Keycloak login (account console)
  await page.goto(KC + '/realms/ou-lab/account/');
  await page.fill('#username', 'bob'); await page.fill('#password', PW); await page.click('#kc-login');
  await page.waitForURL(/realms\/ou-lab\/account/, { timeout: 30000 });
  check('Keycloak sign-in (the only password entry)', authPosts.length === 1, 'authenticate POSTs=' + authPosts.length);

  // 2. open webmail
  const chain = []; page.on('framenavigated', f => { if (f === page.mainFrame()) chain.push(new URL(f.url()).host + new URL(f.url()).pathname); });
  await page.goto(WEB + '/web/');
  await ready();
  check('webmail opened without second password prompt', authPosts.length === 1 && page.url().startsWith(WEB + '/web'), 'redirect chain: ' + chain.join(' > '));
  const dn = await page.evaluate(() => container.getUser().getDisplayName());
  const smtp = await page.evaluate(() => container.getUser().getSMTPAddress ? container.getUser().getSMTPAddress() : '');
  check('mailbox loaded, bob visible', /bob/i.test(dn), `displayName="${dn}" smtp=${smtp}`);
  const folders = await page.evaluate(() => container.getHierarchyStore().getDefaultStore().getDefaultFolder('inbox') ? 'inbox ok' : 'no inbox');
  check('default store inbox resolvable', folders === 'inbox ok', folders);
  const ck = (await ctx.cookies(WEB)).map(c => `${c.name}:httpOnly=${c.httpOnly},secure=${c.secure},sameSite=${c.sameSite}`);
  console.log('cookies', ck.join(' | '));
  const html = await page.content();
  check('no JWT in page HTML', !/eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\./.test(html));
  await page.screenshot({ path: SHOTS + '/1-webmail-sso.png' });

  // 3. deep links (fresh navigation, session already active)
  for (const [name, q] of [['calendar', 'action=context&view=calendar'], ['contact', 'action=context&view=contacts']]) {
    await page.goto(WEB + '/web/?' + q); await ready();
    const c = await ctxName();
    check(`deep link ?${q} opens ${name} view`, c === name, 'current context=' + c);
    await page.screenshot({ path: SHOTS + `/2-deeplink-${name}.png` });
  }

  // 4. deep link survives the SSO round trip from a signed-out webmail (new browser context, Keycloak SSO cookie still valid? use same ctx, drop webmail cookies)
  await ctx.clearCookies({ domain: 'sso.ou-lab.internal' });
  await page.goto(WEB + '/web/?action=context&view=calendar'); await ready();
  const c2 = await ctxName();
  check('deep link survives OIDC redirect (fresh webmail session, Keycloak SSO)', c2 === 'calendar' && authPosts.length === 1, 'context=' + c2 + ' authPosts=' + authPosts.length);

  // 5. logout from Keycloak ends webmail session
  const t0 = Date.now();
  await page.goto(KC + '/realms/ou-lab/account/');
  // Keycloak RP-initiated logout without id_token_hint shows a confirm page
  await page.goto(KC + '/realms/ou-lab/protocol/openid-connect/logout');
  const btn = page.locator('#kc-logout'); if (await btn.count()) await btn.click();
  await sleep(1500);
  const afterKc = await ctx.request.get(KC + '/realms/ou-lab/account/', { maxRedirects: 0 }).then(r => r.status()).catch(() => 'err');
  console.log('keycloak account after logout -> HTTP', afterKc);
  // webmail API request with the still-held webmail cookie: is the session still alive right now?
  const alive = async () => { const r = await page.goto(WEB + '/web/'); await sleep(2500); return /auth\.ou-lab\.internal/.test(page.url()) ? 'kc-login' : (await page.evaluate(() => typeof container !== 'undefined' && !!container.getUser)) ? 'webmail-up' : 'other'; };
  const immediately = await alive();
  console.log('webmail state immediately after Keycloak logout:', immediately, '(t+' + Math.round((Date.now() - t0) / 1000) + 's)');
  fs.writeFileSync(SHOTS + '/immediate.txt', immediately);
  let ended = immediately === 'kc-login', tEnd = ended ? 0 : null;
  const maxWait = +(process.env.LOGOUT_WAIT || 420) * 1000;
  while (!ended && Date.now() - t0 < maxWait) { await sleep(20000); const s = await alive(); console.log('  t+' + Math.round((Date.now() - t0) / 1000) + 's webmail:', s); if (s === 'kc-login') { ended = true; tEnd = Math.round((Date.now() - t0) / 1000); } }
  check('Keycloak logout ends the webmail session', ended, ended ? 'redirected to Keycloak login after ~' + tEnd + 's' : 'still logged in after ' + maxWait / 1000 + 's');
  await page.screenshot({ path: SHOTS + '/3-after-logout.png' });
  console.log(`-- ${pass} PASS, ${fail} FAIL`);
  await browser.close();
  process.exit(fail ? 1 : 0);
})().catch(async e => { try { const p = globalThis.__page; if (p) { await p.screenshot({ path: SHOTS + "/err.png" }); console.log("URL", p.url()); console.log((await p.innerText("body")).slice(0, 400)); } } catch (_) {}  console.log('ERROR', e.message.split('\n')[0]); process.exit(2); });
