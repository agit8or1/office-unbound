#!/usr/bin/env node
// Browser-based functional AUDIT of one deployed Office Unbound stack (portal, Keycloak, OpenCloud, Collabora, grommunio-web).
// Every user-visible function is one named check (PASS / FAIL / INFO + short reason); the run continues after failures and always exits 0.
// See README.md next to this file for inputs and what each check proves.
//
//   OU_DOMAIN=example.org OU_ENTRY_IP=203.0.113.10 OU_USER=bob OU_USER2=carol \
//   OU_PW_FILE=~/.ou/bob.pw OU_PW2_FILE=~/.ou/carol.pw OU_OUT=./audit-out node stack_functional.cjs
//
// Secrets: passwords are read from files and never printed; tokens stay inside the browser (DAV/Graph calls run in-page); every reason,
// URL and error passes through redact() (code/state/token params, JWTs, both passwords).
'use strict';
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

function loadPlaywright() {
  const tries = [process.env.PLAYWRIGHT_PATH, 'playwright', path.resolve(__dirname, '../../../../ics/e2e/node_modules/playwright'),
    '/home/administrator/office-unbound/ics/e2e/node_modules/playwright'].filter(Boolean);
  for (const t of tries) { try { return require(t); } catch (_) { /* next */ } }
  console.log('FATAL playwright not found (set PLAYWRIGHT_PATH)'); process.exit(0);
}
const { chromium } = loadPlaywright();

// ---- inputs ---------------------------------------------------------------------------------------------------------------------
function need(name) { const v = (process.env[name] || '').trim(); if (!v) { console.log(`FATAL missing env ${name} (see README.md)`); process.exit(0); } return v; }
function readPw(file) {
  const p = file.replace(/^~(?=\/)/, process.env.HOME || '~');
  try { const v = fs.readFileSync(p, 'utf8').replace(/\r?\n$/, ''); if (!v) throw new Error('empty'); return v; }
  catch (e) { console.log(`FATAL cannot read password file ${p}: ${e.code || e.message}`); process.exit(0); }
}
const D = need('OU_DOMAIN').replace(/^\.+|\.+$/g, '');
const IP = need('OU_ENTRY_IP');
const U1 = need('OU_USER');
const U2 = need('OU_USER2');
const PW1 = readPw(need('OU_PW_FILE'));
const PW2 = readPw(need('OU_PW2_FILE'));
const MAIL1 = process.env.OU_USER_EMAIL || (U1.includes('@') ? U1 : `${U1}@${D}`);
const MAIL2 = process.env.OU_USER2_EMAIL || (U2.includes('@') ? U2 : `${U2}@${D}`);
const OUT = path.resolve(process.env.OU_OUT || `stack-functional-out-${new Date().toISOString().replace(/[:.]/g, '-')}`);
const SHOTS = path.join(OUT, 'shots');
const HEADED = process.env.OU_HEADED === '1';
const STEP_TIMEOUT = Number(process.env.OU_STEP_TIMEOUT_S || 150) * 1000;
fs.mkdirSync(SHOTS, { recursive: true });

const APP = `https://app.${D}`, AUTH = `https://auth.${D}`, CLOUD = `https://cloud.${D}`, OFFICE = `https://office.${D}`, MAILWEB = `https://mail.${D}/web/`;
const host = u => { try { return new URL(u).host; } catch (_) { return ''; } };
const STAMP = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);
const PFX = `ou-audit-${STAMP}`;

// ---- redaction ------------------------------------------------------------------------------------------------------------------
const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const PWRE = new RegExp([PW1, PW2].filter(p => p.length >= 3).map(esc).join('|') || '(?!)', 'g');
function redact(v) {
  let s = typeof v === 'string' ? v : (v instanceof Error ? (v.message || String(v)) : JSON.stringify(v));
  if (s == null) return '';
  s = s.replace(PWRE, '<pw>');
  s = s.replace(/([?&#;](?:code|state|session_state|id_token_hint|id_token|access_token|refresh_token|token|access_token_ttl|WOPISrc|nonce|code_challenge|iss)=)[^&#\s"'<>]*/gi, '$1<redacted>');
  s = s.replace(/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g, '<jwt>');
  s = s.replace(/(bearer\s+)[A-Za-z0-9._~+/=-]+/gi, '$1<redacted>');
  return s.length > 400 ? s.slice(0, 400) + '...' : s;
}
const shortUrl = u => redact(String(u || '').split('#')[0]).slice(0, 140);

// ---- result bookkeeping ---------------------------------------------------------------------------------------------------------
const results = [];
const look = [];
let section = '';
let seq = 0;
function slug(s) { return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60); }
async function record(name, status, reason, page, t0) {
  const r = { id: ++seq, section, name, status, reason: redact(reason || ''), ms: t0 ? Date.now() - t0 : 0 };
  if (status === 'FAIL' && page && !page.isClosed()) {
    const f = path.join(SHOTS, `${String(r.id).padStart(3, '0')}-${slug(section + '-' + name)}.png`);
    try { await page.screenshot({ path: f, timeout: 10000 }); r.screenshot = path.relative(OUT, f); } catch (_) { /* page gone */ }
  }
  results.push(r);
  console.log(`${status.padEnd(4)} [${section}] ${name}${r.reason ? ' - ' + r.reason : ''}`);
  return status === 'PASS';
}
// Run one check: fn returns {ok, reason, info?} (info => INFO status). A throw or timeout is a FAIL with the (redacted) error.
// `page` may be a function so the screenshot is taken of the page that is current when the check ends.
async function check(name, page, fn) {
  const t0 = Date.now();
  let timer;
  try {
    const r = await Promise.race([fn(), new Promise((_, rej) => { timer = setTimeout(() => rej(new Error(`timed out after ${STEP_TIMEOUT / 1000}s`)), STEP_TIMEOUT); })]);
    clearTimeout(timer);
    const st = r.info ? 'INFO' : (r.ok ? 'PASS' : 'FAIL');
    return await record(name, st, r.reason, typeof page === 'function' ? page() : page, t0);
  } catch (e) {
    clearTimeout(timer);
    return await record(name, 'FAIL', 'error: ' + (e && e.message ? e.message.split('\n')[0] : String(e)), typeof page === 'function' ? page() : page, t0);
  }
}
function skip(name, why) { return record(name, 'FAIL', 'not run: ' + why); }
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ---- browser helpers ------------------------------------------------------------------------------------------------------------
function trackPage(page) {
  page.__ws = []; page.__5xx = []; page.__authPosts = 0;
  page.on('websocket', ws => {
    const w = { url: ws.url(), opened: Date.now(), closed: false, closedAt: 0 };
    page.__ws.push(w);
    ws.on('close', () => { w.closed = true; w.closedAt = Date.now(); });
  });
  page.on('response', r => { if (r.status() >= 500) page.__5xx.push({ status: r.status(), host: host(r.url()), path: (() => { try { return new URL(r.url()).pathname; } catch (_) { return ''; } })() }); });
  page.on('request', r => { if (r.method() === 'POST' && /login-actions\/authenticate/.test(r.url())) page.__authPosts++; });
  return page;
}
async function newPage(ctx) { const p = await ctx.newPage(); return trackPage(p); }
async function hasLoginForm(page) { return host(page.url()) === host(AUTH) && (await page.locator('#username, input[name=username]').count()) > 0; }
let REALM = process.env.OU_REALM || '';
async function kcLogin(page, user, pw) {
  await page.waitForSelector('#username, input[name=username]', { timeout: 30000 });
  const m = /\/realms\/([^/]+)\//.exec(page.url()); if (m && !REALM) REALM = decodeURIComponent(m[1]);
  await page.fill('#username, input[name=username]', user);
  if (await page.locator('#password').count() === 0) { await page.click('#kc-login, input[type=submit], button[type=submit]'); await page.waitForSelector('#password', { timeout: 20000 }); }
  await page.fill('#password', pw);
  await page.click('#kc-login, input[type=submit], button[type=submit]');
}
async function waitFor(fn, timeout, every = 1000) {
  const end = Date.now() + timeout; let last;
  while (Date.now() < end) { try { last = await fn(); if (last) return last; } catch (_) { /* retry */ } await sleep(every); }
  return last;
}
// Click the first VISIBLE match of several candidate selectors (UIs change between releases). Returns the selector used or null.
async function clickFirst(scope, sels, timeout = 10000, opts = {}) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    for (const s of sels) {
      const l = scope.locator(s).first();
      try { if (await l.isVisible()) { await l.click(opts); return s; } } catch (_) { /* next */ }
    }
    await sleep(400);
  }
  return null;
}
async function visibleAny(scope, sels) { for (const s of sels) { try { if (await scope.locator(s).first().isVisible()) return s; } catch (_) { /* next */ } } return null; }
async function waitFrame(page, pred, timeout) { return waitFor(async () => page.frames().find(f => pred(f.url())) || null, timeout, 500); }
async function portalLinkVisible(page) {
  for (const f of page.frames()) {
    try {
      const n = await f.evaluate(app => Array.from(document.querySelectorAll('a[href]')).filter(a => a.href.startsWith(app) && (a.offsetWidth || a.offsetHeight || a.getClientRects().length)).length, APP);
      if (n > 0) return f === page.mainFrame() ? 'main page' : 'frame ' + host(f.url());
    } catch (_) { /* cross-origin detached */ }
  }
  return null;
}
async function recordLook(app, target) {
  try {
    const l = await target.evaluate(() => {
      const cs = e => getComputedStyle(e);
      const body = document.body, html = document.documentElement;
      const transparent = c => !c || c === 'transparent' || /rgba\(\s*0,\s*0,\s*0,\s*0\s*\)/.test(c);
      let bg = cs(body).backgroundColor; if (transparent(bg)) bg = cs(html).backgroundColor;
      const main = document.querySelector('main, [role=main], #main, #app, #web, .x-viewport, #document-container, #kc-content, .login-pf-page');
      let mainBg = main ? cs(main).backgroundColor : null; if (transparent(mainBg)) mainBg = null;
      const h1 = document.querySelector('h1, h2, button');
      return { title: document.title, background: bg, main_background: mainBg, font_family: cs(body).fontFamily, heading_or_button_font: h1 ? cs(h1).fontFamily : null };
    });
    look.push({ app, url: shortUrl(target.url()), ...l });
    console.log(`LOOK [${app}] title="${l.title}" bg=${l.background}${l.main_background ? ' main=' + l.main_background : ''} font=${l.font_family}`);
  } catch (e) { look.push({ app, error: redact(e) }); }
}

// ---- OpenCloud in-page API (token never leaves the browser) ----------------------------------------------------------------------
// rel: 'name/in/personal/space' (WebDAV, relative to the user's personal drive) or '/absolute/path' on the cloud origin (Graph, OCS).
async function cloudApi(page, method, rel, { body = null, headers = {}, binary = false } = {}) {
  return page.evaluate(async ({ method, rel, body, headers, binary }) => {
    const tok = (() => {
      for (const st of [sessionStorage, localStorage]) for (let i = 0; i < st.length; i++) {
        try { const v = JSON.parse(st.getItem(st.key(i))); if (v && typeof v.access_token === 'string') return v.access_token; } catch (_) { /* not json */ }
      }
      return null;
    })();
    if (!tok) return { status: -1, err: 'no OpenCloud web token in browser storage' };
    const h = Object.assign({ authorization: 'Bearer ' + tok }, headers || {});
    if (!rel.startsWith('/') && !window.__ouDav) {
      const r = await fetch('/graph/v1.0/me/drive', { headers: h });
      if (!r.ok) return { status: r.status, err: 'graph me/drive HTTP ' + r.status };
      const j = await r.json(); window.__ouDav = j.root && j.root.webDavUrl;
      if (!window.__ouDav) return { status: -1, err: 'personal drive has no webDavUrl' };
    }
    const url = rel.startsWith('/') ? rel : window.__ouDav.replace(/\/$/, '') + '/' + rel.split('/').map(encodeURIComponent).join('/');
    const r = await fetch(url, { method, headers: h, body });
    const out = { status: r.status };
    if (binary) { const b = new Uint8Array(await r.arrayBuffer()); let s = ''; for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000)); out.b64 = btoa(s); }
    else out.text = (await r.text()).slice(0, 200000);
    return out;
  }, { method, rel, body, headers, binary });
}
const davExists = async (page, rel) => { const r = await cloudApi(page, 'PROPFIND', rel, { headers: { Depth: '0' } }); return r.status === 207; };

// Minimal ZIP reader (OOXML): returns the concatenated text of every *.xml entry, so a typed marker can be found in docx/xlsx/pptx.
function ooxmlText(buf) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) return null;
  const n = buf.readUInt16LE(eocd + 10); let p = buf.readUInt32LE(eocd + 16); let out = '';
  for (let k = 0; k < n && buf.readUInt32LE(p) === 0x02014b50; k++) {
    const method = buf.readUInt16LE(p + 10), csize = buf.readUInt32LE(p + 20), nlen = buf.readUInt16LE(p + 28), xlen = buf.readUInt16LE(p + 30), clen = buf.readUInt16LE(p + 32), lho = buf.readUInt32LE(p + 42);
    const name = buf.slice(p + 46, p + 46 + nlen).toString('utf8');
    if (name.endsWith('.xml')) {
      const ds = lho + 30 + buf.readUInt16LE(lho + 26) + buf.readUInt16LE(lho + 28);
      const data = buf.slice(ds, ds + csize);
      try { out += (method === 8 ? zlib.inflateRawSync(data) : data).toString('utf8') + '\n'; } catch (_) { /* skip entry */ }
    }
    p += 46 + nlen + xlen + clen;
  }
  return out;
}
async function fileHasMarker(page, name, marker) {
  const r = await cloudApi(page, 'GET', name, { binary: true });
  if (r.status !== 200) return { ok: false, why: `GET HTTP ${r.status}${r.err ? ' ' + r.err : ''}` };
  const buf = Buffer.from(r.b64 || '', 'base64');
  const txt = ooxmlText(buf);
  if (txt == null) return { ok: false, why: `not a zip (${buf.length} bytes)` };
  return { ok: txt.includes(marker), why: `${buf.length} bytes, marker ${txt.includes(marker) ? 'found' : 'absent'}` };
}

// ---- Collabora editor -----------------------------------------------------------------------------------------------------------
const COOL_CANVAS = ['#document-canvas', '#document-container canvas', '.leaflet-canvas-container canvas', 'canvas'];
async function editorState(page) {
  const fr = await waitFrame(page, u => u.startsWith(OFFICE + '/browser/'), 60000);
  if (!fr) return { ok: false, why: 'no Collabora (office host) iframe within 60s; page at ' + shortUrl(page.url()) };
  await fr.waitForSelector('#document-container', { timeout: 60000 });
  const canvas = await waitFor(async () => visibleAny(fr, COOL_CANVAS), 60000, 1000);
  await sleep(6000);                                    // a broken load shows its dialog / drops the socket within a few seconds
  const dlg = await fr.evaluate(() => Array.from(document.querySelectorAll('.vex-dialog-message, .vex-content, .jsdialog-window, #cool-message, .ui-dialog, [role=alertdialog], [role=dialog]'))
    .filter(e => e.offsetWidth || e.offsetHeight).map(e => e.innerText.trim()).filter(Boolean).join(' | ')).catch(() => '');
  const badDlg = /fail|error|unauthori[sz]ed|could not|cannot|unable|not.*load|lost|disconnect|expired/i.test(dlg);
  const ws = page.__ws.filter(w => host(w.url) === host(OFFICE) && /cool|lool/.test(w.url));
  const openWs = ws.filter(w => !w.closed);
  const ok = !!canvas && !badDlg && openWs.length > 0;
  return { ok, frame: fr, canvas, why: `canvas=${canvas ? 'yes' : 'NO'}; dialog=${dlg ? JSON.stringify(dlg.slice(0, 120)) : 'none'}; cool websockets open=${openWs.length}/${ws.length}` };
}
async function typeMarker(page, fr, kind, marker) {
  const cv = fr.locator((await visibleAny(fr, COOL_CANVAS)) || 'canvas').first();
  const box = await cv.boundingBox();
  if (!box) throw new Error('document canvas has no box');
  if (kind === 'spreadsheet') {
    const addr = await visibleAny(fr, ['#addressInput input', 'input#addressInput', '[id^=addressInput] input']);
    if (addr) { await fr.locator(addr).first().fill('A1'); await page.keyboard.press('Enter'); }
    else await page.mouse.click(box.x + 60, box.y + 30);
    await sleep(500);
    await page.keyboard.type(marker, { delay: 40 }); await page.keyboard.press('Enter');
  } else if (kind === 'presentation') {
    await page.mouse.click(box.x + box.width / 2, box.y + box.height * 0.35); await sleep(800);
    await page.keyboard.press('Escape'); await page.keyboard.press('Tab'); await page.keyboard.press('Enter'); await sleep(400);
    await page.keyboard.type(marker, { delay: 40 }); await page.keyboard.press('Escape'); await page.keyboard.press('Escape');
  } else {
    await page.mouse.click(box.x + box.width / 2, box.y + Math.min(box.height / 3, 200)); await sleep(500);
    await page.keyboard.type(marker, { delay: 40 }); await page.keyboard.press('Enter');
  }
  await sleep(1000);
  await page.keyboard.press('Control+s');
}
// Full editor proof for one file that is already opening in `page`: working editor, type, save, file content, reopen.
async function editorProof(label, page, openUrl, kind, name, helper, ctx, marker) {
  let st;
  const okEditor = await check(`${label}: editor works (canvas, no load-failure dialog, cool websocket open)`, page, async () => { st = await editorState(page); return { ok: st.ok, reason: st.why }; });
  if (!okEditor || !st || !st.frame) { await skip(`${label}: type + save`, 'editor not working'); await skip(`${label}: saved file contains the typed text`, 'editor not working'); await skip(`${label}: reopen shows the text`, 'editor not working'); return null; }
  await check(`${label}: type + save (Ctrl+S)`, page, async () => {
    await typeMarker(page, st.frame, kind, marker);
    await sleep(3000);
    const dlg = await st.frame.evaluate(() => Array.from(document.querySelectorAll('.vex-dialog-message, .jsdialog-window, [role=alertdialog]')).filter(e => e.offsetWidth).map(e => e.innerText).join(' | ')).catch(() => '');
    const closedAfter = page.__ws.filter(w => host(w.url) === host(OFFICE) && w.closed).length;
    return { ok: !/fail|error|could not|unable/i.test(dlg) && closedAfter === 0, reason: `typed ${marker.length} chars; dialog=${dlg ? JSON.stringify(dlg.slice(0, 100)) : 'none'}; sockets closed=${closedAfter}` };
  });
  await check(`${label}: saved file contains the typed text (autosave/WOPI PutFile)`, page, async () => {
    const r = await waitFor(async () => { const x = await fileHasMarker(helper, name, marker); return x.ok ? x : (st.last = x, null); }, 60000, 4000);
    return { ok: !!r, reason: r ? r.why : 'after 60s: ' + (st.last ? st.last.why : 'no answer') };
  });
  let p2 = null;
  await check(`${label}: reopen shows the text`, () => p2 || page, async () => {
    await page.close().catch(() => {});
    await sleep(4000);
    p2 = await newPage(ctx);
    await p2.goto(openUrl);
    const s2 = await editorState(p2);
    let wc = '';
    if (kind === 'document' && s2.frame) wc = await s2.frame.locator('#StateWordCount').first().innerText({ timeout: 5000 }).catch(() => '');
    const content = await fileHasMarker(helper, name, marker);
    const wcOk = kind !== 'document' || !wc || !/^\s*0\s/.test(wc);
    return { ok: s2.ok && content.ok && wcOk, reason: `reopen: ${s2.why}; file: ${content.why}${wc ? '; status bar: ' + wc.replace(/\s+/g, ' ').trim() : ''}` };
  });
  return p2;
}

// ---- grommunio-web helpers (run inside the webmail page; uses the app's own client API) ------------------------------------------
async function webmailReady(page, timeout = 60000) {
  return page.waitForFunction(() => typeof container !== 'undefined' && container.getCurrentContext && container.getCurrentContext(), null, { timeout }).then(() => true).catch(() => false);
}
// Create a record in a context's model, fill fields, optionally add a recipient + send action, save through the shadow store.
async function zarafaSave(page, ctxName, fields, { to = null, send = false, start = null, end = null } = {}) {
  return page.evaluate(({ ctxName, fields, to, send, start, end }) => new Promise(resolve => {
    try {
      const model = container.getContextByName(ctxName).getModel();
      const rec = start ? model.createRecord(undefined, new Date(start), new Date(end)) : model.createRecord();
      for (const [k, v] of Object.entries(fields)) rec.set(k, v);
      if (to) {
        const r = Zarafa.core.data.RecordFactory.createRecordObjectByCustomType(Zarafa.core.data.RecordCustomObjectType.ZARAFA_RECIPIENT, {
          display_name: to, smtp_address: to, email_address: to, address_type: 'SMTP',
          object_type: Zarafa.core.mapi.ObjectType.MAPI_MAILUSER, recipient_type: Zarafa.core.mapi.RecipientType.MAPI_TO });
        rec.getRecipientStore().add(r);
      }
      if (send) rec.addMessageAction('send', true);
      const store = container.getShadowStore();
      const done = (ok, why) => { try { store.remove(rec); } catch (_) { /* ignore */ } resolve({ ok, why }); };
      store.on('write', (s, action, result, res, records) => { if ([].concat(records || []).includes(rec)) done(true, 'saved'); }, null, { single: true });
      store.on('exception', (p, type, action, opts, resp) => done(false, 'server exception: ' + (resp && resp.error ? JSON.stringify(resp.error).slice(0, 120) : type)), null, { single: true });
      store.add(rec); store.save(rec);
      setTimeout(() => done(false, 'no write confirmation within 30s'), 30000);
    } catch (e) { resolve({ ok: false, why: 'client API error: ' + e.message }); }
  }), { ctxName, fields, to, send, start, end });
}
async function webmailFind(page, text, timeout, view = null) {
  const target = view ? MAILWEB + '?action=context&view=' + view : MAILWEB;
  let n = 0;
  return waitFor(async () => {
    if (n++ % 3 === 2) { await page.goto(target); await webmailReady(page); }
    else await page.evaluate(() => { try { const s = container.getCurrentContext().getModel().getStore(); s && s.reload && s.reload(); } catch (_) { /* ignore */ } });
    await sleep(2500);
    return (await page.getByText(text, { exact: false }).count()) > 0;
  }, timeout, 2000);
}

// ---- OpenCloud UI helpers -------------------------------------------------------------------------------------------------------
function rowSel(name) { return [`tr:has([data-test-resource-name="${name}"])`, `[data-test-resource-name="${name}"]`, `tr:has-text("${name}")`, `.oc-tile:has-text("${name}")`]; }
async function row(page, name, timeout = 20000) {
  const s = await waitFor(async () => visibleAny(page, rowSel(name)), timeout, 700);
  return s ? page.locator(s).first() : null;
}
async function contextAction(page, name, sels, timeout = 8000) {
  const r = await row(page, name); if (!r) throw new Error(`row "${name}" not visible in the file list`);
  await r.click({ button: 'right' });
  const used = await clickFirst(page, sels, timeout);
  if (!used) { await page.keyboard.press('Escape'); throw new Error(`no menu entry among: ${sels.join(' , ')}`); }
  return used;
}
async function modalFill(page, value) {
  const inp = page.locator('.oc-modal input[type=text], .oc-modal input:not([type]), [role=dialog] input[type=text]').first();
  await inp.waitFor({ state: 'visible', timeout: 10000 });
  await inp.fill(value);
  if (!(await clickFirst(page, ['.oc-modal-body-actions-confirm', '[role=dialog] button:has-text("Create")', '[role=dialog] button:has-text("Rename")', '[role=dialog] button:has-text("Save")'], 3000))) await inp.press('Enter');
}
async function filesHome(page) {
  await page.goto(CLOUD + '/files/spaces/personal');
  await waitFor(async () => visibleAny(page, ['#files-space-table', '.files-table', 'table.oc-table', '.resource-table', '.no-content-message', '#files-view']), 30000, 700);
  await sleep(1500);
}

// =================================================================================================================================
(async () => {
  const started = new Date().toISOString();
  console.log(`Office Unbound stack functional audit  domain=${D} entry=${IP} users=${U1},${U2} out=${OUT}\n`);
  const browser = await chromium.launch({ headless: !HEADED, args: [`--host-resolver-rules=MAP *.${D} ${IP}`] });
  const mkCtx = () => browser.newContext({ viewport: { width: 1366, height: 900 }, acceptDownloads: true, colorScheme: 'light', locale: 'en-US' });
  const ctx1 = await mkCtx(), ctx2 = await mkCtx();
  for (const c of [ctx1, ctx2]) c.setDefaultTimeout(20000);
  const st = { signedIn1: false, signedIn2: false, office: {}, helper1: null, helper2: null };
  const portal = await newPage(ctx1);

  // ---------------------------------------------------------------- PORTAL -----------------------------------------------------
  section = 'portal';
  await check('signed out: portal redirects straight to sign-in', portal, async () => {
    const hops = []; const h = r => { if (r.frame() === portal.mainFrame() && r.request().isNavigationRequest()) hops.push(host(r.url()) + ' ' + r.status()); };
    portal.on('response', h);
    await portal.goto(APP + '/');
    await portal.waitForURL(u => host(u.href) === host(AUTH), { timeout: 30000 });
    portal.off('response', h);
    const form = await hasLoginForm(portal);
    const html200OnApp = hops.some(x => x.startsWith(host(APP) + ' 200'));
    await recordLook('keycloak-login', portal);
    return { ok: form && !html200OnApp, reason: `hops: ${hops.join(' > ')}; login form=${form}` };
  });
  st.signedIn1 = await check('sign in (Keycloak) returns to portal home', portal, async () => {
    await kcLogin(portal, U1, PW1);
    await portal.waitForURL(u => host(u.href) === host(APP), { timeout: 30000 });
    const g = await portal.locator('h1.greet, h1').first().innerText({ timeout: 15000 });
    return { ok: /hello/i.test(g) || (await portal.locator('a.tile').count()) > 0, reason: `"${g}" realm=${REALM || '?'}` };
  });
  if (st.signedIn1) await recordLook('portal', portal);
  const hrefs = {};
  const tileWant = { files: { host: host(CLOUD) }, mail: { host: host(MAILWEB), ctx: 'mail' }, calendar: { host: host(MAILWEB), ctx: 'calendar' }, contacts: { host: host(MAILWEB), ctx: 'contact' } };
  for (const app of Object.keys(tileWant)) {
    if (!st.signedIn1) { await skip(`tile ${app} opens the app without a second sign-in`, 'not signed in'); continue; }
    let p;
    await check(`tile ${app} opens the app without a second sign-in`, () => p, async () => {
      hrefs[app] = await portal.locator(`a.tile[data-app=${app}]`).getAttribute('href', { timeout: 5000 });
      if (!hrefs[app]) return { ok: false, reason: 'tile not on home page' };
      p = await newPage(ctx1);
      const resp = await p.goto(hrefs[app]);
      let ctxName = '';
      if (tileWant[app].ctx) { if (await webmailReady(p)) ctxName = await p.evaluate(() => container.getCurrentContext().getName()); }
      else await waitFor(async () => host(p.url()) === host(CLOUD) && /\/files/.test(p.url()), 30000);
      const login = await hasLoginForm(p) || (await p.locator('input[type=password]').count()) > 0;
      const ok = host(p.url()) === tileWant[app].host && !login && p.__authPosts === 0 && p.__5xx.length === 0 && (!tileWant[app].ctx || ctxName === tileWant[app].ctx);
      const r = { ok, reason: `HTTP ${resp ? resp.status() : '?'} -> ${shortUrl(p.url())}${ctxName ? ' context=' + ctxName : ''}; password prompt=${login}; 5xx=${p.__5xx.length}` };
      if (ok) await p.close(); return r;
    });
  }
  await check('recent files section renders', portal, async () => {
    if (!st.signedIn1) return { ok: false, reason: 'not signed in' };
    await portal.goto(APP + '/');
    const rows = await portal.locator('a.row').count();
    const empty = await portal.locator('#h-recent ~ .empty, p.empty').count();
    const notice = await portal.locator('p.notice').allInnerTexts();
    return { ok: (rows > 0 || empty > 0) && !notice.some(t => /recent files/i.test(t)), reason: `${rows} rows${empty ? ', empty-state shown' : ''}${notice.length ? '; notice: ' + notice.join(' / ') : ''}` };
  });

  // ---------------------------------------------------------------- OFFICE (portal New + Collabora) ----------------------------
  section = 'office';
  // helper tab: OpenCloud web for in-page WebDAV/Graph calls (user 1)
  st.helper1 = await newPage(ctx1);
  const helperOk = st.signedIn1 && await check('OpenCloud web session available for verification calls', st.helper1, async () => {
    await filesHome(st.helper1);
    const r = await waitFor(async () => { const x = await cloudApi(st.helper1, 'GET', '/graph/v1.0/me/drive'); return x.status === 200 ? x : null; }, 30000, 2000);
    return { ok: !!r, reason: r ? 'graph me/drive 200' : 'no token / graph not answering' };
  });
  const KINDS = { document: 'docx', spreadsheet: 'xlsx', presentation: 'pptx' };
  for (const kind of Object.keys(KINDS)) {
    const label = `new ${kind} (${KINDS[kind]})`;
    if (!st.signedIn1) { await skip(`${label}: created from portal`, 'not signed in'); continue; }
    let p, name, url;
    const created = await check(`${label}: created from portal, editor opens`, () => p, async () => {
      p = await newPage(ctx1);
      await p.goto(APP + '/');
      await p.click(`button[data-new=${kind}]`);
      await p.waitForURL(u => host(u.href) === host(CLOUD), { timeout: 30000 });
      url = p.url();
      name = decodeURIComponent(new URL(url).pathname.split('/').pop());
      return { ok: name.endsWith('.' + KINDS[kind]), reason: `file "${name}"` };
    });
    if (!created) continue;
    st.office[kind] = { name, url };
    if (kind === 'document') await recordLook('opencloud-editor-wrapper', p);
    if (kind === 'document') { const fr = await waitFrame(p, u => u.startsWith(OFFICE + '/browser/'), 60000); if (fr) { await fr.waitForSelector('#document-container', { timeout: 60000 }).catch(() => {}); await recordLook('collabora', fr); } }
    if (!helperOk) { await skip(`${label}: editor proof`, 'no OpenCloud verification session'); continue; }
    const p2 = await editorProof(label, p, url, kind, name, st.helper1, ctx1, `OUAUDIT${kind.slice(0, 3).toUpperCase()}${STAMP}`);
    if (p2 && kind === 'document') {
      await check('navigation: way back to portal from the editor', p2, async () => { const w = await portalLinkVisible(p2); return { ok: !!w, reason: w ? 'portal link in ' + w : 'no visible link to ' + APP }; });
    }
    if (p2) await p2.close().catch(() => {});
  }
  section = 'portal';
  await check('recent files lists the new documents', portal, async () => {
    const names = Object.values(st.office).map(o => o.name);
    if (!names.length) return { ok: false, reason: 'no documents were created' };
    await portal.goto(APP + '/');
    const shown = await portal.locator('a.row').evaluateAll(es => es.map(e => e.dataset.file));
    const missing = names.filter(n => !shown.includes(n));
    return { ok: missing.length === 0, reason: missing.length ? 'missing: ' + missing.join(', ') : `${names.length}/${names.length} listed` };
  });
  await check('recent file link opens the file in OpenCloud (no second sign-in)', portal, async () => {
    const href = await portal.locator('a.row').first().getAttribute('href', { timeout: 5000 });
    const p = await newPage(ctx1); await p.goto(href);
    await waitFor(async () => host(p.url()) === host(CLOUD) && !/\/login|oidc-callback/.test(p.url()), 30000);
    const r = { ok: host(p.url()) === host(CLOUD) && !(await hasLoginForm(p)) && p.__authPosts === 0, reason: shortUrl(p.url()) };
    await p.close(); return r;
  });

  // ---------------------------------------------------------------- FILES (OpenCloud UI) -----------------------------------------
  section = 'files';
  const fp = await newPage(ctx1);
  const txtName = `${PFX}.txt`, txtRenamed = `${PFX}-renamed.txt`, folder = `${PFX}-folder`;
  const txtBody = `Office Unbound functional audit ${STAMP}\nline two\n`;
  const filesOk = st.signedIn1 && await check('Files opens with SSO (no second sign-in)', fp, async () => {
    await filesHome(fp);
    const ok = host(fp.url()) === host(CLOUD) && !(await hasLoginForm(fp)) && fp.__authPosts === 0;
    await recordLook('opencloud', fp);
    return { ok, reason: shortUrl(fp.url()) };
  });
  if (filesOk && helperOk) {
    await check('upload a small text file', fp, async () => {
      const inp = fp.locator('#files-file-upload-input, input[type=file]:not([webkitdirectory])').first();
      await inp.setInputFiles({ name: txtName, mimeType: 'text/plain', buffer: Buffer.from(txtBody) });
      const r = await row(fp, txtName, 30000);
      const g = await waitFor(async () => { const x = await cloudApi(fp, 'GET', txtName); return x.status === 200 ? x : null; }, 20000, 2000);
      return { ok: !!r && !!g && g.text === txtBody, reason: `row ${r ? 'shown' : 'NOT shown'}; server copy ${g ? (g.text === txtBody ? 'identical' : 'DIFFERENT') : 'missing'}` };
    });
    await check('download it back (content equal)', fp, async () => {
      const [d] = await Promise.all([fp.waitForEvent('download', { timeout: 20000 }),
        contextAction(fp, txtName, ['.oc-files-actions-download-file-trigger', '[role=menu] :text-is("Download")', 'button:has-text("Download")'])]);
      const got = fs.readFileSync(await d.path(), 'utf8');
      return { ok: got === txtBody, reason: `${d.suggestedFilename()} ${Buffer.byteLength(got)} bytes, ${got === txtBody ? 'equal' : 'DIFFERENT'}` };
    });
    await check('rename', fp, async () => {
      await contextAction(fp, txtName, ['.oc-files-actions-rename-trigger', '[role=menu] :text-is("Rename")', 'button:has-text("Rename")']);
      await modalFill(fp, txtRenamed);
      const ok = await waitFor(async () => (await davExists(fp, txtRenamed)) && !(await davExists(fp, txtName)), 15000, 1500);
      return { ok: !!ok, reason: ok ? 'new name on server, old name gone' : 'server does not show the new name' };
    });
    await check('create folder', fp, async () => {
      const b = await clickFirst(fp, ['#new-file-menu-btn', 'button:has-text("New")'], 8000); if (!b) throw new Error('no New button');
      const f = await clickFirst(fp, ['#new-folder-btn', '.new-file-menu button:has-text("Folder")', '[role=menu] :text-is("Folder")', 'button:has-text("Folder")'], 8000); if (!f) throw new Error('no Folder entry');
      await modalFill(fp, folder);
      const ok = await waitFor(async () => davExists(fp, folder), 15000, 1500);
      return { ok: !!ok, reason: ok ? 'folder exists on server' : 'folder not on server' };
    });
    let shared = false;
    shared = await check(`share folder with ${U2} (internal share)`, fp, async () => {
      await filesHome(fp);
      await contextAction(fp, folder, ['.oc-files-actions-show-shares-trigger', '[role=menu] :text-is("Share")', 'button:has-text("Share")']);
      const inp = fp.locator('#files-share-invite-input, input[placeholder*="name" i], .files-collaborators-autocomplete input').first();
      await inp.waitFor({ state: 'visible', timeout: 15000 });
      await inp.fill(U2);
      const opt = await clickFirst(fp, [`.vs__dropdown-option:has-text("${U2}")`, `[data-testid="recipient-autocomplete-item"]:has-text("${U2}")`, `li[role=option]:has-text("${U2}")`, '.vs__dropdown-option'], 15000);
      if (!opt) throw new Error(`${U2} not offered by the invite search`);
      const sh = await clickFirst(fp, ['#new-collaborators-form-create-button', 'button:has-text("Share")', 'button:has-text("Invite")'], 8000);
      if (!sh) throw new Error('no Share/Invite button');
      await sleep(2500);
      const s = await cloudApi(fp, 'GET', '/ocs/v1.php/apps/files_sharing/api/v1/shares?format=json&path=' + encodeURIComponent('/' + folder), { headers: { 'OCS-APIRequest': 'true' } });
      let users = []; try { users = (JSON.parse(s.text).ocs.data || []).filter(x => String(x.share_type) === '0').map(x => x.share_with); } catch (_) { /* not json */ }
      return { ok: users.length > 0, reason: `OCS HTTP ${s.status}, user shares: ${users.join(', ') || 'none'}` };
    });
    // public link (only if the UI offers it)
    await check('public link create + delete (if offered)', fp, async () => {
      await fp.keyboard.press('Escape').catch(() => {});
      const add = await clickFirst(fp, ['#files-file-link-add-btn', 'button:has-text("Add link")', 'button:has-text("Create link")', 'button:has-text("Add public link")'], 6000);
      if (!add) return { info: true, reason: 'not offered: no "Add link" control in the share panel' };
      await clickFirst(fp, ['.oc-modal-body-actions-confirm', '[role=dialog] button:has-text("Create")'], 4000);
      await sleep(2500);
      const q = async () => { const s = await cloudApi(fp, 'GET', '/ocs/v1.php/apps/files_sharing/api/v1/shares?format=json&path=' + encodeURIComponent('/' + folder), { headers: { 'OCS-APIRequest': 'true' } }); try { return (JSON.parse(s.text).ocs.data || []).filter(x => String(x.share_type) === '3').length; } catch (_) { return -1; } };
      const n1 = await q();
      if (n1 < 1) return { ok: false, reason: 'link not created on server' };
      const menu = await clickFirst(fp, ['.link-edit-dropdown', 'button[aria-label*="link" i][aria-label*="edit" i]', '.oc-files-file-link button[aria-haspopup]', 'button[title*="More" i]'], 6000);
      const del = menu && await clickFirst(fp, ['button:has-text("Delete link")', '[role=menu] :text-is("Delete link")', 'button:has-text("Delete")'], 6000);
      if (del) await clickFirst(fp, ['.oc-modal-body-actions-confirm', '[role=dialog] button:has-text("Delete")'], 5000);
      await sleep(2500);
      const n2 = await q();
      return { ok: n2 === 0, reason: `created (${n1} link); delete control ${del ? 'found' : 'NOT found'}; links after delete: ${n2}` };
    });
    await check('delete', fp, async () => {
      await fp.keyboard.press('Escape').catch(() => {});
      await filesHome(fp);
      await contextAction(fp, txtRenamed, ['.oc-files-actions-delete-trigger', '[role=menu] :text-is("Delete")', 'button:has-text("Delete")']);
      await clickFirst(fp, ['.oc-modal-body-actions-confirm', '[role=dialog] button:has-text("Delete")'], 4000);
      const ok = await waitFor(async () => !(await davExists(fp, txtRenamed)), 15000, 1500);
      return { ok: !!ok, reason: ok ? 'gone from server' : 'still on server' };
    });
    // open a .docx from the Files UI and edit it
    const doc = st.office.document;
    if (doc) {
      let ep;
      const opened = await check('open .docx from the file list in the editor', () => ep, async () => {
        ep = await newPage(ctx1);
        await filesHome(ep);
        const r = await row(ep, doc.name); if (!r) throw new Error('docx not in list');
        await ep.locator(`[data-test-resource-name="${doc.name}"], .oc-resource-name:has-text("${doc.name}")`).first().click().catch(() => r.click());
        await clickFirst(ep, ['button:has-text("Collabora")', '[role=menu] :text("Collabora")', 'button:has-text("Open in")'], 3000);
        const ok = await waitFor(async () => /external/.test(ep.url()), 30000);
        return { ok: !!ok, reason: shortUrl(ep.url()) };
      });
      if (opened) {
        const p2 = await editorProof('docx from Files', ep, ep.url(), 'document', doc.name, st.helper1, ctx1, `OUAUDITFILES${STAMP}`);
        if (p2) await p2.close().catch(() => {});
      }
    } else await skip('open .docx from the file list in the editor', 'no docx was created by the office section');
    await check('navigation: way back to portal from Files', fp, async () => { await filesHome(fp); const w = await portalLinkVisible(fp); return { ok: !!w, reason: w ? 'portal link in ' + w : 'no visible link to ' + APP }; });
    section = 'admin';
    await check('OpenCloud admin-settings closed to a normal user', fp, async () => {
      await fp.goto(CLOUD + '/admin-settings/users');
      await sleep(5000);
      const url = fp.url();
      const ui = await fp.locator('#admin-settings-app, .admin-settings-wrapper, [data-testid="users-table"], #users-table, table:has-text("Role")').count();
      const api = await cloudApi(st.helper1, 'GET', '/graph/v1.0/users?$top=1');
      const ok = !/admin-settings\/users/.test(url) || (ui === 0 && /not found|access|permission|denied/i.test(await fp.locator('body').innerText()));
      return { ok: ok && api.status >= 400, reason: `UI: ${shortUrl(url)}, admin widgets=${ui}; graph /users HTTP ${api.status}` };
    });
    section = 'files';
    // user 2 sees the share
    const u2p = await newPage(ctx2);
    st.signedIn2 = await check(`${U2} signs in`, u2p, async () => {
      await u2p.goto(APP + '/');
      await kcLogin(u2p, U2, PW2);
      await u2p.waitForURL(u => host(u.href) === host(APP), { timeout: 30000 });
      return { ok: (await u2p.locator('a.tile').count()) > 0, reason: shortUrl(u2p.url()) };
    });
    if (shared && st.signedIn2) {
      await check(`${U2} sees the shared folder`, u2p, async () => {
        const ok = await waitFor(async () => {
          await u2p.goto(CLOUD + '/files/shares/with-me');
          await sleep(4000);
          return (await u2p.getByText(folder, { exact: false }).count()) > 0;
        }, 60000, 3000);
        return { ok: !!ok, reason: ok ? 'listed under Shared with me' : 'not listed under Shared with me after 60s' };
      });
    } else await skip(`${U2} sees the shared folder`, !shared ? 'share failed' : `${U2} not signed in`);
    await u2p.close().catch(() => {});
  } else {
    for (const n of ['upload a small text file', 'download it back (content equal)', 'rename', 'create folder', `share folder with ${U2} (internal share)`, `${U2} sees the shared folder`, 'public link create + delete (if offered)', 'delete', 'open .docx from the file list in the editor'])
      await skip(n, filesOk ? 'no OpenCloud verification session' : 'Files did not open');
  }

  // ---------------------------------------------------------------- WEBMAIL ------------------------------------------------------
  section = 'webmail';
  const subj = `OU audit ${STAMP}`;
  const mp = await newPage(ctx1);
  const mailOk = st.signedIn1 && await check('SSO into webmail reaches the inbox (no 500, no password prompt)', mp, async () => {
    const resp = await mp.goto(MAILWEB);
    const ready = await webmailReady(mp);
    const name = ready ? await mp.evaluate(() => container.getCurrentContext().getName()) : '';
    const pw = (await mp.locator('input[type=password]').count()) > 0;
    await recordLook('webmail', mp);
    return { ok: ready && name === 'mail' && mp.__5xx.length === 0 && !pw, reason: `HTTP ${resp ? resp.status() : '?'}; context=${name || 'none'}; 5xx=${mp.__5xx.map(x => x.status + ' ' + x.host + x.path).join(', ') || 'none'}; password prompt=${pw}` };
  });
  if (mailOk) {
    const sent = await check(`compose + send to ${MAIL2}`, mp, async () => {
      const r = await zarafaSave(mp, 'mail', { subject: subj, body: `Audit message ${STAMP}`, isHTML: false }, { to: MAIL2, send: true });
      return { ok: r.ok, reason: r.why };
    });
    // user 2 receives + replies
    const m2 = await newPage(ctx2);
    let u2mail = false;
    if (!st.signedIn2) {
      await m2.goto(MAILWEB);
      if (await hasLoginForm(m2)) { await kcLogin(m2, U2, PW2).catch(() => {}); }
    } else await m2.goto(MAILWEB);
    u2mail = await webmailReady(m2);
    if (sent && u2mail) {
      const got = await check(`${U2} receives it`, m2, async () => { const ok = await webmailFind(m2, subj, 90000); return { ok: !!ok, reason: ok ? 'subject visible in inbox' : 'not in inbox after 90s' }; });
      if (got) {
        await check(`${U2} replies; ${U1} receives the reply`, m2, async () => {
          await m2.getByText(subj).first().click();
          await sleep(1500);
          await m2.keyboard.press('Control+r');
          let how = 'Ctrl+R';
          if (!(await waitFor(async () => (await m2.locator('.zarafa-mailcreatepanel, .x-window:has-text("RE:"), [class*=createpanel]').count()) > 0, 5000, 500))) {
            const b = await clickFirst(m2, ['button:has-text("Reply")', '.x-btn:has-text("Reply")', '[ext\\:qtip*="Reply"]'], 5000); how = b ? 'Reply button' : 'none';
          }
          await sleep(2500);
          await m2.keyboard.type(`Reply ${STAMP}`);
          await m2.keyboard.press('Control+Enter');
          await sleep(1500);
          if (await m2.locator('button:has-text("Send")').first().isVisible().catch(() => false)) await m2.locator('button:has-text("Send")').first().click();
          const ok = await webmailFind(mp, subj, 90000);
          return { ok: !!ok, reason: `reply via ${how}; ${ok ? 'reply visible in ' + U1 + ' inbox' : 'no reply in ' + U1 + ' inbox after 90s'}` };
        });
      } else await skip(`${U2} replies; ${U1} receives the reply`, 'message not received');
    } else {
      await skip(`${U2} receives it`, sent ? `${U2} webmail did not open` : 'send failed');
      await skip(`${U2} replies; ${U1} receives the reply`, 'previous step failed');
    }
    await check('calendar: create event, see it', mp, async () => {
      const t = new Date(); t.setMinutes(0, 0, 0); t.setHours(Math.min(t.getHours() + 1, 22));
      const e = new Date(t.getTime() + 3600e3);
      await mp.goto(MAILWEB + '?action=context&view=calendar'); await webmailReady(mp); await sleep(2000);
      const r = await zarafaSave(mp, 'calendar', { subject: `${subj} event`, location: 'audit' }, { start: t.toISOString(), end: e.toISOString() });
      const seen = r.ok && await webmailFind(mp, `${subj} event`, 30000, 'calendar');
      return { ok: r.ok && !!seen, reason: `${r.why}; ${seen ? 'visible in calendar' : 'NOT visible in calendar'}` };
    });
    await check('contacts: create contact, see it', mp, async () => {
      await mp.goto(MAILWEB + '?action=context&view=contacts'); await webmailReady(mp); await sleep(2000);
      const n = `Audit${STAMP}`;
      const r = await zarafaSave(mp, 'contact', { display_name: `${n} Contact`, fileas: `Contact, ${n}`, given_name: n, surname: 'Contact', email_address_1: `audit-${STAMP}@example.invalid`, email_address_display_name_1: `${n} Contact`, email_address_type_1: 'SMTP' });
      const seen = r.ok && await webmailFind(mp, n, 30000, 'contacts');
      return { ok: r.ok && !!seen, reason: `${r.why}; ${seen ? 'visible in contacts' : 'NOT visible in contacts'}` };
    });
    await check('navigation: way back to portal from webmail', mp, async () => { await mp.goto(MAILWEB); await webmailReady(mp); const w = await portalLinkVisible(mp); return { ok: !!w, reason: w ? 'portal link in ' + w : 'no visible link to ' + APP }; });
    await check(`sign out of webmail (${U2})`, m2, async () => {
      if (!u2mail) return { ok: false, reason: `${U2} webmail not open` };
      await m2.evaluate(() => container.logout()).catch(() => {});
      await sleep(5000);
      await m2.goto(MAILWEB);
      await sleep(4000);
      const inbox = await m2.evaluate(() => typeof container !== 'undefined' && !!container.getCurrentContext).catch(() => false);
      const login = await hasLoginForm(m2) || (await m2.locator('input[type=password]').count()) > 0;
      return { ok: !inbox && login, reason: `after logout, reopening /web/: ${inbox ? 'inbox shown again WITHOUT sign-in' : 'no inbox'}; sign-in form=${login}; at ${shortUrl(m2.url())}` };
    });
    await m2.close().catch(() => {});
  } else {
    for (const n of [`compose + send to ${MAIL2}`, `${U2} receives it`, `${U2} replies; ${U1} receives the reply`, 'calendar: create event, see it', 'contacts: create contact, see it', 'navigation: way back to portal from webmail', `sign out of webmail (${U2})`])
      await skip(n, 'webmail did not open');
  }

  // ---------------------------------------------------------------- ADMIN SURFACES -----------------------------------------------
  section = 'admin';
  const ap = await newPage(ctx1);
  await check('Collabora admin console closed (/browser/dist/admin/admin.html)', ap, async () => {
    const r = await ap.goto(OFFICE + '/browser/dist/admin/admin.html').catch(e => ({ err: e }));
    if (r && r.err) return { ok: /ERR_CONNECTION|ERR_EMPTY|ERR_ABORTED/.test(r.err.message), reason: 'request failed: ' + r.err.message.split('\n')[0] };
    const s = r ? r.status() : 0;
    return { ok: s === 403 || s === 404, reason: `HTTP ${s}${s === 401 ? ' (reachable; only the Collabora admin password protects it)' : ''}${s === 200 ? ' (admin console page served)' : ''}` };
  });
  await check('Keycloak /admin/ closed', ap, async () => {
    const r = await ap.goto(AUTH + '/admin/').catch(e => ({ err: e }));
    if (r && r.err) return { ok: /ERR_CONNECTION|ERR_EMPTY/.test(r.err.message), reason: 'request failed: ' + r.err.message.split('\n')[0] };
    await sleep(3000);
    const s = r ? r.status() : 0; const u = ap.url();
    const consoleShown = /\/admin\/[^/]+\/console/.test(u) || (await ap.locator('#kc-header, #app, [data-testid=realmSelector]').count()) > 0 && /admin/.test(u);
    const ok = s >= 400 && !consoleShown;
    return { ok, reason: `HTTP ${s} -> ${shortUrl(u)}${consoleShown ? ' (admin console / master-realm login served)' : ''}` };
  });
  if (REALM) await check(`Keycloak admin console of realm ${REALM} denies ${U1}`, ap, async () => {
    const r = await ap.goto(`${AUTH}/admin/${encodeURIComponent(REALM)}/console/`).catch(e => ({ err: e }));
    if (r && r.err) return { ok: true, reason: 'request failed (blocked): ' + r.err.message.split('\n')[0] };
    await sleep(6000);
    const body = await ap.locator('body').innerText().catch(() => '');
    const s = r.status();
    const denied = s >= 400 || /forbidden|not authori[sz]ed|access denied|don't have access|do not have access/i.test(body);
    const usable = /Clients|Realm settings|Users\b/.test(body) && !denied;
    return { ok: !usable, reason: `HTTP ${s}; ${usable ? 'admin console USABLE for a normal user' : denied ? 'access denied' : 'console not usable'}` };
  });
  await ap.close().catch(() => {});

  // ---------------------------------------------------------------- PORTAL: account, devices, sessions, sign-out -----------------
  section = 'portal';
  if (st.signedIn1) {
    await check('account page lists sessions incl. this device', portal, async () => {
      await portal.goto(APP + '/account');
      const rows = await portal.locator('table tr:has(th[scope=row])').count();
      const me = await portal.locator('.pill:has-text("This device")').count();
      return { ok: rows > 0 && me === 1, reason: `${rows} session rows, "This device" pills=${me}` };
    });
    await check('account: "Sign out everywhere else" ends another session', portal, async () => {
      const ctxB = await mkCtx(); const pb = await newPage(ctxB);
      try {
        await pb.goto(APP + '/'); await kcLogin(pb, U1, PW1); await pb.waitForURL(u => host(u.href) === host(APP), { timeout: 30000 });
        await portal.goto(APP + '/account');
        const before = await portal.locator('table tr:has(th[scope=row])').count();
        await portal.locator('form[action="/account/sessions/end-others"] button').click();
        await portal.waitForURL(/flash=/, { timeout: 20000 });
        const flash = new URL(portal.url()).searchParams.get('flash');
        const after = await portal.locator('table tr:has(th[scope=row])').count();
        await pb.goto(`${AUTH}/realms/${encodeURIComponent(REALM || 'unknown')}/account/`);
        await sleep(4000);
        const other = await hasLoginForm(pb);
        const stillMe = await portal.locator('.pill:has-text("This device")').count();
        return { ok: flash === 'ended' && other && stillMe === 1, reason: `flash=${flash}; sessions ${before} -> ${after}; other browser asked to sign in again=${other}; this session kept=${stillMe === 1}` };
      } finally { await ctxB.close(); }
    });
    await check('devices: Apple profile download', portal, async () => {
      await portal.goto(APP + '/devices');
      await portal.evaluate(() => document.querySelectorAll('details').forEach(d => { d.open = true; }));
      const [d] = await Promise.all([portal.waitForEvent('download', { timeout: 20000 }), portal.locator('a[href="/devices/apple.mobileconfig"]').first().click()]);
      const t = fs.readFileSync(await d.path(), 'utf8');
      const ok = /\.mobileconfig$/.test(d.suggestedFilename()) && /com\.apple\.mail\.managed/.test(t) && t.includes(MAIL1) && ![PW1, PW2].some(x => t.includes(x));
      return { ok, reason: `${d.suggestedFilename()} ${t.length} bytes; mail payload=${/com\.apple\.mail\.managed/.test(t)}; caldav=${/caldav/.test(t)}; carddav=${/carddav/.test(t)}; has ${MAIL1}=${t.includes(MAIL1)}` };
    });
    await check('devices: Thunderbird config download', portal, async () => {
      await portal.evaluate(() => document.querySelectorAll('details').forEach(d => { d.open = true; }));
      const [d] = await Promise.all([portal.waitForEvent('download', { timeout: 20000 }), portal.locator('a[href="/devices/thunderbird.xml"]').first().click()]);
      const t = fs.readFileSync(await d.path(), 'utf8');
      return { ok: t.includes('<clientConfig') && /incomingServer/.test(t) && /outgoingServer/.test(t), reason: `${d.suggestedFilename()} ${t.length} bytes` };
    });
    await check('navigation: portal has its own home link', portal, async () => { const n = await portal.locator('a.brand[href="/"], nav a[href="/"]').count(); return { ok: n > 0, reason: `${n} home links` }; });
    await check('sign out ends the session everywhere (portal, Files, webmail)', portal, async () => {
      await portal.goto(APP + '/');
      await portal.locator('form.signout button').click();
      await sleep(4000);
      const out = [];
      const pa = await newPage(ctx1); await pa.goto(APP + '/account'); await sleep(2500); out.push(['portal', await hasLoginForm(pa)]); await pa.close();
      const pc = await newPage(ctx1); await pc.goto(CLOUD + '/files/spaces/personal'); await sleep(8000);
      out.push(['files', await hasLoginForm(pc) || !(await waitFor(async () => visibleAny(pc, ['#files-space-table', '.files-table', '.resource-table']), 3000))]); await pc.close();
      const pm = await newPage(ctx1); await pm.goto(MAILWEB); const inbox = await webmailReady(pm, 15000); out.push(['webmail', !inbox]); await pm.close();
      return { ok: out.every(x => x[1]), reason: out.map(([a, b]) => `${a}: ${b ? 'signed out' : 'STILL SIGNED IN'}`).join('; ') };
    });
  } else {
    for (const n of ['account page lists sessions incl. this device', 'account: "Sign out everywhere else" ends another session', 'devices: Apple profile download', 'devices: Thunderbird config download', 'sign out ends the session everywhere (portal, Files, webmail)']) await skip(n, 'not signed in');
  }

  // ---------------------------------------------------------------- cleanup (best effort, own login) ------------------------------
  section = 'cleanup';
  if (st.signedIn1) {
    await check('remove audit files', null, async () => {
      const ctxC = await mkCtx(); const pc = await newPage(ctxC);
      try {
        await pc.goto(APP + '/'); await kcLogin(pc, U1, PW1); await pc.waitForURL(u => host(u.href) === host(APP), { timeout: 30000 });
        await filesHome(pc);
        await waitFor(async () => (await cloudApi(pc, 'GET', '/graph/v1.0/me/drive')).status === 200, 30000, 2000);
        const names = [folder, txtName, txtRenamed, ...Object.values(st.office).map(o => o.name)];
        const res = [];
        for (const n of names) {
          let s = 0;
          for (let i = 0; i < 8 && ![204, 404].includes(s); i++) { s = (await cloudApi(pc, 'DELETE', n)).status; if (![204, 404].includes(s)) await sleep(3000); }
          res.push(`${n}: ${s}`);
        }
        return { info: true, reason: res.join('; ') };
      } finally { await ctxC.close(); }
    });
  }

  await browser.close();
  finish(started);
})().catch(e => { console.log('FATAL ' + redact(String(e && e.stack ? e.stack.split('\n').slice(0, 3).join(' | ') : e))); try { finish(null); } catch (_) { /* ignore */ } process.exit(0); });

function finish(started) {
  const totals = { PASS: 0, FAIL: 0, INFO: 0 };
  for (const r of results) totals[r.status]++;
  const out = { tool: 'stack_functional.cjs', started, finished: new Date().toISOString(), domain: D, entry_ip: IP, users: [U1, U2], totals, checks: results, look };
  fs.writeFileSync(path.join(OUT, 'results.json'), JSON.stringify(out, null, 2));
  console.log('\n================ SUMMARY ================');
  let cur = '';
  for (const r of results) { if (r.section !== cur) { cur = r.section; console.log(`\n${cur.toUpperCase()}`); } console.log(`  ${r.status.padEnd(4)} ${r.name}${r.status !== 'PASS' && r.reason ? '  (' + r.reason + ')' : ''}`); }
  if (look.length) {
    console.log('\nLOOK (title | background | font)');
    for (const l of look) console.log(`  ${l.app.padEnd(26)} ${l.error ? 'error: ' + l.error : `"${l.title}" | ${l.background}${l.main_background ? ' (main ' + l.main_background + ')' : ''} | ${l.font_family}`}`);
  }
  console.log(`\nTOTAL ${results.length} checks: ${totals.PASS} PASS, ${totals.FAIL} FAIL, ${totals.INFO} INFO`);
  console.log(`results: ${path.join(OUT, 'results.json')}  screenshots: ${SHOTS}`);
  process.exit(0);
}
