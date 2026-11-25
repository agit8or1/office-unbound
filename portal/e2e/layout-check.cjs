// Layout check of the portal (UI audit 2026-11-25): no page-level horizontal scroll and nothing outside the viewport at phone and desktop
// widths, light and dark, on every user and admin page, with each shell menu open.
//   PORTAL=http://127.0.0.1:8795 SESSION=<value of the __Host-ou_portal cookie> NODE_PATH=<playwright> node layout-check.cjs
// Run it against a local portal with the test suite's mocks (never a live deployment's session). Exit code 1 on any failure.
// Elements inside .tablewrap may scroll internally (allowed above 640px); closed <details> panels are ignored.
const { chromium } = require('playwright');
const BASE = process.env.PORTAL || 'http://127.0.0.1:8795';
const SESSION = process.env.SESSION;
if (!SESSION) { console.error('SESSION is required'); process.exit(2); }
const PAGES = ['/', '/account', '/devices', '/about', '/search?q=budget', '/admin', '/admin/users', '/admin/users/new', '/admin/groups',
  '/admin/addresses', '/admin/shared', '/admin/storage', '/admin/domains?check=1', '/admin/branding', '/admin/requests'];
const MENUS = ['details.switcher', 'details.create', 'details.notes', 'details.profile'];
const WIDTHS = (process.env.WIDTHS || '320,390,768,1366').split(',').map(Number);
let pass = 0, fail = 0;
(async () => {
  const b = await chromium.launch();
  for (const theme of ['light', 'dark']) for (const w of WIDTHS) {
    const ctx = await b.newContext({ viewport: { width: w, height: 900 }, colorScheme: theme,
      extraHTTPHeaders: { cookie: `__Host-ou_portal=${SESSION}; ou_prefs=${theme}:` } });
    const p = await ctx.newPage();
    for (const path of PAGES) {
      const r = await p.goto(BASE + path, { waitUntil: 'networkidle' });
      if (r.status() === 404 && path.startsWith('/admin')) continue;          // no admin area configured
      const menus = path === '/' ? [null, ...MENUS] : [null];
      for (const m of menus) {
        if (m) { if (!(await p.locator(m + ' > summary').isVisible())) continue; await p.click(m + ' > summary'); }
        const bad = await p.evaluate(() => {
          const vw = document.documentElement.clientWidth;
          const out = [...document.querySelectorAll('body *')].filter(e => {
            const b = e.getBoundingClientRect();
            return b.width && b.right > vw + 1 && !e.closest('.tablewrap, details:not([open])');
          }).slice(0, 3).map(e => e.tagName.toLowerCase() + '.' + String(e.className).split(' ')[0]);
          return { scroll: document.documentElement.scrollWidth - vw, out };
        });
        const ok = bad.scroll <= 0 && bad.out.length === 0;
        ok ? pass++ : fail++;
        if (!ok) console.log(`FAIL ${theme} ${w} ${path}${m ? ' ' + m : ''}: scroll ${bad.scroll} ${bad.out.join(', ')}`);
        if (m) await p.click(m + ' > summary');
      }
    }
    await ctx.close();
  }
  console.log(`${pass} passed, ${fail} failed`);
  await b.close();
  process.exit(fail ? 1 : 0);
})();
