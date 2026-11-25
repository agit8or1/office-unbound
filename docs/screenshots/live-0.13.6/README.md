# officeunbound8 after the in-place change (0.13.6, job 9dbe8139), 2026-11-25

Real deployment, signed in as the test person `doctest` through Keycloak; nothing injected or forced. Each app as it renders with the
browser's light or dark preference (Chromium `prefers-color-scheme`), 1600x900 and 390x844. `report.json`: final URL, computed
background, horizontal overflow for every shot (none overflows).

- Portal: follows the browser (light `#f7f5f0`, dark `#0e151f`), desktop and phone.
- Files: follows the browser (light `#ffffff`, dark `#1a2534`).
- Webmail (mail, calendar, contacts): package 5.2-ou5 (pin in the job's `pkg.install_pinned`). The first capture was light in both
  because `doctest` had a stored choice `light` (a stored choice wins over the default). After setting doctest's own appearance to
  System (the call Settings > Appearance makes, `Grommunio.core.DarkMode.setMode('system')`), webmail follows the browser: light
  browser light, dark browser dark (`data-theme` unset, `dark-mode` class, canvas `#121212` under the navy skin). The desktop
  mail/calendar/contacts shots are from after that change; the phone mail shots from before it. Visible gap: the dark folder tree is
  a warmer grey than the navy panes.
- Chat: signed in end to end (chat → Keycloak → MAS consent → Element home), Office Unbound light theme with the action teal tiles.
  These two shots were taken before the public certificate covered chat, in a throwaway browser profile that trusts the officeunbound8
  deployment CA (verification on). Afterwards the certificate was issued again with chat, matrix and mas (Let's Encrypt, 2026-11-25):
  chat, mas and app now verify with the system trust store. The dark shot is a second session of the same person: Element asks to
  confirm the identity (cross-signing) on its own stock background, which our theme does not replace.
