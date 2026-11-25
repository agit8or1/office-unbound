# officeunbound8 after the in-place change (0.13.6, job 9dbe8139), 2026-11-25

Real deployment, signed in as the test person `doctest` through Keycloak; nothing injected or forced. Each app as it renders with the
browser's light or dark preference (Chromium `prefers-color-scheme`), 1600x900 and 390x844. `report.json`: final URL, computed
background, horizontal overflow for every shot (none overflows).

- Portal: follows the browser (light `#f7f5f0`, dark `#0e151f`), desktop and phone.
- Files: follows the browser (light `#ffffff`, dark `#1a2534`).
- Webmail (mail, calendar, contacts): light in both. The package is 5.2-ou5 (pin in the job's `pkg.install_pinned`), but `doctest`
  has a stored choice `grommunio/v1/main/dark_mode = light` (read in the page: `data-theme="light"`, settings model `light`), and a
  stored choice wins over the new default. Follow-the-browser is not yet shown on a person without a stored choice.
- Chat: signed in end to end (chat → Keycloak → MAS consent → Element home), Office Unbound light theme with the action teal tiles.
  The public certificate does not cover chat/matrix/mas yet (issued before chat), so these two shots use a throwaway browser profile
  that trusts the officeunbound8 deployment CA (verification on). The dark shot is a second session of the same person: Element asks to
  confirm the identity (cross-signing) on its own stock background, which our theme does not replace.
