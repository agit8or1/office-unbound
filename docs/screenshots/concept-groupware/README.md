# Groupware concept alignment (2026-11-26/27): Mail, Calendar, Contacts

Real deployment officeunbound8 (release 0.13.12, webmail package 5.2-ou6), signed in as `doctest`, Chromium 1600x900 (1366x768 where named),
browser light or dark preference (doctest's webmail appearance is "System"). Calendar data: nine `[OU-TEST]` appointments created for these
captures in the week of 23 Nov 2026 (timed, overlapping, outside working hours, weekend, all-day, multi-day all-day) and deleted afterwards.
The browser runs in UTC.

- `before-*`: **live, as deployed** (0.13.12 skin, 5.2-ou6). Nothing injected.
- `after-*`: **browser-injected preview**, not deployed. The deployed `/brand/brand.css` is disabled in the page and the skin rendered by
  `ics/ics/deploy/brand.py` (`grommunio_brand`) from this branch's `grommunio.css` is added with `page.addStyleTag`; the oudashboard plugin
  script of this branch (5.2-ou7) is served in place of the deployed one by Playwright request routing (`page.route`, this browser only). The
  server, the package and doctest's settings are unchanged.
- `*-cal-nowline-*`: the browser clock alone set to Fri 27 Nov 2026 11:20 (`page.clock.setFixedTime`) so the current-time line falls in the
  visible hours; `before-` without, `after-` with the preview.

Views: `mail`, `contacts`, `cal-day`, `cal-workweek`, `cal-week`, `cal-month`, `cal-list` (agenda), each `-light` / `-dark`. The calendar
was opened through the dashboard deep link (`/web/?action=context&view=calendar`) and switched with the toolbar's view buttons.
No page scrolls sideways at 1600 or 1366 (`scrollWidth == clientWidth`, recorded by the capture script).
