# Upstream modifications inventory

Every change Office Unbound makes to, or on top of, an upstream application: why, which upstream version it was made for, what to check on
an upgrade, the automated tests and how to roll it back. Owner brief 2026-11-26 section 20. Preference order: configuration, themes,
plugins/extensions, shared components, adapters, and minimal documented patches only when nothing else works.

## grommunio-web

Upstream: grommunio-web **5.2** (tag `grommunio-web-5.2`, commit `dd9029d9`), AGPL-3.0-or-later; package `ou-grommunio-web`
(`blueprints/build/grommunio-web/recipe.yaml`). Office Unbound code shipped with it (the oudashboard plugin) is AGPL-3.0-or-later as well;
the About/licence notice and upstream copyright lines are kept (recipe `branding`).

| # | Change | Mechanism | Why | Tests |
|---|---|---|---|---|
| 1 | Product name, logos, titles (patches 0001, 0003) | source patches in the package build | rebrand to "Office Unbound Web"; strings and assets only | `ics/tests/test_brand.py`, package pipeline |
| 2 | `?action=context&view=…` deep link (patch 0002, 5.2-ou2, fixed 5.2-ou6) | source patch: a new URL action + a whitelist in `util.php` | portal tiles open Calendar/Contacts directly; upstream supports only `mailto`/`profile` | `ics/tests/test_uiaudit_groupware.py` |
| 3 | Brand stylesheet `/brand/brand.css` | upstream's documented `--brand-*` hook, rendered by `ics/ics/deploy/brand.py` from `blueprints/catalog/templates/brand/grommunio.css`, written by the node agent (cfg.gromox `brand`) | the suite's tokens, fonts, light/dark surfaces | `test_brand.py`, `test_uiaudit_groupware.py`, `test_concept_groupware.py` |
| 4 | oudashboard plugin | upstream plugin API (`plugins/oudashboard`, insertion points `main.maintabbar.left`, `navigation.north`; hook `server.core.settings.init.before`) | Dashboard button to the portal; sysadmin default `dark_mode = system`; **(5.2-ou7)** the app's primary action at the top of the side column | `test_brand.py`, `test_concept_groupware.py` |

### Concept alignment 2026-11-26 (calendar grid, primary action)

**Calendar grid (stylesheet, row 3).** The calendar paints its cells, date headers and appointments with inline colours from the calendar's
colour scheme (`CalendarDaysView`, `CalendarBoxView`, `AppointmentDaysView`), and upstream dark mode darkens the light cells with
`filter: invert(.85) hue-rotate(180deg)` (`client/resources/css/darkmode.css`). The skin overrides those colours with `!important` and drops
the filter, so the grid uses the suite's surface, canvas and line tokens in both themes: neutral date headers with today in the accent, a
quieter half-hour rule, appointments as a tint of their calendar's colour with a solid bar of it, the current-time line in the accent.
Only colours, borders as colours, inset shadows and background images change; no measured geometry (test enforced).
Upgrade notes: re-check, in a new upstream version, (a) that working-hours cells still carry the scheme's fixed `stripworking` colour
`#ffffff` inline (the skin's `[style*="#ffffff" i]` matcher; `ColorSchemes.js`), (b) the class names `k-line-N`, `k-day-N`, `k-today`,
`k-html-header-background`, `k-appointment-box`, `k-calendar-timestrip-indicator-*`, `grommunio-calendar-boxview`, (c) the dark-mode filter
rule being neutralised, (d) that the half-hour rule is still every even `k-line-N` at the default 30-minute zoom (other zoom levels keep a
uniform line colour). The tests read the upstream 5.2 source when it is present and fail on (a), (c) and the indicator.
Rollback: revert `grommunio.css`; the skin is re-rendered and rolled out with the brand digest (in place, `deployment.change`).

**Primary action (plugin, row 4, package 5.2-ou7).** `navigation.north` components are upstream's supported way to put a component at
the top of the side column (the calendar's date picker uses it). The plugin adds one ExtJS button per item-creating context ("New message",
"New event", "New contact", "New task", "New note"), each tied to its context through `navigationContext` (upstream shows it only while
that context is active) and calling the upstream action the toolbar's New menu calls (`Grommunio.<context>.Actions.openCreate…Content`).
ExtJS sizes it (`height: 36`, `margins`), and the plugin moves its buttons in front of the other north components (the date picker) with
`Container#insert` before the panel renders, so ExtJS lays everything out itself. The stylesheet paints it (accent, white 600 text) and,
only while it exists (`:has(.ou-primary-new)`), turns the toolbar's New split button from copper to the bar navy: the split button stays,
because its menu holds every item type (meeting request, distribution list, …). Labels are English (`_()` with strings upstream does not
translate). Upgrade notes: re-check the insertion point name, `navigationContext` handling in `NavigationPanel.js`, and the five action
names. Rollback: package 5.2-ou6 (the skin degrades by itself: without the button the toolbar New stays copper).

### Assessed and not done (no supported mechanism)

- **48 px top bar.** The main tab bar is 36 px by constructor constants (`MainViewport.createTopbarContainer`: `height: 36,
  boxMinHeight: 36, boxMaxHeight: 36`, toolbar 54 px). No setting or insertion point changes it; CSS would desynchronise ExtJS's own layout
  (forbidden), and a plugin resizing the viewport at runtime would be a geometry override in all but name. Kept at 36 px with the suite's
  navy, the Dashboard pill and the app tabs (Mail, Calendar, Contacts, Tasks, Notes) as the bar's "app name" part.
- **64 px app rail.** The viewport is a border layout whose west region is the navigation panel; Ext 3's border layout allows one item per
  region and grommunio-web exposes no viewport-level insertion point (only `main.content.tabpanel`, `main.maintabbar.*`, `main.toolbar.*`,
  `navigation.*`). A rail would need a source patch to `MainViewport.js`. Closest consistent alternative in place: the app tabs in the bar
  (the rail's Mail/Calendar/Contacts items) plus the Dashboard button to the portal, whose own rail reaches Files, Docs and Chat.
- **Global search in the bar.** grommunio-web's search is per list (the field above each list, styled as the suite's field). No hook places
  a field in the tab bar that drives it.
- **Mail list rows with initials and preview text.** The list request skips the body (`MailGrid#viewConfigGetRowClass` renders only the
  subject in compact rows), so there is no preview text to show without a server change; the only column hook,
  `context.mail.griddefaultcolumn`, appends columns after the flag column, so an initials column would sit at the far right.
- **Selected-view marker in the toolbar.** Day/Work week/Week/Month/List buttons carry no pressed class (2026-11-25 finding, unchanged).
