# Office Unbound design system and app shell

Owner brief 2026-11-23 ("Major UI/UX Redesign"): one coherent product, a useful dashboard, differentiated dark surfaces, light mode
equally polished, honest data only. This file is the design reference; the tokens themselves live in ONE file.

## Tokens: `blueprints/catalog/templates/brand/ou-brand.css`

The only definition. `portal/app/static/portal.css` and `ics/frontend/src/style.css` carry copies that `ics/tests/test_brand.py`
keeps equal, and `ics/ics/deploy/brand.py` renders every app skin (Keycloak, OpenCloud, webmail) from it. Text tokens are AA
(>= 4.5:1) on every surface in both themes, checked by the same test.

| Layer (back to front) | Token | Light | Dark |
|---|---|---|---|
| App bar (stays dark in both themes) | `--ou-bar-bg` | `#14243a` navy | `#080d14` charcoal |
| Page canvas | `--ou-bg` | `#f7f5f0` warm paper | `#0e151f` |
| Side panels | `--ou-side` | `#f4f2ed` | `#121a26` |
| Cards / widgets | `--ou-surface` | `#ffffff` | `#1a2534` |
| Menus, hover | `--ou-raised` | `#fbfaf7` | `#212e40` |
| Selected rows | `--ou-sel` | `#e4ebf2` | `#1f3d4a` |

Accents: copper `--ou-accent` is the brand (mark, top-bar "New", links); muted teal `--ou-action` is for primary buttons and
selected states (today in the week strip, the chosen theme). Status: `--ou-ok` green, `--ou-warn` amber, `--ou-bad` restrained red.
Every app has one restrained colour (`--ou-app-mail`, `-calendar`, `-contacts`, `-files`, `-doc`, `-sheet`, `-slide`, `-chat`),
used for its icon only, never for large areas. Type: IBM Plex Sans/Mono, Source Serif for page titles, self-hosted (SIL OFL).

Theme: System by default (`prefers-color-scheme`); the portal's Appearance switch (account menu) sets `data-theme` on `<html>`,
which wins both ways. Stored per browser in the `ou_prefs` cookie (`<theme>:<hidden widgets>`, HttpOnly, read only by the portal).

## App shell (portal `base.html`)

One bar: mark + organisation name, app switcher (Dashboard, Mail, Calendar, Contacts, Files, Chat when deployed; collapses into an
Apps menu below 820 px), file search, "New" (document, spreadsheet, presentation, email, event, upload/folder), account menu
(account and security, devices, Organisation admin for tenant admins only, Appearance, Sign out). Menus are `<details>`: the
portal's content security policy allows no script, so everything works without JavaScript and with the keyboard.

## Dashboard (`home.html`)

Welcome line with the date and the two most used actions; app tiles; a 12-column widget board (4/4/4 then 8/4; 6/6 below
1280 px; one column below 760 px): Inbox, This week, Quick create, Recent files (live), Shared with me (live). Widgets can be hidden
("Customise"); a hidden widget's data is not even requested. Search (`/search`) is a real search of the user's files and folders.

Honesty rule: nothing is shown that was not read. Mail and calendar have no dashboard data source yet, so their widgets say so and
offer working actions (Compose opens a new message, New event opens the calendar). Tasks and Notes are not shown: no such app is
deployed. Admin and ICS information never appears on the user dashboard.

## Upstream limitations (stage 1)

- Webmail, calendar and contacts (grommunio-web) and Files (OpenCloud) keep their own layouts; they share the tokens through their
  supported theming hooks (grommunio-web `/brand/brand.css`, OpenCloud theme + `web.config.styles`) and the "Dashboard" control
  back to the portal. Stage 2 restyles them further through the same hooks only (no DOM scripting, no upstream fork).
- The theme choice is per app, not the portal's switch (the apps cannot read the portal's cookie without a script in their pages):
  grommunio-web uses its own saved setting (`grommunio/v1/main/dark_mode`: light by default; Light, Dark or System under its
  Settings, read in `client/grommunio/core/DarkMode.js`), OpenCloud its own theme choice.
- Unread counts and the next meeting need a mailbox data source for the portal (EWS/IMAP with the user's sign-in): not verified
  yet, so not shown.
- Calendar has no "new event" deep link in grommunio-web 5.2; "New event" opens the calendar.

## Stage 2: Mail, Calendar, Contacts (grommunio-web skin)

Through the one supported hook, `/brand/brand.css` (`grommunio.css` adapter, "Suite redesign" block). The webmail is ExtJS, which lays
out every panel in pixels from its own measurements, so the block changes colours, borders, type and inset shadows only; no size,
margin, padding, position or display (enforced by `ics/tests/test_brand.py::test_the_webmail_redesign_restyles_without_touching_extjs_layout`).

| Area | Change |
|---|---|
| Main menu | sentence case like the portal and Files; active app on `--ou-bar-2` with the copper underline |
| Toolbar | own surface and rule; secondary icons quieter; the New button keeps the brand colour |
| Folder, calendar and address-book pane | the side layer (`--ou-side`); selection = `--ou-sel` with a 3px teal bar, bold name; unread counts teal |
| "Open shared ..." buttons | quiet secondary buttons instead of tinted blocks |
| Lists | muted column titles; unread rows marked with a teal bar; calm empty state |
| Panes | the canvas shows between list, reading pane and folders; tab strip on `--ou-bg2` (was near-black in dark) |
| Calendar | today in teal in the date picker and the grid; week numbers muted (were red in dark); Today button secondary |

Upstream specifics that needed matching selectors (found with a rule probe on officeunbound8): the menu's uppercase comes from
`#grommunio-mainmenu.grommunio-maintabbar > .x-toolbar-ct .x-btn button.x-btn-text`; dark mode colours today's date gold
(`.x-date-today .x-date-date`), the tab strip `--dm-bg` and the picker's Today button `--dm-selected`, all `!important`.

Not changed: the reading pane's content, message compose, the settings pages and dialogs (upstream defaults with the shared tokens);
Files keeps its stage-1 skin (its colours come from the token-derived `theme.json` roles).

## Sign-in page (Keycloak theme)

The fields sit on the suite's raised surface with the shared line colour; focus underline in the action teal (PatternFly's dark grey
`#353535` field and blue underline before). Through PatternFly's own `--pf-v5-c-form-control--*` properties in the theme's stylesheet
(`keycloak-login.css`, `keycloak-account.css`), nothing else changed. Evidence: `docs/screenshots/signin-v5/` (live sign-in page,
1440 and 390 wide, light and dark; `after-*` with the new stylesheet added in the browser only, so its logo URL does not resolve there).

## Evidence

Screenshots (local preview of the real portal app against the test suite's mocks): `docs/screenshots/portal-v5/` (`before-*` =
portal 0.4.0; the rest = 0.5.0 at 2560x1440, 1920x1080, 1366x768, tablet and phone, light and dark, open menus, search). No
horizontal scrolling at any size (checked by the screenshot script).

Apps (officeunbound8, signed in as the `doctest` user, 1600x900): `docs/screenshots/apps-v5/` (`before-*` = the deployed skin;
`after-*` = the stage-2 `brand.css` added in the browser only, the deployment unchanged; dark = the webmail's own `dark-mode`
class, as when the user picks Dark in its settings).
