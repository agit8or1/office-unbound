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
- Notifications (0.13.1): a bell in the top bar on every page with the Files notifications (shares, space membership), read
  server-side from the endpoint Files' own bell uses (`/ocs/v2.php/apps/notifications/api/v1/notifications`, OpenCloud 9.1.0 userlog),
  at most once a minute per session; the text is OpenCloud's, shown escaped. Dismissing stays in Files (no write from the portal).
  Mail and calendar reminders are not included (no verified mailbox source, see limitations).

## Dashboard (`home.html`)

Welcome line with the date and the two most used actions; app tiles; a 12-column widget board (4/4/4 then 8/4; 6/6 below
1280 px; one column below 760 px): Inbox, This week, Quick create, Recent files (live), Shared with me (live). Widgets can be hidden
("Customise"); a hidden widget's data is not even requested. Search (`/search`) is a real search of the user's files and folders.

Honesty rule: nothing is shown that was not read. Mail and calendar have no dashboard data source yet, so their widgets say so and
offer working actions (Compose opens a new message, New event opens the calendar). Tasks and Notes are not shown: no such app is
deployed. Admin and ICS information never appears on the user dashboard.
- Favourites (0.13.1): the files and folders starred in Files, from the same search Files' own Favourites view sends (KQL
  `is:favorite`, recorded on officeunbound8); "All favourites" opens that view. Recent files spans two rows on wide screens with
  Favourites and Shared with me stacked beside it; the first row (Inbox, This week, Quick create) has equal heights.

## Upstream limitations (stage 1)

- Webmail, calendar and contacts (grommunio-web) and Files (OpenCloud) keep their own layouts; they share the tokens through their
  supported theming hooks (grommunio-web `/brand/brand.css`, OpenCloud theme + `web.config.styles`) and the "Dashboard" control
  back to the portal. Stage 2 restyles them further through the same hooks only (no DOM scripting, no upstream fork).
- The theme choice is per app, not the portal's switch (the apps cannot read the portal's cookie without a script in their pages):
  grommunio-web uses its own saved setting (`grommunio/v1/main/dark_mode`; Light, Dark or System under its Settings, read in
  `client/grommunio/core/DarkMode.js`), OpenCloud its own theme choice. Until a user chooses, both follow the browser like the portal's
  default: OpenCloud does so itself (fresh profile, live: surface `#ffffff` light, `#18263a` dark), webmail from 5.2-ou5 through the
  Office Unbound plugin's sysadmin default `dark_mode = system` (upstream's default is light; a stored choice wins over the default).
  Chat opens light: Element applies a custom theme only with its system-theme setting off.
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
| List search | a visible field (the field border as an inset shadow, so ExtJS measures nothing new; teal ring on focus); it was borderless |

Upstream specifics that needed matching selectors (found with a rule probe on officeunbound8): the menu's uppercase comes from
`#grommunio-mainmenu.grommunio-maintabbar > .x-toolbar-ct .x-btn button.x-btn-text`; dark mode colours today's date gold
(`.x-date-today .x-date-date`), the tab strip `--dm-bg` and the picker's Today button `--dm-selected`, all `!important`.

Not changed: the reading pane's content, message compose, the settings pages and dialogs (upstream defaults with the shared tokens).

## Stage 2: Files (OpenCloud Web skin)

Through `web.config.styles` (`opencloud.css`, "Suite redesign" block): colours, borders, outlines and shadows only (enforced by
`test_brand.py::test_the_files_redesign_restyles_without_touching_opencloud_layout`). Selectors from the deployed build's own styles.

| Area | Change |
|---|---|
| Navigation | the selected place on `--ou-sel` with the 3px teal bar (was a white card with an outline) |
| Tabs (Shares) | the chosen tab in ink with a teal line |
| Text fields, filters | the field border `--ou-field` (was the muted text colour: a bright outline in dark); focus ring in the action teal (was lilac) |
| File list | a selected row keeps the selection colour and gets the teal bar (`tr.oc-table-highlighted`; seen in the build, not on screen: the test account has no files) |

Focus: text fields focus in the action teal in every app (the portal's own fields were copper; copper stays the focus colour of
links and buttons).

Field borders (all apps): `--ou-field` (light `#90856f`, dark `#607a9d`) is at least 3:1 on every surface a field sits on (WCAG 1.4.11,
`test_field_borders_reach_3_to_1_on_every_surface_a_field_sits_on`); the line tokens stay for separators. Used by the portal's inputs,
the sign-in fields, Files and the webmail search. Evidence: `docs/screenshots/files-v5/` (`before-*` = the deployed skin and palette; `after-*` = the 0.13
palette and this block added in the browser only, the deployment unchanged).

## Sign-in page (Keycloak theme)

The fields sit on the suite's raised surface with the shared line colour; focus underline in the action teal (PatternFly's dark grey
`#353535` field and blue underline before). Through PatternFly's own `--pf-v5-c-form-control--*` properties in the theme's stylesheet
(`keycloak-login.css`, `keycloak-account.css`), nothing else changed. Evidence: `docs/screenshots/signin-v5/` (live sign-in page,
1440 and 390 wide, light and dark; `after-*` with the new stylesheet added in the browser only, so its logo URL does not resolve there).

## Chat (Element Web custom themes)

Element's supported runtime theming (`setting_defaults.custom_themes` in its `config.json`, docs/theming.md of element-web 1.12.35):
two themes, "Office Unbound" and "Office Unbound Dark", generated from the shared tokens (`brand.element_themes`, rendered by
`configure.element_config`): navy sidebar, the side layer for the room list, the surface for the timeline, the action teal as accent.
Limits: Element applies a custom theme only with its "match system theme" setting off, so chat opens in the light theme and each user
can choose the dark one under Settings, Appearance; Element keeps its own fonts (theme font faces need font files on the chat front).
Accent contrast (checked against the deployed bundle, `theme-dark-custom.css` of the element-web image): Element paints white text on
its accent (home page buttons, toasts, search highlights) and uses the same accent as text on the timeline (29 rules). With the dark
action teal `#6cb8b2`, white text on it was 2.3:1 (Element's own default `#0dbd8b`: 2.4:1). No single teal reaches 4.5:1 for both, so
the accent is `brand.fill_shade(action)`: the lightest shade of the action teal with white text at 3:1 (WCAG large text and UI
components), dark `#4ea29b`; as text it stays at 4.5:1 or more on the timeline and the room list (`test_brand.py`). Light keeps the
action teal (white 6.2:1). Known gap: normal-size white text on the dark accent is below 4.5:1, and the accent as text on Element's
menus and the selected room is about 4.3:1 and 3.6:1. Element's compound text and focus colours keep the brighter action teal.
Not yet seen in a browser: chat reaches officeunbound8 with the in-place change; screenshots then.

## Evidence

Screenshots (local preview of the real portal app against the test suite's mocks): `docs/screenshots/portal-v5/` (`before-*` =
portal 0.4.0; the rest = 0.5.0 at 2560x1440, 1920x1080, 1366x768, tablet and phone, light and dark, open menus, search). No
horizontal scrolling at any size (checked by the screenshot script). Account, devices and About pages in the new shell at 1440 and 390
wide, light and dark (`account-*`, `devices-*`, `about-*`); the devices page used to scroll sideways on a phone (its setting tables
widened the `.stack` grid), fixed with `grid-template-columns: minmax(0, 1fr)`.

Apps (officeunbound8, signed in as the `doctest` user, 1600x900): `docs/screenshots/apps-v5/` (`before-*` = the deployed skin;
`after-*` = the stage-2 `brand.css` added in the browser only, the deployment unchanged; dark = the webmail's own `dark-mode`
class, as when the user picks Dark in its settings).
