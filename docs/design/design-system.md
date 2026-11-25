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

Accents: copper `--ou-accent` is the brand (mark, the "New" create button of an app bar, the active app underline); muted teal
`--ou-action` is for primary buttons, links (`--ou-link`), focus (`--ou-focus`) and selected states (today in the week strip, the
chosen theme). See "Roles" below (UI audit 2026-11-25: links were copper in some places and teal in others). Status: `--ou-ok` green, `--ou-warn` amber, `--ou-bad` restrained red.
Every app has one restrained colour (`--ou-app-mail`, `-calendar`, `-contacts`, `-files`, `-doc`, `-sheet`, `-slide`, `-chat`),
used for its icon only, never for large areas. Type: IBM Plex Sans/Mono, Source Serif for page titles, self-hosted (SIL OFL).

Theme: System by default (`prefers-color-scheme`); the portal's Appearance switch (account menu) sets `data-theme` on `<html>`,
which wins both ways. Stored per browser in the `ou_prefs` cookie (`<theme>:<hidden widgets>`, HttpOnly, read only by the portal).

### Roles (UI audit 2026-11-25)

| Role | Token | Light | Dark | Use |
|---|---|---|---|---|
| Primary action | `--ou-action` / `--ou-action-hover` / `--ou-action-ink` | `#2d6a68` / `#245654` / white | `#6cb8b2` / `#86c7c1` / `#0e151f` | primary buttons, selected states, the selected-item bar |
| Brand accent | `--ou-accent` / `--ou-accent-hover` (`--ou-a` = organisation accent if set) | `#a9481f` / `#923d1a` | `#ec9a70` / `#f0a982` | the mark, the "New" create button of an app bar, the active app underline. Not for ordinary buttons or links |
| Link | `--ou-link` | `#2d6a68` | `#6cb8b2` | text links, underlined in running text (>= 4.5:1 on every surface and on `--ou-sel`) |
| Focus | `--ou-focus`, `--ou-focus-w` 2px, `--ou-focus-offset` 2px | `#2d6a68` | `#6cb8b2` | the one focus ring of every control (>= 3:1 on every surface); inside the navy bar `--ou-bar-text` |
| Information | `--ou-info` / `--ou-info-bg` | `#3e5878` / `#e2e8f0` | `#9fb8d6` / `#22344c` | neutral notices (the console's `--info` values) |
| Healthy / warning / critical | `--ou-ok`, `--ou-warn`, `--ou-bad` + `-bg` | | | status text, badges, small tints; a full-width tinted block only for a real, current problem |
| Overlay | `--ou-scrim` | navy 45 % | black 60 % | behind dialogs and the mobile drawer |

`--ou-teal` equals `--ou-action` (kept for existing references). Checked by `ics/tests/test_uiaudit_system.py` (contrast of every role on
`bg`, `bg2`, `side`, `surface`, `raised`, `sel`, both themes; the forced dark block equals the system one).

Surfaces: the layer table above, back to front. A panel is one of these layers, never an ad-hoc grey, beige, blue or black. Side panels
(`--ou-side`) sit next to the canvas or cards and are separated by a `--ou-line` rule (the side/canvas step alone is 1.03:1 light, 1.05:1
dark: not visible without the rule). Selection = `--ou-sel` + a 3px `--ou-action` bar on the leading edge + weight 500/600: the tint alone is
only 1.07-1.5:1 against its neighbours. Separators `--ou-line`; control outlines `--ou-line-2`; text-field borders `--ou-field` (3:1).

### Typography

IBM Plex Sans for everything, Plex Mono only for technical values (hashes, versions, IP addresses, paths, code); Source Serif only for the
portal's greeting. Weights 400 (body), 500 (labels, nav items, buttons), 600 (headings, numbers); no other weights, no letter spacing except
the uppercase overline (`--ou-fs-xs`, 600, .04em, used sparingly for group titles). Sentence case everywhere (buttons too: "Sign in").

| Step | Token | Size / line height | Use |
|---|---|---|---|
| xs | `--ou-fs-xs` | 12px / 1.5 | metadata, captions, table column headings, badges. Nothing is smaller |
| sm | `--ou-fs-sm` | 13px / 1.5 | secondary text, form labels, nav items, dense tables |
| md | `--ou-fs-md` | 14px / 1.5 | body, controls, table cells |
| lg | `--ou-fs-lg` | 16px / 1.25 | card, panel and dialog titles |
| xl | `--ou-fs-xl` | 20px / 1.25 | page titles (console, account, admin); the sign-in title on phones |
| 2xl | `--ou-fs-2xl` | 24px / 1.25 | the one top heading of a page (portal greeting, sign-in title) |

### Spacing and sizes

One 4px scale: `--ou-sp-1` 4, `-2` 8, `-3` 12, `-4` 16, `-5` 20, `-6` 24, `-8` 32, `-12` 48 px.

| Element | Value |
|---|---|
| Card padding | 16px (`sp-4`), 20px (`sp-5`) for a page's main card; gap between cards 16px |
| Page gutter | 24px desktop, 16px below 576px (the sign-in card, the portal, the console) |
| App bar | `--ou-bar-h` 46px |
| Toolbar | `--ou-toolbar-h` 44px |
| Buttons and fields | `--ou-control-h` 36px, `--ou-control-h-sm` 30px (bar controls, compact toolbars); padding 0 12px (`sp-3`) |
| Nav items | `--ou-nav-item-h` 32px, 8px gap icon/label |
| Table rows | `--ou-row-h` 40px; `--ou-row-h-dense` 32px for operations tables |
| Section header margin | 24px above, 12px below |
| Empty state | inside the region it describes, centred, 48px (`sp-12`) from the top; an icon of at most 48px, a sentence, one action |
| Dialogs | `--ou-dialog-w` 560px max, full width minus 16px gutters on phones |

### Radii, borders, shadows, focus

`--ou-radius-sm` 3px (buttons, fields, badges), `--ou-radius` 4px (cards, panels, tables), `--ou-radius-lg` 6px (menus, popovers, dialogs,
toasts), `--ou-radius-pill` for status pills and avatars only. Borders 1px. Shadows: none on cards in the canvas (border only) or
`--ou-shadow`; `--ou-shadow-lg` for floating layers (menus, dialogs, toasts). No glass, no blur, no gradients. Hover = the next layer
(`--ou-raised`/`--ou-bg2`); pressed/selected = `--ou-sel`; disabled = `--ou-muted` text, no outline change, `cursor: default`. Focus: a 2px
`--ou-focus` outline 2px outside the control (text fields: around the whole field, offset 0), never removed without a replacement.

### Icons

Standard: the in-repo 24x24 outline icons the portal (`portal/app/templates/_icons.html`) and the console (`ics/frontend/src/ui/icons.ts`)
already ship: stroke `currentColor`, round caps and joins, stroke width 1.75 (portal 1.7, console 1.8 today: within tolerance, new icons
1.75), no fill, no icon font, no CDN (ADR-0002). Their geometry is Lucide's; a missing glyph is taken from Lucide (ISC licence, FOSS) and
inlined in the same style, so the set never mixes families. Sizes: `--ou-icon-sm` 16px inline and in navigation, `--ou-icon` 18px toolbar
and icon buttons, `--ou-icon-lg` 20px app tiles and the app bar; larger only for an empty-state illustration (max 48px). Icons sit on the
text's centre line with an 8px gap. Every icon-only control has an `aria-label` and a tooltip (`title`); decorative icons `aria-hidden`.
Destructive actions use the label and `--ou-bad`, never the icon alone, and ask for confirmation. No emoji as icons.

Vendor icons stay where replacing them would need DOM changes or break the supported hooks: grommunio-web's sprite and SVG icons (ExtJS
measures them), OpenCloud Web's Remix icons, Element's Compound icons, Keycloak/PatternFly's Font Awesome eye toggle. They are recoloured
through the skins (muted for secondary actions), not replaced.

### Who owns what

| Surface | Layout owner | Styling hook (supported) | Adapter |
|---|---|---|---|
| Portal, dashboard, org admin | Office Unbound (`portal/`) | own templates and `portal.css` (token blocks copied verbatim) | none |
| ICS console | Office Unbound (`ics/frontend`) | own `style.css` (shared values mapped, `test_brand.py`) | none |
| Sign-in, account (Keycloak 26) | Keycloak/PatternFly 5 | theme "ou": `theme.properties` styles, messages | `keycloak-login.css`, `keycloak-account.css` |
| Mail, calendar, contacts (grommunio-web 5.2) | grommunio-web (ExtJS) | `/brand/brand.css` + oudashboard plugin | `grommunio.css` (colours/borders only) |
| Files, Docs (OpenCloud Web 8.2, Collabora) | OpenCloud | theme.json roles + `web.config.styles` | `opencloud.css`, `brand._roles` |
| Chat (Element Web 1.12) | Element | config.json `custom_themes` + `branding` | `brand.element_themes`, `brand.element_branding` |

Every adapter is generated by `ics/ics/deploy/brand.py` from `ou-brand.css`; no adapter contains a literal colour except Element's themes
(Element cannot read CSS custom properties: the values are filled in from the tokens at generation time).

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

## Files UI audit (2026-11-25, OpenCloud Web 8.2.2)

Hooks, read from the deployed web build: `theme.json` `designTokens` carries **colours (`roles` -> `--oc-role-*`) and `fontFamily` only**
(web-runtime design-system install); spacing, sizes, empty states, list density and the view mode have no theme option, so they are in
`opencloud.css`. OpenCloud lays out with CSS (Vue + Tailwind, nothing measured in script), so a small, scoped "Files UI audit" block may set
spacing and sizes; it sits before the colour-only stage-2 block (`test_uiaudit_files.py` limits its selectors and properties). No token
value changed.

| Area | Rule |
|---|---|
| Top bar | `#oc-topbar` redefines `--color-role-chrome`/`--color-role-on-chrome` as well as `--oc-role-*`: the Tailwind utilities read the `--color-role-*` copies that `:root` resolved once, so the phone search bar was paper under light text (Cancel invisible) |
| Search | scope chip ("All files") in `--ou-bar-text`, search button `--ou-bar-muted` on the `--ou-bar-2` field (both >= 4.5:1); the chip was ink on navy (invisible in light); the field's focus ring in `--ou-bar-text` (the fields' teal ring is under 3:1 on the light navy) |
| Phones (<= 640px) | the upstream logo is hidden: the icon-only Dashboard control already shows the mark (or the organisation logo); the inline rename pencil is hidden (Rename stays in the row menu), which gives names 28px more |
| Navigation | 39px items (were 45px); labels medium (500, were bold 700), the current place semibold (600) with the stage-2 selection bar |
| Empty states | the illustration 72px (was 120px), the block `min-height: min(45vh, 24rem)` instead of a 65vh centre; title 17px medium in ink, hint muted |
| File list | all column headings muted (Status, Tags, Actions were ink, the sortable ones muted); rename pencil on row hover, keyboard focus or selection for mouse users |
| Thumbnails | a `--ou-line` hairline on previews (text files render as white pages, glaring squares in dark) |

Kept upstream (no supported hook, or not a defect): the default view per folder (tiles/list from the URL `view-mode`), the column set per
width (OpenCloud's own breakpoints), middle truncation of long names with the full name as tooltip, the 120px illustrations' artwork and
the space reserved above the list for the batch-action bar. Evidence: `docs/screenshots/uiaudit-files/` (`before-*` = the deployed skin;
`after-*` = the generated `ou.css` of this branch injected in the browser only, the deployment unchanged).

## Sign-in page (Keycloak theme)

The fields sit on the suite's raised surface with the shared line colour; focus underline in the action teal (PatternFly's dark grey
`#353535` field and blue underline before). Through PatternFly's own `--pf-v5-c-form-control--*` properties in the theme's stylesheet
(`keycloak-login.css`, `keycloak-account.css`), nothing else changed. Evidence: `docs/screenshots/signin-v5/` (live sign-in page,
1440 and 390 wide, light and dark; `after-*` with the new stylesheet added in the browser only, so its logo URL does not resolve there).

UI audit 2026-11-25 (`docs/screenshots/uiaudit-system/signin-*`, 320/390/768/1366/1920, light and dark; `after-*` = the generated skin
injected in the browser only):
- Stale stylesheet in browsers: Keycloak serves theme resources under one URL per Keycloak build with a 30-day max-age and answers gzip
  requests from a cache it does not refresh when a theme file changes. officeunbound8 sent browsers a 7111-byte `ou.css` from before
  0.13.0 (PatternFly's `#36373a` fields and `#1fa7f8` focus line on screen) while the theme volume held the current 8618-byte file
  (served only to clients without gzip). The theme now names the skin by content (`ou-<sha256:10>.css`, `brand.versioned`; plain
  `ou.css` kept for pages rendered from theme properties read earlier). Keycloak caches theme properties until it restarts, so a brand
  change reaches the sign-in page after the identity service restarts (see known limitations).
- Primary button in the action teal (was copper), links `--ou-link`, one 2px `--ou-focus` ring around the whole field (was copper
  outline on the input plus PatternFly's 2px underline in teal/blue), the masthead's controls focus in the bar text colour.
- Phones: a 16px gutter around the card (it touched the screen edges, border and corners cut off) and a 20px title (24px from 576px).
- Sentence case: "Sign in", "Forgot password?", "Back to sign-in" (messages; upstream "Sign In", "Forgot Password?", "« Back to Login").
- Account console: the selected navigation item carries the teal bar like Files, webmail and the console (was copper).

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
Seen in a browser on officeunbound8 (2026-11-25, `docs/screenshots/live-0.13.6/`): sign-in through Keycloak and MAS, Element home in the
light theme with the action teal.

UI audit 2026-11-25 (`docs/screenshots/uiaudit-system/chat-*`; `after-*` = the generated config.json served to the browser only):
- Element's auth pages (sign-in, "Confirm your digital identity") showed its stock landscape photo, Element's logo and its Blog/Mastodon/
  GitHub links. config.json `branding` (element-web 1.12.35 `AuthPage`, `AuthFooter`, `AuthHeaderLogo`): `welcome_background_url` = a
  base64 SVG filled with `--ou-bar-bg` (Element writes the value unquoted into `url()`, so no plain SVG text), `auth_header_logo_url` =
  the mark, `auth_footer_links` = "Office Unbound Dashboard" to the portal (empty without a portal). Element always adds "Powered by
  Matrix" and the "Learn more" link to its own documentation (not configurable).
- Compound (Element's newer components) kept its near-black primary buttons ("Create recovery key", "Use another device") and in dark a
  `#101317` canvas (black secondary buttons on the navy card). The custom themes map `--cpd-color-bg-action-primary-*` and
  `--cpd-color-text-on-solid-primary` to the action teal and its ink (6.2:1 light, 8.0:1 dark), the canvas to `--ou-surface`, the subtle
  tints to `--ou-bg2`/`--ou-line`, the secondary outline to `--ou-line-2`, focus to `--ou-focus` (Element accepts any `--cpd-*` key).
- Limits: Element Web has no phone layout for these pages (at 390px the identity card is wider than the screen; the branding changes no geometry; Element
  points phone users to its mobile apps); fonts stay Element's (Inter): custom-theme font faces need font files the chat front does not
  serve, and data: URIs in config.json would add about 200 KB per theme to every load.

## Evidence

Screenshots (local preview of the real portal app against the test suite's mocks): `docs/screenshots/portal-v5/` (`before-*` =
portal 0.4.0; the rest = 0.5.0 at 2560x1440, 1920x1080, 1366x768, tablet and phone, light and dark, open menus, search). No
horizontal scrolling at any size (checked by the screenshot script). Account, devices and About pages in the new shell at 1440 and 390
wide, light and dark (`account-*`, `devices-*`, `about-*`); the devices page used to scroll sideways on a phone (its setting tables
widened the `.stack` grid), fixed with `grid-template-columns: minmax(0, 1fr)`.

Apps (officeunbound8, signed in as the `doctest` user, 1600x900): `docs/screenshots/apps-v5/` (`before-*` = the deployed skin;
`after-*` = the stage-2 `brand.css` added in the browser only, the deployment unchanged; dark = the webmail's own `dark-mode`
class, as when the user picks Dark in its settings).

## Groupware

## Files

## Portal

## Console (ICS) — UI audit 2026-11-25

The console keeps its own concept (graphite top bar, paper navigation, copper primary buttons) on the shared tokens; its copy
of the shared values is checked by `ics/tests/test_brand.py`, the form-field border `--field` (= `--ou-field`, 3:1 on every
console surface) by `ics/tests/test_console_tokens.py`. Built assets in `ics/ics/static` are rebuilt from the source in the
same branch (static drift 0).

| Element | Rule |
|---|---|
| Page title / card title / section label | 19 px 600 ink / 14 px 600 ink / 12.5 px 600 muted, sentence case (no uppercase tracking anywhere: nav groups, table heads, sub-heads) |
| Body / secondary / metadata | 14 px / 12.5 px muted; Plex Mono 12.5 px only for identifiers, versions, hashes and config |
| Cards | 16 px padding everywhere (flush cards: 16 px header inset = table cell inset), radius 4 px, 1 px line, no shadow |
| KPI strip | one bordered strip, hairlines between cells; label 12.5 px with a 16 px icon, value 22 px (20 px on phones), sub 12.5 px; 4 columns, 2 below 1100 px. Tone only on the value (and its icon): red = a real problem (critical health, nodes down, critical incidents), amber = needs attention (approvals waiting), everything healthy or idle stays ink |
| Status badges | 20 px pill, tone colour on its tint, sentence case (first letter only, the text itself is unchanged) |
| Tables | 12.5 px sentence-case heads on the side layer, 10/16 px cells, top-aligned rows, the identifier column does not wrap; wide tables scroll inside their card (focusable region) |
| Selection | navigation and table rows: `--sel`/`--nav-sel` with a 3 px teal bar; tabs and wizard steps: teal underline |
| Incidents | neutral row with a 3 px severity bar and the severity badge; no red/amber background blocks; "all clear" is a line of text with a green check |
| Empty states | 40 px neutral icon (no copper tile), title, one sentence, the next action; compact variant is a quiet single line inside a card |
| Wizards (kit) | same radii, 36 px buttons, 38 px fields with the `--field` border and the teal focus ring as the rest of the console; current step and chosen option in teal, the primary action copper |
| Charts | 210 px plot (130 px on phones), y axis 0/50/100 %, four x ticks; a 24 h axis shows weekday + hour; donut categories use teal, slate, copper, blue (never the warning amber) |

Responsive shell: 280 px navigation rail, 240 px from 861 to 1280 px, off-canvas below 861 px (menu button only there;
the closed drawer is `visibility: hidden` so Tab skips it; opening moves focus into it, Escape closes it and returns focus).
Phone breadcrumbs show the parent and the page. Overview order: status strip, active incidents, onboarding (first run),
apps, utilization + distribution, health matrix + deployment activity (no audit log on the overview).

Evidence: `docs/screenshots/uiaudit-console/` (`before-*` = 8cea4b7, `after-*` = this branch; real console against the e2e
backend and seed; pages marked `infra` answer `/api/v1/infra/*` in the browser with a fixed test fixture so populated
layouts can be seen; no product data is invented).
