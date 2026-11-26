# Office Unbound app shell (concept alignment 2026-11-26)

The one frame every user-facing app shows (`docs/design/concepts/*.webp`). Measurements are CSS px at 1600 px wide concept renders.
Colours are tokens from `blueprints/catalog/templates/brand/ou-brand.css` only: never a literal colour in an app skin.

## Top bar (all apps, admin surfaces too)
- Height **48**, background `--ou-bar-bg`, text `--ou-bar-text`; bottom edge none.
- Left: the mark (20 px) + "Office Unbound" (14/600) + a 1 px divider (`--ou-bar-line`) + the app name (14/400, muted bar text).
- Centre: global search, max-width 520, height 30, radius 6, background `--ou-bar-field` (a lighter navy), placeholder names what the
  app searches ("Search mail and people", "Search files, folders and libraries"), a `/` key hint at the right. Where an app has no
  search of its own the field opens the portal search.
- Right: launcher (grid icon), help, notifications (bell + count badge in `--ou-accent`), avatar 30 px (initials on `--ou-accent`,
  presence dot when the app knows it). Icons 18 px, hit area 32 px, tooltips on every icon.

## Rail (user apps; admin surfaces use their own side navigation instead)
- Width **64**, background `--ou-side`, right border `--ou-line`.
- Items top to bottom: Home, Mail, Calendar, Contacts, Files, Docs, Chat, Meet (only when meetings are deployed), Calls (only when
  telephony is deployed); Settings pinned to the bottom. Hidden items are never shown greyed out.
- Item: 56 x 48, icon 20 px over a label 11/500; active item: `--ou-surface` background, radius 8, a 3 px `--ou-accent` bar on the
  left edge of the rail, label in `--ou-ink`; badge: 16 px pill `--ou-accent` with white 10/600 count, top-right of the icon, only for
  real counts (unread mail, unread chat), never a placeholder.
- Keyboard: the rail is a `nav` with `aria-label="Apps"`, items are links (deep links, history), focus ring `--ou-focus`.
- Collapsed is the default (icon + label as above). Expanded (labels beside icons, 200 px) is a per-user preference stored with the
  portal's existing `ou_prefs`.
- Below 768 px: the rail becomes a bottom bar of the first five items plus "More".

## App column (inside each app)
- The app's primary action sits at the top of its own side column as a full-width copper button ("New message", "New event",
  "+ New" in Files): `--ou-accent` background, white 13/600 text, radius 6, height 36.
- Side column background `--ou-side`, section labels 11/600 uppercase `--ou-muted` with 0.04em tracking.

## Implementation owners
| App | Mechanism (supported hook) |
|---|---|
| Portal | server-rendered `base.html` (ours) |
| ICS console | Vue layout (ours); admin variant: bar + own side navigation |
| grommunio-web | brand stylesheet + the existing Office Unbound app bar; structural changes via grommunio-web settings/plugins, never ExtJS geometry through CSS |
| OpenCloud | theme.json + brand CSS + the supported web extension mechanism |
| Element | custom theme in `config.json` (`setting_defaults.custom_themes`), `branding` keys |
| Office Unbound Docs | its own build (ou6+): header colours only |
