# Files and Chat concept alignment (2026-11-26/27)

Live officeunbound8 (release v0.13.12) as `doctest`, Chromium 1600x900 at 1x (phone 390x844).

- `before-*`: the deployed apps as they are.
- `after-files-*`: the same live Files app with the files this branch generates (`brand.opencloud_files`: ou.css, home.js,
  translations.json, and the web config with `customTranslations`) served **to the browser only** (Playwright route); nothing was
  deployed. The populated list shows a temporary `[OU-TEST] files demo` folder (three small text files) created for the screenshots and
  deleted afterwards, trash emptied. `after-files-empty-light.png` was taken before the search width was finalised (field narrower than
  in the list shots).
- `after-chat-identity-*`: the live identity gate with the generated `config.json` served to the browser only (teal compound primary
  button, Inter instead of Nunito). `before-chat-identity-*`: the deployed config.
- `after-chat-home-structure-light.png`: the generated home page (`brand.element_home_html`) in the live app, from an intermediate build
  that still shipped Plex font faces (the font is Plex there and the toast's primary button is near-black: the upstream defect described in
  docs/design/upstream-modifications.md, fixed by shipping no faces). Only the page structure is current; the signed-in session used for it
  ended during the work, and the account's other devices could not be verified without changing its encryption identity, so no later
  signed-in capture exists.
- `before-chat-consent-light.png`: the MAS consent page with Element's logo; `oidc_metadata.logo_uri` replaces it once Element
  registers its client again (not previewable without a new registration).
