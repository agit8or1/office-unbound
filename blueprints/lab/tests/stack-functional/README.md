# Stack functional audit (browser)

`stack_functional.cjs` drives headless Chromium (Playwright) through one deployed Office Unbound stack as a normal user and records every
user-visible function as a named check: **PASS**, **FAIL** or **INFO** (recorded only), each with a short reason. It continues after failures.
The exit code is **always 0** because this is an audit. Read the totals, not the exit code.

Status: written but **not yet run against a deployment**. The OpenCloud and grommunio-web steps use selectors and client APIs from
upstream releases (see "Fragile parts"). On the first run, read each FAIL reason and its screenshot before deciding whether the product
or the selector is at fault.

## Inputs (environment)

| Variable | Meaning |
|---|---|
| `OU_DOMAIN` | Deployment domain. The apps are `app.`, `auth.`, `cloud.`, `office.` and `mail.` (webmail at `/web/`) under this domain. |
| `OU_ENTRY_IP` | Entry (edge) address. Chromium gets `--host-resolver-rules=MAP *.<domain> <entry-ip>`, so no DNS or hosts-file change is needed. |
| `OU_USER`, `OU_USER2` | Two normal (non-admin) accounts. |
| `OU_PW_FILE`, `OU_PW2_FILE` | Files holding their passwords. A single trailing newline is stripped. Passwords are never printed. |
| `OU_OUT` | Output directory (default `./stack-functional-out-<time>`). |
| optional `OU_USER_EMAIL`, `OU_USER2_EMAIL` | Mail addresses (default `<user>@<domain>`). |
| optional `OU_REALM` | Keycloak realm (default: read from the sign-in URL). |
| optional `OU_HEADED=1`, `OU_STEP_TIMEOUT_S` (150), `PLAYWRIGHT_PATH` | Debugging and tuning. |

```
cd blueprints/lab/tests/stack-functional
OU_DOMAIN=example.org OU_ENTRY_IP=203.0.113.10 OU_USER=bob OU_USER2=carol \
OU_PW_FILE=~/.ou/bob.pw OU_PW2_FILE=~/.ou/carol.pw OU_OUT=/tmp/ou-audit node stack_functional.cjs
```

The script loads Playwright from `PLAYWRIGHT_PATH`, then `require('playwright')`, then `ics/e2e/node_modules/playwright`.

## Output

- Console: one line per check, then a summary grouped by section, a LOOK table and the totals.
- `$OU_OUT/results.json`: every check (`section`, `name`, `status`, `reason`, `ms`, `screenshot`), the totals and the `look` records.
- `$OU_OUT/shots/NNN-<section>-<check>.png`: a screenshot for each failed check.

**Secrets.** Passwords come only from the password files. OpenCloud tokens stay inside the browser: WebDAV, Graph and OCS calls run as
`fetch` in the OpenCloud page. Every reason and URL goes through `redact()`, which removes `code`, `state`, `session_state`, `id_token_hint`,
`token`, `access_token` and `WOPISrc` parameters, JWTs, bearer values and both passwords. Cookies are never read.

**Side effects on the deployment.** The run creates files, mail, a calendar event and a contact, all named `ou-audit-<stamp>` or
`OU audit <stamp>`. It sends one mail and one reply between the two users. It ends user 1's other sessions and signs both users out.
The cleanup step deletes the audit files from OpenCloud. The mail, the event and the contact stay.

## Checks and what each one proves

**portal**
- *signed out: portal redirects straight to sign-in*: `app.` sends a signed-out browser straight to Keycloak with no portal page served first (the hops are recorded).
- *sign in (Keycloak) returns to portal home*: the Keycloak login lands on the portal home page.
- *tile files, mail, calendar, contacts opens the app without a second sign-in*: each tile reaches the right host with no password prompt, no Keycloak credential POST and no 5xx. For the mail tiles, grommunio-web must open in the right context (`mail`, `calendar` or `contact`).
- *recent files section renders*: the section shows rows or the empty state, with no "could not be loaded" notice.
- *recent files lists the new documents*: the three documents from the office section appear in the list.
- *recent file link opens the file in OpenCloud*: the link works through SSO.
- *account page lists sessions incl. this device*: the sessions table has rows and exactly one "This device" marker.
- *"Sign out everywhere else" ends another session*: user 1 signs in from a second browser context and clicks the button on the first. The second context's Keycloak account page must then ask for sign-in again, while this session stays.
- *devices: Apple profile download*: the `.mobileconfig` downloads with mail, CalDAV and CardDAV payloads and the user's address, and contains no password.
- *devices: Thunderbird config download*: `config-v1.1.xml` downloads with incoming and outgoing servers.
- *navigation: portal has its own home link*.
- *sign out ends the session everywhere*: after the portal sign-out, new tabs of the portal, Files and webmail must all be signed out.

**office** (each runs for document/docx, spreadsheet/xlsx and presentation/pptx, created with the portal's New buttons)
- *created from portal, editor opens*: the portal creates the file and redirects into OpenCloud's editor route.
- *editor works*: the Collabora iframe (`office.` host, `/browser/`) shows `#document-container` and a document canvas. No error dialog (failed to load, unauthorised, lost connection) appears within six seconds, and at least one Collabora websocket is open and stays open.
- *type + save (Ctrl+S)*: a unique marker is typed into the document, A1 or the first slide placeholder, then saved. No error dialog may appear and no socket may drop.
- *saved file contains the typed text*: within 60 s, the file fetched from WebDAV has the marker inside its OOXML parts. This proves the WOPI PutFile round trip.
- *reopen shows the text*: the editor is closed and the file reopened. The editor must work again and the stored file must still hold the marker. For Writer, the status-bar word count must not be 0.
- *navigation: way back to portal from the editor*: a visible link to `app.` exists in the editor page or its frames.

**files** (OpenCloud web UI; each result is confirmed on the server through WebDAV or OCS)
- *Files opens with SSO*; *upload a small text file* (server copy is byte-identical); *download it back* (UI download, content equal); *rename*; *create folder*.
- *share folder with USER2*: the internal share is made through the share panel and confirmed through OCS.
- *USER2 sees the shared folder*: the folder is listed under Shared with me in user 2's browser.
- *public link create + delete (if offered)*: INFO if the UI has no Add-link control.
- *delete*: the file is gone from the server.
- *open .docx from the file list in the editor*: the docx is opened by clicking it in the file list, then gets the full editor proof as above.
- *navigation: way back to portal from Files*.

**webmail** (grommunio-web)
- *SSO into webmail reaches the inbox*: `mail.` `/web/` opens in the mail context with no 5xx response and no password form.
- *compose + send to USER2*: the message is created and sent through grommunio-web's own client data API in the page (`Zarafa` records plus the shadow store), not through SMTP.
- *USER2 receives it*: the subject appears in user 2's inbox within 90 s.
- *USER2 replies; USER1 receives the reply*: the reply uses the UI (Ctrl+R or the Reply button, then Ctrl+Enter or Send) and must appear in user 1's inbox.
- *calendar: create event, see it*; *contacts: create contact, see it*: the item is created through the client API, then its text must be visible in the calendar or contacts view.
- *navigation: way back to portal from webmail*.
- *sign out of webmail (USER2)*: after `container.logout()`, opening `/web/` again must not show the inbox without signing in.

**admin** (must be closed to normal users)
- *Collabora admin console closed*: PASS only for 403, 404 or a refused connection. A 401 is a FAIL because the console is reachable and only the admin password protects it.
- *Keycloak /admin/ closed*: PASS only if it is blocked (4xx and no admin console or master-realm login served).
- *Keycloak admin console of realm denies USER1*: the realm's console must not be usable by the user.
- *OpenCloud admin-settings closed to a normal user*: the user-management UI is not shown, and Graph `/users` answers 4xx.

**look**: For the Keycloak login, portal, OpenCloud, the OpenCloud editor wrapper, Collabora and webmail, the run records `document.title`, the computed body background (or the html background if the body is transparent), the main container background, and the body and heading font families. Use it to compare skinning across the apps.

**cleanup**: deletes the audit files through WebDAV, retrying while Collabora still holds a WOPI lock. Recorded as INFO.

## Fragile parts

- OpenCloud UI selectors (`#files-file-upload-input`, `.oc-files-actions-*-trigger`, `#files-share-invite-input`, `.oc-modal-*`) come from ownCloud Web and OpenCloud web. Each step tries several candidate selectors and text fallbacks.
- grommunio-web steps use the WebApp client API (`container.getContextByName(..).getModel().createRecord()`, `container.getShadowStore()`). If an API call throws, the reason says `client API error`.
- Collabora websocket tracking relies on Playwright reporting websockets from the cross-origin editor iframe. If a reason says `cool websockets open=0/0` while the canvas is present, check this first.
- The presentation edit selects the first placeholder with Tab, then Enter, then types. A different template layout may need another key sequence.

TLS is always verified (project rule: never disable TLS verification). Run it against a deployment whose names serve publicly trusted certificates, or add the deployment CA to the browser's trust store.
