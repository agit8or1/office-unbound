# Office Unbound user portal

What an ordinary employee opens: SSO launcher (mail, calendar, contacts, files, new document), recent files, account page, device onboarding.
Separate from `ics/` (operator console). Results and limits: `docs/status/portal-results.md`.

* `app/` FastAPI BFF (OIDC code+PKCE, server-side tokens, `__Host-` session cookie), Jinja2 templates, one CSS file, no JS.
* `deploy/` systemd unit, env example, installer (run inside the machine), Keycloak client registration (`run-kc-client.sh` inside ou-id1).
* `tests/` `pytest` with a mock IdP/OpenCloud (needs fastapi, httpx, PyJWT, jinja2, python-multipart, cryptography).
* `e2e/portal-e2e.js` Playwright run against the real lab (see header for env).
* `e2e/layout-check.cjs` no horizontal overflow at 320/390/768/1366 px, light and dark, every page and open menu (local portal with the test mocks; see header).

Config is environment only (`deploy/portal.env.example`); the client secret is read from a file. Lab deploy: see section 2 of the results doc.
