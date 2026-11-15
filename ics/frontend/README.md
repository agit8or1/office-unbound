# ICS operator console (frontend)

Vue 3 + Vite + TypeScript single-page app for the ICS API (`/api/v1`). Hash routing (`#/overview`), no runtime dependencies besides `vue` and `qrcode`,
everything bundled (no CDN, no external fonts, no inline script/style), so it works under the UI CSP below.

Pages: login (password + TOTP), invite enrollment, Overview, Endpoints, Plans (approve/reject), Jobs, Inventory, Users (admin), Audit (approver+), Plan preview.
Pages and buttons appear only for roles that may use them; the server remains the authority and its error text is shown verbatim (401/403/429 handled).

## Commands (Node 22)
```
npm ci                 # install
npm run dev            # Vite dev server, proxies /api and /readyz to 127.0.0.1:8088 (note: __Host- cookies need HTTPS or localhost)
npm run typecheck      # vue-tsc
npm test               # vitest (API client: CSRF header, errors, 401/429)
npm run build          # outputs to ../ics/static
```

## Deploy
The FastAPI app serves `ics/ics/static/` at `/ui/` (`/` redirects there). Build, then re-run the backend installer, which copies code + static files
and restarts the service:
```
cd ics/frontend && npm run build && cd .. && sudo sh deploy/install.sh
```
Static responses carry their own CSP (`default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; ...`); API responses keep
the strict `default-src 'none'`. `deploy/install.sh` excludes `node_modules` from the copy.

## Notes
- The session cookie is `__Host-` + Secure; use the console over HTTPS (or `localhost`) once TLS termination exists.
- Audit paging is client-side over the newest N (<=500) entries because the API has only `limit`.
