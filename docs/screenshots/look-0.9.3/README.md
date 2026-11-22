# 0.9.3 look: evidence

Screenshots of the restyle against the officeunbound.com interface concepts (`reference-website-concept.png`).

| File | What | How it was made |
|---|---|---|
| `console-*.png` | ICS console (login, overview; light, dark, mobile) | Built console bundle, Playwright, mocked API |
| `portal-*.png` | User portal home and account (light, dark) | Portal rendered by its test fixture (mock identity provider, signed-in test user), Playwright |
| `reference-website-concept.png` | The website's proposed interface concept | officeunbound.com, read-only |

Evidence level: **unit** (rendered locally). The Keycloak sign-in, OpenCloud and webmail skins are checked by `ics/tests/test_brand.py`
(token equality, contrast ≥ 4.5:1) but not yet seen on a live deployment; that check happens after the 0.9.3 deploy.
