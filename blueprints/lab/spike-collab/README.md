# Collaboration spike (Phase 6): chat + meetings

Lab only. Results: `docs/status/collaboration-lab-results.md`. Licenses: `docs/status/third-party-inventory.md` section 5a.

| Machine | Stack | Names |
|---|---|---|
| `ou-chat1` (192.168.186.245, MemoryMax 1.5G) | PostgreSQL 16, Synapse (matrix.org deb, pinned), matrix-authentication-service (release binary, sha256), Element Web (release tarball, sha256), nginx | `chat.`, `matrix.`, `mas.ou-lab.internal` |
| `ou-meet1` (192.168.186.246, MemoryMax 2G) | Jitsi Meet debs (pinned, held), Prosody `token` auth, nginx, Office Unbound token service (FastAPI) | `meet.`, `meet-auth.ou-lab.internal` |

Identity is Keycloak realm `ou-lab` on `ou-id1` (new confidential clients `ou-matrix`, `ou-meet`).

## Order
1. Lab CA leafs: copy `../common` into `ou-id1` and run `lab-ca.sh` there (issues `chat` and `meet` leafs; `lab.env` has `IP_CHAT/IP_MEET`).
2. Keycloak clients: `kc-collab-clients.py` inside `ou-id1` (env `KC_URL KC_CA KC_ADMIN_PASSWORD_FILE SECRET_DIR`).
3. Host: `./00-host-create-machines.sh` (clone `ou-base-noble`, static IP, caps, CA trust, cert bundle). Add the new names to the ICS host `/etc/hosts`.
4. Copy the client secrets from `ou-id1:/root/ou-lab-secrets/kc-ou-{matrix,meet}-client-secret` to `/root/ou-lab-secrets/` in the target machine (root, 0600).
5. `ou-chat1`: `10-install-chat.sh`. `ou-meet1`: `20-install-meet.sh`, then `21-install-token-service.sh`.
6. Tests from the ICS host (`tests/`, needs `requests PyJWT playwright websocket-client` and a Chromium whose HOME NSS db trusts the lab CA; see `collab_lib.py`): `c01_matrix.py`, `c02_deprovision.py`, `c03_jitsi.py`, `c04_element_ui.py`, `c05_backchannel.py`.

## Things the scripts encode (learned the hard way)
- Synapse needs a `C` collation database; MAS needs `WorkingDirectory=/opt/mas` (policy.wasm, templates under `share/`) and the `adminapi` listener resource for the lifecycle API.
- jitsi-meet postinst only configures nginx if the `nginx` package itself is installed (not `nginx-light`); Ubuntu 24.04 Prosody runs on Lua 5.4 but `lua-inspect` ships only 5.1-5.3 (symlink 5.3 -> 5.4, otherwise `auth_token` fails to load and every session gets "No available SASL mechanisms").
- `jitsi-meet-tokens` leaves empty `app_id=""`/`app_secret=""` lines that override anything set earlier: `patch-prosody-jwt.py` replaces those.
- Files written into a `PrivateUsers=pick` machine from the host appear as `nobody`: create them through `systemd-run -M <machine>`.
