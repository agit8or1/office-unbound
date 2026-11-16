# Catalog: collaboration components (chat, meetings, telephony) - 2026-11-15

Status: **Implemented and unit-tested (pure planner + check runners against local fake servers). Not deployed anywhere.** Nothing here proves the services work in production; the service evidence is the lab results cited below.

## What was added
| Piece | Where |
|---|---|
| Components `chat`, `meetings`, `telephony` | `blueprints/catalog/components/{chat,meetings,telephony}.yaml` |
| Profiles: three new VMs (`chat`, `meet`, `pbx`) + optional entries | `profiles/{small,medium,large,ha}.yaml` (edge got `after:` entries; lab/msp-multi/dedicated untouched) |
| Schema: `Port.port_end` (ranges), `Port.default_enabled`, `HealthCheck.body_contains`, `Component.notices/ha_note/os_images`, check kinds `sip_options_tls`, `jitsi_jwt` | `ics/ics/deploy/catalog.py` |
| Plan: opt-in ports (`PlanInput.enabled_ports`, `component:port`), range-aware port conflicts, notices/HA/OS warnings | `ics/ics/deploy/plan.py` |
| Check runners + migration `0012c` (DB CHECK constraint) | `ics/ics/checks.py`, `ics/migrations/versions/0009c_collab_check_kinds.py` |
| Wizard: plain-language optional components + chat federation opt-in | `ics/frontend/src/wizards/deploy/*`, `api.ts` |
| Tests | `ics/tests/test_deploy_collab.py` (14), `frontend/.../deploy/state.test.ts` (3 new) |

## Component facts
| | chat | meetings | telephony |
|---|---|---|---|
| Artifacts | Synapse 1.165.0, MAS 1.29.0, Element Web 1.12.35 (OCI, **`artifact_unpinned`**); postgresql-16 16.15, nginx 1.24.0 (ubuntu-noble) | Jitsi web 1.0.9442, Prosody 0.12.4, Jicofo 1.0.1205, JVB 2.3.318, token service 0.1.0-spike (OCI, **unpinned**); nginx | `ou-asterisk 22.12.0-ou1` from `ob-apt-dev` (pinned package); PBX helper + JsSIP softphone (OCI, **unpinned**) |
| Memory | 1536 MB + 3/user (lab peak 1.27 GiB under 1.5G cap; per-user ASSUMPTION) | 2048 MB + 2/user (lab peak 1.68 GiB under 2G cap; per-user ASSUMPTION) | 768 MB + 0.5/user (ou-pbx2 cap held, idle 206 MiB; per-user ASSUMPTION) |
| Cores | 2 + 0.004/user (ASSUMPTION) | 2 + 0.01/user (ASSUMPTION, no load test) | 1 + 0.004/user (ASSUMPTION) |
| Volumes | pgdata, media (`/var/lib/matrix-synapse`), config (signing key, MAS secret) | none (stateless) | voicemail spool, `/etc/asterisk/ou` |
| Ports | 443 (edge), **8448 federation: closed unless `enabled_ports: [chat:federation]`** | 443 (edge), UDP 10000 | SIP-TLS 5061, WSS 8089, RTP UDP 10000-10200, 443 softphone (edge). **No PSTN trunk port exists.** |
| Health | `GET /_matrix/client/versions` (body has `versions`); `GET /_matrix/client/v3/login` (body has `m.login.sso`, i.e. the MAS-delegated login is offered); cert | `jitsi_jwt`: XMPP-over-WebSocket handshake, anonymous session must be refused; cert | `sip_options_tls`: SIP OPTIONS over TLS; cert 5061 and 8089 |
| Backup | `online_dump` (pg_dump synapse+mas, media, signing key, MAS secrets); **not drilled** (warning) | `stateless` | `config_tar` (site config + spool); **not drilled** |
| Depends on | identity (Keycloak OIDC; LDAP for telephony) | identity | identity |

Every plan containing these lists their `notices` as warnings (federation off by default, E2EE key recovery not evaluated, no TURN relay packaged, token service is a spike, **no outside line and no emergency calling**).

## Placement and refusal rules (all tested)
- Each component has its own VM in the stock profiles; `small` carries them as optional, off by default; `medium`/`large`/`ha` default `chat` + `meetings` on, telephony optional off. A disabled optional drops its VM from the plan.
- Co-location is refused through the existing port-conflict check, now range-aware: `chat`+`meetings` (both 443), `meetings`+`telephony` (UDP 10000 inside 10000-10200), `edge`+any of them.
- `ha`: all VMs have 2 replicas with anti-affinity (JVB on distinct nodes); one node = refusal. `component_ha_note` warnings state that replicas are independent stacks (no Synapse worker/Postgres replication, no JVB shard routing, no PBX failover).
- **Unpinned artifacts are a blocking error** (`artifact_unpinned`, `executable: false`; the plan is still previewable). With the real catalog every plan containing chat/meetings is blocked until the pipeline produces signed images; telephony stays blocked by its helper/softphone images even though `ou-asterisk` itself is pinned. No digest was invented.
- Capacity uses the same formulas path as other components (VM overhead + ceil formulas); assumption-labelled inputs appear in the `sizing_assumptions` warning.

## Open items (honest list)
1. **OCI images for Synapse, MAS, Element, Jitsi parts, token service, PBX helper, softphone are not built/signed.** The lab ran vendor packages; production per ADR-0007/0008 needs own builds. Digests are `sha256:` placeholders; versions are the lab-tested upstream versions (token service / PBX helper / softphone `0.1.0-*` versions are placeholders).
2. `ou-asterisk` was built and tested on **Debian 12** only; the catalog default OS is Ubuntu 24.04 (plan warning `component_os_unvalidated`). The plan has one OS image for all VMs, so a per-component OS is not expressible yet. The package is in the **dev** channel only (`ob-apt-dev`); promotion to stable is not done.
3. The two new check runners are unit-tested against local fake servers (TLS SIP responder, fake Prosody websocket). They have **not** been run against ou-meet1 / ou-pbx2. The Jitsi probe checks that token auth is enforced for anonymous sessions (as lab test C03 does); a positive JWT-accepted probe needs the token secret from the vault and is not implemented. SIP OPTIONS accepts 2xx, and 401/403/404 (Asterisk may answer an unidentified peer that way), as "stack alive".
4. Migration `0012c` (new `checks.kind` values) must be applied on every ICS database before such checks are registered; it is not applied anywhere by this change. `actions.py` check-create accepts the new kinds.
5. Chat's PostgreSQL is its own instance on the chat VM (not the identity database); a Postgres-on-identity-VM option was not built. TURN, Jibri, federation delegation (`.well-known`), E2EE key backup, Element X/mobile apps, PSTN trunks, load tests: not done (see lab docs). HA replication is not validated for any of the three.
6. Existing tests that assumed the 5-VM medium/ha layout were updated (`test_deploy_plan.py`, `test_deploy_exec.py`): medium/large/ha now include chat and meetings by default.
7. Wizard text for the three components is shown when the catalog description is missing; the catalog descriptions are authoritative.
