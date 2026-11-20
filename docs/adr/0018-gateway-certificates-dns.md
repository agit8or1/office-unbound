# ADR-0018: One public IP: gateway, routing, certificates and DNS

Status: **accepted (design)**, 2026-11-20; section 11 supersedes the ACME placement of sections 2 and 5. Multiple public IPs, hybrid
allocation, private-only installations and IP address management: [ADR-0019](0019-network-deployment-modes.md) (PLANNED / FUTURE). Owner request: "Centralized Gateway, DNS Routing & SSL Certificate Management" (single public IPv4 per
installation, automatic routing/certificates/DNS, Gateway & Certificates UI, multi-tenant isolation, 90-day hands-off renewal).
Status words: ADR-0000. Nothing below is "working" until a results document says so with executed evidence.

## 1. What exists today (inspected before designing)
| Piece | Where | State |
|---|---|---|
| **Edge** component: nginx on 80/443, one site per web host name, routes to the service on loopback or over verified HTTPS to the TLS proxy of its VM | `blueprints/catalog/components/edge.yaml`, `configure.edge_runbooks`, agent `cfg.nginx_site` | deployed on real VMs (e2e-fo*/gw*) |
| **Name settings**: per-deployment and per-tenant domains, every catalog host renamable to a label or a full FQDN, conflict detection | `plan.py` `NameSettings`, `plan["names"]` | 0.6.0 (this change) |
| **Default site**: a bare IP / unknown name goes to the scope's portal (single tenant) or is refused (`444`, multi-tenant: no tenant enumeration) | agent `cfg.nginx_default` | 0.6.0 |
| **Certificates**: a private CA per scope (deployment or tenant), NameConstraints = the scope's domains, leaf per VM for exactly its names; keys made per configuration run | `configure.ca/_tls_for`, agent `cfg.tls` (per-name CA files) | deployed; not publicly trusted |
| **DNS**: the plan computes A/CNAME/MX/TXT records; inside the deployment they are served by managed `/etc/hosts` blocks | `plan.dns`, `cfg.hosts` | no public DNS is touched |
| **Public ports**: catalog `ports[]` with exposure public/edge/internal/local; per-VM nftables allowances | catalog, `cfg.firewall`, `plan.firewall` | VM-level only, no single-IP port plan |
| **Health**: per-component checks (HTTP/TLS/SMTP banner) run by the ICS and the agent | `checks`, `guest.probe` | deployed |

So the "gateway" is not a new product: it is the **edge**, promoted to a dedicated, hardened role with publicly trusted certificates, L4 forwarding
and an ICS-side control plane. Nothing that works today is replaced.

## 2. Gateway implementation: evaluation and decision
| | nginx (BSD-2) + ICS-side ACME | Traefik v3 (MIT) | Caddy 2 (Apache-2.0) | HAProxy (GPL-2) |
|---|---|---|---|---|
| Already integrated, typed runbooks, audited | **yes** | no | no | no |
| HTTP/1.1, HTTP/2, WebSocket, SSE, large uploads, long-lived | yes (in use: OpenCloud, Collabora WS) | yes | yes | yes |
| SNI routing of raw TLS on 443 (L4) + TCP/UDP forwarding | yes (`stream` + `ssl_preread`) | yes | plugin (layer4, not core) | yes |
| Graceful reload without dropping connections | yes (`nginx -s reload`) | yes (dynamic) | yes (admin API) | yes (seamless reload) |
| Built-in ACME | no -> done by the ICS | yes | yes | no |
| Where ACME account key + DNS API tokens live | **ICS (vault)** | on the gateway (`acme.json`, env) | on the gateway (storage) | ICS |
| Control surface on the public host | none (agent: signed, allowlisted runbooks) | file/HTTP provider or Docker socket | admin API on the gateway | runtime API socket |

**Decision: nginx stays the data plane; certificates and DNS are a control-plane function of the ICS.** The deciding requirement is "compromise of a
public application must not grant control of ICS or Proxmox": with Traefik or Caddy the internet-facing process would hold the ACME account key, the
DNS provider API token (which can re-point the whole zone) and every private key in one file. With the ICS doing ACME (python `acme` library of the
certbot project, Apache-2.0, Ubuntu package `python3-acme`), the gateway holds only the private keys of the names it serves, no DNS credential,
no ACME account, and no API: it is configured exclusively through the agent's closed-schema runbooks, which the ICS signs. Traefik remains the
documented alternative if a future deployment needs a dynamic API (re-evaluate if nginx `stream` limits are hit).

## 3. Topology (one public IP)
```
Internet ── public IPv4 ── NAT/port-forward (owner's router/firewall) ──> gateway VM (edge)
  80/443  ──> nginx http: host-based routes -> backends (loopback / verified HTTPS to other VMs, other Proxmox hosts)
  443 TLS ──> nginx stream ssl_preread: SNI turn.<domain> -> TURN TLS (else -> the http block)       (L4 sharing of 443, section 6)
  25/465/587/993 ──> nginx stream: TCP passthrough -> groupware VM (TLS terminated by Postfix/gromox: STARTTLS needs it)
  3478 udp/tcp, 5349, media ranges, 5060/5061 ──> forwarded per allocation table (or direct NAT to the meet/pbx VM: UDP media is not proxied)
ICS (never public) ── agent (mutual TLS, signed requests) ──> gateway / every VM
```
The ICS, Proxmox and agent ports are never forwarded. Backends accept traffic only from the gateway (per-VM nftables, `exposure: edge`).
One public IP and one gateway VM are a **single point of failure** (Proxmox HA restart is recovery, not HA). Two gateways behind a VRRP address
(keepalived) are a later option; the design keeps all gateway state reproducible from the ICS so a second instance is a configuration, not a migration.

## 4. Data model (ICS database; desired state derived from plans, observed state from probes)
- **dns_zones**: `id, deployment_id, scope (tenant|null), domain, public_ipv4, public_ipv6?, provider (manual|cloudflare|...), credential_id ->
  credentials (vault), managed bool, verified_at, ownership_token`. A zone belongs to exactly one scope; a domain can be claimed by one scope only
  (unique on `domain`, plus TXT ownership verification for customer-owned domains).
- **dns_records** (desired): `zone_id, name, type, value, ttl, source (plan|acme|manual), managed bool` + **dns_observations**: `name, type, seen_values,
  resolver, checked_at, status (ok|missing|wrong|conflict)`. Only records the ICS created (tracked by provider record id) are ever changed or deleted.
- **gateway_routes**: `id, deployment_id, scope, hostname, path_prefix?, component, backend_vm, backend_port, backend_protocol (http|https|tcp|udp|tls-passthrough),
  public (bool; false = internal-only, split horizon), enabled, max_body_mb, timeouts, websocket, state (planned|validating|live|disabled|failed),
  last_error`. Derived from `plan.dns` + catalog ports; unique on `(hostname, path_prefix)` across the whole installation (takeover protection).
- **certificates**: `id, scope, names[], kind (acme|imported|deployment-ca), issuer, serial, not_before, not_after, key_enc (vault, per certificate),
  cert_pem, chain_pem, acme_order_url, renew_after, status, last_error, history -> certificate_events`. One key per certificate; no shared wildcard
  key across scopes. Wildcards only per scope and only with DNS-01.
- **acme_accounts**: `directory (production|staging|custom e.g. Pebble), key_enc, contact (owner-provided, optional), created_at`.
- **port_allocations**: `public_port, proto, purpose, deployment_id, scope, component, backend_vm, backend_port, mode (http|sni|tcp|udp|range)`,
  unique on `(public_port, proto)` except `443/tcp` which is shared by mode `http`/`sni` with unique SNI names. Conflicts are plan errors.

## 5. Certificates
Issuance and renewal are **ICS jobs** (typed action `cert.issue`, plus the renewal scheduler with no approval for renewals of an already approved name
set): ACME order -> challenge -> finalize -> store (vault) -> push to the gateway (`cfg.tls` with the publicly trusted chain) -> `nginx reload`
-> TLS probe of every name. Challenges: **HTTP-01** pushed to the gateway as a challenge file (new runbook `cfg.acme_challenge`, tokens only),
**DNS-01** through the zone's provider (required for wildcards). Renewal at 1/3 lifetime remaining (≈30 days for 90-day certificates), retries with
backoff, alert after the first failure, incident at 14 days remaining. Rate-limit guard: per-registered-domain counter against Let's Encrypt's
published limits; staging directory for every first attempt of a new name set. Import of existing certificates (PEM, validated: chain, key match,
names, expiry). The deployment CA keeps serving internal hops (backend TLS between VMs) and names without public DNS (labs, split horizon).

## 6. Non-HTTP protocols and port sharing
- SMTP 25/465/587, IMAPS 993: TCP passthrough (the mail server terminates TLS; STARTTLS cannot be terminated by a proxy without breaking SMTP).
- TURN: `turns` on **5349/tcp** by default; TURN-over-TLS on **443** only via SNI routing (`turn.<domain>` -> coturn) and only when the TURN name is
  distinct from every HTTPS name; clients that send no SNI cannot be split from HTTPS on the same IP:port -> documented as unsupported, fallback 5349.
- RTP/SRTP media and WebRTC UDP: forwarded ranges directly to the media VM (no proxying); one allocation range per installation; a second meetings
  or PBX instance needs a disjoint range (allocation conflict = plan error).
- SIP 5060/5061: forwarded to the PBX VM; never exposed unless telephony is installed and the operator enables the port (opt-in `enabled_ports`).
- The allocation table is the single source for the owner's router port-forwards: the wizard prints the exact forward list.

## 7. DNS automation
Wizard: primary domain, public IP (auto-detected by an ICS check, confirmed by the owner), provider, API token (minimal scope: one zone, DNS edit),
managed yes/no. Without a provider: manual instructions (exact records) and continuous validation. Providers: a small interface
`list/create/update/delete(record_id)`; first Cloudflare (API token, zone-scoped), then others as needed (Namecheap's API requires IP allow-listing and
account-wide credentials: documented, opt-in). Public IP change detection: periodic check, plan for record updates (approval unless auto-update was
authorized for that zone). Wildcard records optional. Split horizon: internal-only routes have no public record and no public certificate.

## 8. Multi-tenant
Each tenant scope owns its zones, routes, certificates and keys (already true for the private CAs and secrets in 0.6.0). A tenant administrator's
API (tenant API, ADR-0013) can request names only inside its verified zones; the uniqueness constraints in section 4 make hostname takeover a
database error, not a policy check. The gateway serves all tenants from separate certificate files; the default site never reveals a tenant.

## 9. Delivery plan (roadmap phase P2.9, GitHub milestone "Gateway & certificates")
| Step | Content | Depends on |
|---|---|---|
| G1 | this ADR; data model migration; routes + port allocations derived from plans, shown read-only | - |
| G2 | ACME client in the ICS (`cert.issue`, renewal scheduler, inventory, history), tested end to end against **Pebble** (Let's Encrypt's open-source test CA) in the lab | G1 |
| G3 | `cfg.acme_challenge` + publicly trusted certificates on the gateway, TLS probes, expiry alerts | G2 + owner: public IP, domain |
| G4 | DNS: provider interface + Cloudflare, manual mode, validation/observation, IP-change detection, DNS-01 | G1 + owner: provider token |
| G5 | L4: nginx `stream` (mail passthrough, SNI routing), port allocation table, router forward list | G1 |
| G6 | Gateway & Certificates UI (overview, routes, certificates, DNS health) + setup wizard | G1-G5 |
| G7 | acceptance: one IP, Mail/Drive/Docs/Chat/Meetings via the wizard, staged 90-day renewal (short-lived Pebble certificates) | all |
Owner inputs needed for G3/G4 production runs: the public IPv4 (and NAT forwards), the domain, and a DNS provider token. Everything else proceeds now.

## 10. Additions (owner, 2026-11-20: "Centralized gateway, subdomain routing & public IP architecture")
- **ICS outage**: the gateway's configuration is static files written by the agent; nginx keeps serving with the ICS down (no runtime dependency,
  no API on the gateway). Renewals are due ~30 days before expiry, so an ICS outage of weeks does not expire a certificate.
- **Fail closed**: unknown host names get `444` (multi-tenant) or the scope's own portal (single tenant, only one organisation exists). A route can
  never fall back to another tenant (0.6.0, `cfg.nginx_default`; negative test in `test_deploy_names.py`).
- **Trusted proxy headers**: backends accept `X-Forwarded-*` only from the gateway's address (nginx `real_ip`/`set_real_ip_from` on the TLS proxies,
  Keycloak `KC_PROXY_HEADERS` behind loopback/edge only); the gateway overwrites, never appends client-supplied values. G1 adds a test per backend.
- **Separate gateway VM**: the shared edge of multi-tenant layouts is already its own VM. Single-tenant layouts co-locate the edge with identity to save
  a VM; G1 adds a `gateway: dedicated` placement option (default for MSP installs) instead of a second proxy.
- **Mail with one IP and several tenants**: port 25 can go to one host only, so the gateway VM runs a **mail ingress** (Postfix as relay only:
  `relay_domains` = verified tenant domains, `transport_maps` recipient domain -> that tenant's groupware VM, no local mailboxes, no open relay,
  TLS with the per-domain certificate by SNI). IMAPS 993 and SMTPS 465 are implicit TLS: routed by SNI (`mail.<tenant domain>`) with nginx
  `stream ssl_preread`, credentials stay with the tenant's own server. Submission on 587 (STARTTLS) cannot be split by name: single tenant ->
  forwarded; multi-tenant -> clients use 465 (documented in onboarding/autoconfig), 587 stays closed unless one tenant owns the installation.
- **Acceptance (G7)** adds the owner's list: three subdomains on one IP, valid HTTPS, renewal, two customer domains, unknown FQDN rejected, duplicate
  FQDN rejected, tenant A cannot route to tenant B, backend move updates routing, new app adds its route, removal removes only its route, failed
  change restores the previous state, traffic survives an ICS outage, external mail and non-HTTP ingress, alerts for certificate and backend failures.

## 11. Gateway independence from the ICS (owner, 2026-11-20: "Gateway independence & high availability") -- supersedes parts of 2 and 5
**Decision change:** the gateway renews its own certificates. The ICS being down for longer than the renewal margin must not expire anything, so
waiting for the ICS (section 5) is not enough.
- **Split of ACME duties.** HTTP-01 issuance and renewal run **on the gateway** (certbot from Ubuntu, Apache-2.0, `certonly --webroot`, own ACME
  account, keys generated on the gateway and never leaving it except as an encrypted backup to the ICS) for exactly the names in the signed
  configuration the ICS approved; the gateway cannot add a name. DNS-01 (wildcards, names without public HTTP) stays **in the ICS**: a DNS
  provider token can re-point the whole zone and is never placed on the internet-facing host. A DNS-01 certificate is pushed to the gateway
  with 30 days of margin, so ICS outages shorter than that are covered; longer ones raise an alert on the gateway's local status page.
- **Last known good, locally.** Gateway configuration is a **revision bundle** (routes, tenant/domain map, allowed backends, certificate
  references) applied by one agent runbook (`cfg.gateway_apply`): validate the whole bundle (`nginx -t` on a staging tree), keep the previous
  revision, switch atomically (symlink swap), graceful reload, local probe of every route, then commit; any failure restores the previous
  revision. A transaction interrupted by a lost management connection is finished or reverted from the local journal at the next agent start.
  The gateway never deletes routes or certificates because the ICS is unreachable; nginx has no runtime dependency on the ICS.
- **Revisions and drift.** The gateway reports its active revision and certificate state with every agent health report. The ICS compares with its
  desired revision: a newer valid gateway state (e.g. a renewed certificate) is adopted, never overwritten by an older ICS copy; a real difference
  becomes a drift finding with an approval-gated reconciliation plan (`gateway.reconcile`), like VM drift today.
- **Events during outages.** The agent keeps a bounded, deduplicated local event journal (renewals, reloads, probe failures) and the ICS collects it on
  reconnect. An unreachable ICS is a management-connectivity warning on the gateway and in the ICS, never an "applications offline" state; ICS-side
  alerts distinguish gateway failure, backend failure and management-channel loss.
- **Concurrency.** One gateway transaction at a time (agent-side lock + ICS job serialisation per gateway).
- **Not HA.** ICS independence is not gateway redundancy: one gateway VM and one public IP remain a single point of failure (UI and docs say so).
  The bundle format and gateway-held state are designed so a standby gateway can be added later (config + encrypted key sync, VRRP) without a rewrite.
- **Settings -> Network & Domains -> Gateway** (G6) shows: gateway host/management IP, public IP, running state, ICS connection, active revision, last
  sync, routes, domains, certificates and renewal state, backend health summary, last configuration backup; actions: validate, test public
  connectivity, synchronise (= reconcile plan), check certificates, staging renewal test, routing table, logs, redacted report, restore an approved
  revision. No private key or credential is ever returned.
- **Acceptance (G7)** adds: ICS service stop, ICS reboot, management channel cut, gateway restart (routes and certificates recovered), invalid
  configuration rejected, failed update rolled back, unknown domains rejected, renewal while the ICS is down, reconciliation after reconnect,
  tenant isolation through the gateway, customer traffic with the ICS database unavailable.

Delivery order stays G1-G7; G2 now builds the gateway-side renewal (certbot, revision bundle) first and the ICS-side DNS-01 second.
