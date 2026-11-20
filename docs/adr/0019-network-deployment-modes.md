# ADR-0019: Network deployment modes, hybrid IP allocation and IP address management (FUTURE)

Status: **Proposed — PLANNED / FUTURE, not authorized for development** (owner, 2026-11-20: "ROADMAP / DOCUMENTATION UPDATE ONLY. DO NOT
IMPLEMENT THIS FEATURE NOW."). Extends [ADR-0018](0018-gateway-certificates-dns.md). Roadmap: P10.11 (deferred). Status words: ADR-0000.
Nothing in this document is implemented unless it is listed under "What exists today" with its evidence.

## What exists today (verified; unchanged by this ADR)
| Capability | Evidence |
|---|---|
| Single public IP: routing by name on the ICS host (TLS passthrough by SNI, console LAN-only or by name), verified from the internet | `ics/deploy/public-entry/`, docs/status/host-changes.md 2026-11-20 |
| Per-deployment gateway (edge) with host-name routing, default site (portal or refuse), per-tenant CAs | 0.6.0, `ics/tests/test_deploy_names.py` |
| Public Let's Encrypt certificates issued and renewed by the gateway itself (HTTP-01), staging then production, verified live | 0.7.0, `ics/tests/test_gateway_certs.py`, host-changes 2026-11-20 |
| Settings → Network & domains: public address, one forward table, DNS/port checks that prove which machine answered | 0.6.1/0.7.0, `ics/tests/test_netsettings.py` |
| Management access for the console's public name (public / LAN-VPN / allow list) through a root helper socket | 0.7.1, `ics/tests/test_console_access.py` |
Everything below is **PLANNED / FUTURE**.

## 1. Installation network modes (planned)
* **Mode A — Single public IP (default, partly implemented: see above).** All HTTP(S) services by name behind one gateway; mail through a
  shared mail ingress (ADR-0018 §10, planned); certificates centrally renewed; NAT with documented forwards; port-conflict detection; shared
  outbound mail IP with SPF/DKIM/DMARC and reputation monitoring; IPv6 where available. Protocols that cannot share a port by name (SMTP 25,
  STARTTLS submission 587, SIP, TURN/UDP media) get explicit listeners or relays (§5); no unsafe protocol multiplexing.
* **Mode B — Multiple public IPs.** An inventory of public/private IPv4/IPv6; assignment of IPs to gateways, tenants, services or tenant groups;
  a dedicated IP per customer (optional, never required for multi-tenancy); separate IPs for mail, web and collaboration; dedicated outbound
  SMTP IPs; several gateway instances; allocations across hosts/clusters where the network allows; unused/conflicting/reserved detection;
  explicit routing policies and tenant boundaries; HA and load balancing (§8). One gateway code base for every mode.
* **Mode C — Private / internal only.** No public IP; internal DNS and private CAs (the existing deployment CA) or administrator-supplied
  trusted internal certificates; VPN access; no public-certificate dependency; no unnecessary external listeners; local package/update
  mirrors; documented limits (no external mail delivery, federation, PSTN, push notifications, public collaboration).

## 2. Hybrid allocation (planned)
One installation may mix: customer A on the shared IP, B with a dedicated IP, C with a dedicated outbound mail IP, D private/VPN-only — all
managed by the same ICS and data model. Per-service/per-tenant assignment where technically possible; dedicated outbound independent of
inbound web routing; moves between shared and dedicated; per-IP usage reports; conflict detection; cross-customer routing impossible by
construction (unique, owner-scoped assignments).

## 3. Setup wizard and administration (planned)
Setup choice: **Single public IP (recommended) / Multiple public IPs / Private-internal only**, visible and changeable later (§10).
**Settings → Network & Domains → IP Address Management:** interfaces, public/private addresses, static assignments, gateways and routes, NAT
detection and forward recommendations, DNS requirements, certificate assignments, tenant-to-IP and application-to-IP maps, inbound/outbound
mail IPs, gateway health, port usage and conflicts, allocation status, validation, approval-gated changes, audit history. A simple default
view for single-IP installations; an advanced view for experienced administrators.

## 4. Configuration recommendations (planned; deterministic, no AI required)
Inputs: tenants, users, available public IPs, mail volume, concurrent meetings/calls, current network, gateways and Proxmox hosts, bandwidth
and resources, isolation and HA requirements. Outputs with their reasoning, separating measured data from estimates (e.g. one shared IP for a
small installation; separate mail egress for a high-volume sender; a dedicated IP where isolation/compliance/reputation justify it;
additional gateways when measured capacity or redundancy require). Never allocates or reroutes without administrator approval.

## 5. One gateway/control-plane model (planned; builds on ADR-0018 §9-§11)
Shared and dedicated IPs, several gateways, host-name web routing, L4 TCP/UDP forwarding, certificate issuance/renewal, service discovery,
config generation, health checks, validation, versioned revision bundles with rollback — the same components for every mode.
Invariants carried over from ADR-0018 §11: traffic and renewals continue without the ICS; last-known-good configuration on the gateway;
atomic/rollback-safe changes; audit; private keys in protected stores, tenant certificate material isolated; no client traffic through the
privileged ICS process; management interfaces LAN/VPN or allow-list by default.
Routing classes to document per service: HTTP reverse proxy (web apps, EWS/ActiveSync/MAPI/DAV, Autodiscover); L4 SNI passthrough
(IMAPS 993, SMTPS 465, TURN-TLS when on 443); dedicated listeners/ingress services (SMTP 25 mail ingress, submission 587); media relays
(TURN/UDP, RTP ranges, SIP). SNI alone does not route STARTTLS protocols or UDP.

## 6. Mail ingress, egress and reputation (planned)
Inbound: central SMTP ingress for many domains, routing by validated recipient domain and mailbox, tenant isolation, no open relay,
antispam/antivirus, per-domain policies, safe queues/retries, multiple MX where appropriate. Outbound: shared or dedicated egress IPs,
domain-specific identities, enforced authorized senders, correct HELO/EHLO, SPF/DKIM/DMARC, PTR/rDNS validation with the records the IP
provider must set, queue/bounce/delivery tracking, rate limits and abuse protection, per-egress-IP reputation. Design: shared ingress,
separately configurable egress. A dedicated IP is never presented as a guarantee of inbox placement.

## 7. DNS automation and certificates (planned; extends ADR-0018 §5/§7/§11)
Manual DNS; provider adapters (Cloudflare first, extensible); optional RFC 2136 for private infrastructure; validation before and after
deployment; public IP change detection; DNS-01 and HTTP-01; wildcards where appropriate; expiry monitoring and renewal (implemented for
HTTP-01, 0.7.0); deployment to the correct gateways; revocation/replacement; protection against overlapping tenant domains and
unauthorized claims; least-privilege, domain-scoped DNS credentials only.

## 8. High availability and scaling (planned)
Several gateways, active/passive and (where appropriate) active/active, health-based failover, capacity monitoring, connection draining,
redundant routing, IP failover where the network supports it, load-balancer compatibility, certificate/config sync, protection against two
gateways owning the same configuration. Prerequisites stated per design (floating IPs need shared L2 / provider failover / VRRP, or an
upstream load balancer). Anycast, BGP and multi-site routing are separate optional future items.

## 9. Security and tenant isolation (all modes)
Default-deny exposure; explicit tenant/service boundaries; cross-tenant routing denial; isolated certificates/keys/credentials; restricted
gateway management; approval-gated changes; durable audit; protection against DNS rebinding and host-name confusion; refusal of unauthorized
IP or domain assignment; safe handling of invalid Host/SNI; SSRF protection on configurable upstreams; strict validation of IPs, CIDRs,
targets and ports; rate limits on management/provisioning; fail-closed on unsafe changes; cross-tenant leakage tests. A dedicated IP is
never a substitute for network, application, identity, storage and administrative isolation.

## 10. Migration between modes (planned)
Single ⇄ multiple IPs, shared ⇄ dedicated tenant IP, private ⇄ public. Each: impact assessment, destination availability, port conflicts,
DNS/firewall/NAT/certificate prerequisites, mail reputation/SPF/PTR effects, expected interruptions and propagation delays, an approved
migration plan, previous gateway configuration kept until verification, staged cutover where feasible, reachability checks from inside and
outside, rollback, data/identity/configuration preserved, full audit. No promise of zero downtime: migrations that can interrupt TCP
sessions, mail connections, calls or meetings are named as such.

## 11. Capacity, billing and MSP integration (planned)
Inventory of assigned public IPs (shared vs dedicated, per customer), utilization and capacity forecasts, gateway utilization, optional
dedicated-IP and customer-specific mail-egress offerings, MSP provisioning API for IP requests, clientst0r billing/provisioning hooks,
audit of assignment and release, scarcity reporting. Not an ISP/IPAM platform: integrate with existing infrastructure systems.

## 12. Acceptance (when authorized)
1 single IP with several domains and tenants · 2 multiple IPs with dedicated tenant assignments · 3 hybrid · 4 private-only without
unnecessary listeners · 5 IPv4 and IPv6 · 6 HTTP(S) host routing · 7 SMTP domain-aware ingress · 8 outbound mail IP selection ·
9 SPF/DKIM/DMARC/DNS validation · 10 issuance and renewal with the ICS down · 11 gateway restart/recovery · 12 invalid configuration
rollback · 13 duplicate IP and port-conflict detection · 14 cross-tenant routing/access denial · 15 IP reassignment and mode migration ·
16 DNS propagation warnings · 17 no management exposure beyond policy · 18 multi-gateway HA/failover where configured · 19 monitoring,
alerting, audit consistency · 20 unchanged single-IP behaviour after multi-IP support. Results distinguish simulated, laboratory and real
infrastructure evidence.

## 13. Placement and order
Roadmap **P10.11 (deferred)**; GitHub milestone "Network modes & IP management (future)". Not in the current queue: the single-IP gateway work
continues under ADR-0018 (milestone "Gateway & certificates", issues #23-#30). Logical order once authorized (not dates):
**F1** unified network model + IP inventory → **F2** multi-IP gateway assignment, dedicated services → **F3** hybrid tenant allocation,
separate mail egress → **F4** DNS automation, validation, allocation management → **F5** gateway HA, scaling, failover → **F6** mode
migration, MSP API, billing hooks → **F7** integration, security and acceptance testing.

### Dependencies and tensions noted (for the future design)
* F1 depends on ADR-0018 G1 (gateway data model) — the network model must extend it, not replace it.
* Mail ingress (ADR-0018 §10 / G5) is a prerequisite for multi-tenant mail in Mode A and for F3.
* The current public entry lives on the ICS host (temporary, ADR-0018 §10 "separate gateway VM"); Modes A/B assume a dedicated gateway VM,
  so moving the entry off the ICS host comes first.
* Gateway-side HTTP-01 renewal (ADR-0018 §11) does not work in Mode C; there the deployment CA or imported certificates apply.
* The tenancy mode (issue #32: single / multi tenant) is independent of the network mode; both are setup choices.
