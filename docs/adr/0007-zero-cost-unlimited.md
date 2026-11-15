# ADR-0007 Zero-cost, unlimited software requirement (foundational)
Status: Accepted (2026-11-15, owner directive) — supersedes any earlier "buy a subscription" option.
Mandatory third-party software licensing/subscription/support/API/LLM spend = $0. No per-user, per-mailbox, per-document, per-connection charges and no artificial user/org/connection limits in anything we ship. Infrastructure (hardware, power, bandwidth, domains) is operational cost, not licensing.
Consequences:
- Evaluate source + actual license, not the vendor's packaged edition. Vendor packaging restrictions are not disqualifying if the source license lets us build/modify/distribute ourselves.
- Where permitted, Office Unbound builds and ships its own packages/images from pinned upstream source with minimal patches (prefer small patch queues over deep forks). Must rename/rebrand where trademarks require.
- Component gate (all mandatory): source available; self-hostable; commercial use permitted; no per-user licensing; no connection caps; no mandatory subscription or external API; independently maintainable; customer data portable; unrestricted growth. Source build preferred.
- Every component, incl. transitive deps, bundled binaries, fonts, codecs, plugins, is recorded in docs/status/third-party-inventory.md before adoption. Unclear license = not adopted.
- Our own core has no seat limits; quotas exist only as operator-adjustable resource protection.
- External AI/SMS/PSTN are optional, opt-in, default off and $0.
- Build pipeline (ADR-0008, planned): pinned source, reproducible where feasible, SBOM, vuln + license scan, signed artifacts, staged release channels, rollback, customer-controlled upgrades. ICS must be able to drive it.
