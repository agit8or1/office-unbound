# Glossary

Plain-language terms used in the console and this guide. "Evidence" is where each is defined in the repo.

| Term | Meaning |
|---|---|
| **Action** | One kind of change the ICS knows how to make (for example `endpoint.register`, `user.invite`). The list is closed: there is no "run any command". `GET actions` lists them. |
| **Plan** | A written request to perform one action with exact parameters. Nothing happens when you create a plan. It is fingerprinted (hash) so it cannot be altered after approval. |
| **Approval** | A decision by an approver on a plan. Risk decides how many are needed: low = automatic, normal = one approver who is not the requester, high = two different approvers. Requesters never approve their own plans. Evidence: [ics/README.md](../../ics/README.md). |
| **Job** | The one-time run of an approved plan. It re-checks the plan hash first, records progress and result, and is never silently re-run if it fails. |
| **Audit log** | Tamper-evident record of every plan, approval and job (hash chain + HMAC). Verify with `ics.cli verify-chain`. |
| **Endpoint** | A connection from the ICS to an infrastructure system; today a Proxmox cluster. Holds the address, the pinned TLS identity, encrypted API tokens and the allowed scope. Shown under **Integrations**. |
| **Inventory** | What the ICS has learned from an endpoint (nodes, storage, networks, VMs), refreshed every 5 minutes. |
| **Scope / allowlist** | What the ICS may touch on an endpoint: pools, storage, networks, templates and **nodes**. Empty means nothing (deny by default). |
| **Protected VM** | A VM the ICS must never change, notably the VM the ICS itself runs in. |
| **Node agent** (`ou-agent`) | Small unprivileged service on a managed machine that runs only signed, pre-approved runbooks (restart a listed service, report disk usage). Enrolled with a one-time token and verified fingerprints. |
| **Runbook** | A fixed, named procedure the node agent may execute. |
| **Check / incident / remediation** | A check probes a service on a schedule; a failing check opens one incident; a remediation policy may restart the failed service within strict limits. |
| **Maintenance window** | A period in which alerts and remediation are suppressed (always announced). |
| **Deployment** | One customer environment planned and created by the ICS from a profile, on an endpoint. **Implementing.** |
| **Profile** | A size/shape template for a deployment (which components, how many users, high availability or not), defined in `blueprints/catalog/`. |
| **Component** | One part of a deployment (identity, groupware, files, office, edge, monitoring agent). |
| **Drift** | The difference between what a deployment should look like and what is actually there. Reported only; the ICS does not auto-repair. |
| **Wizard** | An optional guided form on the dashboard ("Start guided setup", "Start deployment wizard") that builds a plan for you. Never opened automatically. |
| **Passive controller** | A restored ICS with its worker and monitoring switched off until you deliberately cut over. Prevents two controllers acting on the same nodes. |
| **Break-glass** | Emergency use of the host command line (`ics.cli`) by someone with root on the ICS host. Always audited as actor `cli`. |
| **Lab-proven** | Executed in the isolated lab only. Not a statement about production. |
