# Customers and approvals

Label: **Tested** (automated tests against the test database and a mock Proxmox). **Not run on a real cluster.** The only console screen for customers is the Providers console ([providers-ui.md](../status/providers-ui.md)).
Evidence: [credential-vault.md](../status/credential-vault.md), [provider-stack-integration.md](../status/provider-stack-integration.md), tests `ics/tests/test_vault_m.py` and `ics/tests/test_provider_stack.py`; operator scoping and tenant fixes in [tenant-isolation-results.md](../status/tenant-isolation-results.md).
Read first: [Installing the ICS](installing-the-ics.md) (accounts) and the [Glossary](glossary.md).

## 1. The approval model in one minute
Every change is a **plan**. The ICS computes its risk and how many different approvers it needs:
| Risk | Approvers needed | Examples |
|---|---|---|
| low | none (auto-approved, still planned and audited) | `inventory.refresh`, `plan.archive` |
| normal | one approver who is not the requester | `check.delete`, `maintenance.cancel` |
| high | two different approvers, neither the requester | `endpoint.register`, `deployment.create`, `customer.create`, `user.invite` of an approver |
Effective rules are shown read-only by `GET access-policy` (console: Users and roles). A plan is bound to a hash of its parameters, so an approval cannot be reused for a different change. Pending plans expire after 7 days.
A working installation therefore needs **at least three people**: one requester and two approvers.

## 2. Inviting approvers
First two approvers, on the ICS host (prints a one-time token, valid 24 hours, single use; hand it over privately):
```
cd /opt/office-unbound/ics && sudo -u ics .venv/bin/python -m ics.cli create-admin --username approver1 --role approver
```
Later accounts are invited from the console (**Administration > Users and roles**), which files a `user.invite` plan. Inviting a viewer or operator is low risk. Inviting an **approver or admin is high risk** (two approvers and a written justification).
The invite has no password and cannot log in. A host operator then issues the token: `cd /opt/office-unbound/ics && sudo -u ics .venv/bin/python -m ics.cli issue-enrollment --username <name>`. The person enrolls with their own password and a TOTP code.
Rules that protect the approvers: nobody changes their own account, the last active admin is protected, the target of a plan cannot decide it, and an approver created or elevated by a requester cannot decide that requester's plans. See [Users and access](users-and-access.md).

## 3. Customers
Every Proxmox endpoint and credential belongs to exactly one customer. Endpoints that existed before customers were introduced belong to the default customer "MSP (internal)".
Create and change customers with the plans `customer.create` and `customer.update`. Both are admin-only and **high risk** (two approvers), and only an admin with all-customers scope can request them.
| Field | Meaning |
|---|---|
| `name` | unique name |
| `msp_owned` | true for infrastructure the MSP itself owns |
| `provisioning_mode` | `auto`, `customer_approval` or `monitoring_only` (default `auto` when MSP-owned, otherwise `customer_approval`) |
| `contact_name`, `contact_email` | who the customer approval links are meant for |
| `extra_approvals` | per category, 0 to 3 more distinct ICS approvers: `delete_guest`, `remove_storage`, `network_change`, `expand_permissions`, `revoke_credential` |

## 4. Approval policies: what each mode does at plan time
| Mode | Effect |
|---|---|
| `auto` | normal ICS approval rules only |
| `customer_approval` | the **customer** must approve before the job is released, in addition to the ICS approvers |
| `monitoring_only` | every action that changes something is refused (HTTP 403); read-only monitoring still works |
Extra approvals add that many more distinct ICS approvers for the matching category (for example widening Proxmox permissions is `expand_permissions`).

## 5. Scoping operators to customers
By default an operator sees all customers. To restrict someone, an admin requests `operator.set_scope` (high risk, two approvers) with the username and either `all_customers` or a list of customer ids. The server then hides everything outside that list (HTTP 404) for endpoints, infrastructure, metrics, credentials, customers, approvals, plans and jobs, and refuses plans that name no customer.
Known gap: checks, nodes, alert channels and customer identity stacks are not yet bound to a customer, so a scoped operator cannot create those plans, and reading the audit log needs the all-customers scope.

## 6. Customer approval links (customers have no ICS login)
Used when the customer owns the cluster and must agree to the permission design.
1. An operator creates the approval (`POST /customer-approvals`, then `.../submit`). The ICS returns a link of the form `/approve#t=<token>` **once**. The token is in the URL fragment, so it never reaches server logs.
2. **The ICS sends no email.** Deliver the link yourself, out of band.
3. The link is single use, expires (default 72 hours, maximum 7 days) and is rate limited. The customer sees the exact proposal (for Proxmox: every role, path and privilege, plus the package files) and approves with name, email, a statement and the proposal hash.
4. The decision, IP address and browser are written to the audit log (`customer_approval.approved`, `.rejected`, `.changes_requested`, `.provisioned`). A second single-use completion link confirms provisioning afterwards.
A customer login is never an infrastructure credential, and the ICS never recreates a credential the customer revoked ([provider access recovery](../runbooks/provider-access-recovery.md)).
Limit: a Mode A plan that waits on a customer link outlives its 15-minute admin credential and must be re-planned. Use Mode B for customer-owned clusters ([Connecting Proxmox](connecting-proxmox.md)).

## 7. Typical first-customer sequence
1. `customer.create` (admin only, high risk, two approvers).
2. Connect the customer's Proxmox: [Connecting Proxmox](connecting-proxmox.md) (the endpoint is created for that customer).
3. Optionally `operator.set_scope` for the engineers who serve only that customer.
4. Build the environment: [Deploying a customer environment](deploying-a-customer.md).
