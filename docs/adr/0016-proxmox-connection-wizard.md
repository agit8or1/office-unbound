# ADR-0016: Proxmox connection and access management wizard (sign-in, discover, select, authorize)

Status: Accepted (2026-11-16). Implementation in progress on branch `pve-wizard`. Phases and evidence are listed below.

## Context

The owner directive of 2026-11-16 replaces the token-first connection wizard with this flow:

**Connect → Discover → Select → Authorize → Done**, reusable indefinitely as **Manage Resources → Select Changes → Apply → Done**.

It must work with a Proxmox user name, password and second factor. The administrator must not create tokens, ACLs or fingerprints by hand.

The provisioning engine already existed and is reused unchanged:

- `providers/proxmox/provisioning.py` covers design, plan, apply with rollback, verify and drift.
- `scope_change.py` handles incremental widen and narrow.
- Token rotation and revocation are typed actions.
- The credential vault, approvals, jobs and the hash-chained audit are reused as they are.

What was missing:

- a sign-in that handles a second factor
- a discovery tree
- authorization of individual existing guests
- inventory sync with "discovered, not authorized"
- a single graphical flow for both first setup and later changes

## Decision

### Sign-in (`provisioning/adminsession.py`, `/api/v1/pve-sessions`)

- The ICS logs in to the Proxmox API itself with `POST /access/ticket`.
  - If the account has a second factor, Proxmox returns a challenge ticket (`NeedTFA`). The TFA step answers with `totp:`, `recovery:` or `yubico:`.
  - **Only the resulting ticket and CSRF token are kept.** They live in the vault as a `temporary_provisioning` credential (provider `pve-admin`) for at most 30 minutes.
  - The password and the TFA code exist only for the duration of the request. They are never stored, logged or echoed; validation errors name fields only.
- A session belongs to the ICS user who created it, one Proxmox address and its exact TLS anchor.
  - A plan that names `admin_session` gets the ticket copied into its own temporary credential at creation (`create_plan`).
  - The copy is refused for any other user, address or anchor, so a ticket is never sent to another server.
  - Clients cannot supply `admin_ticket` themselves.
  - The session is destroyed after a successful apply, reconcile, scope change, rotate or revoke, and on sign-out or expiry.
- Rate limits: 10 sign-in attempts per operator and per target host every 10 minutes. A session ends after 5 wrong second-factor codes.

### TLS trust

- `POST /api/v1/pve-sessions/tls` performs only the handshake.
  - A certificate that is publicly valid for the host name needs no manual step. The issuing root is pinned, not the leaf, so ACME renewals keep working.
  - Otherwise the wizard shows the presented SHA-256 fingerprint and where to compare it (the Proxmox UI under *System > Certificates*, or `openssl` on the node), or the administrator pastes the cluster CA.
- Verification is never disabled.

### Access model (`provisioning/model.py`)

- The new preset `operations` means monitoring plus power control.
- The new scope list `managed_vmids` names existing VMs and containers authorized one by one. It becomes an ACL on `/vms/<vmid>` with `propagate=0`, so Proxmox enforces it natively.
  - Role `operate` = `VM.Audit` + `VM.PowerMgmt`.
  - Selecting a node never grants rights on its guests: node ACLs carry `Sys.Audit` only in node scope modes.
- The new typed action `guest.power` (start / shutdown / stop / reboot) works only on `managed_vmids`.
  - It never touches protected guests, the ICS's own VM or templates. The node and type are read from Proxmox.
  - Risk is low for start and normal otherwise.

### Reuse

- Initial setup = `provider.provision.plan_preview` + `provider.provision.apply`, both with `admin_session`.
- Later changes = `provider.scope.change` (incremental ACL diff), `provider.permissions.reconcile` (repair), and `provider.token.rotate` / `provider.token.revoke`. Each can use `admin_session`.

## Known Proxmox limitations (stated in the UI and the plan's enforcement list)

| Limitation | Consequence / safest alternative |
|---|---|
| WebAuthn/passkey second factors are bound to the Proxmox web origin. | The ICS cannot answer them. The wizard says so and offers TOTP, a recovery key or an existing privileged API token. |
| Proxmox has no API to revoke a ticket early. | The ICS destroys every copy it holds. The ticket expires on the Proxmox side within 2 hours. |
| `VM.Allocate` covers both create and delete in a pool. | Deletion stays an ICS-gated typed action with its own approval (`deployment.destroy`, high risk). Proxmox alone cannot separate it. |
| Pool ACLs do not restrict the node a guest is created on. | The node allowlist is enforced by the ICS broker (existing note). |
| VMID ranges, guest types and resource caps cannot be expressed in ACLs. | They are enforced by the ICS (existing notes). |
| A restricted token sees only what it is authorized for. | Discovering *new, unauthorized* resources needs read-only audit on `/` for the inventory token only (Phase 3, an explicit option). |

## Phases (each gated by tests before it is called working)

1. **Sign-in with TFA, ticket-only storage, TLS look-up, discovery API.** Done on branch. Tests: `tests/test_admin_session.py`, 15 passing against the simulator.
2. **Operations preset, `managed_vmids`, `guest.power`.** Code done. Fixed in passing: `image.import` plans were refused at execution (endpoint binding missing on verify). Tests: `tests/test_operate.py`.
3. Inventory sync: snapshot per endpoint; new / missing / renamed or reused VMID; dashboard count; drift → "Connection requires attention".
4. Console: the new wizard (Connect → Discover tree → Access → Permissions → Review/Apply) and Manage Connection (edit mode on the same steps).
5. Deployment target picker from authorized scope; docs; e2e.

Every phase is simulator-tested first. Real-cluster evidence comes from pve06, once the owner connects it.
