# Users and access

Two separate populations: **ICS operators** (people who run the control plane) and **customer users** (mail/files/SSO accounts of a customer stack).
Evidence: [ics/README.md](../../ics/README.md), [user-lifecycle-results.md](../status/user-lifecycle-results.md), [portal-results.md](../status/portal-results.md).

## ICS operators
Local accounts, argon2id password + mandatory TOTP, server-side sessions (max 10 per user, `auth/logout-all`), independent of any customer IdP. Roles: viewer < operator < approver < admin.

**Invite a user** (admin): plan `user.invite` (viewer/operator: low risk; approver/admin: **high**, two approvers, mandatory justification). The invite has no password or TOTP and cannot log in.
A host operator then issues the one-time token out of band:
```
sudo -u ics /opt/office-unbound/ics/.venv/bin/python -m ics.cli issue-enrollment --username <name>
```
The person enrolls (own password, TOTP) as described in [installing-the-ics.md](installing-the-ics.md). Tokens last 24 h, single use, stored hashed.

**Privileged-role workflow:** approver/admin accounts and any role change (`user.set_role`) are high risk. Rules: nobody targets their own account; the last active admin is protected; the target cannot decide the plan;
an approver created or elevated by the requester cannot decide that requester's plans. Other actions: `user.disable` / `user.enable` (high for approver/admin targets), `user.revoke_sessions`, `user.revoke_invite`.
The Users page and `GET access-policy` show the effective rules.

**Lockout / recovery:** `ics.cli unlock --username X` clears login throttling; `issue-enrollment` resets password, TOTP and sessions.

**Break-glass:** anyone with root on the ICS host (or `sudo -u ics`) can create accounts and read keys through the CLI. This is by design (ADR-0002), is audited as actor `cli`, and cannot be prevented. Restrict host root accordingly.
Lab demo accounts (`lab-op`, `lab-ap1`, `lab-ap2`) hold all two-person roles: delete them before any real use (accepted lab risk, review M5).
Not implemented: password change endpoint, session listing UI (**Planned**).

## Customer users (one stack: LDAP + Keycloak + OpenCloud + Gromox)
Register the stack once with `idm.stack.register` (high). The ICS uses narrow service identities: LDAP `cn=svc-ics` (write under `ou=people`, member add/remove on existing groups, cannot read passwords),
Keycloak client `ou-ics` (`manage-users`, `view-users`, `query-clients`), and node-agent runbooks for Gromox/OpenCloud. Lab setup: `ics/scripts/lab_user_lifecycle.py setup`.

| Action | Risk | Effect |
|---|---|---|
| `idm.user.create` | normal | LDAP entry + groups, Gromox mailbox sync, OpenCloud visibility check, one-time enrollment token. Immutable id = LDAP `entryUUID` |
| `idm.user.update_groups` | normal; high for privileged groups | Entitlement change re-syncs Gromox; removal ends the Keycloak session |
| `idm.user.disable` | normal | LDAP lock, Keycloak disable + logout + offline-token revoke, Gromox suspend + mailbox quarantine, then VERIFY probing every path |
| `idm.user.enable` | normal | Unlock/reactivate; old password replaced; new one-time enrollment issued |
| `idm.user.delete` | high | Only after disable; LDAP + Keycloak removed; **mailbox data retained** (no purge action) |
| `idm.reconcile` | low | Read-only drift report across the four systems; never auto-repairs |

There is **no initial password**. Only the plan's requester can reveal the enrollment token (once, `POST identity/enrollments/{plan_id}/reveal`); the user redeems it with `POST identity/enroll` and chooses their own password.

**Measured revocation (lab, same session):** every probed path refused within about 5 s of the LDAP lock (Keycloak password login 0.1 s, refresh tokens 2 s, IMAP/EWS/ActiveSync 2 s, OpenCloud tokens 4-5 s). The ICS VERIFY step fails the job loudly if any path stays valid (target <= 60 s); the user remains disabled.

### Known revocation gaps (do not rely on these)
- **OpenCloud app tokens resurrect on re-enable**: a token minted before a disable was accepted again after `idm.user.enable` (finding in the run). A revoke path is not implemented. Treat an enable after a security-driven disable as needing manual app-token review.
- **ActiveSync device wipe** is not implemented (no admin-api); the disable only blocks authentication.
- **Gromox open IMAP sessions** are ended by a quarantine workaround (mailbox store mode 0000), not by a native kick.
- An LDAP lock alone does **not** end Keycloak SSO/offline tokens (>420 s measured, KI-2). Always deprovision through the ICS action, which revokes in Keycloak.
- The user portal keeps a session until its access token (5 min) cannot be refreshed; back-channel logout is not implemented, and disabled-user behaviour was not tested with the portal ([portal-results.md](../status/portal-results.md)).
- Mailbox purge/export is **Planned**; deleted users' mailboxes stay on disk.
