# Runbook: provider access recovery (break-glass)

Principles
- ICS operator access (local accounts + TOTP, ADR-0002) is independent of any customer or tenant identity. Recovery never uses tenant
  admin or employee logins, and a customer login is never an infrastructure credential.
- The customer always keeps control of their infrastructure. ICS never recreates, resurrects or "works around" a revoked or expired
  credential. Access returns only when the customer (or the MSP, for MSP-owned infrastructure) issues a NEW credential and it is
  connected through the setup wizard / `credential.replace`.
- Never paste a secret into a ticket, chat, shell history or URL. Secrets are entered only in the wizard (HTTPS) and travel in the
  plan's encrypted secret part.

Find the state first: `GET /api/v1/credentials?customer_id=...` (status, expires_at, last_validated_at) and
`GET /api/v1/credentials/{id}` (rotation history). `credential.test` re-validates a credential without changing anything.

| Situation | Symptom | Action |
|---|---|---|
| Token expired | status `expired`, expiry alert, inventory errors "credential is expired" | Customer issues a new token. Operator submits `credential.replace` (or `credential.rotate` if the token id is unchanged) with the new secret. The new secret is test-authenticated BEFORE anything is stored; the old record is retired and kept for a 7-day grace period, then purged. |
| Service account disabled at the provider | `credential.test` fails, status `invalid` | Customer re-enables the account or creates a new one. Run `credential.test`; if the token id changed use `credential.replace`. |
| Permissions removed | probe/inventory shows missing privileges, provisioning refused | Show the customer the permission plan (the wizard prints the exact `pveum` commands). For customer-owned infra use the customer approval link so the customer reviews and confirms the grant. Re-run the probe. Do NOT widen allowed pools/storage to compensate. |
| ICS unavailable | UI/API down | Provider access is unaffected (it lives in the providers). On the ICS host: `systemctl status ics`, `journalctl -u ics`, `python -m ics.cli verify-chain`. Restore from backup if needed (restore-drill doc). Operator login recovery: `python -m ics.cli issue-enrollment --username NAME`. Workloads on the customer infrastructure keep running; only management pauses. |
| Vault inaccessible (key file missing/permissions/corrupt) | ICS refuses to start or jobs fail with "cannot read vault key" / "decryption failed" | There is no plaintext fallback. Restore the key file (root:ics 0640) from the sealed offline copy; check `ls -l`. If the key is truly lost the stored secrets are unrecoverable by design: every credential must be re-issued by its owner (customer or MSP) and re-entered via the wizard; stale records are revoked with `credential.revoke`. After a key swap that changed the key, run `python -m ics.cli rewrap-master` BEFORE the swap (see docs/status/credential-vault.md). |
| Customer revoked access | `credential.test` 401, provider audit shows deletion | Treat as authoritative. Run `credential.revoke` (destroys the stored secret, records reason). The endpoint stays registered but cannot be used. Do not retry, do not create replacement tokens yourself. If access should resume, the customer issues a new credential and approves it (approval link). |

Reconnect with new credentials (any case above)
1. Customer issues the credential in the provider (token with the minimum role from the permission plan; never root, never privsep=0).
2. Operator: wizard "reconnect", or plan `credential.replace {credential_id, secret, identity, expires_at, reason}`. High risk: two ICS approvers
   (plus the customer policy's extra approvals, plus the customer approval link for customer-owned infra when permissions change).
3. The job authenticates the new credential against the provider first; on failure nothing is persisted.
4. Verify: `GET /credentials/{id}` shows `active`, `last_validated_at` set; run `inventory.refresh`.
5. Audit trail: `GET /credentials/access-review` and the hash-chained audit (`credential.replaced`, `credential.use`).

Emergency stop (suspected leak): `credential.revoke` on the credential (ICS side, immediate secret destruction), then tell the customer to
delete the token at the provider. Revocation by ICS never substitutes for deletion at the provider.
