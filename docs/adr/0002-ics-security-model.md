# ADR-0002 ICS security model
Status: Accepted (2026-11-15)
1. Operators: local ICS accounts (argon2id + mandatory TOTP), server-side sessions, CSRF protection. Independent of any tenant IdP → doubles as break-glass. Roles: viewer, operator, approver, admin. Requester can never approve own action.
2. Infra credentials: separate identities per purpose. Inventory = privilege-separated Proxmox token with PVEAuditor (read-only). Mutations = a second token scoped to an approved pool/storage/bridge only. Never root@pam, never privsep=0.
3. TLS: always verified, against a CA bundle or an operator-supplied SHA-256 fingerprint pinned at registration. No TOFU, no verify=False anywhere (rejects Depl0y pattern).
4. Secrets: AES-256-GCM encrypted in DB; key in a separate root-owned file readable only by the ICS service user; decryption failure = hard error (no plaintext fallback). Secrets never in logs, audit details, API responses or LLM prompts.
5. Actions: closed catalog of typed actions with validated parameters (no free-form command, image, mount, script fields). Flow: plan → approve (risk-tiered; high risk = 2 approvers) → single-use job → execution → verification. Adopted from rem0te design.
6. Audit: append-only, SHA-256 hash-chained (port of rem0te audit/chain.ts), no request bodies containing secrets; DB role for the app has no UPDATE/DELETE on audit table.
7. No SSH-with-sudo, termproxy, guest-agent exec, or Docker socket exposed via ICS APIs.
