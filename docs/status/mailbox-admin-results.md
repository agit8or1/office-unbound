# Mailbox and storage administration (aliases, shared mailboxes, quotas): results

Date: 2026-11-16. Branch `mbx-be`. Status words follow ADR-0000: **Integrated in lab** for aliases, shared-mailbox lifecycle and read access, mail quotas and OpenCloud storage quotas (real Gromox/OpenCloud/LDAP/Keycloak through a development ICS and sidecar agents). **Not proven:** a delivered `From:` header equal to the shared mailbox (send-as), see "Findings".

## 1. What was built
| Piece | Where |
|---|---|
| Typed actions `idm.user.set_aliases`, `idm.shared_mailbox.create/delete/grant/revoke`, `idm.user.set_mail_quota`, `idm.user.set_storage_quota` (closed models, plan-time policy, executors, hash-chained audit, no secrets in audit/jobs) | `ics/ics/mailadmin.py`, registered in `actions.py`; migration `0010b` (tables `idm_aliases`, `idm_shared_mailboxes`, `idm_shared_grants`, `idm_quotas`) |
| Fixed node runbooks `gromox.set_aliases / shared_create / shared_delete / shared_access / shared_state / set_quota / mail_usage` (closed-shape params, validated by the agent AND again by the helper) | `ics/agent/ou_agent/{mbxspec,mbxhelper}.py`, unit `deploy/runbooks/ou-rb-gromox-mbx@.service` (runs as user `gromox`, not root), polkit renderer, installer, `agent.json` |
| Tenant (Organization Admin) API | `/api/v1/tenant/{aliases,shared,quotas}`, `/users/{uid}/aliases`, `/shared/*`, `/users/{uid}/quota/{mail,files}`; approval policy unchanged (delete of a shared mailbox = high risk = second administrator or MSP) |
| Portal | `/admin/addresses`, `/admin/shared[/{name}]`, `/admin/storage` (usage bars as `<progress>` with labels); the "Planned" labels for these items are gone |
| Lab proof | `ics/scripts/lab_mailbox_admin.py`, `ics/scripts/lab_agent_sidecar_be.sh` |

### Design decisions (and why)
* **Aliases: Gromox `aliases` table, not LDAP.** `gw-ldap-sync.py` maps only `mail` -> login/`users.username`, `entryUUID`, `displayName`, `memberOf`, lock; it does not read an alias attribute (and a multi-valued `mail` would break its one-user-per-mail logic). So the source of truth is the fixed runbook `gromox.set_aliases` (replace semantics inside one SQL transaction) plus the ICS table. The sync never touches `aliases`. Postfix needs a lookup, otherwise it rejects the alias at RCPT time: `virtual_alias_maps = mysql:/etc/postfix/mysql-valias.cf` (`SELECT mainname FROM aliases WHERE aliasname='%s'`), installed by `install-agent.sh` when the runbook is enabled. Domains: the stack's `mail_domain` plus optional `alias_domains` (new field in `idm.stack.register`, MSP-controlled); the node enforces the same list from root-owned `/etc/ou-rb/gromox.json`. Uniqueness is checked across ALL stacks of the customer (users, aliases, shared mailboxes, including deleted ones whose data is retained) in the ICS and again against the Gromox tables.
* **Shared mailbox: Gromox-native.** `users` row with `address_status = 4` (SHARED), password `!`, no `externid`: authmgr refuses every login and the LDAP sync never adopts it. Store created with `gromox-mkprivate` / `gromox-mkmidb`. Delete = suspend + drop all grants; data is retained and the address can never be reused (same rule as deleted users).
* **Access mapping (source: gromox `exch/exmdb/store.cpp`, `store2.cpp write_delegates`, `message.cpp defer_check_repr`, `exch/ews/context.cpp`):** full access = folder rights `1531` (ReadAny, Create, EditOwned, DeleteOwned, EditAny, DeleteAny, CreateSubfolder, Owner, Visible; the value the GW05 lab uses) on the root, IPM subtree and every non-search folder of the store (rows in the store's sqlite `permissions` table); send-as = line in `config/sendas.txt`; send-on-behalf = line in `config/delegates.txt` (the files admin-api's `write_delegates` writes). The helper writes them atomically as the `gromox` user (WAL files stay owned by gromox).
* **Mail quota: store properties** `PR_STORAGE_QUOTA_LIMIT 0x3FF5`, `PR_PROHIBIT_SEND_QUOTA 0x666E`, `PR_PROHIBIT_RECEIVE_QUOTA 0x666A` (PT_LONG, KiB) written into the store's `store_properties` (the quota check reads them from sqlite on every delivery/send, `exch/exmdb/common_util.cpp cu_store_msgsize_limit_reached`, so no restart or exmdb call is needed). One number (`limit_mb`) sets all three; overrides are possible per property. Usage = `PR_MESSAGE_SIZE_EXTENDED`. No CLI exists for numeric store properties (`gromox-mbop` only sets named ones), which is why this goes through sqlite like the GW05 ACLs.
* **Storage quota: OpenCloud Graph, minimal role = Admin.** `PATCH /graph/v1.0/drives/{id}` `{"quota":{"total":N}}`. OpenCloud's roles are fixed; changing a PERSONAL space quota needs `Drives.ReadWriteQuota.Personal`, which only the **Admin** role carries (Space Admin covers project spaces). So the ICS holds ONE dedicated directory user (`svc-ocquota`, group `opencloudAdmin`) whose password is a vault secret of the stack (`oc_quota_user` / `oc_quota_password`, AAD-bound like the other stack secrets, never in audit). The ICS gets its token with the stack's direct-grant client and uses exactly: `GET /graph/v1.0/drives?$filter=driveType eq 'personal'` (usage + quota of every personal drive in one call) and `PATCH /graph/v1.0/drives/{id}` (unit-tested: nothing else is called). The Admin role is broader than needed (it is the smallest OpenCloud offers): mitigations are the dedicated account, vault storage, MSP-only configuration (tenant admins cannot supply it) and the narrow client code. App tokens (`opencloud auth-app`) cannot be used instead: the Graph API answered 401 for them on this lab (measured), they only work for WebDAV/auth-app endpoints.

## 2. Tests executed
* `ics/tests/test_mailadmin.py` 12 tests PASS: strict models, hostile agent parameters (SQL/shell/path/type confusion), alias add/remove/uniqueness/foreign domain/other stack of the same customer, node refusal leaves the record unchanged, shared mailbox lifecycle incl. second-admin delete and non-reuse, grants/revokes, org-admin gating, mail quota set/clear with usage, storage quota via the files service (fake client), the three Graph calls only, no secrets in audit.
* `ics/tests/test_mbxhelper.py` 5 tests PASS: the node helper against a real sqlite store with Gromox's table shapes: domain and uniqueness rules, shared-only operations, folder-rights rows, `sendas.txt`/`delegates.txt` contents and mode, quota properties and usage, spool not trusted (re-validation), agent wiring.
* Portal `portal/tests`: **28 PASS** (26 + 2 new: pages, CSRF on every change, forwarded payloads, admin-only, no script/inline style).
* Full backend suite (`ICS_TEST_ENV_FILE=/etc/office-unbound/ics-test-f.env pytest -q -p no:cacheprovider`, own DB `ics_test_f`): **560 passed** in 736 s (migration chain test pinned to head `0010b`).

## 3. Lab proof (`lab_mailbox_admin.py prove`): 32 PASS / 0 FAIL
Dev ICS on 127.0.0.1:8126 (database `ics_test_f`, no other connection), real OpenLDAP + Keycloak, sidecar agents `ou-agent-be` (port 8446, own state and trust, code in `/opt/ou-agent-be`) on `ou-gw1` and `ou-files1`; the production ICS and the production agents' trust were not touched. Three fresh people created through ICS plans (one-time enrollment, own passwords). Output (`prove-final`): 
```
PASS SMTP accepts mail for the alias address - accepted by postfix (virtual alias map)
PASS mail to the alias is delivered to the owner (IMAP) - arrived in mba9883b7's INBOX, To: salesc3ca45@ou-lab.internal
PASS an address that is not an alias is refused - refused: 550
PASS an alias already used by another person is refused (409) / a foreign domain is refused (422)
PASS after removal the alias is refused again - refused: 550
PASS nobody can log in to the shared mailbox directly - refused: Wrong username or password, or administratively blocked
PASS a person without a grant cannot read it (EWS) - ErrorAccessDenied
PASS the grantee reads the shared mailbox via EWS - message visible
PASS after revoking full access the person is refused (EWS) - ErrorAccessDenied
PASS a person on the delegate list can submit mail in the shared mailbox's name (EWS) - NoError
PASS a person without any grant cannot submit in its name - ErrorAccessDenied
PASS after revoking, the same person is refused - ErrorAccessDenied   /  nothing arrived from the refused attempt
PASS quota stored in the mailbox's store properties - 3ff50003|1024 666a0003|1024 666e0003|1024
PASS receive limit enforced: mail over the quota is NOT delivered - gromox-delivery: "user's mailbox has reached quota limit"
PASS send limit enforced: a person over quota cannot send - ErrorItemSave
PASS quota removed: delivery works again
PASS quota visible to the person's own client - {'remaining': 1048576, 'state': 'normal', 'total': 1048576, 'used': 0}
PASS an upload within the quota succeeds - HTTP 201          PASS an upload beyond the quota is refused - HTTP 507 (Insufficient Storage)
PASS quota removed: the same upload now succeeds - HTTP 201  PASS no password or token in the audit log
```
Plans ran as normal-risk (one approver) except the test-user deletes in cleanup (high, two approvers). Cleanup removed the test people.

## 4. Findings and limits (honest)
1. **Send-as is NOT proven.** On this lab's Gromox 3.13 build the EWS submit path accepted a person on `delegates.txt` (send-on-behalf) and refused everyone without a grant, but (a) the delivered `From:` stayed the submitter, `Sender:` was absent (`INFO headers ... From=mbb... Sender=None`), and (b) a person with only `sendas.txt` got `ErrorAccessDenied`. A person with full folder access was also allowed to submit (store-owner rule), so revoking send-as does not stop someone who still has full access. The lists are written in exactly the format of admin-api/exmdb (`write_delegates`), and the reference source (newer than the installed build) honours `sendas.txt`; the installed build evidently does not behave like it. Needs a Gromox rebuild/upgrade check before send-as is promised to customers; until then the portal states what each right means and send-as should be treated as unverified.
2. EWS **could not send at all** on this lab before this work (`vmime.connect sendmail://localhost: No factory available`, E-3117). Fixed on `ou-gw1` with `outgoing_smtp_url=smtp://127.0.0.1:25` in `/etc/gromox/gromox.cfg` (host change below); the installer does not set it yet: add it to the Gromox node blueprint.
3. Quota enforcement is size-at-check: a mailbox is "full" once the store size reaches the limit (a single big message can overshoot); with 1 MB limit one 600 KB message was delivered and the following ones refused ("reached quota limit"). Usage is read from `PR_MESSAGE_SIZE_EXTENDED` (fresh in the lab).
4. Direct sqlite writes (permissions, store properties) bypass exmdb: proven to take effect immediately (read per check), but a future Gromox could cache; the alternative is a small exmdb client.
5. OpenCloud: the quota identity needs the Admin role (see above). A person's personal drive exists only after their first OpenCloud sign-in; before that the action fails with a plain message. File-quota usage in the portal needs the same identity.
6. Not covered: the tenant API/portal were not run against these real nodes (unit/portal tests with mocks only); IMAP shared folders / Outlook auto-mapping; aliases for shared mailboxes; domain-level default quotas; usage warnings by mail.

## 5. Operating it
* Gromox node: `OU_MAIL_DOMAIN=<domain> OU_ALIAS_DOMAINS=a.test,b.test sh install-agent.sh <addr> <host>` with the new runbooks in `agent.json` (installs unit, polkit entry, helper, postfix alias map, `/etc/ou-rb/gromox.json`). Stack: `idm.stack.register` with optional `alias_domains` and, for file quotas, `oc_quota_user` + `oc_quota_password` + `probe_client_id`.
* Lab: `lab_agent_sidecar_be.sh` (on the node, with the agent tree copied to `/root/be-src`), then `lab_mailbox_admin.py prep | up | prove | cleanup | down` (uses `lab_org_admin.py` plumbing, `BE_DIR` state, DB `ics_test_f`; TOTP of the operators means two logins within 30 s fail: wait between commands).
