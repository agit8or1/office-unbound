# Tenant isolation results (acceptance A20, agent AS)

Date 2026-11-15. A20 (owner directive): "Two isolated customer deployments pass cross-customer access-denial tests. Do not mistake multiple application-level organization IDs for proven secure multi-tenancy. Test at least two independent customer deployments before claiming isolation."
Status values per ADR-0000. Everything marked PASS below was executed; evidence is the output of `blueprints/lab/tests/t20_tenant_isolation.py` (full run: **153 PASS, 1 FAIL, 1 SKIP**; the FAIL is the known backup-encryption gap, 2.5).

## 1. What was built

Two independent customer stacks, identity + files tier only (no groupware/office, to fit host memory), built with the documented installers (`spike-identity-files/kc/install-kc.sh`, `install-openldap.sh`, `files/install-files.sh`) driven by `blueprints/lab/tenant/build-customer.sh a|b` (per-customer `lab.env`; the installers are unchanged except two small parameterisations, see 6).

| | Customer A | Customer B |
|---|---|---|
| domain / realm / LDAP base | `custa.ou-lab.internal` / `custa` / `dc=custa,dc=ou-lab,dc=internal` | `custb...` / `custb` / `dc=custb,...` |
| machines (nspawn, zone oulab) | `ou-ca-id` .61 (2G cap): lab CA, OpenLDAP, PostgreSQL 16, Keycloak 26.8.2; `ou-ca-files` .62 (1.5G cap): OpenCloud 9.1.0 + nginx | `ou-cb-id` .71, `ou-cb-files` .72 |
| separate | lab CA (generated on its own id machine, CA key never leaves it; the two CA certificates differ), Keycloak signing keys (no common `kid`), LDAP admin/bind/ICS passwords, Keycloak DB, OpenCloud JWT/transfer secrets, test-user passwords (all generated per machine under `/root/ou-lab-secrets`) | same |
| seed | users alice(admin) bob carol dave erin in BOTH (same usernames, different uuids and passwords); files, a project space and a password-protected public link per customer (created by the test) | same |

The files tier was started without the document-editing service (`OU_SKIP_COLLAB=1`, new switch in install-files.sh). Agent AO's clean-room fixes are not on main, so the current scripts were used. Discrepancies found: (a) `install-kc.sh` hard-coded the realm template (realm name, `ou-lab.internal`, base DN); it is now rendered from `lab.env`; (b) `install -m 0600 /dev/stdin` fails in the nspawn PrivateUsers=pick containers (permission denied), so the bundle transfer in `build-customer.sh` uses `cat >` under umask 077.

## 2. Results by area

### 2.1 Identity (56 PASS, 0 FAIL), every denial has a paired control
- I00: issuers differ, same username `alice` in both, CA files differ, no shared signing `kid`; each side's CA does not validate the other side's TLS certificates.
- I01-I04: A's access and ID tokens are rejected by B's OpenCloud (Graph, WebDAV `/remote.php/dav/files/alice`, `/dav/spaces`) and B's Keycloak userinfo, and vice versa (HTTP 401); controls: each token works at home.
- I05: A's refresh and OFFLINE refresh tokens at B's token endpoint (`invalid_grant`), and vice versa; controls: they work at home.
- I06: same-username collision: A alice's password at B's Keycloak and B alice's at A's fail.
- I07: forged/tampered tokens, each sent to OpenCloud (Graph + WebDAV) and Keycloak userinfo, all HTTP 401: attacker-key RS256 with B's `kid` and B alice's iss/uuid/sub; alg=none; HS256 with B's public modulus as secret; A's genuine signature with payload edited to B's iss+uuid; B's signature edited to A's iss+uuid; in-realm identity swap (A alice token edited to bob's uuid, sent to A).
- I08: the ICS service-account token and client secret of A's `ou-ics` client cannot be used against B's admin API or B's token endpoint (control: it manages A's users).
- I09: OpenCloud app tokens (auth-app) of A are refused by B (control: work at A).
- I10: A's LDAP bind secret does not bind to B's directory even with certificate verification skipped.

### 2.2 Files (42 PASS, 0 FAIL)
Seed and controls pass (own file, own project space by id, own public link resolves). Denied: B's locally valid **admin** token asking B's OpenCloud for A's real personal-drive id, project-space id, file id and a guessed `/dav/spaces/<A space>/<file>` path (404, no content); A's tokens against B's real ids/paths (401); A's public-link token on B's `/dav/public-files/<token>` (404, with the correct link password); permission/link listing of A's item by id from B (404); share-into: A alice inviting B's bob (user id from B's directory) into her own file is refused (control: inviting A's bob works), B admin inviting onto A's item id (refused), A's token driving B's share API (401).

### 2.3 Network (7 PASS, 1 SKIP): the lab limitation is real
Both customers sit in the same nspawn zone `oulab` (one L2 bridge `vz-oulab`, shared /24). **Without any extra rule 11 of 11 cross-customer connections succeed** (A files to B's Keycloak/LDAPS/OpenCloud and the reverse, also IPv6 link-local). The lab zone itself provides NO isolation, so the identity/files results above are application-level separation (separate CAs, keys, directories, token validation), not network-level.
A per-customer rule was added on the host (`blueprints/lab/tenant/nft-per-customer.nft`, `table bridge ou_tenant_t20`, forward hook, matching bridge ports `vb-ou-ca-*` <-> `vb-ou-cb-*`, so IPv4, IPv6 and ICMP are all covered). With it: 0/11 cross probes open, IPv6 link-local closed, ICMP closed, 6/6 intra-customer probes and the operator host's access unaffected. The test loads and deletes the rule (not persistent).
SKIP N07: an in-guest firewall layer was not tested (no nftables in the customer containers).
Verdict: a host-side filter on a shared bridge is a lab emulation. It holds only while the rule set is complete and every new machine is covered. Production design in section 4.

### 2.4 ICS: customers, vault, operator scoping (44 PASS; dev ICS on 127.0.0.1:8122, DB `ics_test_g`, throw-away keys)
Both customers and both stacks' identity endpoints (LDAP + Keycloak + files URL + real service-account credentials) were registered through the real API (plan, two approvals, worker job). Operators scoped to A and to B through the typed `operator.set_scope` action.
- Credentials, endpoints, customer records, customer-approval links (list/get/submit/cancel), plan targets (`credential.test`/`credential.revoke`/`inventory.refresh` on the other customer's object: 404), plan list, identity stacks/users/reconcile runs, deployments: a scoped operator sees and can use only its own customer's objects (404, existence not disclosed). No credential, LDAP or Keycloak secret appears in list responses.
- Vault AAD: relabelling A's credential row to customer B makes it undecryptable; copying A's ciphertext onto B's row is refused (both executed).
- A's approval link shows only A's proposal; an altered token gets a uniform 404.
- **Two real isolation holes were found by this test and fixed in this branch**: (1) `GET /deployments`, `/deployments/{slug}[/resources|events|drift]`, the change/destroy previews, `POST /deployments/plan` and `/jobs/{id}/steps` were not scoped to the operator's customers (a scoped operator saw every customer's deployments); now scoped via the owning endpoint's customer. (2) Identity stacks (`/identity/stacks|users|reconcile`) had no customer binding at all; `idm.stack.register` now takes `customer_id` (it is part of the secret's AAD through the config hash), listings are scoped and identity actions resolve the stack's customer for plan scoping; stacks without `customer_id` are visible to all-customers operators only. Before the fix the same test printed `FAIL S16 ... foreign deployments listed: ['dep-a-...', 'dep-b-...']` and `FAIL S17 ... foreign identity stack listed: ['stack-a', 'stack-b']`. Regression tests: `ics/tests/test_tenant_scope.py`.

### 2.5 Backups (3 PASS, 1 FAIL = known gap)
Agent AB's backup product is not on main, so only the existing lab scripts (`blueprints/lab/backup/id-backup.sh`) were tested. PASS: separate backup directory per customer, A's archive has no reference to B's domain/realm and vice versa (with a control that each archive does contain its own domain, so the grep is not vacuous). **FAIL B02: the archives are plain tar, not encrypted under a per-customer key.** "A's key cannot open B's repository" cannot be met or tested with these scripts. The archive holds the customer's secrets (Keycloak DB/admin, LDAP admin/bind, TLS keys), so the backup host is a cross-customer blast radius for anyone who can read it.

## 3. Not tested / residual risks
- L2 network isolation is not achievable in this lab (one bridge); only a host-side emulation was tested. In-guest firewalls not tested.
- Groupware, document editing, chat/meet, telephony tiers were not built per customer: no isolation claim for them. Mail (Gromox) in particular must be tested the same way.
- The stacks share kernel, hypervisor, ICS host, `/etc/hosts` and the nspawn base image: no claim about side channels or host compromise. Production uses separate VMs.
- One ICS serves all customers; separation there is application-level (customer scoping, vault AAD), proven on the HTTP surfaces listed only. Not covered: monitoring checks, nodes, alert channels (listed in the vault doc as not customer-bound), the agent protocol, provider/deployment plan actions beyond those tested, scoped-operator plans on deployments by endpoint name.
- The password-grant test client `ou-lab-test` exists in both lab realms (must not exist in production).
- Token tests used realm defaults (300 s access tokens). Back-channel logout and revocation across tenants not tested.

## 4. What must be true in production
1. One isolated stack per customer on its own VLAN/SDN zone (ADR-0006), default deny between customer networks and towards the ICS except documented management ports, enforced outside the guests (hypervisor/SDN) and in the guests. Re-run T20 section `network` there: expected "0 cross probes open without any host rule" (here: 11/11 open without the rule).
2. Per-customer CA, signing keys, directory, database and secrets (as built here), no shared client secrets, no password-grant test clients.
3. Backups encrypted under a per-customer key held outside the backup host, separate repositories, restore tested per customer; a test that A's key cannot open B's repository (missing here).
4. Customer-scoped operator accounts for customer work, all-customers scope only for MSP admins; extend scoping to the remaining global tables before multi-tenant operator use.
5. Re-run `t20_tenant_isolation.py` per release against two reference stacks; a FAIL is a release blocker.

## 5. How to reproduce
```
blueprints/lab/tenant/build-customer.sh a ; blueprints/lab/tenant/build-customer.sh b     # sudoer on the lab host
ics/.venv/bin/python blueprints/lab/tests/t20_tenant_isolation.py                           # OU_T20_SECTIONS=identity,files,network,ics,backup
```
The machines `ou-ca-*`/`ou-cb-*` were powered off after the run.

## 6. Repository changes
`blueprints/lab/tenant/` (build script, nft rule), `blueprints/lab/tests/t20_tenant_isolation.py`, `install-kc.sh` (realm template rendered from lab.env), `install-files.sh` (`OU_SKIP_COLLAB`), ICS scoping fixes in `deploy/api.py`, `main.py`, `identity.py`, `tenancy/scope.py`, tests `ics/tests/test_tenant_scope.py` (together with the vault, identity, deploy and provider-stack suites: 108 tests passed on `ics_test_g`).
