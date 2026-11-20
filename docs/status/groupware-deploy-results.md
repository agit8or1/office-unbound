# Groupware in the deployed stack (cfg.gromox), 2026-11-19

Status vocabulary: ADR-0000. Goal: the ICS deploys mail, calendar and contacts (gromox stack) as part of a customer deployment, configured
end to end by typed agent runbooks (no shell), users signing in with their directory password.

## What the engine does now
- **Catalog** (`blueprints/catalog/components/groupware.yaml`): Office Unbound's noble builds (ou-gromox / php-mapi 3.13-ou3+noble1,
  ou-grommunio-web 5.2-ou2, -dav 1.9-ou1, -sync 2.7-ou1) from the signed dev channel, plus distribution packages as floors (MariaDB,
  Postfix + postfix-mysql, Cyrus SASL, nginx, ldap-utils). Ports: SMTP 25, submission 587, SMTPS 465, IMAPS 993, HTTPS 443 (clients:
  EWS, MAPI/HTTP, ActiveSync, Autodiscover, CalDAV/CardDAV, webmail at `mail.<domain>`), 8447 (the edge). Health checks: SMTP banner 25 and
  587, IMAPS TLS, web TLS.
- **ICS** (`ics/ics/deploy/configure.py` `groupware_runbooks`): name resolution, peer firewall, a deployment-CA certificate for
  `mail.<domain>` and `autodiscover.<domain>`, then `cfg.gromox` with the mail domain, a per-deployment database password (vault), the
  directory's read-only bind (`svc-bind`), the entitlement group `mail-users` and the administrator's mailbox.
- **Agent** (`ics/agent/ou_agent/cfghelper.py` `gromox`, closed schema `cfgspec.check_gromox`): MariaDB database and account; gromox
  configuration (mysql/ldap adaptors, IMAP TLS, HTTP on loopback, delivery on 127.0.0.1:24); schema; organisation, domain and public store;
  per entitled directory entry a mailbox linked by `entryUUID` (gromox authenticates it against LDAP); Postfix (domain delivered by LMTP,
  submission 587/465 with SASL -> saslauthd -> PAM -> pam_gromox, sender-login check, no relay, outbound internet mail **not enabled yet**);
  PHP-FPM pools for web, ActiveSync and DAV with php-mapi; nginx on 443 and 8447; the zcore socket lockdown of security review 4 M1.
  Ported from the lab scripts in `blueprints/lab/spike-groupware/`. Enabled only on VMs whose package allow-list holds `ou-gromox`.

## Lab result (Ubuntu 24.04, noble packages, lab machine `ou-cfg1`, 2026-11-19 21:50-22:05Z)
Executed with the real helper (`cfghelper.handle`) and throw-away values on top of the directory `cfg.ldap_init` had built there.
Three defects found on the way and fixed in the runbook: PHP-FPM socket directory missing (`/run/php-fpm`, now also a tmpfiles entry),
gromox exits when the node's own name does not resolve (now mapped to 127.0.1.1 in a managed hosts block when needed), saslauthd socket
moved into the Postfix spool did not match the noble unit's PID file (default `/run/saslauthd` kept; the submission services are not
chrooted); plus the gromox state tree and delivery queue directories (owned by `gromox`).

Functional checks (`gwverify.py`, TLS verified against the deployment CA, the administrator's directory password):

| Check | Result |
|---|---|
| SMTP 25 banner / EHLO | PASS (250) |
| SMTP 25 STARTTLS, inbound message for the mailbox accepted | PASS |
| SMTP 25 refuses relaying to another domain | PASS (550) |
| Submission 587 STARTTLS + AUTH with the directory password + send | PASS |
| Submission 587 rejects a wrong password | PASS (535) |
| IMAPS 993 login (LDAP) and both messages (inbound + submitted) in the INBOX | PASS |
| IMAPS 993 rejects a wrong password | PASS |
| HTTPS 443 and 8447: webmail login page | PASS (200 / 200) |
| HTTPS 443 ActiveSync OPTIONS with credentials | PASS (200) |
| HTTPS 443 CalDAV PROPFIND with credentials | PASS (207) |
| HTTPS 443 EWS without credentials | PASS (401) |
| zcore socket 0660 in a 0710 directory (review 4 M1) | PASS |

**13/13**, again **13/13 after a reboot** of the machine (every service enabled and active, socket directory and lockdown re-applied), and a
second run of `cfg.gromox` succeeds without changes (idempotent). A directory address that has no entry is skipped with its reason.

## Real-VM result (ICS 0.5.0, deployment e2e-gw1, pve06, 2026-11-19 23:58 - 2026-11-20 00:21Z)
Three VMs (identity+edge, files+office, groupware) cloned from golden image v8 (template 136, agent 0.5.0-ou10), configured end to end by
the deployment job: **all ten health checks ok**, among them the four groupware checks: SMTP 25 banner + EHLO, submission 587 banner + EHLO,
IMAPS 993 TLS 1.3 and web 8447 TLS 1.3 (certificate valid for the deployment names). First attempt, no defect. A send/receive test on the
real VM is still to be run (the lab ran it, 13/13).

## Not yet
- Send/receive and client tests on the real VM; signing in needs the administrator password, which the console does not show yet (0.5.1).
- Outbound internet mail, SPF/DKIM/DMARC, spam and virus filtering, MX in public DNS: Stage 3, needs the owner's public IP and domain.
- Edge route for webmail; single sign-on (Keycloak) for webmail; mailbox lifecycle actions for users created after the deployment.
