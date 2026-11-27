# Demo organisation: Northstar Advisory Group

Status (ADR-0000 words): **IMPLEMENTED, TESTED AGAINST FAKES ONLY.** The seeding tool and its safeguards are covered by unit tests against
in-memory stand-ins of every application (`ics/tests/test_demo_seed.py`, `ics/tests/test_demo_seed_fakes.py`). It has **not been run
against a real deployment**. No demo deployment exists yet; creating one needs the owner's authorisation (VMs, DNS).

Owner brief 2026-11-26, section 18: a dedicated, isolated demonstration environment with entirely fictional business data, filled by a
repeatable, idempotent mechanism that uses the real applications and their APIs.

## What it creates

Everything is fictional. People and outside organisations are invented; outside organisations appear only in text and use the
reserved `.example` domain. Every address that receives anything is a seeded person at the demo deployment's own domain.

| Area | What | Count | How (always signed in as that person) |
|---|---|---|---|
| Directory | people in 7 departments (Leadership, Advisory, Finance, Operations, Marketing, People & Culture, IT), 2 of them organisation admins | 20 | `directory.account.set` plans (the People panel's typed action), approved in the console |
| Mail | threads / messages / mailbox copies (Inbox of each recipient, Sent of the sender) | 12 / 22 / 101 | IMAPS `APPEND` into the person's own folders |
| | attachments (generated documents), flagged copies, unread copies | 8 / 6 / 5 | flags set on `APPEND` |
| Calendar | meetings with internal attendees (2 recurring, 9 upcoming); invitations | 10 / 27 | CalDAV `PUT` in the organizer's calendar; grommunio-dav's own scheduling delivers the invitations to the (internal) attendees |
| | team calendar "Northstar Team Calendar" (in Grace Abernathy's account) with events | 1 / 6 | CalDAV `MKCALENDAR` + `PUT` |
| Tasks | tasks, some "assigned by" a colleague (in the text: CalDAV has no assignment) | 10 | CalDAV `PUT` (VTODO) in the person's task list |
| Files | project and department folders in the owners' personal spaces | 8 | OpenCloud WebDAV `MKCOL` |
| | documents (5), spreadsheets (4), presentations (3), ODF and OOXML, generated in memory; 3 carry document comments | 12 | WebDAV `PUT` |
| | shares to colleagues (edit or view, role taken from OpenCloud's own list) | 16 | Graph `invite` |
| Chat | rooms (General, Announcements, two project rooms, Finance questions, IT help) / direct messages / messages | 6 / 4 / 25 | Matrix client-server API (`createRoom`, `join`, `send`, `m.direct`) |
| MSP view (optional) | further fictional tenants "Harbor Lane Dental (demo)", "Copperline Logistics (demo)" (customers without deployments, provisioning mode monitoring only) | 2 | `customer.create` plans; multi-tenant installations only |

`python -m ics.cli demo-seed --dry-run` prints exactly this plan (counts, names, departments, folders, rooms) without contacting
anything.

Notifications come from the applications themselves (share notifications in Files, meeting requests in mail, chat unread counts).
Avatars: the applications show initials; no pictures are uploaded.

## Safeguards (each one is a test)

| # | Safeguard | Test (`ics/tests/test_demo_seed.py`) |
|---|---|---|
| 1 | The deployment slug and its domain both carry a demo label (`demo`, `demo-*` or `*-demo`). `officeunbound8` and `officeunbound.com` are refused whatever their labels. | `test_names_must_carry_a_demo_label`, `test_marking_needs_a_demo_name_and_is_refused_for_production` |
| 2 | ICS marker: the approved, high-risk, admin-only typed action `demo.deployment.mark` (audited). The marker is bound to the deployment's id **and** domain. `demo=false` removes it. | `test_the_marker_binds_id_and_domain_and_unmarking_removes_it` |
| 3 | Typed confirmation `--i-understand-this-is-the-demo <slug>` equal to the target. | `test_confirmation_must_repeat_the_slug`, `test_cli_refuses_without_target_or_confirmation` |
| 4 | The directory holds only `ou-admin`, `admin` and the seeded people; anyone else means the deployment is in real use and everything is refused. | `test_foreign_people_mean_the_deployment_is_in_real_use`, `test_accounts_are_requested_once_...` |
| 5 | Every HTTP request (including redirects during sign-in) goes to https on the demo domain or its subdomains; anything else is refused before a connection is made. IMAP likewise. TLS is always verified. | `test_http_requests_outside_the_demo_domain_are_refused_before_sending`, `test_a_redirect_out_of_the_demo_domain_is_refused`, `test_imap_outside_the_demo_domain_is_refused_before_connecting`, `test_the_tool_has_no_smtp_and_no_tls_bypass` |
| 6 | Every recipient (mail, meeting organizer and attendees, share recipients, chat members) is a seeded person at the demo domain. | `test_every_recipient_is_a_seeded_person_at_the_demo_domain`, `test_meetings_are_valid_icalendar_with_internal_attendees_only` |
| 7 | No SMTP: messages are placed with IMAP `APPEND`. Meeting invitations are produced by the groupware for internal attendees only (6). | `test_the_tool_has_no_smtp_and_no_tls_bypass` |
| 8 | Passwords: generated per person at run time (`secrets.token_urlsafe`), stored only in the ICS vault (`deployment_secrets`, `demo-pw-<uid>`) and as the plans' encrypted secret; never printed, logged or in audit details. Optional export only to a NEW 0600 file outside any git checkout. | `test_accounts_are_requested_once_with_vault_passwords_that_are_never_shown`, `test_password_export_is_0600_and_never_inside_a_git_checkout` |
| 9 | Idempotent: deterministic ids (`X-OU-Demo-Id` header, `ou-demo-` iCalendar UIDs and CalDAV names, folder paths, `#ou-demo-*` room aliases, `ou.demo.id` in chat messages); create-only writes (`If-None-Match: *` so invitations are never sent twice). The anchor day is kept in the manifest, so a re-run builds the same plan. Pending account plans are not requested twice. | `test_full_seed_is_idempotent_and_reset_removes_it`, `test_the_plan_is_deterministic_and_dates_avoid_weekends` |
| 10 | Reset removes only what the seed names; a person's own unrelated mail stays. | `test_full_seed_is_idempotent_and_reset_removes_it`, `test_reset_requests_account_deletion_...` |

## Creating the demo deployment (owner authorisation needed)

1. Choose a domain with a demo label that the owner controls, for example `demo.officeunbound.com` (the deployment then serves
   `app.demo.officeunbound.com`, `mail.demo.officeunbound.com`, `cloud.`, `auth.`, `chat.`, `matrix.`, `mas.`). Never the production
   domain.
2. Create DNS records for those names (owner) and, if needed, router forwarding for ACME.
3. In the console, create a deployment with a slug carrying a demo label, for example `northstar-demo`, on that domain, with
   groupware, files and chat (the usual deployment wizard; approve `deployment.create`). It is a separate deployment: separate VMs,
   directory, mail store, files and chat. Nothing is shared with `officeunbound8`.
4. When it is active, request **`demo.deployment.mark`** `{deployment: northstar-demo, confirm: northstar-demo}` (Plans, new plan, or
   `POST /api/v1/plans`) and approve it. The plan is refused if the slug or domain has no demo label.
5. The ICS host must resolve the demo names (public DNS, or entries recorded in `docs/status/host-changes.md`) and trust their
   certificate (public certificate, or pass the deployment CA with `--ca-file`).

## Running

On the ICS host, as the service user:

```
sudo -u ics .venv/bin/python -m ics.cli demo-seed --dry-run --domain demo.officeunbound.com      # the plan, nothing contacted
sudo -u ics .venv/bin/python -m ics.cli demo-seed --deployment northstar-demo \
     --i-understand-this-is-the-demo northstar-demo --operator <your ICS admin> --timezone Europe/Berlin
```

The first run requests 20 `directory.account.set` plans and exits with code 3. Approve them in the console (Plans), wait for the jobs,
then run the same command again: it now fills mail, calendars, tasks, files and chat. Options: `--only mail,calendar,files,chat`,
`--skip-accounts`, `--msp-tenants`, `--ca-file`, `--export-passwords /root/northstar-demo.tsv` (a new 0600 file outside any git checkout,
for signing in as demo people to take screenshots). Exit codes: 0 done, 1 an application stopped the run (message says where),
2 refused by a safeguard, 3 waiting for plan approval.

Re-running is safe: existing objects are kept, nothing is duplicated, invitations are not sent again.

After seeding, one manual step: Grace Abernathy shares "Northstar Team Calendar" with the team in webmail (CalDAV has no sharing in
grommunio-dav; see limitations).

## Reset

```
sudo -u ics .venv/bin/python -m ics.cli demo-seed --deployment northstar-demo \
     --i-understand-this-is-the-demo northstar-demo --operator <your ICS admin> --reset [--msp-tenants]
```

Order: chat (room aliases removed, every member leaves and forgets the room), files (the seeded folders; they go to the owners'
trash bins), calendar (every `ou-demo-` object in every calendar, organizers first, and the team calendar), mail (every message with
`X-OU-Demo-Id`, and in the Inbox the server's meeting requests and cancellations for `ou-demo-` meetings). Then one
`directory.account.delete` plan (high risk) per seeded person; approve them and run `--reset` again to drop the stored passwords and the
manifest. `--msp-tenants` requests `customer.update disabled=true` for the demo tenants (customers are not deleted).

## Evidence and screenshots

- Only real captures of the demo deployment, made by signing in as demo people. No injected UI, no fabricated API responses.
- Every screenshot or recording used in documentation, the website or marketing is labelled **"demo data"** and comes from the demo
  deployment only, never from `officeunbound8` or a customer deployment.
- Names, companies and content shown are the fictional ones from `ics/ics/demo/org.py`.

## Known limitations

- Not yet run against real applications: the sign-in walk (Keycloak form, MAS compat SSO "continue" page), Gromox IMAP `FETCH`/`SEARCH`
  behaviour, grommunio-dav scheduling of PUT meetings, OpenCloud Graph `invite` and role names are implemented from the protocols and
  verified only against fakes. Expect adjustments on the first real run.
- Sharing the team calendar is manual (grommunio-dav does not load the CalDAV sharing plugin; MAPI/EWS permissions are not used here).
- Tasks cannot be assigned through CalDAV; "assigned by" is in the task text.
- OpenCloud project spaces need the space-admin role, so project folders live in the project lead's personal space and are shared.
- Chat reset leaves empty rooms on the homeserver (purging needs Synapse's admin API, which is not exposed).
- Generated documents are minimal but standard packages; they have not yet been opened in Collabora on a real deployment.
- Attendee responses: attendees marked as accepted are shown as accepted in the organizer's event; no reply messages are generated.
