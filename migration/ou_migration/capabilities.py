"""Target platform capability facts and source-feature -> target mapping.

Facts come from docs/status/groupware-lab-results.md (lab, 2026-11-15), docs/ARCHITECTURE.md and
docs/status/collaboration-eval.md. Status vocabulary:

  lab-verified  a lab test printed PASS (groupware-lab-results.md section 3)
  unproven      component present but the specific behaviour was not tested in the lab
  planned       on the roadmap, not implemented (ARCHITECTURE.md section 3 / collaboration-eval.md)
  none          no equivalent in the target and none planned

Update this table when lab evidence changes; the report always prints the status next to each mapping.
"""
from __future__ import annotations

TARGET_CAPS = {
    "mail.imap_smtp": ("lab-verified", "IMAP/IMAPS + SMTP delivery for 7 users (GW01); SMTP submission with AUTH (587) not configured"),
    "mail.mapi_http": ("lab-verified", "MAPI/HTTP Connect/Disconnect + Autodiscover (GW02); real Outlook profile/cached mode/NSPI/free-busy NOT proven"),
    "mail.ews": ("lab-verified", "EWS GetFolder/FindItem/CreateItem (GW02)"),
    "mail.activesync": ("lab-verified", "EAS OPTIONS/FolderSync/Sync (GW03); device provisioning policy and real phones NOT proven"),
    "cal.caldav_carddav": ("lab-verified", "CalDAV/CardDAV PUT/GET/REPORT, isolation (GW04); iTIP scheduling and Apple/Thunderbird/DAVx5 clients NOT proven"),
    "mail.shared_mailbox": ("lab-verified", "shared mailbox with ACL delivered/read via EWS (GW05); ACLs were SQL-inserted in the lab, production ACL tooling NOT built"),
    "mail.import_export": ("lab-verified", "gromox-exm2mt/gromox-import logical export/import round-trip (GW07); no dedupe, ACLs not exported; this is the only tested bulk-load path"),
    "mail.aliases": ("unproven", "alias addresses are LDAP/gromox attributes; multi-alias provisioning through ICS idm.user.* not evidenced for this migration case"),
    "mail.distribution_lists": ("unproven", "gromox supports mailing lists; not exercised in the lab; LDAP groups are provisioned by ICS"),
    "mail.archive_mailbox": ("none", "no in-place archive mailbox concept; archive content would be imported into a folder tree"),
    "mail.journaling_retention": ("none", "mail archiving/journaling is not present in public gromox source (ARCHITECTURE.md 3.3); retention policies/legal hold: none"),
    "mail.out_of_office_rules": ("unproven", "OOF and server-side rules not tested in the lab"),
    "files.opencloud": ("lab-verified", "OpenCloud 9.1.0 spaces/shares + desktop sync (identity-files-lab-results.md)"),
    "files.office_editing": ("unproven", "Collabora own build still Implementing; lab functional tests used vendor CODE only"),
    "files.sharepoint_lists_pages": ("none", "no SharePoint-style lists, pages, web parts, content types, workflows or metadata columns"),
    "files.permissions_model": ("unproven", "OpenCloud spaces/roles/share links exist; mapping of nested SharePoint/Drive permissions is manual"),
    "chat.teams_like": ("planned", "Matrix Synapse + Element evaluated on paper only (collaboration-eval.md, status Researching); no history import path exists"),
    "meetings": ("planned", "Element Call/LiveKit or Jitsi evaluated on paper only"),
    "automation.power_automate": ("none", "no Power Automate/Apps Script-equivalent workflow engine planned"),
    "forms.survey": ("none", "no Microsoft Forms / Google Forms equivalent planned"),
    "identity.ldap_keycloak": ("lab-verified", "OpenLDAP (authoritative) + Keycloak OIDC; entryUUID immutable id; ICS idm.user.create/update_groups"),
    "identity.passwords": ("none", "source password hashes cannot be exported; every user receives a one-time enrollment token (no initial password exists)"),
    "identity.mfa_migration": ("none", "source MFA registrations (Authenticator, security keys) are not transferable; users re-enrol TOTP"),
    "calendar.rooms_resources": ("unproven", "resource mailboxes not exercised in the lab"),
    "outlook.new_outlook_mobile": ("none", "New Outlook for Windows and Outlook mobile cannot use MAPI/EWS against non-Microsoft servers (ARCHITECTURE.md 4)"),
}

# impact levels: blocker (cannot migrate that function), major (manual work / feature loss), minor, info
RULES = [
    # id, title, test(signals/inv)->count or bool, cap, impact, advice
    dict(id="U-TEAMS", provider="m365", title="Teams / Microsoft 365 group-connected teams",
         key=lambda inv: inv.signals.get("teams_count", 0), cap="chat.teams_like", impact="major",
         advice="Chat history cannot be migrated (no Graph export without Teams export APIs and no import target). Agree an archive/export "
                "approach with the customer; chat/meetings are Phase 6 (planned)."),
    dict(id="U-SPLISTS", provider="m365", title="SharePoint sites (lists, pages, workflows not assessed per site)",
         key=lambda inv: inv.signals.get("site_count", 0), cap="files.sharepoint_lists_pages", impact="major",
         advice="Document libraries can be mapped to OpenCloud spaces; lists, pages, web parts and metadata have no target. "
                "A per-site content-type review (needs Sites.Read.All, not requested by this assessment) is required before commitment."),
    dict(id="U-PAUTO", provider="m365", title="Power Automate / Power Apps plans enabled",
         key=lambda inv: bool(inv.signals.get("power_automate_plan") or inv.signals.get("power_apps_plan")),
         cap="automation.power_automate", impact="major",
         advice="Plan presence only (not usage). Inventory flows with the Power Platform admin tools; none can be migrated."),
    dict(id="U-ENGAGE", provider="m365", title="Viva Engage (Yammer) / Stream / Sway / Planner plans enabled",
         key=lambda inv: any(inv.signals.get(k) for k in ("viva_engage_plan", "stream_plan", "sway_plan", "planner_plan")),
         cap="chat.teams_like", impact="minor", advice="Plan presence only; confirm actual use with the customer."),
    dict(id="U-FORMS", provider="m365", title="Microsoft Forms / Bookings plans enabled",
         key=lambda inv: any(inv.signals.get(k) for k in ("forms_plan", "bookings_plan")), cap="forms.survey", impact="minor",
         advice="Plan presence only; forms/booking pages must be recreated."),
    dict(id="U-ARCHIVE", provider="m365", title="Users with in-place archive mailbox",
         key=lambda inv: sum(1 for u in inv.users if u.has_archive), cap="mail.archive_mailbox", impact="minor",
         advice="Archive content has no separate store in the target; plan a folder-tree import and size the mailbox accordingly."),
    dict(id="U-SHARED", provider="m365", title="Probable shared mailboxes (heuristic)",
         key=lambda inv: sum(1 for u in inv.users if u.shared_mailbox_guess), cap="mail.shared_mailbox", impact="minor",
         advice="Heuristic only: unlicensed, sign-in-blocked users that own a mailbox. Confirm with Exchange Online (Get-Mailbox -RecipientTypeDetails SharedMailbox). "
                "Delegations (FullAccess/SendAs) cannot be read by this assessment and ACL tooling in the target is not built."),
    dict(id="U-DL", provider="m365", title="Distribution lists / mail-enabled security groups",
         key=lambda inv: sum(1 for g in inv.groups if g.kind in ("distribution", "mail-security")), cap="mail.distribution_lists",
         impact="minor", advice="Recreate as lists/groups; membership export is available from this inventory counts; nested/dynamic DLs need review."),
    dict(id="U-DYNGRP", provider="m365", title="Dynamic membership groups",
         key=lambda inv: inv.signals.get("dynamic_group_count", 0), cap="identity.ldap_keycloak", impact="minor",
         advice="Membership rules are not portable; materialise current members into static groups."),
    dict(id="U-HOLD", provider="m365", title="Retention policies / eDiscovery / litigation hold (NOT ASSESSED)",
         key=lambda inv: "unknown", cap="mail.journaling_retention", impact="blocker",
         advice="Not readable with the minimum permission set. If the customer has holds or regulatory retention, migration must not proceed "
                "until a compliance owner decides (target has no retention/legal-hold)."),
    dict(id="U-MFA", provider="any", title="MFA/passkey registrations and passwords",
         key=lambda inv: len(inv.users), cap="identity.mfa_migration", impact="info",
         advice="All users re-enrol; plan communications and help-desk load (no initial password exists in the target)."),
    dict(id="U-NEWOUTLOOK", provider="any", title="Outlook clients: New Outlook / Outlook mobile",
         key=lambda inv: "unknown", cap="outlook.new_outlook_mobile", impact="major",
         advice="Client inventory is not part of this assessment. New Outlook and Outlook mobile will fall back to IMAP/SMTP only."),
    dict(id="G-SITES", provider="google", title="Google Sites found in drive sample",
         key=lambda inv: inv.signals.get("google_sites_in_sample", 0), cap="files.sharepoint_lists_pages", impact="major",
         advice="No target for sites; export static content manually. Counts are from the sampled accounts only."),
    dict(id="G-FORMS", provider="google", title="Google Forms found in drive sample",
         key=lambda inv: inv.signals.get("google_forms_in_sample", 0), cap="forms.survey", impact="minor",
         advice="Forms must be recreated; responses export to sheets/CSV manually."),
    dict(id="G-SCRIPT", provider="google", title="Apps Script projects found in drive sample",
         key=lambda inv: inv.signals.get("apps_script_in_sample", 0), cap="automation.power_automate", impact="major",
         advice="Scripts and add-ons cannot run in the target."),
    dict(id="G-GROUPS", provider="google", title="Google Groups (mailing lists / collaborative inboxes)",
         key=lambda inv: len(inv.groups), cap="mail.distribution_lists", impact="minor",
         advice="Mailing-list groups map to lists; collaborative-inbox/ Q&A usage has no equivalent."),
    dict(id="G-RES", provider="google", title="Calendar resources (rooms/equipment)",
         key=lambda inv: inv.counts.get("resource_calendars", 0), cap="calendar.rooms_resources", impact="minor",
         advice="Resource mailboxes are unproven in the target lab."),
    dict(id="G-VAULT", provider="google", title="Google Vault retention/holds (NOT ASSESSED)",
         key=lambda inv: "unknown", cap="mail.journaling_retention", impact="blocker",
         advice="Not readable with the scopes requested. Confirm with a Vault admin; target has no retention/legal-hold."),
    dict(id="G-MFA", provider="google", title="2-Step Verification / passkeys and passwords",
         key=lambda inv: len(inv.users), cap="identity.mfa_migration", impact="info",
         advice="All users re-enrol; no initial password exists in the target."),
]


def map_features(inv) -> list[dict]:
    out = []
    for r in RULES:
        if r["provider"] not in ("any", inv.provider):
            continue
        k = r["key"](inv)
        if k is False or k == 0:
            continue
        st, fact = TARGET_CAPS[r["cap"]]
        out.append({"id": r["id"], "title": r["title"], "count": k if isinstance(k, int) and not isinstance(k, bool) else None,
                    "state": "not-assessed" if k == "unknown" else "detected",
                    "target_capability": r["cap"], "target_status": st, "target_fact": fact,
                    "impact": r["impact"], "advice": r["advice"]})
    return out
