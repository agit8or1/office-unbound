"""Microsoft 365 read-only collector (Microsoft Graph v1.0, application permissions).

Minimum permission tiers (see docs/status/migration-assessment.md for citations):

  core      User.Read.All, Group.ReadBasic.All, GroupMember.Read.All, Organization.Read.All,
            Domain.Read.All, Reports.Read.All
  optional  Calendars.Read + Contacts.Read   (--deep-counts: per-user $count of events/contacts;
                                              these permissions can read content tenant-wide -> restrict
                                              with an Exchange Application Access Policy / RBAC for Applications)

No message, event, contact or file content is requested; ``$count`` and usage-report endpoints only.
"""
from __future__ import annotations

import csv
import io
import logging

from ..auth import GraphAuth
from ..checkpoint import Checkpoint
from ..http import HttpClient, HttpError
from ..model import Domain, Group, Inventory, Site, User
from .base import Stage, now_iso

log = logging.getLogger("ou_migration.m365")

GRAPH = "https://graph.microsoft.com/v1.0"
REPORT_PERIOD = "D30"
USER_SELECT = ("id,userPrincipalName,displayName,mail,proxyAddresses,accountEnabled,userType,"
               "assignedLicenses,onPremisesSyncEnabled,createdDateTime")
GROUP_SELECT = ("id,displayName,mail,mailEnabled,securityEnabled,groupTypes,"
                "resourceProvisioningOptions,membershipRule")

# assignedPlans[].service values (organization resource) that indicate an enabled source capability.
# Presence = plan is licensed/enabled in the tenant; it is NOT evidence of use.
PLAN_SIGNALS = {
    "TeamspaceAPI": "teams_plan", "Teams": "teams_plan", "MicrosoftCommunicationsOnline": "teams_plan",
    "ProcessSimple": "power_automate_plan", "PowerAppsService": "power_apps_plan",
    "YammerEnterprise": "viva_engage_plan", "MicrosoftStream": "stream_plan", "Sway": "sway_plan",
    "MicrosoftPlanner": "planner_plan", "To-Do": "todo_plan", "MicrosoftForms": "forms_plan",
    "MicrosoftBookings": "bookings_plan", "OfficeForms": "forms_plan",
}


class M365Collector:
    def __init__(self, http: HttpClient, auth: GraphAuth, ckpt: Checkpoint, *, graph_base=GRAPH,
                 deep_counts=False, deep_max_users=500, page_size=999):
        self.http, self.auth, self.ckpt = http, auth, ckpt
        self.base = graph_base.rstrip("/")
        self.deep_counts, self.deep_max_users, self.page_size = deep_counts, deep_max_users, page_size

    # -- helpers -----------------------------------------------------------------------------------------
    def _get(self, url, params=None, extra=None):
        h = self.auth.headers()
        h.update(extra or {})
        return self.http.request("GET", url, headers=h, params=params).json()

    def _paged(self, url, params, st, extra=None):
        """Yield pages of ``value``; resumable via st['next'] (an @odata.nextLink) and st['items']."""
        items = st.setdefault("items", [])
        nxt = st.get("next")
        first = nxt is None and not items
        while first or nxt:
            j = self._get(nxt or url, params if first else None, extra)
            first = False
            items.extend(j.get("value", []))
            nxt = j.get("@odata.nextLink")
            st["next"] = nxt
            self.ckpt.save()
        return items

    def _report_csv(self, name, period=REPORT_PERIOD):
        """Reports answer 302 -> pre-authenticated URL (must be fetched without Authorization)."""
        r = self.http.request("GET", f"{self.base}/reports/{name}(period='{period}')",
                              headers=self.auth.headers(), expect=(200,), allow_redirect_status=True)
        if r.status != 200:
            loc = r.headers.get("location")
            if not loc:
                raise HttpError(r.status, "report redirect without Location")
            r = self.http.request("GET", loc, headers={})  # no bearer token to the download host
        return list(csv.DictReader(io.StringIO(r.text())))

    # -- collection --------------------------------------------------------------------------------------
    def collect(self) -> Inventory:
        inv = Inventory(provider="m365", collected_at=now_iso())
        stage = Stage(inv, self.ckpt)

        def org(st):
            j = self._get(f"{self.base}/organization")
            o = (j.get("value") or [{}])[0]
            inv.tenant_id, inv.tenant_name = o.get("id", ""), o.get("displayName", "")
            inv.signals["on_prem_sync_enabled"] = bool(o.get("onPremisesSyncEnabled"))
            for p in o.get("assignedPlans", []):
                if p.get("capabilityStatus") == "Enabled" and p.get("service") in PLAN_SIGNALS:
                    inv.signals[PLAN_SIGNALS[p["service"]]] = True
            for d in o.get("verifiedDomains", []):
                inv.domains.append(Domain(d["name"], True, bool(d.get("isDefault")),
                                          [s.strip() for s in (d.get("capabilities") or "").split(",") if s.strip()]))
            return {"id": inv.tenant_id, "name": inv.tenant_name, "signals": inv.signals,
                    "domains": [vars(d) for d in inv.domains]}

        r = stage.run("organization", org, required_permission="Organization.Read.All")
        if r and not inv.tenant_id:  # resumed
            inv.tenant_id, inv.tenant_name = r["id"], r["name"]
            inv.signals.update(r["signals"])
            inv.domains = [Domain(**d) for d in r["domains"]]

        def domains(st):
            items = self._paged(f"{self.base}/domains", None, st)
            known = {d.name.lower(): d for d in inv.domains}
            for d in items:
                dom = known.get(d["id"].lower())
                if dom is None:
                    dom = Domain(d["id"], bool(d.get("isVerified")), bool(d.get("isDefault")))
                    inv.domains.append(dom)
                dom.verified = bool(d.get("isVerified"))
                dom.is_default = bool(d.get("isDefault"))
                dom.services = list(d.get("supportedServices") or dom.services)
            return [vars(d) for d in inv.domains]

        r = stage.run("domains", domains, required_permission="Domain.Read.All")
        if r:
            inv.domains = [Domain(**d) for d in r]

        def users(st):
            items = self._paged(f"{self.base}/users", {"$select": USER_SELECT, "$top": self.page_size}, st)
            return [_user(u) for u in items]

        r = stage.run("users", users, required_permission="User.Read.All")
        by_login: dict[str, User] = {}
        if r:
            inv.users = [User(**u) for u in r]
            by_login = {u.login.lower(): u for u in inv.users}
            inv.counts["guests"] = sum(u.user_type == "guest" for u in inv.users)

        def groups(st):
            items = self._paged(f"{self.base}/groups", {"$select": GROUP_SELECT, "$top": self.page_size}, st)
            out = [_group(g) for g in items]
            return out

        r = stage.run("groups", groups, required_permission="Group.ReadBasic.All")
        if r:
            inv.groups = [Group(**g) for g in r]

        def members(st):
            done = st.setdefault("counts", {})
            for g in inv.groups:
                if g.source_id in done:
                    continue
                try:
                    r = self.http.request("GET", f"{self.base}/groups/{g.source_id}/members/$count",
                                          headers={**self.auth.headers(), "ConsistencyLevel": "eventual"})
                    done[g.source_id] = int(r.text().strip())
                except HttpError as e:
                    if e.status in (401, 403):
                        raise
                    inv.warnings.append(f"members count failed for one group: HTTP {e.status}")
                    done[g.source_id] = None
                if len(done) % 50 == 0:
                    self.ckpt.save()
            for g in inv.groups:
                g.members = done.get(g.source_id)
            return None

        if inv.groups:
            stage.run("group_members", members, required_permission="GroupMember.Read.All")
        # NOTE: ``members`` mutates group objects; on resume (done stage) counts are re-applied from the checkpoint
        st = self.ckpt.data["stages"].get("group_members", {})
        for g in inv.groups:
            if g.members is None and st.get("counts", {}).get(g.source_id) is not None:
                g.members = st["counts"][g.source_id]

        # usage reports -> mailbox / OneDrive / SharePoint volumes (no content read).
        # Stage results hold per-login metrics so a resumed run re-applies them.
        def mailbox_report(st):
            out = {}
            for row in self._report_csv("getMailboxUsageDetail"):
                upn = row.get("User Principal Name", "")
                if row.get("Is Deleted", "").lower() == "true":
                    continue
                if "@" not in upn:
                    return {"concealed": True}
                out[upn.lower()] = {
                    "bytes": _int(row.get("Storage Used (Byte)")), "items": _int(row.get("Item Count")),
                    "archive": (row.get("Has Archive", "").lower() == "true") if "Has Archive" in row else None,
                    "last": row.get("Last Activity Date") or None}
            return out

        def onedrive_report(st):
            out = {}
            for row in self._report_csv("getOneDriveUsageAccountDetail"):
                if row.get("Is Deleted", "").lower() == "true":
                    continue
                owner = row.get("Owner Principal Name", "")
                if "@" not in owner:
                    return {"concealed": True}
                out[owner.lower()] = {"bytes": _int(row.get("Storage Used (Byte)")),
                                      "files": _int(row.get("File Count"))}
            return out

        if by_login:
            r = stage.run("report_mailbox", mailbox_report, required_permission="Reports.Read.All")
            if r and r.get("concealed") is True and len(r) == 1:
                inv.warnings.append("mailbox report: user names are concealed (tenant privacy setting); "
                                    "disable 'Display concealed user, group, and site names' to attribute usage per user")
                inv.coverage["report_mailbox"] = "partial: names concealed"
            elif r:
                n = 0
                for login, m in r.items():
                    u = by_login.get(login)
                    if u:
                        u.mailbox_bytes, u.mailbox_items = m["bytes"], m["items"]
                        u.has_archive, u.last_activity = m["archive"], m["last"]
                        n += 1
                inv.counts["mailboxes_in_report"] = n
            for u in inv.users:  # shared-mailbox heuristic (estimate): mailbox, sign-in blocked, no licence
                if u.mailbox_bytes is not None and not u.enabled and u.licensed is False:
                    u.shared_mailbox_guess = True

            r = stage.run("report_onedrive", onedrive_report, required_permission="Reports.Read.All")
            if r and r.get("concealed") is True and len(r) == 1:
                inv.warnings.append("OneDrive report: owner names are concealed (tenant privacy setting)")
                inv.coverage["report_onedrive"] = "partial: names concealed"
            elif r:
                n = 0
                for login, m in r.items():
                    u = by_login.get(login)
                    if u:
                        u.file_bytes, u.file_count = m["bytes"], m["files"]
                        n += 1
                inv.counts["onedrive_accounts_in_report"] = n

        def sharepoint_report(st):
            rows = self._report_csv("getSharePointSiteUsageDetail")
            sites = []
            for row in rows:
                sites.append(vars(Site(row.get("Site Id", ""), row.get("Site URL", ""), row.get("Root Web Template", ""),
                                       _int(row.get("Storage Used (Byte)")), _int(row.get("File Count")),
                                       _int(row.get("Page View Count")), row.get("Is Deleted", "").lower() == "true")))
            return sites

        r = stage.run("report_sharepoint", sharepoint_report, required_permission="Reports.Read.All")
        if r:
            inv.sites = [Site(**s) for s in r if not s["is_deleted"]]

        if self.deep_counts and inv.users:
            self._deep(inv, stage)

        # signals from verified inventory
        inv.signals["teams_count"] = sum(g.has_team for g in inv.groups)
        inv.signals["m365_group_count"] = sum(g.kind in ("m365-group", "team") for g in inv.groups)
        inv.signals["dynamic_group_count"] = sum(g.dynamic for g in inv.groups)
        inv.signals["site_count"] = len(inv.sites)
        inv.signals["sites_with_pages_template"] = sum(1 for s in inv.sites if "communication" in s.template.lower())
        inv.signals["guest_users"] = inv.counts.get("guests", 0)
        return inv

    def _deep(self, inv, stage):
        eligible = [u for u in inv.users if u.user_type == "member" and u.mailbox_bytes is not None]
        sample = eligible[: self.deep_max_users]
        if len(sample) < len(eligible):
            inv.warnings.append(f"deep counts sampled {len(sample)} of {len(eligible)} mailboxes")
        inv.signals["deep_count_sample_size"] = len(sample)
        inv.signals["deep_count_population"] = len(eligible)

        def deep(st):
            done = st.setdefault("per_user", {})
            for u in sample:
                if u.source_id in done:
                    continue
                rec = {}
                for key, path in (("events", "events"), ("contacts", "contacts")):
                    try:
                        r = self.http.request("GET", f"{self.base}/users/{u.source_id}/{path}/$count",
                                              headers={**self.auth.headers(), "ConsistencyLevel": "eventual"})
                        rec[key] = int(r.text().strip())
                    except HttpError as e:
                        if e.status in (401, 403):
                            raise
                        rec[key] = None
                done[u.source_id] = rec
                if len(done) % 25 == 0:
                    self.ckpt.save()
            ev = [d["events"] for d in done.values() if d.get("events") is not None]
            co = [d["contacts"] for d in done.values() if d.get("contacts") is not None]
            inv.counts["sample_events_total"], inv.counts["sample_contacts_total"] = sum(ev), sum(co)
            inv.counts["sample_events_users"], inv.counts["sample_contacts_users"] = len(ev), len(co)
            return {"events_users": len(ev), "contacts_users": len(co)}

        r = stage.run("deep_counts", deep, required_permission="Calendars.Read / Contacts.Read")
        st = self.ckpt.data["stages"].get("deep_counts", {})
        if r and "sample_events_total" not in inv.counts:  # resumed
            done = st.get("per_user", {})
            ev = [d["events"] for d in done.values() if d.get("events") is not None]
            co = [d["contacts"] for d in done.values() if d.get("contacts") is not None]
            inv.counts.update(sample_events_total=sum(ev), sample_contacts_total=sum(co),
                              sample_events_users=len(ev), sample_contacts_users=len(co))


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _user(u: dict) -> dict:
    proxies = u.get("proxyAddresses") or []
    primary = next((p[5:] for p in proxies if p.startswith("SMTP:")), u.get("mail") or "")
    aliases = [p[5:] for p in proxies if p.startswith("smtp:")]
    return vars(User(
        source_id=u["id"], login=u.get("userPrincipalName", ""), display_name=u.get("displayName") or "",
        mail=primary or u.get("mail") or "", aliases=aliases, enabled=bool(u.get("accountEnabled", True)),
        user_type="guest" if (u.get("userType") == "Guest" or "#EXT#" in u.get("userPrincipalName", "")) else "member",
        licensed=bool(u.get("assignedLicenses")) if "assignedLicenses" in u else None))


def _group(g: dict) -> dict:
    types = g.get("groupTypes") or []
    unified = "Unified" in types
    mail, sec = bool(g.get("mailEnabled")), bool(g.get("securityEnabled"))
    team = "Team" in (g.get("resourceProvisioningOptions") or [])
    if unified:
        kind = "team" if team else "m365-group"
    elif mail and sec:
        kind = "mail-security"
    elif mail:
        kind = "distribution"
    else:
        kind = "security"
    return vars(Group(g["id"], g.get("displayName") or "", g.get("mail") or "", kind, None,
                      "DynamicMembership" in types, team))
