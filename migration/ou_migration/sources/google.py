"""Google Workspace read-only collector (Admin SDK Directory + Reports, optional Gmail/Drive metadata).

Domain-wide delegation scopes (all read-only; add each to the service account's DWD allow-list):

  core      admin.directory.user.readonly, admin.directory.group.readonly, admin.directory.domain.readonly,
            admin.directory.customer.readonly, admin.reports.usage.readonly
  optional  admin.directory.resource.calendar.readonly           (room/resource count)
  deep      gmail.metadata   (users.getProfile -> messagesTotal; impersonates each sampled user)
            drive.metadata.readonly (files.list with fields=size,shared,mimeType,permissions/type ONLY:
                                     no names, no content; impersonates each sampled user)

Reports API data lags 2-3 days; the collector walks back up to ``max_back`` days to find a populated date.
"""
from __future__ import annotations

import datetime as dt
import logging

from ..auth import GoogleAuth
from ..checkpoint import Checkpoint
from ..http import HttpClient, HttpError
from ..model import Domain, Group, Inventory, User, bucketize
from .base import Stage, now_iso

log = logging.getLogger("ou_migration.google")

DIR = "https://admin.googleapis.com/admin/directory/v1"
REPORTS = "https://admin.googleapis.com/admin/reports/v1"
GMAIL = "https://gmail.googleapis.com/gmail/v1"
DRIVE = "https://www.googleapis.com/drive/v3"
S = "https://www.googleapis.com/auth/"
SC_USER, SC_GROUP, SC_DOMAIN, SC_CUSTOMER = (S + "admin.directory.user.readonly", S + "admin.directory.group.readonly",
                                            S + "admin.directory.domain.readonly", S + "admin.directory.customer.readonly")
SC_USAGE, SC_RESOURCE = S + "admin.reports.usage.readonly", S + "admin.directory.resource.calendar.readonly"
SC_GMAIL, SC_DRIVE = S + "gmail.metadata", S + "drive.metadata.readonly"
MB = 1024 * 1024
GAPPS = "application/vnd.google-apps."


class GoogleCollector:
    def __init__(self, http: HttpClient, auth: GoogleAuth, ckpt: Checkpoint, *, dir_base=DIR, reports_base=REPORTS,
                 gmail_base=GMAIL, drive_base=DRIVE, deep=False, deep_max_users=25, deep_max_files_per_user=20000,
                 today: dt.date | None = None, max_back=6):
        self.http, self.auth, self.ckpt = http, auth, ckpt
        self.dir, self.reports, self.gmail, self.drive = dir_base, reports_base, gmail_base, drive_base
        self.deep, self.deep_max_users, self.deep_max_files = deep, deep_max_users, deep_max_files_per_user
        self.today = today or dt.date.today()
        self.max_back = max_back

    def _paged(self, url, params, key, scopes, st, subject=None):
        items = st.setdefault("items", [])
        token = st.get("next")
        started = bool(items) or token is not None
        while not started or token:
            p = dict(params)
            if token:
                p["pageToken"] = token
            j = self.http.request("GET", url, headers=self.auth.headers(scopes, subject), params=p).json()
            items.extend(j.get(key, []))
            token = j.get("nextPageToken")
            st["next"] = token
            started = True
            self.ckpt.save()
        return items

    def collect(self) -> Inventory:
        inv = Inventory(provider="google", collected_at=now_iso())
        stage = Stage(inv, self.ckpt)

        def customer(st):
            j = self.http.request("GET", f"{self.dir}/customers/my_customer",
                                  headers=self.auth.headers([SC_CUSTOMER])).json()
            return {"id": j.get("id", ""), "name": j.get("customerDomain", "")}

        r = stage.run("customer", customer, required_permission="admin.directory.customer.readonly")
        if r:
            inv.tenant_id, inv.tenant_name = r["id"], r["name"]

        def domains(st):
            j = self.http.request("GET", f"{self.dir}/customer/my_customer/domains",
                                  headers=self.auth.headers([SC_DOMAIN])).json()
            out = []
            for d in j.get("domains", []):
                out.append(vars(Domain(d["domainName"], bool(d.get("verified")), bool(d.get("isPrimary")))))
                for a in d.get("domainAliases", []) or []:
                    out.append(vars(Domain(a["domainAliasName"], bool(a.get("verified")), False, ["alias of " + d["domainName"]])))
            return out

        r = stage.run("domains", domains, required_permission="admin.directory.domain.readonly")
        if r:
            inv.domains = [Domain(**d) for d in r]

        def users(st):
            items = self._paged(f"{self.dir}/users", {"customer": "my_customer", "maxResults": 500, "projection": "basic",
                                                      "fields": "nextPageToken,users(id,primaryEmail,name/fullName,aliases,"
                                                                "isAdmin,isDelegatedAdmin,suspended,archived,creationTime,lastLoginTime,"
                                                                "isEnrolledIn2Sv)"},
                                "users", [SC_USER], st)
            return [_user(u) for u in items]

        r = stage.run("users", users, required_permission="admin.directory.user.readonly")
        by_login = {}
        if r:
            inv.users = [User(**u) for u in r]
            by_login = {u.login.lower(): u for u in inv.users}
            inv.counts["admins"] = sum(1 for u in inv.users if u.is_admin)

        def groups(st):
            items = self._paged(f"{self.dir}/groups", {"customer": "my_customer", "maxResults": 200}, "groups",
                                [SC_GROUP], st)
            return [vars(Group(g["id"], g.get("name", ""), g.get("email", ""), "google-group",
                               _int(g.get("directMembersCount")))) for g in items]

        r = stage.run("groups", groups, required_permission="admin.directory.group.readonly")
        if r:
            inv.groups = [Group(**g) for g in r]

        def resources(st):
            items = self._paged(f"{self.dir}/customer/my_customer/resources/calendars", {"maxResults": 500}, "items",
                                [SC_RESOURCE], st)
            return len(items)

        r = stage.run("resources", resources, required_permission="admin.directory.resource.calendar.readonly")
        if r is not None:
            inv.counts["resource_calendars"] = r

        def usage(st):
            """accounts:* quota parameters per user from the Reports API (no content)."""
            params = "accounts:used_quota_in_mb,accounts:gmail_used_quota_in_mb,accounts:drive_used_quota_in_mb"
            for back in range(2, 2 + self.max_back):
                d = (self.today - dt.timedelta(days=back)).isoformat()
                try:
                    items = self._paged(f"{self.reports}/usage/users/all/dates/{d}",
                                        {"parameters": params, "maxResults": 1000}, "usageReports", [SC_USAGE], st)
                except HttpError as e:
                    if e.status == 400:  # data for this date not available yet
                        st.pop("items", None)
                        st.pop("next", None)
                        continue
                    raise
                if items:
                    out = {}
                    for it in items:
                        email = (it.get("entity") or {}).get("userEmail", "").lower()
                        p = {x["name"]: _int(x.get("intValue")) for x in it.get("parameters", []) if "name" in x}
                        out[email] = p
                    return {"date": d, "users": out}
                st.pop("items", None)
                st.pop("next", None)
            raise HttpError(404, "no Reports API usage data in the look-back window")

        r = stage.run("usage_report", usage, required_permission="admin.reports.usage.readonly")
        if r and by_login:
            inv.counts["usage_report_date_" + r["date"]] = len(r["users"])
            for email, p in r["users"].items():
                u = by_login.get(email)
                if not u:
                    continue
                gm, dr = p.get("accounts:gmail_used_quota_in_mb"), p.get("accounts:drive_used_quota_in_mb")
                u.mailbox_bytes = gm * MB if gm is not None else None
                u.file_bytes = dr * MB if dr is not None else None
                # item counts are NOT in the Reports API; stay None unless --deep (Gmail profile)

        if self.deep and inv.users:
            self._deep(inv, stage)

        inv.signals["group_count"] = len(inv.groups)
        inv.signals["guests"] = 0
        return inv

    # -- opt-in per-user metadata sampling (impersonates each sampled user; counts only) -------------------
    def _deep(self, inv, stage):
        eligible = [u for u in inv.users if not u.suspended]
        eligible.sort(key=lambda u: -(u.file_bytes or 0))  # biggest accounts first: worst-case oriented sample
        sample = eligible[: self.deep_max_users]
        inv.signals["deep_count_sample_size"] = len(sample)
        inv.signals["deep_count_population"] = len(eligible)
        if len(sample) < len(eligible):
            inv.warnings.append(f"deep scan sampled the {len(sample)} largest of {len(eligible)} active accounts")

        def deep(st):
            done = st.setdefault("per_user", {})
            for u in sample:
                if u.source_id in done:
                    continue
                rec = {}
                try:
                    j = self.http.request("GET", f"{self.gmail}/users/me/profile",
                                          headers=self.auth.headers([SC_GMAIL], u.login)).json()
                    rec["messages"] = _int(j.get("messagesTotal"))
                except HttpError as e:
                    rec["messages"] = None
                    rec["gmail_err"] = e.status
                rec["drive"] = self._scan_drive(u.login)
                done[u.source_id] = rec
                self.ckpt.save()
            return None

        stage.run("deep_scan", deep, required_permission="gmail.metadata / drive.metadata.readonly (DWD allow-list)")
        done = self.ckpt.data["stages"].get("deep_scan", {}).get("per_user", {})
        buckets, shared, anyone, domain_wide, files, kinds = {}, 0, 0, 0, 0, {}
        for u in sample:
            rec = done.get(u.source_id)
            if not rec:
                continue
            u.mailbox_items = rec.get("messages")
            d = rec.get("drive")
            if d:
                u.file_count = d["files"]
                files += d["files"]
                shared += d["shared"]
                anyone += d["anyone"]
                domain_wide += d["domain"]
                for k, v in d["buckets"].items():
                    buckets[k] = buckets.get(k, 0) + v
                for k, v in d["kinds"].items():
                    kinds[k] = kinds.get(k, 0) + v
                if d["truncated"]:
                    inv.warnings.append("drive scan truncated for one account (file cap reached)")
        if files:
            inv.file_size_buckets = buckets
            inv.sharing = {"sample_files": files, "sample_shared_files": shared,
                           "sample_anyone_link_files": anyone, "sample_domain_link_files": domain_wide}
            inv.signals["sample_gapps_kinds"] = kinds
            inv.signals["google_forms_in_sample"] = kinds.get("form", 0)
            inv.signals["google_sites_in_sample"] = kinds.get("site", 0)
            inv.signals["apps_script_in_sample"] = kinds.get("script", 0)

    def _scan_drive(self, subject):
        sizes, shared, anyone, domain, kinds, n = [], 0, 0, 0, {}, 0
        token, truncated = None, False
        while True:
            p = {"pageSize": 1000, "spaces": "drive", "corpora": "user",
                 "fields": "nextPageToken,files(size,shared,mimeType,permissions(type))"}
            if token:
                p["pageToken"] = token
            try:
                j = self.http.request("GET", f"{self.drive}/files", headers=self.auth.headers([SC_DRIVE], subject),
                                      params=p).json()
            except HttpError:
                return None
            for f in j.get("files", []):
                n += 1
                mt = f.get("mimeType", "")
                if mt.startswith(GAPPS):
                    k = mt[len(GAPPS):]
                    kinds[k] = kinds.get(k, 0) + 1
                if f.get("size") is not None:
                    sizes.append(int(f["size"]))
                if f.get("shared"):
                    shared += 1
                types = {x.get("type") for x in f.get("permissions", [])}
                anyone += "anyone" in types
                domain += "domain" in types
            token = j.get("nextPageToken")
            if n >= self.deep_max_files:
                truncated = bool(token)
                break
            if not token:
                break
        return {"files": n, "shared": shared, "anyone": anyone, "domain": domain, "buckets": bucketize(sizes), "kinds": kinds,
                "truncated": truncated}


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _user(u: dict) -> dict:
    return vars(User(
        source_id=u["id"], login=u["primaryEmail"], display_name=(u.get("name") or {}).get("fullName", ""),
        mail=u["primaryEmail"], aliases=list(u.get("aliases") or []), enabled=not u.get("suspended", False),
        suspended=bool(u.get("suspended")), is_admin=bool(u.get("isAdmin") or u.get("isDelegatedAdmin")),
        last_activity=u.get("lastLoginTime")))
