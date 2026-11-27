"""The orchestrator: `python -m ics.cli demo-seed` (docs/admin/demo-organization.md).

    resolve_target   safeguards 1-3 (names, ICS marker bound to id + domain, typed confirmation) before anything else
    accounts_phase   safeguard 4 (no foreign people), then one directory.account.set plan per missing person (approved in the console)
    content phase    mail, calendar, files, chat, each signed in as the person through the application's own protocol
    reset            removes what the seed names (X-OU-Demo-Id, ou-demo- UIDs/aliases, its folder paths, its people via
                     directory.account.delete plans, its password secrets once the person is gone)

Per-person passwords are generated here (secrets.token_urlsafe) and live only in the vault (deployment_secrets 'demo-pw-<uid>'), and
optionally in a 0600 file outside any git checkout (export_passwords). They are never printed or logged; the plans carry them as their
encrypted secret like any People-panel password."""
from __future__ import annotations

import datetime as dt
import json
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import text

from . import clients, guard, officefiles, org, planner

MANIFEST_KEY = "demo.manifest"
OC_CLIENT = "OpenCloudDesktop"      # public PKCE client of the realm template (loopback redirect)
PHASES = ("mail", "calendar", "files", "chat")


def secret_name(uid: str) -> str:
    return "demo-pw-" + uid.replace(".", "-")     # deployment_secrets.name: ^[a-z][a-z0-9-]{1,40}$


def new_password() -> str:
    return secrets.token_urlsafe(18)              # 24 characters of [A-Za-z0-9_-]: accounts.USER_PASSWORD


@dataclass
class Target:
    deployment_id: str
    slug: str
    domain: str
    plan: dict
    hosts: dict = field(default_factory=dict)     # mail, cloud, auth, matrix

    @property
    def issuer(self) -> str:
        from ..deploy import configure
        return f"https://{self.hosts['auth']}/realms/{configure.REALM}"

    @property
    def server_name(self) -> str:
        return self.hosts["matrix"]


def hosts_of(plan: dict) -> dict:
    from ..deploy import configure
    mail = next((x["name"] for x in plan.get("dns", []) if x.get("component") == "groupware" and x.get("type") == "A"), None)
    return {"mail": mail or configure.fq(plan, None, "mail"), "cloud": configure.fq(plan, None, "cloud"),
            "auth": configure.fq(plan, None, "auth"), "matrix": configure.fq(plan, None, "matrix")}


def resolve_target(db, slug: str, confirm: str | None) -> Target:
    from ..deploy import appaccess, configure
    guard.check_confirm(slug, confirm)
    d = db.execute(text("SELECT * FROM deployments WHERE slug = :s AND status NOT IN ('destroyed', 'destroying')"), {"s": slug}).first()
    if d is None:
        raise guard.DemoRefused(f"deployment {slug} not found")
    plan = appaccess._applied_plan(db, d)
    if plan is None:
        raise guard.DemoRefused("the deployment has no applied plan yet")
    domain = configure.scope(plan, None)["domain"]
    guard.check_names(slug, domain)
    guard.check_marker(db, str(d.id), slug, domain)
    t = Target(str(d.id), slug, domain, plan, hosts_of(plan))
    for h in t.hosts.values():
        if not guard.host_allowed(h, domain):
            raise guard.DemoRefused(f"the deployment serves {h} outside its own domain: refused")
    return t


# ---------------------------------------------------------------- manifest
def manifest(db, slug: str) -> dict:
    row = db.execute(text("SELECT value FROM system_settings WHERE key = :k"), {"k": MANIFEST_KEY}).first()
    return dict((row.value or {}).get(slug) or {}) if row else {}


def save_manifest(db, slug: str, value: dict | None) -> None:
    row = db.execute(text("SELECT value FROM system_settings WHERE key = :k"), {"k": MANIFEST_KEY}).first()
    allm = dict(row.value or {}) if row else {}
    if value is None:
        allm.pop(slug, None)
    else:
        allm[slug] = value
    db.execute(text("INSERT INTO system_settings (key, value, updated_at, updated_by) VALUES (:k, CAST(:v AS jsonb), now(), 'demo') "
                    "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now(), updated_by = EXCLUDED.updated_by"),
               {"k": MANIFEST_KEY, "v": json.dumps(allm)})
    db.commit()


def seed_plan(db, t: Target, tz: str = "UTC", today: dt.date | None = None) -> planner.SeedPlan:
    """The anchor day and time zone of the first run are kept, so every re-run builds the same plan."""
    m = manifest(db, t.slug)
    if not m:
        m = {"seed": org.SEED_TAG, "deployment_id": t.deployment_id, "anchor": (today or dt.date.today()).isoformat(), "tz": tz, "rooms": {}}
        save_manifest(db, t.slug, m)
    sp = planner.SeedPlan(t.domain, dt.date.fromisoformat(m["anchor"]), m.get("tz") or tz)
    guard.check_addresses(sp, t.domain)
    return sp


# ---------------------------------------------------------------- passwords
def password(rt, t: Target, uid: str) -> str:
    from ..deploy import configure
    return configure.secret(rt, t.deployment_id, secret_name(uid), new_password)


def has_password(db, t: Target, uid: str) -> bool:
    return db.execute(text("SELECT 1 FROM deployment_secrets WHERE deployment_id = :d AND name = :n"),
                      {"d": t.deployment_id, "n": secret_name(uid)}).first() is not None


def export_passwords(rt, t: Target, path: str) -> int:
    """Writes 'email<TAB>password' lines to a NEW 0600 file outside any git checkout. Returns the number of lines; prints nothing."""
    p = Path(path).expanduser().resolve()
    for parent in [p.parent, *p.parent.parents]:
        if (parent / ".git").exists():
            raise guard.DemoRefused("refusing to write passwords inside a git checkout")
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    n = 0
    with os.fdopen(fd, "w") as f:
        for person in org.PEOPLE:
            f.write(f"{person.uid}@{t.domain}\t{password(rt, t, person.uid)}\n")
            n += 1
    return n


# ---------------------------------------------------------------- accounts (typed plans, approved in the console)
def _operator(db, username: str):
    from ..auth import User
    row = db.execute(text("SELECT id, username, role, created_by, role_set_by FROM users WHERE username = :u AND NOT disabled"),
                     {"u": username}).first()
    if row is None:
        raise guard.DemoRefused(f"no active ICS account {username}")
    return User(row)


def _inflight(db, action: str, slug: str, uid: str) -> str | None:
    row = db.execute(text(
        "SELECT p.id FROM plans p LEFT JOIN jobs j ON j.plan_id = p.id WHERE p.action = :a AND p.params->>'deployment' = :s "
        "AND p.params->>'username' = :u AND (p.status = 'pending_approval' OR (p.status = 'approved' AND (j.id IS NULL OR j.status IN ('queued', 'running')))) "
        "ORDER BY p.created_at DESC LIMIT 1"), {"a": action, "s": slug, "u": uid}).first()
    return str(row.id) if row else None


def _people(rt, db, slug: str, people_fn=None) -> list[dict]:
    from ..deploy import accounts
    return (people_fn or accounts.people)(rt, db, slug)["people"]


def accounts_phase(rt, t: Target, operator: str, people_fn=None) -> dict:
    from ..actions import ActionType, create_plan
    with rt.session() as db:
        people = _people(rt, db, t.slug, people_fn)
        guard.check_people(people, set(org.BY_UID))
        present = {p["username"] for p in people}
        user = _operator(db, operator)
        out = {"present": sorted(present & set(org.BY_UID)), "requested": [], "waiting": []}
        for p in org.PEOPLE:
            if p.uid in present:
                continue
            pid = _inflight(db, "directory.account.set", t.slug, p.uid)
            if pid:
                out["waiting"].append(pid)
                continue
            res = create_plan(db, rt, user, ActionType.directory_account_set,
                              {"deployment": t.slug, "username": p.uid, "password": password(rt, t, p.uid), "role": p.role,
                               "display_name": p.name}, None)
            out["requested"].append(res["plan_id"])
    return out


def reset_accounts(rt, t: Target, operator: str, people_fn=None) -> dict:
    from ..actions import ActionType, create_plan
    with rt.session() as db:
        people = _people(rt, db, t.slug, people_fn)
        guard.check_people(people, set(org.BY_UID))
        present = {p["username"] for p in people}
        user = _operator(db, operator)
        out = {"requested": [], "waiting": [], "secrets_removed": 0}
        for p in org.PEOPLE:
            if p.uid in present:
                pid = _inflight(db, "directory.account.delete", t.slug, p.uid)
                if pid:
                    out["waiting"].append(pid)
                else:
                    out["requested"].append(create_plan(db, rt, user, ActionType.directory_account_delete,
                                                        {"deployment": t.slug, "username": p.uid}, None)["plan_id"])
            elif has_password(db, t, p.uid):
                db.execute(text("DELETE FROM deployment_secrets WHERE deployment_id = :d AND name = :n"),
                           {"d": t.deployment_id, "n": secret_name(p.uid)})
                out["secrets_removed"] += 1
        db.commit()
    return out


# ---------------------------------------------------------------- MSP view tenants (ICS customers without deployments)
def tenants_phase(rt, t: Target, operator: str, reset: bool = False) -> dict:
    from ..actions import ActionType, create_plan
    from .. import tenancy_mode
    with rt.session() as db:
        if tenancy_mode.get(db) != "multi":
            return {"skipped": "the installation is single-tenant: there is no MSP tenant list to fill"}
        user = _operator(db, operator)
        out = {"requested": [], "present": []}
        for dt_ in org.MSP_TENANTS:
            row = db.execute(text("SELECT id, disabled_at IS NOT NULL AS disabled FROM customers WHERE name = :n"), {"n": dt_.name}).first()
            if reset:
                if row is not None and not row.disabled:
                    out["requested"].append(create_plan(db, rt, user, ActionType.customer_update,
                                                        {"customer_id": str(row.id), "disabled": True}, None)["plan_id"])
                continue
            if row is not None:
                out["present"].append(dt_.name)
                continue
            out["requested"].append(create_plan(db, rt, user, ActionType.customer_create,
                                                {"name": dt_.name, "slug": dt_.slug, "contact_name": dt_.contact_name,
                                                 "contact_email": dt_.contact_email, "provisioning_mode": "monitoring_only"}, None)["plan_id"])
    return out


# ---------------------------------------------------------------- content
class Seeder:
    """Content phases. `http` is an httpx.Client built by clients.http_client (HostGuard installed); `imap_factory` builds the IMAP
    connection (tests pass fakes). Passwords come from the vault through `pw(uid)`."""

    def __init__(self, t: Target, sp: planner.SeedPlan, pw, http, imap_factory=None, ca_file: str | None = None, log=print):
        self.t, self.sp, self.pw, self.h, self.imf, self.ca, self.log = t, sp, pw, http, imap_factory, ca_file, log
        self.counts: dict[str, dict[str, int]] = {}

    def _c(self, phase: str, key: str, n: int = 1) -> None:
        self.counts.setdefault(phase, {}).setdefault(key, 0)
        self.counts[phase][key] += n

    def _email(self, uid: str) -> str:
        return f"{uid}@{self.t.domain}"

    def _imap(self, uid: str) -> clients.Imap:
        return clients.Imap(self.t.hosts["mail"], self.t.domain, self._email(uid), self.pw(uid), ca_file=self.ca, factory=self.imf)

    def _dav(self, uid: str) -> clients.Dav:
        d = clients.Dav(self.h, f"https://{self.t.hosts['mail']}/dav/", self._email(uid), self.pw(uid))
        d.discover()
        return d

    # ----- mail
    def mail(self) -> None:
        by_owner: dict[str, list[planner.Delivery]] = {}
        for d in self.sp.deliveries():
            by_owner.setdefault(d.owner, []).append(d)
        for uid, items in by_owner.items():
            im = self._imap(uid)
            try:
                for folder in ("INBOX", "SENT"):
                    have = im.demo_ids(folder)
                    for d in (x for x in items if x.folder == folder):
                        if d.demo_id in have:
                            self._c("mail", "kept")
                        else:
                            im.append(folder, d.flags, d.when, d.message)
                            self._c("mail", "created")
            finally:
                im.close()

    def reset_mail(self) -> None:
        for p in org.PEOPLE:
            im = self._imap(p.uid)
            try:
                for folder in ("INBOX", "SENT"):
                    self._c("mail", "removed", im.delete_demo(folder))
            finally:
                im.close()

    # ----- calendar + tasks
    def calendar(self) -> None:
        objs = self.sp.calendar()
        for uid in dict.fromkeys(o.owner for o in objs):
            dav = self._dav(uid)
            if uid == org.TEAM_CALENDAR["owner"]:
                if dav.mkcalendar(dav.collection(org.TEAM_CALENDAR["slug"]), org.TEAM_CALENDAR["name"]):
                    self._c("calendar", "calendars_created")
            have: dict[str, dict[str, str]] = {}
            for o in (x for x in objs if x.owner == uid):
                col = dav.collection(o.collection)
                if col not in have:
                    have[col] = dav.uids(col)
                # an existing UID is kept: re-sending it would make the server re-send every invitation (first real run 2026-11-27)
                created = o.uid not in have[col] and dav.put_once(col + o.href, o.ics)
                self._c("calendar", "created" if created else "kept")

    def reset_calendar(self) -> None:
        owners = list(dict.fromkeys([o.owner for o in self.sp.calendar()] + [p.uid for p in org.PEOPLE]))   # organizers first
        for uid in owners:
            dav = self._dav(uid)
            for cal in dav.calendars():
                for href in dav.demo_hrefs(cal):
                    self._c("calendar", "removed", int(dav.delete(href)))
            if uid == org.TEAM_CALENDAR["owner"]:
                url = dav.collection(org.TEAM_CALENDAR["slug"])
                if dav.exists(url) and dav.delete(url):
                    self._c("calendar", "calendars_removed")

    # ----- files
    def _files(self, uid: str) -> clients.Files:
        tok = clients.oidc_token(self.h, self.t.issuer, OC_CLIENT, uid, self.pw(uid))
        f = clients.Files(self.h, f"https://{self.t.hosts['cloud']}", tok)
        f.open_drive()
        return f

    def files(self) -> None:
        for folder in org.FOLDERS:
            f = self._files(folder.owner)
            self._c("files", "folders_created", f.mkdirs(folder.path))
            for key in folder.files:
                ok = f.put_if_absent(f"{folder.path}/{key}", officefiles.render(org.FILES[key]), officefiles.mime(key))
                self._c("files", "created" if ok else "kept")
            item = f.item_id(folder.path)
            for uid, role in folder.shares:
                ok = f.share(item, f.user_id(uid, self._email(uid)), role)
                self._c("files", "shares_created" if ok else "shares_kept")

    def reset_files(self) -> None:
        for folder in org.FOLDERS:
            f = self._files(folder.owner)
            if f.item_id(folder.path) and f.delete(folder.path):
                self._c("files", "folders_removed")

    # ----- chat
    def _mx(self, uid: str) -> str:
        return f"@{uid}:{self.t.server_name}"

    def _alias(self, key: str) -> str:
        return f"#{org.UID_PREFIX}{key}:{self.t.server_name}"

    def _sessions(self, uids) -> dict[str, clients.Matrix]:
        base = f"https://{self.t.hosts['matrix']}"
        out = {}
        for u in uids:
            out[u] = clients.Matrix.login(self.h, base, u, self.pw(u))
        return out

    def chat(self, rooms_out: dict) -> None:
        uids = list(dict.fromkeys(u for r in org.ROOMS for u in (r.creator, *r.members)))
        s = self._sessions(uids)
        try:
            for r in org.ROOMS:
                c = s[r.creator]
                room = c.alias_room(self._alias(r.key))
                if room is None:
                    # only a direct chat invites in createRoom: Synapse refuses larger invite lists at creation ("Cannot invite so many users at
                    # once", first real run 2026-11-27); the members are invited one by one below
                    room = c.create_room(org.UID_PREFIX + r.key, r.name, r.topic,
                                         [self._mx(u) for u in r.members if u != r.creator] if r.direct else [], r.direct)
                    self._c("chat", "rooms_created")
                else:
                    self._c("chat", "rooms_kept")
                rooms_out[r.key] = room
                mem = c.members(room)
                for u in r.members:
                    if u == r.creator or mem.get(self._mx(u)) == "join":
                        continue
                    if mem.get(self._mx(u)) != "invite":
                        c.invite(room, self._mx(u))
                    s[u].join(room)
                    self._c("chat", "joined")
                if r.direct:
                    a, b = r.members[0], r.members[1]
                    s[a].mark_direct(self._mx(b), room)
                    s[b].mark_direct(self._mx(a), room)
                have = c.demo_ids(room)
                for key, demo_id, sender, body in self.sp.chat_messages():
                    if key != r.key:
                        continue
                    if demo_id in have:
                        self._c("chat", "messages_kept")
                    else:
                        s[sender].send(room, demo_id, body)
                        self._c("chat", "messages_created")
        finally:
            for m in s.values():
                m.logout()

    def reset_chat(self) -> None:
        uids = list(dict.fromkeys(u for r in org.ROOMS for u in (r.creator, *r.members)))
        s = self._sessions(uids)
        try:
            for r in org.ROOMS:
                room = s[r.creator].alias_room(self._alias(r.key))
                if room is None:
                    continue
                s[r.creator].delete_alias(self._alias(r.key))
                for u in dict.fromkeys((*r.members, r.creator)):
                    s[u].leave(room)
                self._c("chat", "rooms_removed")
        finally:
            for m in s.values():
                m.logout()


def run_content(rt, t: Target, sp: planner.SeedPlan, phases, *, http, imap_factory=None, ca_file=None, reset: bool = False) -> dict:
    sd = Seeder(t, sp, lambda uid: password(rt, t, uid), http, imap_factory, ca_file)
    with rt.session() as db:
        m = manifest(db, t.slug)
    order = ["chat", "files", "calendar", "mail"] if reset else list(PHASES)   # reset: calendar before mail (cancellations land in inboxes)
    for ph in (x for x in order if x in phases):
        if reset:
            getattr(sd, "reset_" + ph)()
        elif ph == "chat":
            rooms = dict(m.get("rooms") or {})
            sd.chat(rooms)
            m["rooms"] = rooms
        else:
            getattr(sd, ph)()
        m.setdefault("phases", {})[ph] = {"at": dt.datetime.now(dt.timezone.utc).isoformat(), "reset": reset, **sd.counts.get(ph, {})}
    with rt.session() as db:
        save_manifest(db, t.slug, m)
    return sd.counts


# ---------------------------------------------------------------- command line (ics.cli demo-seed)
EXIT_REFUSED, EXIT_WAIT = 2, 3
DRY_RUN_DOMAIN = "demo.northstar.example"


def add_arguments(p) -> None:
    p.add_argument("--deployment", help="slug of the demo deployment (marked by the approved action demo.deployment.mark)")
    p.add_argument(guard.CONFIRM_FLAG, dest="confirm", metavar="SLUG", help="type the target slug again to confirm it is the demo deployment")
    p.add_argument("--dry-run", action="store_true", help="print the plan (counts, names) and contact nothing: no database, no network")
    p.add_argument("--domain", help=f"dry run only: the domain to plan for (default {DRY_RUN_DOMAIN})")
    p.add_argument("--operator", help="your ICS admin account: the directory plans are requested in its name and approved in the console")
    p.add_argument("--only", default=",".join(PHASES), help=f"content phases, comma separated (default: {','.join(PHASES)})")
    p.add_argument("--skip-accounts", action="store_true", help="content only (every seeded person must already exist)")
    p.add_argument("--msp-tenants", action="store_true", help="also request the fictional MSP tenants (multi-tenant installations only)")
    p.add_argument("--reset", action="store_true", help="remove what the seed created (content first, then directory.account.delete plans)")
    p.add_argument("--timezone", default="UTC", help="time zone of the office hours used for mail and meetings (first run only)")
    p.add_argument("--ca-file", help="extra trusted CA bundle (the deployment CA) for HTTPS and IMAPS; verification is never disabled")
    p.add_argument("--export-passwords", metavar="PATH", help="write the demo people's sign-ins to a NEW 0600 file outside any git checkout")


def _say(out, obj) -> None:
    print(json.dumps(obj, indent=1, sort_keys=True), file=out)


def main(args, rt_factory=None, http_factory=None, imap_factory=None, people_fn=None, out=None) -> int:
    import sys
    out = out or sys.stdout
    phases = [x.strip() for x in (args.only or "").split(",") if x.strip()]
    bad = [x for x in phases if x not in PHASES]
    if bad:
        print(f"unknown phase(s): {', '.join(bad)}", file=sys.stderr)
        return EXIT_REFUSED
    try:
        if args.dry_run:
            domain = (args.domain or DRY_RUN_DOMAIN).lower()
            guard.check_names(args.deployment or "dry-run-demo", domain)
            sp = planner.SeedPlan(domain, dt.date.today(), args.timezone)
            guard.check_addresses(sp, domain)
            _say(out, {"dry_run": True, "reset": args.reset, "phases": phases, "plan": sp.summary(),
                       "people": [{k: a[k] for k in ("email", "display_name", "role", "department", "title")} for a in sp.accounts()]})
            return 0
        if args.domain:
            raise guard.DemoRefused("--domain is for --dry-run only: a real run takes the domain from the marked deployment")
        if not args.deployment:
            raise guard.DemoRefused("--deployment is required")
        if not args.operator and not (args.skip_accounts and not args.msp_tenants):
            raise guard.DemoRefused("--operator (your ICS admin account) is required to request the directory plans")
        if rt_factory is None:
            from ..runtime import Runtime
            rt_factory = Runtime
        rt = rt_factory()
        with rt.session() as db:
            t = resolve_target(db, args.deployment, args.confirm)
            sp = seed_plan(db, t, args.timezone)
        mk_http = http_factory or (lambda: clients.http_client(t.domain, args.ca_file))
        if args.reset:
            if phases:
                with mk_http() as h:
                    _say(out, {"reset": run_content(rt, t, sp, phases, http=h, imap_factory=imap_factory, ca_file=args.ca_file, reset=True)})
            res = {} if args.skip_accounts else reset_accounts(rt, t, args.operator, people_fn)
            if args.msp_tenants:
                res["tenants"] = tenants_phase(rt, t, args.operator, reset=True)
            _say(out, {"reset_accounts": res})
            if res and not res.get("requested") and not res.get("waiting") and set(phases) == set(PHASES):
                with rt.session() as db:
                    save_manifest(db, t.slug, None)
            return EXIT_WAIT if res.get("requested") or res.get("waiting") else 0
        if not args.skip_accounts:
            acc = accounts_phase(rt, t, args.operator, people_fn)
            if args.msp_tenants:
                acc["tenants"] = tenants_phase(rt, t, args.operator)
            _say(out, {"accounts": {"present": len(acc["present"]), "requested_plans": acc["requested"], "waiting_plans": acc["waiting"],
                                    **({"tenants": acc["tenants"]} if "tenants" in acc else {})}})
            if acc["requested"] or acc["waiting"]:
                print(f"approve the {len(acc['requested']) + len(acc['waiting'])} plan(s) in the console (Plans), wait for the jobs, "
                      "then run the same command again", file=out)
                return EXIT_WAIT
        with rt.session() as db:
            missing = [p.uid for p in org.PEOPLE if not has_password(db, t, p.uid)]
        if missing:
            raise guard.DemoRefused(f"{len(missing)} seeded people have no stored password (run without --skip-accounts first)")
        if args.export_passwords:
            _say(out, {"passwords_exported": export_passwords(rt, t, args.export_passwords), "file_mode": "0600"})
        if phases:
            with mk_http() as h:
                _say(out, {"content": run_content(rt, t, sp, phases, http=h, imap_factory=imap_factory, ca_file=args.ca_file)})
        return 0
    except guard.DemoRefused as e:
        print(f"refused: {e}", file=sys.stderr)
        return EXIT_REFUSED
    except clients.SeedError as e:
        print(f"stopped: {e}", file=sys.stderr)
        return 1
