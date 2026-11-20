"""Directory account runbooks (cfg.ldap_list, cfg.ldap_groups, cfg.ldap_lock, cfg.ldap_delete): the closed schemas, and the root helper against an
in-memory directory standing behind Ctx.run (ldapsearch answers from it, ldapmodify LDIF is recorded and applied)."""
import base64
import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
from ou_agent import cfghelper as h  # noqa: E402
from ou_agent import cfgspec as c  # noqa: E402
from ou_agent import firstboot  # noqa: E402
from ou_agent.proto import Reject  # noqa: E402

from ics.guest import agentcall, cloudinit  # noqa: E402

D = "acme.example"
B = "dc=acme,dc=example"
BIND = f"cn=svc-bind,ou=system,{B}"
NEW = ("cfg.ldap_list", "cfg.ldap_groups", "cfg.ldap_lock", "cfg.ldap_delete")


def P(uid):
    return f"uid={uid},ou=people,{B}"


def G(cn):
    return f"cn={cn},ou=groups,{B}"


# ---------------------------------------------------------------- registration
def test_registered_everywhere():
    for r in NEW:
        assert r in c.CFG_RUNBOOKS and r in c.CHECKS and r in h.DISPATCH and r in agentcall.GUEST_RUNBOOKS
        assert r in firstboot.RUNBOOKS
        # enabled at first boot only on the identity VM (slapd allowlisted), never on every configured VM
        assert r in cloudinit.DIRECTORY_CFG and r not in cloudinit.CFG_RUNBOOKS


# ---------------------------------------------------------------- schemas
def _chk(action, p):
    return c.CHECKS[action](p, {"enabled": True})


def test_valid_params_pass_unchanged():
    for action, p in (("cfg.ldap_list", {"domain": D}),
                      ("cfg.ldap_groups", {"domain": D, "uid": "jane.doe", "add": ["mail-users", "opencloudUser"], "remove": ["org-admin"]}),
                      ("cfg.ldap_groups", {"domain": D, "uid": "jane", "add": [], "remove": []}),
                      ("cfg.ldap_lock", {"domain": D, "uid": "jane", "locked": True}),
                      ("cfg.ldap_lock", {"domain": D, "uid": "jane", "locked": False}),
                      ("cfg.ldap_delete", {"domain": D, "uid": "jane"})):
        assert _chk(action, dict(p)) == p


@pytest.mark.parametrize("action,p", [
    ("cfg.ldap_list", {"domain": D, "filter": "(uid=*)"}),
    ("cfg.ldap_list", {}),
    ("cfg.ldap_list", {"domain": "dc=x)(uid=*"}),
    ("cfg.ldap_groups", {"domain": D, "uid": "a)(uid=*", "add": [], "remove": []}),
    ("cfg.ldap_groups", {"domain": D, "uid": "jane", "add": ["mail users"], "remove": []}),
    ("cfg.ldap_groups", {"domain": D, "uid": "jane", "add": [], "remove": ["x,ou=groups"]}),
    ("cfg.ldap_groups", {"domain": D, "uid": "jane", "add": [f"g{i:02d}" for i in range(c.MAX_GROUPS + 1)], "remove": []}),
    ("cfg.ldap_groups", {"domain": D, "uid": "jane", "add": ["mail-users", "mail-users"], "remove": []}),
    ("cfg.ldap_groups", {"domain": D, "uid": "jane", "add": ["mail-users"], "remove": ["mail-users"]}),
    ("cfg.ldap_groups", {"domain": D, "uid": "jane", "add": "mail-users", "remove": []}),
    ("cfg.ldap_groups", {"domain": D, "uid": "jane", "add": []}),
    ("cfg.ldap_lock", {"domain": D, "uid": "jane", "locked": 1}),
    ("cfg.ldap_lock", {"domain": D, "uid": "jane", "locked": "true"}),
    ("cfg.ldap_lock", {"domain": D, "uid": "jane", "locked": True, "until": "x"}),
    ("cfg.ldap_lock", {"domain": D, "uid": "Jane\nuid: x", "locked": True}),
    ("cfg.ldap_delete", {"domain": D, "uid": "ou-admin"}),
    ("cfg.ldap_delete", {"domain": D, "uid": "*"}),
    ("cfg.ldap_delete", {"domain": D, "uid": "jane", "force": True}),
])
def test_refusals(action, p):
    with pytest.raises(Reject):
        _chk(action, p)


# ---------------------------------------------------------------- the helper against an in-memory directory
class Dir:
    """dn -> {attr: [values]}; answers the helper's ldapsearch argv and applies its ldapmodify LDIF (add/delete/replace, delete entry)."""

    def __init__(self):
        self.e = {}
        self.ldif = []

    def person(self, uid, display="", locked=None, extra=None):
        a = {"objectClass": ["inetOrgPerson"], "uid": [uid], "mail": [f"{uid}@{D}"], "cn": [uid], "sn": ["Doe"], "givenName": [uid.capitalize()],
             "userPassword": ["{SSHA}c2VjcmV0c2VjcmV0"]}
        if display:
            a["displayName"] = [display]
        if locked:
            a["pwdAccountLockedTime"] = [locked]
        a.update(extra or {})
        self.e[P(uid)] = a

    def group(self, cn, *uids):
        self.e[G(cn)] = {"objectClass": ["groupOfNames"], "cn": [cn], "member": [BIND, *(P(u) for u in uids)]}

    def members(self, cn):
        return self.e[G(cn)]["member"]

    @staticmethod
    def _val(k, v):
        if any(ord(ch) > 127 for ch in v) or k == "userPassword":
            return f"{k}:: {base64.b64encode(v.encode()).decode()}"
        return f"{k}: {v}"

    def search(self, argv):
        base, scope = argv[argv.index("-b") + 1], argv[argv.index("-s") + 1]
        i = argv.index("-b") + 2
        if argv[i] == "-z":
            i += 2
        flt, attrs = argv[i], argv[i + 1:]
        oc = flt[len("(objectClass="):-1]
        if scope == "base":
            hits = [base] if base in self.e else []
        else:
            hits = [dn for dn in self.e if dn.partition(",")[2] == base]
            if not hits and base not in self.e:
                return subprocess.CompletedProcess(argv, 32, "", "No such object")
        hits = [dn for dn in hits if oc == "*" or oc in self.e[dn]["objectClass"]]
        out = []
        for dn in hits:
            lines = [f"dn: {dn}"]
            for k, vs in self.e[dn].items():
                if "1.1" in attrs or (attrs and k not in attrs):
                    continue
                lines += [self._val(k, v) for v in vs]
            out.append("\n".join(lines) + "\n")
        return subprocess.CompletedProcess(argv, 0, "\n".join(out), "")

    def modify(self, ldif):
        self.ldif.append(ldif)
        lines = ldif.strip("\n").split("\n")
        dn = lines[0][len("dn: "):]
        assert lines[1].startswith("changetype: ")
        if lines[1] == "changetype: delete":
            del self.e[dn]
            return
        assert dn in self.e, dn
        ent, i = self.e[dn], 2
        while i < len(lines):
            op, attr = lines[i].split(": ")
            vals = []
            i += 1
            while i < len(lines) and lines[i] != "-":
                vals.append(lines[i].split(": ", 1)[1])
                i += 1
            i += 1
            if op == "add":
                assert not set(vals) & set(ent.get(attr, [])), "adding a value already present"
                ent.setdefault(attr, []).extend(vals)
            elif op == "replace":
                ent[attr] = vals
            elif op == "delete":
                assert attr in ent and all(v in ent[attr] for v in vals), "deleting an absent value"
                ent[attr] = [v for v in ent[attr] if v not in vals] if vals else []
                if not ent[attr]:
                    del ent[attr]

    def run(self, ctx, argv, input=None, env=None, timeout=300, check=True, what=None):
        if argv[0] == h.BIN["ldapsearch"]:
            assert argv[1:9] == ["-LLL", "-o", "ldif-wrap=no", "-Q", "-Y", "EXTERNAL", "-H", "ldapi:///"]
            return self.search(argv)
        assert argv == [h.BIN["ldapmodify"], "-Q", "-Y", "EXTERNAL", "-H", "ldapi:///"], argv
        self.modify(input)
        return subprocess.CompletedProcess(argv, 0, "", "")


@pytest.fixture()
def d(monkeypatch):
    dd = Dir()
    for o in ("people", "groups"):
        dd.e[f"ou={o},{B}"] = {"objectClass": ["organizationalUnit"], "ou": [o]}
    monkeypatch.setattr(h.Ctx, "run", lambda self, *a, **k: dd.run(self, *a, **k))
    return dd


def _run(action, params):
    return h.handle({"action": action, "params": params}, {"runbooks": {action: {"enabled": True}}})


def test_ldap_list_parses_people_and_groups_and_never_returns_a_password(d):
    d.person("ou-admin", "Office Unbound Administrator")
    d.person("jane", "Jäne Dœ", locked="000001010000Z")   # non-ASCII: the directory answers it base64 (`::`)
    d.person("bob")
    d.group("org-admin", "ou-admin")
    d.group("mail-users", "ou-admin", "jane")
    r = _run("cfg.ldap_list", {"domain": D})
    assert r["suffix"] == B and r["truncated"] is False
    people = {p["uid"]: p for p in r["people"]}
    assert people["jane"] == {"uid": "jane", "mail": f"jane@{D}", "display_name": "Jäne Dœ", "given_name": "Jane", "surname": "Doe",
                              "groups": ["mail-users"], "locked": True}
    assert people["bob"]["display_name"] == "bob" and people["bob"]["groups"] == [] and people["bob"]["locked"] is False
    assert people["ou-admin"]["groups"] == ["mail-users", "org-admin"]
    assert r["groups"] == [{"cn": "mail-users", "members": ["jane", "ou-admin"]}, {"cn": "org-admin", "members": ["ou-admin"]}]
    blob = repr(r).lower()
    assert "password" not in blob and "ssha" not in blob and "c2vjcmv0" not in blob
    assert d.ldif == []   # read-only


def test_ldif_parser_folds_lines_decodes_base64_and_drops_password_attributes():
    text = ("# comment\ndn: uid=jane,ou=people," + B + "\nuid: jane\ndisplayName:: " + base64.b64encode("Jäne".encode()).decode() + "\n"
            "description: a long\n  folded value\nuserPassword:: e1NTSEF9eHh4\npwdHistory: x\ncn;lang-de: Johanna\njpegPhoto:< file:///x\n\n"
            "dn:: " + base64.b64encode(f"cn=grüppe,ou=groups,{B}".encode()).decode() + "\nmember: " + P("jane") + "\n")
    e = h.ldif_entries(text)
    assert e[0] == (P("jane"), {"uid": ["jane"], "displayname": ["Jäne"], "description": ["a long folded value"], "cn": ["Johanna"]})
    assert e[1] == (f"cn=grüppe,ou=groups,{B}", {"member": [P("jane")]})


def test_ldap_list_searches_are_fixed_and_capped(d, monkeypatch):
    seen = []
    orig = d.search
    monkeypatch.setattr(d, "search", lambda argv: seen.append(argv) or orig(argv))
    _run("cfg.ldap_list", {"domain": D})
    assert [a[a.index("-b") + 1:] for a in seen] == [
        [f"ou=groups,{B}", "-z", "2000", "(objectClass=groupOfNames)", "cn", "member"],
        [f"ou=people,{B}", "-z", "2000", "(objectClass=inetOrgPerson)", *h.PEOPLE_ATTRS]]
    assert not any("userPassword" in a for a in seen)


def test_ldap_list_stays_within_the_result_budget(d):
    for i in range(600):
        d.person(f"user{i:04d}", "Some Rather Long Display Name Here")
    d.group("mail-users", *[f"user{i:04d}" for i in range(600)])
    r = _run("cfg.ldap_list", {"domain": D})
    assert r["truncated"] is True and len(json.dumps(r)) <= h.LIST_BUDGET and r["people"]


def test_ldap_groups_adds_and_removes_with_exact_ldif_and_is_idempotent(d):
    d.person("ou-admin")
    d.person("jane")
    d.group("org-admin", "ou-admin", "jane")
    d.group("mail-users")
    d.group("opencloudUser", "jane")
    r = _run("cfg.ldap_groups", {"domain": D, "uid": "jane", "add": ["mail-users", "opencloudUser"], "remove": ["org-admin"]})
    assert r == {"uid": "jane", "added": ["mail-users"], "removed": ["org-admin"]}
    assert d.ldif == [f"dn: {G('mail-users')}\nchangetype: modify\nadd: member\nmember: {P('jane')}\n",
                      f"dn: {G('org-admin')}\nchangetype: modify\ndelete: member\nmember: {P('jane')}\n"]
    d.ldif.clear()
    r = _run("cfg.ldap_groups", {"domain": D, "uid": "jane", "add": ["mail-users"], "remove": ["org-admin"]})
    assert r == {"uid": "jane", "added": [], "removed": []} and d.ldif == []


def test_ldap_groups_refuses_unknown_groups_and_persons_before_changing_anything(d):
    d.person("jane")
    d.group("mail-users")
    with pytest.raises(h.Failed, match="unknown group: nope"):
        _run("cfg.ldap_groups", {"domain": D, "uid": "jane", "add": ["mail-users", "nope"], "remove": []})
    with pytest.raises(h.Failed, match="does not exist"):
        _run("cfg.ldap_groups", {"domain": D, "uid": "ghost", "add": ["mail-users"], "remove": []})
    assert d.ldif == []


def test_ldap_groups_keeps_the_last_org_admin(d):
    d.person("ou-admin")
    d.group("org-admin", "ou-admin")
    with pytest.raises(h.Failed, match="last member of org-admin"):
        _run("cfg.ldap_groups", {"domain": D, "uid": "ou-admin", "add": [], "remove": ["org-admin"]})
    assert d.ldif == []


def test_ldap_lock_uses_ppolicy_and_never_touches_the_password(d):
    d.person("jane")
    pw = list(d.e[P("jane")]["userPassword"])
    assert _run("cfg.ldap_lock", {"domain": D, "uid": "jane", "locked": True}) == {"uid": "jane", "locked": True, "changed": True}
    assert d.ldif == [f"dn: {P('jane')}\nchangetype: modify\nreplace: pwdAccountLockedTime\npwdAccountLockedTime: 000001010000Z\n"]
    assert _run("cfg.ldap_lock", {"domain": D, "uid": "jane", "locked": True})["changed"] is False
    assert _run("cfg.ldap_lock", {"domain": D, "uid": "jane", "locked": False}) == {"uid": "jane", "locked": False, "changed": True}
    assert d.ldif[-1] == f"dn: {P('jane')}\nchangetype: modify\ndelete: pwdAccountLockedTime\n"
    assert _run("cfg.ldap_lock", {"domain": D, "uid": "jane", "locked": False})["changed"] is False
    assert d.e[P("jane")]["userPassword"] == pw and len(d.ldif) == 2
    assert not any("userPassword" in x for x in d.ldif)
    with pytest.raises(h.Failed, match="does not exist"):
        _run("cfg.ldap_lock", {"domain": D, "uid": "ghost", "locked": True})


def test_ldap_lock_turns_a_failure_lockout_into_the_administrative_lock(d):
    d.person("jane", locked="20261120101010Z")
    assert _run("cfg.ldap_lock", {"domain": D, "uid": "jane", "locked": True})["changed"] is True
    assert d.e[P("jane")]["pwdAccountLockedTime"] == ["000001010000Z"]


def test_ldap_delete_removes_memberships_before_the_entry(d):
    d.person("ou-admin")
    d.person("jane")
    d.group("org-admin", "ou-admin", "jane")
    d.group("mail-users", "jane")
    d.group("opencloudUser", "ou-admin")
    r = _run("cfg.ldap_delete", {"domain": D, "uid": "jane"})
    assert r == {"uid": "jane", "deleted": True, "groups_removed": ["mail-users", "org-admin"]}
    assert d.ldif == [f"dn: {G('mail-users')}\nchangetype: modify\ndelete: member\nmember: {P('jane')}\n",
                      f"dn: {G('org-admin')}\nchangetype: modify\ndelete: member\nmember: {P('jane')}\n",
                      f"dn: {P('jane')}\nchangetype: delete\n"]
    assert P("jane") not in d.e and d.members("mail-users") == [BIND] and d.members("org-admin") == [BIND, P("ou-admin")]
    assert _run("cfg.ldap_delete", {"domain": D, "uid": "jane"}) == {"uid": "jane", "deleted": False, "groups_removed": []}


def test_ldap_delete_a_sole_member_keeps_the_group_valid(d):
    d.person("jane")
    d.e[G("solo")] = {"objectClass": ["groupOfNames"], "cn": ["solo"], "member": [P("jane")]}   # groupOfNames needs a member
    _run("cfg.ldap_delete", {"domain": D, "uid": "jane"})
    assert d.ldif[0] == f"dn: {G('solo')}\nchangetype: modify\nreplace: member\nmember: {BIND}\n" and d.members("solo") == [BIND]


def test_ldap_delete_refuses_the_last_org_admin_and_ou_admin(d, monkeypatch):
    d.person("ou-admin")
    d.person("boss")
    d.group("org-admin", "boss")
    with pytest.raises(h.Failed, match="last member of org-admin"):
        _run("cfg.ldap_delete", {"domain": D, "uid": "boss"})
    with pytest.raises(Reject):
        _run("cfg.ldap_delete", {"domain": D, "uid": "ou-admin"})
    with pytest.raises(h.Failed, match="cannot be deleted"):   # the helper's own guard, should a spool skip the schema
        h.ldap_delete({"domain": D, "uid": "ou-admin"}, h.Ctx({}))
    assert d.ldif == [] and P("boss") in d.e
