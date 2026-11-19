"""cfg.gromox, the groupware node configuration (agent/ou_agent/cfghelper.py `gromox`), and its ICS side (deploy/configure.py
`groupware_runbooks`, guest/cloudinit.py `GROUPWARE_CFG`).

The runbook itself runs real programs against fixed system paths; its end-to-end proof is the lab run on Ubuntu 24.04 with the noble
packages (docs/status/groupware-deploy-results.md: 13/13 functional checks, reboot, idempotent re-run) and the real-VM deployment.
These tests pin the security-relevant parts: the closed schema, no secret on a command line, SQL quoting of directory-supplied values,
least-privilege enablement and audit redaction."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
from ou_agent import cfghelper as h  # noqa: E402
from ou_agent import cfgspec as c  # noqa: E402
from ou_agent import firstboot  # noqa: E402
from ou_agent.proto import Reject  # noqa: E402

from ics.deploy import configure  # noqa: E402
from ics.guest import cloudinit as ci  # noqa: E402

PW = "Abcdefghijklmnop_qrstuv-0123456789"
PW2 = "ZyxwvutsrqponmlkjI-0987654321_abc"
OK = {"domain": "e2e.example", "hostname": "mail.e2e.example", "tls_name": "deployment", "db_password": PW, "ldap_host": "ldap.e2e.example",
      "bind_password": PW2, "group": "mail-users", "mailboxes": ["ou-admin@e2e.example"]}


def test_a_valid_request_passes_unchanged():
    assert c.check_gromox(dict(OK), {"enabled": True}) == OK


@pytest.mark.parametrize("change", [
    {"mailboxes": ["ou-admin@other.example"]},                 # a mailbox outside the deployment's mail domain
    {"mailboxes": ["a'b@e2e.example"]},                        # quote in the local part (SQL)
    {"mailboxes": ["x)(mail=*@e2e.example"]},                  # LDAP filter injection
    {"mailboxes": ["ou-admin@e2e.example", "ou-admin@e2e.example"]},
    {"mailboxes": [f"u{i}@e2e.example" for i in range(c.MAX_MAILBOXES + 1)]},
    {"hostname": "mail.evil.example"},                         # a host name outside the domain
    {"ldap_host": "ldap.evil.example"},                        # the directory of another deployment
    {"db_password": "short"},
    {"db_password": PW + "'"},
    {"bind_password": PW + "\nldap_host=ldaps://evil"},        # a line injected into ldap_adaptor.cfg
    {"group": "mail users"},
    {"extra": 1},
])
def test_the_closed_schema_refuses(change):
    with pytest.raises(Reject):
        c.check_gromox({**OK, **change}, {"enabled": True})


def test_the_agent_knows_the_runbook_and_scrubs_the_database_password():
    assert "cfg.gromox" in c.CFG_RUNBOOKS and "cfg.gromox" in firstboot.RUNBOOKS and h.DISPATCH["cfg.gromox"] is h.gromox
    x = h.Ctx(dict(OK))
    assert x.scrub(f"mysql: access denied for {PW} and {PW2}") == "mysql: access denied for *** and ***"


def test_sql_quoting_of_directory_values():
    assert h._q("O'Brien \\ x") == "'O''Brien \\\\ x'"


def test_the_directory_bind_password_never_reaches_a_command_line(tmp_path, monkeypatch):
    seen = {}

    def run(argv, input=None, env=None, timeout=300, check=True, what=None):
        seen["argv"], seen["env"] = list(argv), dict(env or {})
        pwfile = argv[argv.index("-y") + 1]
        seen["file"] = (open(pwfile).read(), oct(os.stat(pwfile).st_mode & 0o777))
        out = ("dn: uid=ou-admin,ou=people,dc=e2e,dc=example\nentryUUID: 0a1b2c3d-0000-4000-8000-00000000abcd\n"
               "displayName:: " + __import__("base64").b64encode("Zoë Admin".encode()).decode() + "\n"
               "memberOf: cn=mail-users,ou=groups,dc=e2e,dc=example\n")
        return type("R", (), {"stdout": out, "returncode": 0})()

    monkeypatch.setattr(h, "RESULT_DIR", str(tmp_path))
    x = h.Ctx(dict(OK))
    monkeypatch.setattr(x, "run", run)
    who = h._ldap_people(x, OK, "dc=e2e,dc=example", "ou-admin@e2e.example")
    assert who == {"uuid": "0a1b2c3d-0000-4000-8000-00000000abcd", "name": "Zoë Admin", "groups": {"cn=mail-users,ou=groups,dc=e2e,dc=example"}}
    assert PW2 not in " ".join(seen["argv"]) and seen["file"] == (PW2, "0o600")
    assert seen["env"]["LDAPTLS_REQCERT"] == "demand" and seen["env"]["LDAPTLS_CACERT"].endswith("/ca.crt")
    assert "ldaps://ldap.e2e.example" in seen["argv"] and "-x" in seen["argv"]
    assert os.listdir(tmp_path) == []                                   # the password file is gone


def _plan():
    return {"input": {"domain": "e2e.example"},
            "vms": [{"name": "id", "components": ["identity", "edge"]}, {"name": "gw", "components": ["groupware"]}],
            "dns": [{"name": "auth.e2e.example", "type": "A", "value": "vm:id"}, {"name": "mail.e2e.example", "type": "A", "value": "vm:gw"},
                    {"name": "autodiscover.e2e.example", "type": "CNAME", "value": "mail.e2e.example"}],
            "firewall": [{"vm": "id", "from": "gw", "proto": "tcp", "port": 636}]}


class _Agent:
    def address(self, vm):
        return {"id": "10.0.0.10", "gw": "10.0.0.11"}[vm]


def test_groupware_runbooks_carry_the_deployment_values(monkeypatch):
    secrets = {}
    monkeypatch.setattr(configure, "secret", lambda rt, dep, name, make=None: secrets.setdefault(name, f"{name}-" + "x" * 20))
    monkeypatch.setattr(configure, "_tls", lambda ctx, vm, domain, names: {"runbook": "cfg.tls", "params": {"names": names.get(vm)}})
    ctx = type("Ctx", (), {"deployment_id": "d1", "rt": None, "slug": "e2e", "plan": _plan(), "env": type("E", (), {"agent": _Agent()})()})()
    rb = configure.groupware_runbooks(ctx, "gw")
    assert [r["runbook"] for r in rb] == ["cfg.hosts", "cfg.firewall", "cfg.tls", "cfg.gromox"]
    g = rb[-1]["params"]
    assert c.check_gromox(g, {"enabled": True}) == g                    # what the ICS sends is what the agent accepts
    assert g["hostname"] == "mail.e2e.example" and g["ldap_host"] == "ldap.e2e.example" and g["mailboxes"] == ["ou-admin@e2e.example"]
    assert g["bind_password"] == secrets["ldap-bind-password"] and g["db_password"] == secrets["gw-db-password"]
    assert rb[2]["params"]["names"] == ["autodiscover.e2e.example", "mail.e2e.example"]
    assert configure.BUILDERS["groupware"] is configure.groupware_runbooks and "groupware" in configure.CONFIGURED
    red = json.dumps(configure.redact("cfg.gromox", g))
    assert secrets["ldap-bind-password"] not in red and secrets["gw-db-password"] not in red


def test_cfg_gromox_is_enabled_only_where_the_groupware_may_be_installed():
    from tests.test_guest_bootstrap import spec
    gw = ci.agent_config(spec(configure=True, pkg_allowlist=["ou-gromox", "postfix"],
                              ou_repo={**ci.OU_REPO_PLACEHOLDER, "key_armored": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nxx\n-----END PGP PUBLIC KEY BLOCK-----"}))
    other = ci.agent_config(spec(configure=True, pkg_allowlist=["nginx"],
                                 ou_repo={**ci.OU_REPO_PLACEHOLDER, "key_armored": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nxx\n-----END PGP PUBLIC KEY BLOCK-----"}))
    assert gw["runbooks"]["cfg.gromox"] == {"enabled": True} and "cfg.ldap_init" in gw["runbooks"]
    # a VM without groupware never enables it, so it still boots from an image whose agent predates cfg.gromox (first boot refuses unknown runbooks)
    assert "cfg.gromox" not in other["runbooks"] and "cfg.ldap_init" in other["runbooks"]
