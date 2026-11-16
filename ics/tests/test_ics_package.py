"""ou-ics package (ADR-0008/0011): static guarantees of the recipe, maintainer scripts and build metadata. The behavioural proof (install, upgrade,
rollback in fresh machines) is docs/status/ics-package-results.md; these tests keep the properties it relies on from regressing."""
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "blueprints" / "build"
DEB = BUILD / "ics" / "debian"
DEPLOY = ROOT / "ics" / "deploy"


def _recipe_mod():
    spec = importlib.util.spec_from_file_location("ou_recipe_under_test", BUILD / "lib" / "recipe.py")
    src = (BUILD / "lib" / "recipe.py").read_text().rsplit("\nmain()", 1)[0]   # import without running main()
    mod = importlib.util.module_from_spec(spec)
    mod.__dict__["__file__"] = str(BUILD / "lib" / "recipe.py")
    exec(compile(src, "recipe.py", "exec"), mod.__dict__)
    return mod


@pytest.mark.parametrize("tag,deb", [("v0.1.0", "0.1.0"), ("v0.2.3", "0.2.3"), ("v0.1.1-dev.1", "0.1.1~dev.1"), ("0.3.0-rc.2", "0.3.0~rc.2")])
def test_debian_version_from_tag(tag, deb):
    assert _recipe_mod().deb_version_from_tag(tag) == deb


@pytest.mark.parametrize("tag", ["main", "v1", "v1.2", "v1.2.3.4", "v1.2.3-", "latest"])
def test_bad_tags_are_refused(tag):
    with pytest.raises(SystemExit):
        _recipe_mod().deb_version_from_tag(tag)


def test_prerelease_sorts_before_release():
    r = subprocess.run(["dpkg", "--compare-versions", "0.1.1~dev.1-ou1", "lt", "0.1.1-ou1"])
    r2 = subprocess.run(["dpkg", "--compare-versions", "0.1.1~dev.1-ou1", "gt", "0.1.0-ou1"])
    assert r.returncode == 0 and r2.returncode == 0


def test_recipe_is_dynamic_and_keeps_versions():
    r = yaml.safe_load((BUILD / "ics" / "recipe.yaml").read_text())
    assert r["source"]["dynamic"] is True and r["packages"] == ["ou-ics"] and r["keep_versions"] is True
    assert "fetch-wheels.sh" in r["prefetch"]


def test_lock_is_fully_hashed_and_covers_both_pythons():
    lock = (ROOT / "ics" / "requirements.lock").read_text()
    pins = re.findall(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)", lock, re.M)
    assert len(pins) > 20
    blocks = re.split(r"\n(?=[A-Za-z0-9_.-]+==)", lock)
    for b in blocks:
        if re.match(r"[A-Za-z0-9_.-]+==", b):
            assert "--hash=sha256:" in b, b.split("\n")[0]
    fw = (DEB / "fetch-wheels.sh").read_text()
    assert "--require-hashes" in fw and "--only-binary=:all:" in fw and "cp311" in fw and "cp312" in fw


def test_rules_never_rewrite_wheels_and_ship_the_pieces():
    rules = (DEB / "rules").read_text()
    assert re.search(r"^override_dh_strip_nondeterminism:\s*$", rules, re.M)      # empty override: wheel hashes must survive
    for needle in ("ou-ics-setup", "ou-ics-preupgrade-backup", "ou-ics-rollback", "ics-backup.sh", "write_build_info.py", "ics-tuning.env", "sysusers", "tmpfiles",
                   "blueprints/catalog", "wheels"):
        assert needle in rules, needle
    assert (DEB / "ics-tuning.env").is_file()


@pytest.mark.parametrize("script", ["ou-ics.preinst", "ou-ics.postinst", "ou-ics.prerm", "ou-ics.postrm"])
def test_maintainer_scripts_parse(script):
    assert subprocess.run(["bash", "-n", str(DEB / script)]).returncode == 0


@pytest.mark.parametrize("script", ["ou-ics-setup", "ou-ics-preupgrade-backup", "ou-ics-rollback"])
def test_pkg_helpers_parse(script):
    assert subprocess.run(["bash", "-n", str(DEPLOY / "pkg" / script)]).returncode == 0


def test_postinst_order_is_the_contract():
    t = (DEB / "ou-ics.postinst").read_text()
    order = ['"$LIB/ou-ics-setup"', "--no-index --find-links", "which this version does not know", '"$LIB/ou-ics-preupgrade-backup" "configure"', "-m ics.migrate",
             "systemctl restart ics-migrate.service ics.service"]
    pos = []
    for n in order:
        assert n in t, n
        pos.append(t.index(n))
    assert pos == sorted(pos), "provision -> offline venv -> schema check -> backup gate -> migrate -> start"
    assert "--require-hashes" in t and "bin/pip" in t and "install -q --no-index" in t and "--index-url" not in t
    # a failing backup or migration must stop the configure step
    assert re.search(r"ou-ics-preupgrade-backup\" \"configure\" \|\| fail", t) and re.search(r"ics\.migrate \) \\\n\s+\|\| fail", t)


def test_preinst_backs_up_before_unpack_and_prerm_is_safe():
    pre = (DEB / "ou-ics.preinst").read_text()
    assert "ou-ics-preupgrade-backup" in pre and "exit 1" in pre and "upgrade-preflight" in pre
    prerm = (DEB / "ou-ics.prerm").read_text()
    assert "upgrade|failed-upgrade) ;;" in prerm and prerm.rstrip().endswith("exit 0")
    assert "dropdb" not in prerm and "DROP" not in prerm
    postrm = (DEB / "ou-ics.postrm").read_text()
    assert "DROP" not in postrm and "dropdb" not in postrm
    assert not re.search(r"\brm\b[^\n]*(/etc|/var/backups|/var/lib/office-unbound|postgresql)", postrm)


def test_setup_never_overwrites_keys():
    t = (DEPLOY / "pkg" / "ou-ics-setup").read_text()
    assert "O_EXCL" in t and "Not touching it" in t and "database 'ics' already holds data" in t


def test_units_load_the_conffile_and_stay_hardened():
    u = (DEPLOY / "ics.service").read_text()
    assert "EnvironmentFile=-/etc/office-unbound/ics-tuning.env" in u and "NoNewPrivileges=true" in u and "ReadOnlyPaths=/opt/office-unbound /etc/office-unbound" in u


def test_build_info_records_the_pinned_commit_and_package(tmp_path):
    root = tmp_path / "src"
    (root / "ics" / "migrations" / "versions").mkdir(parents=True)
    (root / "ics" / "migrations" / "versions" / "0001_x.py").write_text('revision = "0001"\ndown_revision = None\n')
    (root / "VERSION").write_text("1.2.3\n")
    (root / ".ou-source-commit").write_text("0123456789abcdef0123456789abcdef01234567\n")
    out = tmp_path / "BUILD_INFO.json"
    env = {"PATH": "/usr/bin:/bin", "SOURCE_DATE_EPOCH": "1700000000", "OU_PACKAGE_VERSION": "1.2.3-ou1", "GIT_CEILING_DIRECTORIES": str(tmp_path)}
    subprocess.run([sys.executable, str(DEPLOY / "write_build_info.py"), str(root), str(out)], check=True, env=env)
    d = json.loads(out.read_text())
    assert d["commit"] == "0123456789abcdef0123456789abcdef01234567" and d["dirty"] is False
    assert d["package"] == "ou-ics 1.2.3-ou1" and d["built_at"] == "2023-11-14T22:13:20Z" and d["schema_head"] == "0001"


def test_bootstrap_from_repo_pins_the_key():
    t = (DEPLOY / "bootstrap.sh").read_text()
    assert "--from-repo" in t and "signed-by=" in t and "refusing to trust it" in t and "REPO_FPR" in t
    assert subprocess.run(["bash", "-n", str(DEPLOY / "bootstrap.sh")]).returncode == 0
