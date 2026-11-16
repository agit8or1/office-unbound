"""ics.cli upgrade-preflight: decision logic (pure), fact gathering against the test database, and the CLI exit code."""
import json
import time
from pathlib import Path

from ics import cli, upgrade
from ics.upgrade import Facts, evaluate, verdict

GB = 1024 ** 3


def good(**kw) -> Facts:
    f = Facts(db_size_bytes=50 * 1024 ** 2, free_backup_bytes=10 * GB, free_opt_bytes=10 * GB, last_backup_epoch=time.time() - 600,
              db_head="0010", code_heads=["0010"], code_revisions={"0009", "0010"})
    for k, v in kw.items():
        setattr(f, k, v)
    return f


def levels(f, **kw):
    return {c.name: c.level for c in evaluate(f, **kw)}


def test_all_good_is_ready():
    cs = evaluate(good())
    assert verdict(cs) == 0
    assert all(c.level == "OK" for c in cs)


def test_disk_space_blocks():
    assert levels(good(free_backup_bytes=100 * 1024 ** 2))["disk.backup"] == "FAIL"
    assert levels(good(db_size_bytes=4 * GB, free_backup_bytes=8 * GB))["disk.backup"] == "FAIL"   # needs 3x
    assert levels(good(free_opt_bytes=10 * 1024 ** 2))["disk.opt"] == "FAIL"
    assert verdict(evaluate(good(free_backup_bytes=1))) == 1


def test_backup_freshness_only_warns():
    assert levels(good(last_backup_epoch=None))["backup"] == "WARN"
    assert levels(good(last_backup_epoch=time.time() - 3 * 86400))["backup"] == "WARN"
    assert levels(good(last_backup_epoch=time.time() - 3 * 86400), max_backup_age_s=10 * 86400)["backup"] == "OK"
    assert verdict(evaluate(good(last_backup_epoch=None))) == 0       # the package takes its own backup


def test_running_jobs_block_queued_warn():
    assert levels(good(running_jobs=1))["jobs.running"] == "FAIL"
    assert levels(good(running_deployments=2))["jobs.running"] == "FAIL"
    assert levels(good(queued_jobs=3))["jobs.queued"] == "WARN"
    assert verdict(evaluate(good(queued_jobs=3))) == 0


def test_standby_is_reported():
    assert levels(good(worker_enabled=False))["standby"] == "WARN"
    assert levels(good(monitor_enabled=False))["standby"] == "WARN"
    assert levels(good())["standby"] == "OK"


def test_schema_states():
    assert levels(good(db_head="0009"))["schema"] == "INFO"          # behind: migrations will run
    cs = evaluate(good(db_head="9999"))                              # ahead of the code: only the restore path is safe
    assert {c.name: c.level for c in cs}["schema"] == "FAIL" and verdict(cs) == 1


def test_database_unreadable_blocks():
    assert levels(good(db_ok=False))["database"] == "FAIL"


def test_newest_backup_reads_manifests(tmp_path):
    for ts, head in (("20260101T000000Z", "0008"), ("20260301T120000Z", "0010")):
        d = tmp_path / ts
        d.mkdir()
        (d / "MANIFEST").write_text(f"created_utc={ts}\nalembic_head={head}\n")
        (d / "ics-backup.tar").write_bytes(b"x")
    broken = tmp_path / "20260901T000000Z"      # newer but without its archive: ignored
    broken.mkdir()
    (broken / "MANIFEST").write_text("created_utc=20260901T000000Z\n")
    (tmp_path / "junk").mkdir()
    ts, head = upgrade._newest_backup(str(tmp_path))
    assert head == "0010" and time.strftime("%Y%m%d", time.gmtime(ts)) == "20260301"
    assert upgrade._newest_backup(str(tmp_path / "missing")) == (None, None)


def test_code_revisions_from_tree():
    heads, revs = upgrade._code_revisions(Path(upgrade.__file__).resolve().parent.parent / "migrations" / "versions")
    assert len(heads) == 1 and heads[0] in revs and "0001" in revs


def test_gather_against_database(rt, tmp_path):
    with rt.session() as db:
        f = upgrade.gather(db, rt.settings, backup_dir=str(tmp_path / "bk"), opt_dir=str(tmp_path))
        assert f.db_ok and f.db_size_bytes > 0 and f.code_heads
        assert f.running_jobs == 0 and f.queued_jobs == 0 and f.last_backup_epoch is None
        assert verdict(evaluate(f)) == 0


def test_cli_exit_code_and_json(rt, monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(cli, "Runtime", lambda: rt)
    assert cli.main(["upgrade-preflight", "--backup-dir", str(tmp_path / "bk"), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ready"] is True and {c["name"] for c in out["checks"]} >= {"database", "disk.backup", "schema", "standby"}
    monkeypatch.setattr(upgrade, "gather", lambda *a, **k: good(running_jobs=2))
    assert cli.main(["upgrade-preflight", "--backup-dir", str(tmp_path)]) == 1
    assert "NOT READY" in capsys.readouterr().out
