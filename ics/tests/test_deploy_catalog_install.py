"""Regression (production, 2026-11-15): install.sh must ship the deployment catalog where ics.deploy.catalog reads it;
otherwise /api/v1/catalog/* returns 500 on an installed ICS even though tests (run from the checkout) pass."""
import pathlib, re

ROOT = pathlib.Path(__file__).resolve().parents[2]


def test_install_script_installs_catalog_to_the_runtime_path():
    s = (ROOT / "ics" / "deploy" / "install.sh").read_text()
    assert "blueprints/catalog" in s and "/opt/office-unbound/blueprints/catalog" in s


def test_runtime_catalog_path_matches_install_destination():
    src = (ROOT / "ics" / "ics" / "deploy" / "catalog.py").read_text()
    # the default resolution is relative to the installed package: /opt/office-unbound/ics/ics/deploy -> /opt/office-unbound/blueprints/catalog
    assert "OU_CATALOG_DIR" in src
    assert (ROOT / "blueprints" / "catalog").is_dir() and any((ROOT / "blueprints" / "catalog").glob("*.yaml"))


def test_the_opencloud_health_check_matches_the_real_status_response():
    # real VM e2e-fo4 (2026-11-19): OpenCloud 9.1.0 answers `"installed": true` (pretty-printed); the catalog looked for `"installed":true`
    # and the deployment failed health verification with "HTTP 200 (expected text missing)". Body recorded from the lab ou-files1 (9.1.0).
    import pathlib
    from ics.deploy.catalog import get_catalog
    body = (pathlib.Path(__file__).parent / "fixtures" / "opencloud-9.1.0-status.php.json").read_text()
    hc = next(h for h in get_catalog().components["files"].health_checks if h.name == "opencloud-status")
    assert hc.path == "/status.php" and hc.body_contains in body
