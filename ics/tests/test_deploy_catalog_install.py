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
