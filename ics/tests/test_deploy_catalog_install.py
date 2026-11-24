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


def test_every_catalog_unit_uses_host_networking():
    # real VM e2e-fo5 (2026-11-19, Ubuntu 24.04 podman 4.9.3): the first unit on a private podman network (Collabora) failed to start with
    # "failed to mount runtime directory for rootless netns: no such file or directory"; the host-network units (Keycloak, OpenCloud, collaboration)
    # run. Until a private network is proven on a real VM, every catalog unit uses host networking behind the guest firewall's default drop.
    from ics.deploy.catalog import get_catalog
    units = [(c.name, a.name, a.unit.type) for c in get_catalog().components.values() for a in c.artifacts if getattr(a, "unit", None)]
    assert units and all(t == "container-hostnet" for _, _, t in units), [u for u in units if u[2] != "container-hostnet"]


def test_only_the_document_engine_gets_sys_chroot_and_the_plan_carries_it():
    # real VM e2e-fo6 (2026-11-19): Collabora under DropCapability=ALL cannot chroot its document processes (EPERM), so coolwsd never answers
    # /hosting/discovery; SYS_CHROOT is the one capability it gets back (lab: answered with exactly that). Nothing else gets one.
    from ics.deploy.catalog import get_catalog
    from ics.deploy.plan import _install_params
    cat = get_catalog()
    caps = {(c.name, a.name): list(a.unit.capabilities) for c in cat.components.values() for a in c.artifacts if getattr(a, "unit", None)}
    assert caps[("office", "collabora")] == ["SYS_CHROOT"]
    assert all(v == [] for k, v in caps.items() if k != ("office", "collabora")), caps
    unit = [r for r in _install_params(cat.components["office"], "e.example") if r["runbook"] == "podman.deploy_unit"]
    assert len(unit) == 1 and unit[0]["params"]["capabilities"] == ["SYS_CHROOT"]
    files = [r for r in _install_params(cat.components["files"], "e.example") if r["runbook"] == "podman.deploy_unit"]
    assert files and all("capabilities" not in r["params"] for r in files)


def test_every_image_of_a_component_is_pulled_before_its_configuration_names_it(monkeypatch):
    """cfg.volume_files is refused for an image the node has not verified. Chat's configuration names element-web (its first container by
    name) while element-web is its last artifact: the expanded install must pull every image before the first configuration runbook
    (officeunbound8 job 1a635703, 2026-11-24). Checked for every catalog component with images, with a configuration naming each image."""
    from ics.deploy import configure
    from ics.deploy.catalog import load_catalog
    from ics.deploy.plan import _install_params
    cat = load_catalog()
    checked = 0
    for name, c in cat.components.items():
        rbs = _install_params(c, "e.example")
        images = [r["params"]["image"] for r in rbs if r["runbook"] == "podman.pull_verified"]
        if len(images) < 1:
            continue
        cfg = [{"runbook": "cfg.volume_files", "params": {"image": im}} for im in reversed(images)]
        monkeypatch.setitem(configure.BUILDERS, name, lambda ctx, vm, cfg=cfg: cfg)
        out = configure.expand(None, "vm", name, rbs)
        assert sorted(map(str, out)) == sorted(map(str, rbs + cfg)), name   # nothing dropped or duplicated
        pulled = set()
        for r in out:
            if r["runbook"] == "podman.pull_verified":
                pulled.add(r["params"]["image"])
            elif r["runbook"] in ("cfg.volume_files", "podman.deploy_unit"):
                assert r["params"]["image"] in pulled, (name, r["runbook"], r["params"]["image"])
        first_cfg = next(n for n, r in enumerate(out) if r["runbook"].startswith("cfg."))
        assert all(n < first_cfg for n, r in enumerate(out) if r["runbook"] == "podman.pull_verified"), name
        assert [r for r in out if r["runbook"] == "podman.deploy_unit"] == [r for r in rbs if r["runbook"] == "podman.deploy_unit"], name
        checked += 1
    assert checked >= 5 and "chat" in cat.components
