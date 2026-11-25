"""PA-20 / PA-30 / PA-31 (PUBLIC-ALPHA-READINESS): experimental features are off unless the host owner opts in with ICS_EXPERIMENTAL."""
import pytest
from pydantic import ValidationError

from ics import config, experimental
from ics.tenancy_mode import TenancyMode

from .test_deploy_plan import cap, codes, generate_plan, inp, pinned


@pytest.fixture
def off():
    experimental.configure(())
    yield
    experimental.configure(experimental.FEATURES)


def test_the_setting_parses_known_names_and_refuses_unknown_ones():
    assert experimental.parse(" Meetings , remote-wipe") == {"meetings", "remote-wipe"}
    assert experimental.parse(None) == frozenset()
    with pytest.raises(RuntimeError, match="unknown feature"):
        experimental.parse("meetings,everything")
    assert config.Settings.__dataclass_fields__["experimental"].default == frozenset()   # off unless configured


def test_lab_prototypes_are_marked_experimental_in_the_catalog():
    cat = pinned()
    assert cat.components["meetings"].maturity == "experimental"
    assert cat.components["telephony"].maturity == "experimental"
    assert {n for n, c in cat.components.items() if c.maturity == "experimental"} == {"meetings", "telephony"}


def test_an_experimental_component_is_never_on_by_default(off):
    p = generate_plan(inp(profile="medium"), cap(), pinned())   # medium lists meetings among its default options
    present = {c for v in p["vms"] for c in v["components"]}
    assert "meetings" not in present and "telephony" not in present
    assert "component_experimental" not in codes(p["errors"])


def test_asking_for_an_experimental_component_is_refused_with_the_reason(off):
    p = generate_plan(inp(profile="medium", optional={"meetings": True}), cap(), pinned())
    e = [x for x in p["errors"] if x["code"] == "component_experimental"]
    assert len(e) == 1 and e[0]["component"] == "meetings" and "ICS_EXPERIMENTAL=meetings" in e[0]["message"]


def test_the_opt_in_allows_it():
    experimental.configure({"meetings"})
    try:
        p = generate_plan(inp(profile="medium", optional={"meetings": True}), cap(), pinned())
        assert "component_experimental" not in codes(p["errors"])
        assert "meetings" in {c for v in p["vms"] for c in v["components"]}
    finally:
        experimental.configure(experimental.FEATURES)


def test_a_multi_tenant_plan_is_refused(off):
    p = generate_plan(inp(profile="msp-multi", tenants=2), cap(), pinned())
    assert "tenancy_experimental" in codes(p["errors"])


def test_the_multi_tenant_installation_mode_is_refused_when_the_plan_is_made(off):
    assert TenancyMode(mode="single").mode == "single"
    with pytest.raises(ValidationError, match="ICS_EXPERIMENTAL=multi-tenant"):
        TenancyMode(mode="multi")


def test_remote_wipe_is_refused(off):
    with pytest.raises(experimental.NotEnabled, match="FULL wipe"):
        experimental.require("remote-wipe")
    assert [s["enabled"] for s in experimental.state()] == [False] * len(experimental.FEATURES)
