"""Administration > System read-only endpoint."""
H = "/api/v1"


def test_system_info_admin_only(mk_user, login, client):
    assert client.get(f"{H}/system").status_code == 401
    vw = login(mk_user("vw", "viewer"))
    assert vw[0].get(f"{H}/system").status_code == 403
    adm = login(mk_user("adm", "admin"))
    r = adm[0].get(f"{H}/system")
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["version"] and "migration_head" in j and j["database_bytes"] > 0
    assert set(j["checks"]) == {"database", "worker", "audit_chain"} and j["checks"]["database"] is True
    assert j["worker_enabled"] is False and j["threads"] == []
    assert "known" in j["backup"] and j["disk"]["total"] > 0
