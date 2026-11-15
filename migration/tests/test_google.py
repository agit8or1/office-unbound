import json

import pytest

from conftest import A, ALL_SCOPES, TODAY, make_ckpt
from fakeserver import fixture
from ou_migration.auth import AuthError
from ou_migration.sources.google import GoogleCollector


def collect(http, auth, g, path, **kw):
    b = g.base
    return GoogleCollector(http, auth, make_ckpt(path, "google", "k"), dir_base=b + "/dir", reports_base=b + "/reports",
                           gmail_base=b + "/gmail", drive_base=b + "/drive", today=TODAY, **kw).collect()


def test_dwd_jwt_is_signed_and_scoped(http, google_auth, google):
    google_auth.token([A + "admin.directory.user.readonly"])
    c = google.issued[0]
    assert c["iss"] == "sa@proj.iam.gserviceaccount.example" and c["sub"] == "admin@example.test"
    assert c["scope"] == A + "admin.directory.user.readonly" and c["aud"].endswith("/gtoken")


def test_scope_not_allow_listed_gives_clear_error(http, google_auth, google):
    google.dwd_allowed = set()
    with pytest.raises(AuthError) as e:
        google_auth.token([A + "admin.directory.user.readonly"])
    assert "unauthorized_client" in str(e.value)


def test_full_collect(http, google_auth, google, ckpt_path):
    inv = collect(http, google_auth, google, ckpt_path)
    assert inv.tenant_id == "C01abc234"
    assert [(d.name, d.verified) for d in inv.domains] == [("example.test", True), ("alias.example.test", True), ("second.example.test", False)]
    assert len(inv.users) == 3 and len(google.seen("/dir/users")) == 2          # paging via nextPageToken
    carol = next(u for u in inv.users if u.login == "carol@example.test")
    assert carol.is_admin and carol.aliases == ["c.chen@example.test"]
    assert carol.mailbox_bytes == 10240 * 1048576 and carol.file_bytes == 20480 * 1048576
    assert next(u for u in inv.users if u.login == "erin@example.test").suspended
    assert [g.members for g in inv.groups] == [3, 2]
    assert inv.counts["resource_calendars"] == 2
    assert set(inv.coverage.values()) == {"ok"}


def test_reports_lag_walks_back_to_available_date(http, google_auth, google, ckpt_path):
    inv = collect(http, google_auth, google, ckpt_path)
    days = [r.path.rsplit("/", 1)[1] for r in google.seen("/reports/usage")]
    assert days[0] > days[-1] and days[-1] == google.data_date and len(days) == 2   # day-2 -> 400, day-3 -> ok
    assert any(k.startswith("usage_report_date_") for k in inv.counts)


def test_rate_limit_403_retried(http, google_auth, google, ckpt_path, sleeper):
    google.script("GET", "/dir/groups", [(403, {}, fixture("google/throttle_403.json"))])
    inv = collect(http, google_auth, google, ckpt_path)
    assert len(inv.groups) == 2 and http.throttle_events == 1 and sleeper.calls


def test_missing_scope_is_partial_failure_not_abort(http, google_auth, google, ckpt_path):
    google.dwd_allowed = ALL_SCOPES - {A + "admin.reports.usage.readonly"}
    inv = collect(http, google_auth, google, ckpt_path)
    assert inv.coverage["usage_report"].startswith("failed") and "unauthorized_client" in inv.coverage["usage_report"]
    assert inv.coverage["users"] == "ok"
    assert len(inv.users) == 3 and all(u.mailbox_bytes is None for u in inv.users)


def test_auth_error_inside_stage_does_not_leak_key(http, google_auth, google, ckpt_path, rsa_key):
    google.dwd_allowed = set()
    try:
        collect(http, google_auth, google, ckpt_path)
    except AuthError as e:
        assert "PRIVATE KEY" not in str(e)


def test_resume_google(http, google_auth, google, ckpt_path):
    collect(http, google_auth, google, ckpt_path)
    n = len(google.requests)
    inv = collect(http, google_auth, google, ckpt_path)
    assert len(google.requests) == n and inv.users[0].mailbox_bytes is not None


def test_deep_scan_metadata_only(http, google_auth, google, ckpt_path):
    inv = collect(http, google_auth, google, ckpt_path, deep=True, deep_max_users=2)
    carol = next(u for u in inv.users if u.login == "carol@example.test")
    assert carol.mailbox_items == 4321 and carol.file_count == 5
    assert inv.sharing["sample_anyone_link_files"] == 2 and inv.sharing["sample_files"] == 10
    assert inv.signals["google_forms_in_sample"] == 2 and inv.signals["google_sites_in_sample"] == 2
    assert sum(inv.file_size_buckets.values()) == 6 and inv.file_size_buckets["5-25 GiB"] == 2
    drive_reqs = google.seen("/drive/files")
    assert drive_reqs and all("name" not in r.query.get("fields", [""])[0] for r in drive_reqs)
    assert all(r.query.get("fields", [""])[0].startswith("nextPageToken,files(size,shared,mimeType") for r in drive_reqs)
    subjects = {c["sub"] for c in google.issued}
    assert {"carol@example.test", "dave@example.test"} <= subjects and "erin@example.test" not in subjects   # suspended skipped


def test_checkpoint_contains_no_tokens_or_key(http, google_auth, google, ckpt_path, rsa_key):
    collect(http, google_auth, google, ckpt_path, deep=True, deep_max_users=1)
    text = open(ckpt_path).read()
    assert "FAKE-G|" not in text and "PRIVATE KEY" not in text


def test_google_auth_from_env_requires_private_keyfile(http, google_keyfile, google, tmp_path):
    import os
    from ou_migration.auth import GoogleAuth
    from ou_migration.secrets import SecretError
    a = GoogleAuth.from_env(http, {"OU_GOOGLE_SA_KEY_FILE": google_keyfile, "OU_GOOGLE_ADMIN_SUBJECT": "admin@example.test"})
    assert a.token([A + "admin.directory.user.readonly"])
    os.chmod(google_keyfile, 0o644)
    with pytest.raises(SecretError):
        GoogleAuth.from_env(http, {"OU_GOOGLE_SA_KEY_FILE": google_keyfile, "OU_GOOGLE_ADMIN_SUBJECT": "admin@example.test"})
