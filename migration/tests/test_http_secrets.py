import logging
import os

import pytest

from ou_migration.http import HttpClient, HttpError, TransportError, parse_retry_after
from ou_migration.secrets import Redacted, SecretError, load_secret, read_secret_file
from fakeserver import GRAPH_SECRET, GRAPH_TOKEN, fixture


def test_429_retry_after_honoured_then_success(server, http, sleeper):
    body = fixture("graph/throttle_429.json")
    server.script("GET", "/x", [(429, {"Retry-After": "7"}, body), (429, {"Retry-After": "3"}, body), (200, {}, {"ok": True})])
    r = http.request("GET", server.base + "/x")
    assert r.json() == {"ok": True}
    assert sleeper.calls == [7.0, 3.0]            # exact Retry-After, no jitter
    assert http.throttle_events == 2 and http.retries == 2


def test_503_without_retry_after_uses_exponential_backoff(server, http, sleeper):
    server.script("GET", "/x", [(503, {}, b"{}"), (503, {}, b"{}"), (200, {}, {"ok": 1})])
    http.request("GET", server.base + "/x")
    assert len(sleeper.calls) == 2 and sleeper.calls[1] > sleeper.calls[0]


def test_retry_exhaustion_raises(server, http):
    server.script("GET", "/x", [(429, {"Retry-After": "0"}, b"{}")] * 10)
    with pytest.raises(HttpError) as e:
        http.request("GET", server.base + "/x")
    assert e.value.status == 429


def test_google_403_rate_limit_is_retried_but_plain_403_is_not(server, http, sleeper):
    body = fixture("google/throttle_403.json")
    server.script("GET", "/g", [(403, {}, body), (200, {}, {"ok": 1})])
    assert http.request("GET", server.base + "/g").json() == {"ok": 1}
    server.script("GET", "/h", [(403, {}, {"error": {"code": 403, "message": "insufficient scopes", "errors": [{"reason": "forbidden"}]}})])
    with pytest.raises(HttpError):
        http.request("GET", server.base + "/h")


def test_404_not_retried(server, http, sleeper):
    with pytest.raises(HttpError):
        http.request("GET", server.base + "/nothing")
    assert sleeper.calls == []


def test_retry_after_http_date():
    assert parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT", now=1445412480 - 30) == 30.0
    assert parse_retry_after("12") == 12.0 and parse_retry_after("junk") is None


def test_plain_http_refused_unless_loopback_flag():
    with pytest.raises(TransportError):
        HttpClient().request("GET", "http://127.0.0.1:1/x")
    with pytest.raises(TransportError):
        HttpClient(allow_loopback_http=True).request("GET", "http://example.com/x")


def test_redirect_not_followed_and_no_bearer_on_download(graph, graph_auth, http):
    r = http.request("GET", graph.base + "/graph/v1.0/reports/getMailboxUsageDetail(period='D30')",
                     headers=graph_auth.headers(), allow_redirect_status=True)
    assert r.status == 302 and "/download/" in r.headers["location"]
    # a plain request WITHOUT allow_redirect_status must not silently follow
    with pytest.raises(HttpError):
        http.request("GET", graph.base + "/graph/v1.0/reports/getMailboxUsageDetail(period='D30')", headers=graph_auth.headers())


def test_secret_file_rules(tmp_path):
    p = tmp_path / "s"
    p.write_text("topsecret\n")
    os.chmod(p, 0o644)
    with pytest.raises(SecretError) as e:
        read_secret_file(str(p))
    assert "topsecret" not in str(e.value)
    os.chmod(p, 0o600)
    assert read_secret_file(str(p)) == "topsecret"
    link = tmp_path / "l"
    link.symlink_to(p)
    with pytest.raises(SecretError):
        read_secret_file(str(link))


def test_load_secret_env_and_file_and_missing(tmp_path):
    assert load_secret("X", environ={"X": "v"}) == "v"
    p = tmp_path / "s"
    p.write_text("fromfile")
    os.chmod(p, 0o600)
    assert load_secret("X", environ={"X_FILE": str(p), "X": "ignored"}) == "fromfile"
    with pytest.raises(SecretError) as e:
        load_secret("X", environ={})
    assert "X_FILE" in str(e.value)


def test_redacted_never_leaks():
    r = Redacted("hunter2")
    assert "hunter2" not in repr(r) and "hunter2" not in str(r) and "hunter2" not in f"{r}" and r.reveal() == "hunter2"


def test_no_secrets_or_tokens_in_logs(graph, graph_auth, http, caplog):
    caplog.set_level(logging.DEBUG)
    graph.script("GET", "/graph/v1.0/organization", [(429, {"Retry-After": "0"}, b"{}")])
    http.request("GET", graph.base + "/graph/v1.0/organization", headers=graph_auth.headers())
    text = caplog.text
    assert GRAPH_TOKEN not in text and GRAPH_SECRET not in text and "Bearer" not in text
