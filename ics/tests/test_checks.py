"""Check kinds against local fake services (TLS always verified: CA bundle or pin)."""
import json

import pytest
from pydantic import ValidationError

from ics import checks
from .lab_mock import EWS_OK, HttpsMock, ImapMock, SmtpMock


def run(kind, cfg, pw=None):
    return checks.run_check(kind, checks.validate_config(kind, cfg), pw, allow_loopback=True)


@pytest.fixture()
def web():
    routes = {("GET", "/health"): (200, b'{"status":"ok","db":{"up":true},"items":[{"n":7}]}'),
              ("GET", "/down"): (503, b"unavailable")}
    s = HttpsMock(routes)
    yield s
    s.stop()


def test_trust_anchor_is_mandatory_for_tls_checks():
    for kind, cfg in (("http", {"url": "https://127.0.0.1/"}), ("tcp_tls", {"host": "h.example", "port": 443}),
                      ("imap_login", {"host": "h.example", "username": "u"}), ("ews_getfolder", {"url": "https://h/EWS", "username": "u"})):
        with pytest.raises(ValidationError, match="exactly one of ca_pem or fingerprint_sha256"):
            checks.validate_config(kind, cfg)
    with pytest.raises(ValidationError):  # both
        checks.validate_config("http", {"url": "https://h/", "ca_pem": "x", "fingerprint_sha256": "a" * 64})
    with pytest.raises(ValidationError):
        checks.validate_config("http", {"url": "http://h/", "fingerprint_sha256": "a" * 64})
    with pytest.raises(ValidationError):  # unknown/free-form fields
        checks.validate_config("smtp_banner", {"host": "h.example", "command": "id"})


def test_http_status_body_and_json_field(web):
    base = {"url": web.base + "/health", "fingerprint_sha256": web.fp}
    assert run("http", base).status == "ok"
    assert run("http", {**base, "body_contains": '"status":"ok"'}).status == "ok"
    assert run("http", {**base, "body_contains": "missing"}).status == "critical"
    assert run("http", {**base, "json_path": "db.up", "json_equals": True}).status == "ok"
    assert run("http", {**base, "json_path": "items.0.n", "json_equals": 7}).status == "ok"
    assert run("http", {**base, "json_path": "db.up", "json_equals": False}).status == "critical"
    assert run("http", {**base, "json_path": "nope.x"}).status == "critical"
    o = run("http", {"url": web.base + "/down", "fingerprint_sha256": web.fp})
    assert o.status == "critical" and "503" in o.message
    assert run("http", {"url": web.base + "/down", "fingerprint_sha256": web.fp, "expect_status": 503}).status == "ok"


def test_http_ca_bundle_and_wrong_pin(web):
    assert run("http", {"url": web.base + "/health", "ca_pem": web.pem}).status == "ok"
    o = run("http", {"url": web.base + "/health", "fingerprint_sha256": "ab" * 32})
    assert o.status == "critical" and "pinned" in o.message
    n = len(web.seen)
    run("http", {"url": web.base + "/health", "fingerprint_sha256": "cd" * 32})
    assert len(web.seen) == n  # no HTTP request was sent to an untrusted peer


def test_http_connection_refused_is_critical_not_exception():
    o = run("http", {"url": "https://127.0.0.1:9/", "fingerprint_sha256": "a" * 64, "timeout_seconds": 2})
    assert o.status == "critical" and o.message


def test_http_loopback_refused_when_guard_is_on(web):
    o = checks.run_check("http", checks.validate_config("http", {"url": web.base + "/health", "fingerprint_sha256": web.fp}), None, allow_loopback=False)
    assert o.status == "critical" and "not an allowed destination" in o.message


@pytest.mark.parametrize("days,status", [(60, "ok"), (15, "warning"), (3, "critical")])
def test_tcp_tls_certificate_expiry(days, status):
    s = ImapMock(days=days)
    try:
        o = run("tcp_tls", {"host": "127.0.0.1", "port": s.port, "fingerprint_sha256": s.fp})
        assert o.status == status, o
        assert abs(o.details["days_left"] - days) <= 1
    finally:
        s.stop()


def test_tcp_tls_threshold_validation():
    with pytest.raises(ValidationError):
        checks.validate_config("tcp_tls", {"host": "h.example", "port": 443, "fingerprint_sha256": "a" * 64, "warn_days": 5, "crit_days": 9})


def test_imap_login_select_inbox():
    s = ImapMock(user="mon", password="pw-Secret-1")
    try:
        cfg = {"host": "127.0.0.1", "port": s.port, "username": "mon", "fingerprint_sha256": s.fp}
        o = run("imap_login", cfg, "pw-Secret-1")
        assert o.status == "ok" and o.details["exists"] == 3
        bad = run("imap_login", cfg, "wrong-pw-xyz")
        assert bad.status == "critical" and "wrong-pw-xyz" not in bad.message
        s.mailbox_ok = False
        assert run("imap_login", cfg, "pw-Secret-1").status == "critical"
        assert run("imap_login", cfg, None).status == "critical"
    finally:
        s.stop()


def test_imap_checks_pinned_certificate():
    s = ImapMock()
    try:
        o = run("imap_login", {"host": "127.0.0.1", "port": s.port, "username": "mon", "fingerprint_sha256": "ab" * 32}, s.password)
        assert o.status == "critical" and "pinned" in o.message
    finally:
        s.stop()


def test_smtp_banner():
    s = SmtpMock()
    try:
        assert run("smtp_banner", {"host": "127.0.0.1", "port": s.port}).status == "ok"
        assert run("smtp_banner", {"host": "127.0.0.1", "port": s.port, "banner_contains": "mock.example"}).status == "ok"
        assert run("smtp_banner", {"host": "127.0.0.1", "port": s.port, "banner_contains": "Postfix"}).status == "critical"
    finally:
        s.stop()
    s = SmtpMock(banner="554 go away")
    try:
        assert run("smtp_banner", {"host": "127.0.0.1", "port": s.port}).status == "critical"
    finally:
        s.stop()
    assert run("smtp_banner", {"host": "127.0.0.1", "port": 9, "timeout_seconds": 2}).status == "critical"


def test_ews_getfolder_success_and_failures():
    state = {"code": 200, "body": EWS_OK}
    s = HttpsMock({("POST", "/EWS/Exchange.asmx"): lambda h, b: (state["code"], state["body"])})
    try:
        cfg = {"url": s.base + "/EWS/Exchange.asmx", "username": "mon@x.example", "fingerprint_sha256": s.fp}
        o = run("ews_getfolder", cfg, "pw-ews-123")
        assert o.status == "ok"
        method, path, headers, body = s.seen[-1]
        assert headers["Authorization"].startswith("Basic ") and b"GetFolder" in body and b'Id="inbox"' in body
        state["code"] = 401
        o = run("ews_getfolder", cfg, "pw-ews-123")
        assert o.status == "critical" and "401" in o.message and "pw-ews-123" not in o.message
        state.update(code=200, body=b'<x ResponseClass="Error"><m:ResponseCode>ErrorAccessDenied</m:ResponseCode></x>')
        assert run("ews_getfolder", cfg, "pw-ews-123").status == "critical"
        state["body"] = b'<!DOCTYPE x [<!ENTITY a "b">]>' + EWS_OK
        assert "DTD" in run("ews_getfolder", cfg, "pw-ews-123").message
    finally:
        s.stop()


def test_response_size_cap():
    s = HttpsMock({("GET", "/big"): (200, b"x" * (1024 * 1024 + 10))})
    try:
        o = run("http", {"url": s.base + "/big", "fingerprint_sha256": s.fp})
        assert o.status == "critical" and "1 MiB" in o.message
    finally:
        s.stop()
