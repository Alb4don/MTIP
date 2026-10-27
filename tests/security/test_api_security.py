
import pytest
from fastapi.testclient import TestClient

from mtip.api.app import create_app
from mtip.security import InputRejected, RateLimiter, StrikeTracker, detect_attack, validate_outbound_url
from mtip.logging_setup import redact
from tests.conftest import make_bundle, unattributed_bundle, wait_job

LEAK_MARKERS = ("Traceback", "File \"", "/home/", "site-packages", "sqlite3.", "SELECT ", "Exception(")


def _no_leak(response):
    text = response.text
    for marker in LEAK_MARKERS:
        assert marker not in text, marker


def test_security_headers_on_every_response(client):
    for path in ("/", "/api/v1/health", "/api/v1/does-not-exist", "/static/app.js"):
        r = client.get(path)
        assert "default-src 'none'" in r.headers["content-security-policy"]
        assert r.headers["x-frame-options"] == "DENY"
        assert r.headers["x-content-type-options"] == "nosniff"
        assert "server" not in r.headers


def test_docs_and_openapi_disabled(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_state_change_requires_token(client):
    r = client.post("/api/v1/correlation/run", json={})
    assert r.status_code == 403
    r = client.post("/api/v1/correlation/run", json={}, headers={"X-MTIP-Token": "wrong"})
    assert r.status_code == 403


def test_cross_origin_post_rejected(client, auth):
    r = client.post("/api/v1/correlation/run", json={}, headers={**auth, "Origin": "https://evil.example"})
    assert r.status_code == 403


def test_untrusted_host_rejected(client):
    assert client.get("/api/v1/health", headers={"Host": "attacker.example"}).status_code == 400


@pytest.mark.parametrize("payload", [
    "1' OR '1'='1", "x UNION SELECT password FROM users", "<script>alert(1)</script>", "../../etc/passwd",
    "{{7*7}}", "$(id)", "%2e%2e%2fetc", "a;rm -rf /",
])
def test_hostile_looking_ioc_searches_are_safe_and_never_lock_out(client, platform, payload):
    platform.importer.import_bytes(make_bundle(families=2, per_family=2), "feed-a")
    for _ in range(6):
        r = client.get("/api/v1/indicators", params={"search": payload})
        assert r.status_code == 200
        assert r.json()["total"] == 0
        _no_leak(r)
    assert client.get("/api/v1/health").status_code == 200


@pytest.mark.parametrize("payload", ["1' OR '1'='1", "<script>alert(1)</script>", "../../etc/passwd", "$(id)"])
def test_attack_payloads_in_structural_parameters_are_rejected(client, payload):
    r = client.get("/api/v1/inferences", params={"relation": payload})
    assert r.status_code == 400
    _no_leak(r)


def test_ioc_containing_attack_string_is_findable(client, platform):
    platform.importer.import_bytes(unattributed_bundle([("url:value", "http://evil.example.com/../../etc/passwd")]), "feed-x")
    r = client.get("/api/v1/indicators", params={"search": "../../etc"})
    assert r.status_code == 200 and r.json()["total"] == 1


def test_repeated_attacks_block_client(settings, platform):
    app = create_app(settings, platform)
    with TestClient(app, base_url="http://testserver") as c:
        for _ in range(3):
            c.get("/api/v1/inferences", params={"relation": "1 UNION SELECT 1"})
        r = c.get("/api/v1/health")
        assert r.status_code == 403
        assert platform.storage.query_one("SELECT COUNT(*) FROM security_events")[0] >= 3


def test_sql_wildcards_are_literal(client, platform):
    platform.importer.import_bytes(make_bundle(families=2, per_family=2), "feed-a")
    r = client.get("/api/v1/indicators", params={"search": "_"})
    assert r.status_code in (200, 400)
    if r.status_code == 200:
        assert r.json()["total"] == 0


def test_invalid_enum_and_range_values(client):
    assert client.get("/api/v1/indicators", params={"kind": "drop table"}).status_code in (400, 422)
    assert client.get("/api/v1/indicators", params={"limit": 100000}).status_code == 422
    assert client.get("/api/v1/inferences", params={"min_score": 7}).status_code == 422
    r = client.get("/api/v1/jobs/../../etc")
    assert r.status_code in (400, 404)


def test_validation_errors_do_not_echo_input(client, auth):
    secret = "SuperSecretValue123"
    r = client.post("/api/v1/feedback", json={"src_type": secret, "src_id": 1, "dst_type": "malware", "dst_id": 1,
                                              "relation": "inferred-indicates", "verdict": "confirm"}, headers=auth)
    assert r.status_code == 422
    assert secret not in r.text


def test_extra_fields_forbidden(client, auth):
    r = client.post("/api/v1/correlation/run", json={"min_attribution": 0.7, "__proto__": 1}, headers=auth)
    assert r.status_code == 422


def test_oversized_upload_rejected(client, auth, settings):
    r = client.post("/api/v1/imports/file", params={"source": "big"}, content=b"{" + b" " * 10,
                    headers={**auth, "Content-Type": "application/json", "Content-Length": str(settings.max_upload_bytes + 1)})
    assert r.status_code == 413


@pytest.mark.parametrize("name", ["../etc", "a" * 81, "<b>", "analyst", "", " ", "x\ny"])
def test_bad_source_names(client, auth, name):
    r = client.post("/api/v1/imports/file", params={"source": name}, content=b"{}", headers={**auth, "Content-Type": "application/json"})
    assert r.status_code in (400, 422)
    _no_leak(r)


def test_upload_content_type_enforced(client, auth):
    r = client.post("/api/v1/imports/file", params={"source": "feed"}, content=b"<html>", headers={**auth, "Content-Type": "text/html"})
    assert r.status_code == 400


def test_malicious_bundle_fails_job_cleanly(client, auth):
    bomb = b"[" * 5000 + b"]" * 5000
    r = client.post("/api/v1/imports/file", params={"source": "bomb"}, content=bomb, headers={**auth, "Content-Type": "application/json"})
    assert r.status_code == 202
    job = wait_job(client, r.json()["job"]["id"])
    assert job["status"] == "failed" and job["error"] == "document nesting is too deep"


def test_xss_values_are_escaped_in_reports(client, auth, platform):
    payload = unattributed_bundle([("url:value", "http://evil.example.com/<img src=x onerror=alert(1)>")])
    platform.importer.import_bytes(payload, "feed-x")
    platform.importer.import_bytes(make_bundle(families=2, per_family=3), "feed-y")
    platform.engine.run(evaluate=False)
    html = client.get("/api/v1/reports/html")
    assert html.status_code == 200
    assert "<img src=x" not in html.text
    assert "attachment" in html.headers["content-disposition"]


def test_csv_formula_injection_neutralised(client, platform):
    platform.importer.import_bytes(unattributed_bundle([("file:name", "=HYPERLINK(\"http://x\")")]), "feed-x")
    r = client.get("/api/v1/features/indicator_csv/export")
    assert r.status_code == 200
    assert "'=HYPERLINK" in r.text


def test_taxii_private_targets_rejected(client, auth):
    for url in ("http://example.com/taxii2/", "https://127.0.0.1/taxii2/", "https://user:pw@example.com/",
                "https://169.254.169.254/latest/", "https://localhost/taxii2/"):
        r = client.post("/api/v1/taxii/discover", json={"url": url}, headers=auth)
        assert r.status_code in (400, 403, 422), url
        _no_leak(r)
    assert client.get("/api/v1/health").status_code == 403


def test_unhandled_errors_return_generic_message(settings, platform, monkeypatch):
    def boom():
        raise RuntimeError("secret internal detail /home/user/db")
    monkeypatch.setattr(platform, "overview", boom)
    app = create_app(settings, platform)
    with TestClient(app, base_url="http://testserver", raise_server_exceptions=False) as c:
        r = c.get("/api/v1/overview")
        assert r.status_code == 500
        assert "secret" not in r.text and "error_id" in r.json()


def test_rate_limiter():
    rl = RateLimiter(per_minute=60, burst=3)
    assert all(rl.allow("a") for _ in range(3))
    assert not rl.allow("a")
    assert rl.allow("b")


def test_strike_tracker_blocks_and_expires():
    st = StrikeTracker(threshold=2, block_seconds=0)
    assert not st.strike("x")
    assert st.strike("x")
    assert not st.is_blocked("x")


@pytest.mark.parametrize("text,category", [
    ("' or 1=1", "sqli"), ("<svg onload=x>", "xss"), ("..\\windows", "path_traversal"), ("${jndi:ldap://x}", "template_injection"),
    ("| bash", "command_injection"), ("{\"$where\": 1}", "ldap_nosql"), ("node0.fam0-cloudops.com", None), ("com.example.spy", None),
])
def test_detect_attack(text, category):
    assert detect_attack(text) == category


def test_outbound_url_validation_offline_cases():
    for bad in ("ftp://x.com", "https://", "https://a:b@x.com/", "javascript:alert(1)", "https://x.com:99999/"):
        with pytest.raises(InputRejected):
            validate_outbound_url(bad, allow_private=True)
    assert validate_outbound_url("https://taxii.example.com/api/", allow_private=True) == "https://taxii.example.com/api/"


def test_log_redaction():
    line = redact("Authorization: Bearer abc.def token=xyz https://u:p@h.com/x?api_key=123 me@mail.com /home/jhon/x\nFORGED")
    for secret in ("abc.def", "xyz", "u:p@", "123", "me@mail.com", "jhon", "\n"):
        assert secret not in line
