import json

from hypothesis import HealthCheck, given, settings, strategies as st

from mtip.ingest.stix_import import extract_pattern_indicators, load_objects
from mtip.normalize import ALL_KINDS, NormalizationError, normalize, registered_domain
from mtip.security import InputRejected, check_json_depth, detect_attack
from tests.conftest import TOKEN

FUZZ = settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])


@FUZZ
@given(kind=st.sampled_from(ALL_KINDS), raw=st.text(max_size=300))
def test_normalize_only_raises_normalization_error(kind, raw):
    try:
        out = normalize(kind, raw)
    except NormalizationError:
        return
    assert out.kind in ALL_KINDS and isinstance(out.value, str) and len(out.value) <= 4096


@FUZZ
@given(st.from_regex(r"[a-z0-9-]{1,20}(\.[a-z0-9-]{1,20}){1,4}", fullmatch=True))
def test_normalized_domains_are_idempotent(domain):
    try:
        first = normalize("domain", domain)
    except NormalizationError:
        return
    assert normalize(first.kind, first.value) == first
    if first.kind == "domain":
        root = registered_domain(first.value)
        assert root is None or first.value.endswith(root)


@FUZZ
@given(st.text(max_size=500))
def test_pattern_extraction_never_crashes(text):
    found, skipped = extract_pattern_indicators(text)
    assert isinstance(found, list) and skipped >= 0


@FUZZ
@given(st.recursive(st.none() | st.booleans() | st.integers() | st.text(max_size=20),
                    lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=8), children, max_size=4),
                    max_leaves=40))
def test_depth_check_agrees_with_parser(obj):
    data = json.dumps(obj).encode()
    check_json_depth(data, 64)
    try:
        load_objects(data, 64, 1000)
    except InputRejected:
        pass


@FUZZ
@given(st.binary(max_size=2000))
def test_load_objects_on_arbitrary_bytes(data):
    try:
        objs = load_objects(data, 64, 1000)
        assert isinstance(objs, list)
    except InputRejected:
        pass


@FUZZ
@given(st.text(max_size=400))
def test_detect_attack_is_total(text):
    assert detect_attack(text) in (None, "sqli", "xss", "path_traversal", "template_injection", "command_injection", "ldap_nosql")


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
@given(search=st.text(max_size=120), kind=st.text(max_size=20), offset=st.integers(-5, 10**8), limit=st.integers(-5, 2000))
def test_indicator_api_never_500(client, search, kind, offset, limit):
    r = client.get("/api/v1/indicators", params={"search": search, "kind": kind, "offset": offset, "limit": limit})
    assert r.status_code in (200, 400, 403, 422)


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
@given(body=st.dictionaries(st.sampled_from(["src_type", "src_id", "dst_type", "dst_id", "relation", "verdict", "x"]),
                            st.one_of(st.integers(), st.text(max_size=30), st.none(), st.floats(allow_nan=True))))
def test_feedback_api_never_500(client, body):
    raw = json.dumps(body, allow_nan=True).encode()
    r = client.post("/api/v1/feedback", content=raw, headers={"X-MTIP-Token": TOKEN, "Content-Type": "application/json"})
    assert r.status_code in (400, 403, 404, 422)


@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
@given(objects=st.lists(st.fixed_dictionaries({
    "type": st.sampled_from(["indicator", "malware", "relationship", "campaign", "sighting", "x-unknown"]),
    "id": st.text(max_size=60),
    "pattern": st.text(max_size=80),
    "name": st.text(max_size=30),
    "source_ref": st.text(max_size=40),
    "target_ref": st.text(max_size=40),
    "relationship_type": st.sampled_from(["indicates", "uses", "zzz"]),
}), max_size=12))
def test_importer_survives_hostile_objects(platform, objects):
    data = json.dumps({"type": "bundle", "objects": objects}).encode()
    try:
        report = platform.importer.import_bytes(data, "fuzz")
    except InputRejected:
        return
    assert report.status in ("complete", "already-imported")
