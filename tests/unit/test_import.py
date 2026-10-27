import json
from datetime import datetime, timedelta, timezone

import pytest
import stix2

from mtip.ingest.stix_import import (
    TS_BULK, TS_OBSERVED, TS_PUBLICATION, assess_timestamp_quality, extract_pattern_indicators, load_objects,
)
from mtip.security import InputRejected
from tests.conftest import make_bundle, unattributed_bundle


def test_import_counts_and_edges(platform):
    report = platform.importer.import_bytes(make_bundle(families=3, per_family=4, apps_per_family=2), "feed-a")
    assert report.status == "complete"
    assert report.indicators_new == 3 * 6
    assert report.entities_new == 3
    assert report.documented_edges == 3 * 6
    assert report.rejected == 0
    assert platform.storage.query_one("SELECT COUNT(*) FROM indicators")[0] == 18


def test_reimport_is_idempotent(platform):
    data = make_bundle(families=2, per_family=3, apps_per_family=1)
    platform.importer.import_bytes(data, "feed-a")
    again = platform.importer.import_bytes(data, "feed-a")
    assert again.status == "already-imported"
    assert platform.storage.query_one("SELECT COUNT(*) FROM observations")[0] == 8


def test_cross_source_duplicates_are_merged(platform):
    platform.importer.import_bytes(make_bundle(families=2, per_family=3, apps_per_family=1), "feed-a")
    second = unattributed_bundle([("domain-name:value", "NODE0.fam0-cloudops.com"), ("url:value", "hxxp://node1[.]fam0-cloudops.com/x")])
    report = platform.importer.import_bytes(second, "feed-b")
    assert report.duplicates == 1
    assert report.indicators_new == 1
    multi = platform.storage.query_one(
        "SELECT COUNT(*) FROM (SELECT indicator_id FROM observations GROUP BY indicator_id HAVING COUNT(DISTINCT source_id)>=2)")[0]
    assert multi == 1


def test_documented_aliases_merge_entities_across_sources(platform):
    a = stix2.Malware(name="Pegasus", is_family=True, aliases=["Chrysaor"])
    b = stix2.Malware(name="Chrysaor", is_family=True)
    platform.importer.import_bytes(stix2.Bundle(objects=[a]).serialize().encode(), "s1")
    platform.importer.import_bytes(stix2.Bundle(objects=[b]).serialize().encode(), "s2")
    assert platform.storage.query_one("SELECT COUNT(*) FROM entities WHERE etype='malware'")[0] == 1


def test_similar_names_are_not_merged(platform):
    objs = [stix2.Malware(name="NeoSpy", is_family=True), stix2.Malware(name="NemoSpy", is_family=True)]
    platform.importer.import_bytes(stix2.Bundle(objects=objs).serialize().encode(), "s1")
    assert platform.storage.query_one("SELECT COUNT(*) FROM entities")[0] == 2


def test_revoked_and_invalid_objects_skipped_but_rest_imported(platform):
    good = json.loads(unattributed_bundle([("domain-name:value", "ok.example.org")]))
    good["objects"].append({"type": "malware", "id": "malware--not-a-uuid", "name": "x"})
    good["objects"].append({"type": "indicator", "revoked": True, "id": "indicator--44af6c39-c09b-49c5-9de2-394224b04982"})
    good["objects"].append("not an object")
    report = platform.importer.import_bytes(json.dumps(good).encode(), "s1")
    assert report.indicators_new == 1
    assert report.rejected >= 1
    assert report.reject_reasons.get("revoked-or-deprecated") == 1


def test_relationships_resolve_across_imports(platform):
    mal = stix2.Malware(name="Later", is_family=True)
    platform.importer.import_bytes(stix2.Bundle(objects=[mal]).serialize().encode(), "s1")
    ind = stix2.Indicator(pattern="[domain-name:value='late.example.net']", pattern_type="stix", valid_from="2025-01-01T00:00:00Z")
    rel = stix2.Relationship(ind, "indicates", mal.id)
    report = platform.importer.import_bytes(stix2.Bundle(objects=[ind, rel]).serialize().encode(), "s2")
    assert report.unresolved_relationships == 0
    assert report.documented_edges == 1


def test_compound_pattern_creates_same_indicator_edge(platform):
    ind = stix2.Indicator(pattern="[app:id='com.a.b'] AND [app:cert.sha256='" + "ab" * 32 + "']", pattern_type="stix",
                          valid_from="2025-01-01T00:00:00Z", allow_custom=True)
    report = platform.importer.import_bytes(stix2.Bundle(objects=[ind], allow_custom=True).serialize().encode(), "s1")
    assert report.indicators_new == 2
    assert platform.storage.query_one("SELECT COUNT(*) FROM documented_edges WHERE rel_type='same-indicator'")[0] == 1


def test_pattern_extraction_handles_escapes_and_operators():
    found, skipped = extract_pattern_indicators(r"[domain-name:value = 'it\'s.example.com'] OR [url:value LIKE 'http://%']")
    assert skipped == 2
    assert found == []
    found, skipped = extract_pattern_indicators("[ipv4-addr:value = '10.0.0.1']")
    assert found[0][0].key == "ipv4:10.0.0.1" and skipped == 0
    assert extract_pattern_indicators("not a pattern")[1] == 1
    assert extract_pattern_indicators("[a" * 20000)[1] == 1


def test_depth_bomb_rejected():
    data = b"[" * 1000 + b"]" * 1000
    with pytest.raises(InputRejected):
        load_objects(data, 64, 1000)


def test_object_limit_enforced():
    data = json.dumps({"type": "bundle", "objects": [{"type": "x"}] * 11}).encode()
    with pytest.raises(InputRejected):
        load_objects(data, 64, 10)


@pytest.mark.parametrize("data", [b"", b"\xff\xfe\x00", b"{}", b"123", b'{"objects": 5}', b"nul"])
def test_non_stix_rejected(data):
    with pytest.raises(InputRejected):
        load_objects(data, 64, 100)


def test_timestamp_quality():
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    bulk = [t0 + timedelta(seconds=i) for i in range(50)]
    spread = [t0 + timedelta(days=10 * i) for i in range(50)]
    assert assess_timestamp_quality(bulk, False) == TS_BULK
    assert assess_timestamp_quality(spread, False) == TS_PUBLICATION
    assert assess_timestamp_quality(bulk, True) == TS_OBSERVED


def test_sightings_mark_source_as_observed(platform):
    ind = stix2.Indicator(pattern="[domain-name:value='seen.example.com']", pattern_type="stix", valid_from="2025-01-01T00:00:00Z")
    sighting = stix2.Sighting(sighting_of_ref=ind.id, first_seen="2025-02-03T04:05:06Z")
    report = platform.importer.import_bytes(stix2.Bundle(objects=[ind, sighting]).serialize().encode(), "sensor")
    assert report.ts_quality == TS_OBSERVED
    assert platform.storage.query_one("SELECT first_seen FROM indicators")[0] == "2025-02-03T04:05:06Z"
