import json
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import pytest
import stix2

from mtip.correlate.engine import (
    REL_CONFLICT, REL_INFERRED_INDICATES, CorrelationEngine, EngineParams, build_keys,
    filter_generic_keys, load_snapshot, shared_key_tests,
)
from tests.conftest import make_bundle, unattributed_bundle


def _inferred(platform, rel=REL_INFERRED_INDICATES):
    run_id = platform.storage.get_state("active_run")
    return platform.storage.query(
        "SELECT i.value, e.display_name, ie.score, ie.basis FROM inferred_edges ie JOIN indicators i ON i.id=ie.src_id "
        "JOIN entities e ON e.id=ie.dst_id WHERE ie.run_id=? AND ie.rel_type=?", (run_id, rel))


def test_unattributed_indicators_inherit_family_through_registered_domain(platform):
    platform.importer.import_bytes(make_bundle(families=4, per_family=8), "feed-a")
    platform.importer.import_bytes(unattributed_bundle([
        ("domain-name:value", "new-node.fam2-cloudops.com"),
        ("app:id", "com.fam3vendor.newbuild"),
        ("domain-name:value", "totally-unrelated-site.org"),
    ]), "feed-b")
    result = CorrelationEngine(platform.storage).run(EngineParams(holdout_reps=1))
    rows = {r["value"]: r for r in _inferred(platform)}
    assert rows["new-node.fam2-cloudops.com"]["display_name"] == "FamFamily2"
    assert rows["com.fam3vendor.newbuild"]["display_name"] == "FamFamily3"
    assert "totally-unrelated-site.org" not in rows
    basis = json.loads(rows["new-node.fam2-cloudops.com"]["basis"])
    assert "same_root" in basis["reasons"]
    assert result.stats["inferred_attributions"] == 2


def test_documented_associations_are_never_reported_as_inferences(platform):
    platform.importer.import_bytes(make_bundle(families=3, per_family=6), "feed-a")
    CorrelationEngine(platform.storage).run(EngineParams(holdout_reps=1))
    documented = {r[0] for r in platform.storage.query(
        "SELECT src_id FROM documented_edges WHERE src_type='indicator' AND rel_type='indicates'")}
    inferred = {r[0] for r in platform.storage.query(
        "SELECT src_id FROM inferred_edges WHERE rel_type=?", (REL_INFERRED_INDICATES,))}
    assert not (documented & inferred)


def test_shared_hosting_does_not_create_attribution(platform):
    platform.importer.import_bytes(make_bundle(families=3, per_family=6), "feed-a")
    a = stix2.Malware(name="TenantA", is_family=True)
    objs = [a]
    for i in range(5):
        ind = stix2.Indicator(pattern=f"[domain-name:value='a{i}.oss-us-west-1.aliyuncs.com']", pattern_type="stix", valid_from="2025-01-01T00:00:00Z")
        objs += [ind, stix2.Relationship(ind, "indicates", a)]
    platform.importer.import_bytes(stix2.Bundle(objects=objs).serialize().encode(), "feed-c")
    platform.importer.import_bytes(unattributed_bundle([("domain-name:value", "other-tenant.oss-us-west-1.aliyuncs.com")]), "feed-b")
    CorrelationEngine(platform.storage).run(EngineParams(holdout_reps=1))
    assert not [r for r in _inferred(platform) if "aliyuncs" in r["value"]]


def test_keys_spanning_many_families_are_filtered_as_generic(platform):
    platform.importer.import_bytes(make_bundle(families=5, per_family=4), "feed-a")
    snap = load_snapshot(platform.storage)
    keys = build_keys(snap.indicators)
    assert ((keys["ktype"] == "tok") & (keys["key"] == "cloudops")).any()
    filtered = filter_generic_keys(keys, snap.labels, 2)
    assert not ((filtered["ktype"] == "tok") & (filtered["key"] == "cloudops")).any()
    assert (filtered["ktype"] == "root").any()


def test_ambiguous_evidence_abstains(platform):
    f1, f2 = stix2.Malware(name="Alpha", is_family=True), stix2.Malware(name="Beta", is_family=True)
    objs = [f1, f2]
    for fam in (f1, f2):
        for i in range(4):
            ind = stix2.Indicator(pattern=f"[domain-name:value='{fam.name.lower()}{i}.shared-panel-host.net']", pattern_type="stix",
                                  valid_from="2025-01-01T00:00:00Z")
            objs += [ind, stix2.Relationship(ind, "indicates", fam)]
    platform.importer.import_bytes(stix2.Bundle(objects=objs).serialize().encode(), "feed-a")
    platform.importer.import_bytes(make_bundle(families=3, per_family=5), "feed-z")
    platform.importer.import_bytes(unattributed_bundle([("domain-name:value", "who.shared-panel-host.net")]), "feed-b")
    CorrelationEngine(platform.storage).run(EngineParams(holdout_reps=1))
    assert not [r for r in _inferred(platform) if r["value"] == "who.shared-panel-host.net"]


def test_rejected_inference_is_not_reinferred(platform):
    platform.importer.import_bytes(make_bundle(families=3, per_family=6), "feed-a")
    platform.importer.import_bytes(unattributed_bundle([("domain-name:value", "x.fam1-cloudops.com")]), "feed-b")
    engine = CorrelationEngine(platform.storage)
    engine.run(EngineParams(holdout_reps=1))
    row = platform.storage.query_one("SELECT * FROM inferred_edges WHERE rel_type=?", (REL_INFERRED_INDICATES,))
    platform.submit_feedback("indicator", row["src_id"], row["dst_type"], row["dst_id"], REL_INFERRED_INDICATES, "reject")
    engine.run(EngineParams(holdout_reps=1))
    assert _inferred(platform) == []


def test_conflict_detected_when_structure_contradicts_source(platform):
    platform.importer.import_bytes(make_bundle(families=3, per_family=8), "feed-a")
    wrong = stix2.Malware(name="FamFamily0", is_family=True)
    ind = stix2.Indicator(pattern="[domain-name:value='mislabelled.fam2-cloudops.com']", pattern_type="stix", valid_from="2025-01-01T00:00:00Z")
    platform.importer.import_bytes(stix2.Bundle(objects=[wrong, ind, stix2.Relationship(ind, "indicates", wrong)]).serialize().encode(), "feed-x")
    CorrelationEngine(platform.storage).run(EngineParams(holdout_reps=1))
    conflicts = _inferred(platform, REL_CONFLICT)
    assert [r["display_name"] for r in conflicts if r["value"] == "mislabelled.fam2-cloudops.com"] == ["FamFamily2"]


def test_shared_key_test_finds_strong_overlap_and_ignores_noise():
    rng = np.random.default_rng(1)
    rows = [(e, f"k{rng.integers(0, 400)}") for e in range(40) for _ in range(8)]
    rows += [(100, f"core{i}") for i in range(6)] + [(101, f"core{i}") for i in range(6)]
    rows += [(100, "k1"), (101, "k2")]
    fk = pd.DataFrame(rows, columns=["ent_id", "key"])
    out = shared_key_tests(fk, EngineParams(), 42, min_fanout=100)
    pairs = {(int(a), int(b)) for a, b in zip(out["ent_a"], out["ent_b"], strict=True)}
    assert (100, 101) in pairs
    assert len(pairs) == 1


def test_ttp_overlap_already_documented_counts_as_agreement(platform):
    techniques = [stix2.AttackPattern(name=f"T{i}") for i in range(30)]
    camp = stix2.Campaign(name="OpX")
    mal = stix2.Malware(name="ImplantX", is_family=True)
    others = [stix2.Malware(name=f"Other{i}", is_family=True) for i in range(12)]
    rels = [stix2.Relationship(camp, "uses", mal)]
    for t in techniques[:8]:
        rels += [stix2.Relationship(camp, "uses", t), stix2.Relationship(mal, "uses", t)]
    for i, o in enumerate(others):
        for t in techniques[8 + (i % 20): 10 + (i % 20)]:
            rels.append(stix2.Relationship(o, "uses", t))
    platform.importer.import_bytes(stix2.Bundle(objects=[*techniques, camp, mal, *others, *rels]).serialize().encode(), "attack")
    result = CorrelationEngine(platform.storage).run(EngineParams(holdout_reps=0), evaluate=False)
    agreement = result.stats["entity_tests_agreement"]["ttp"]
    assert agreement["significant"] >= 1 and agreement["already_documented"] >= 1
    assert result.stats["inferred_shared_ttp"] == 0


def test_holdout_evaluation_reports_ablations(platform):
    platform.importer.import_bytes(make_bundle(families=6, per_family=10, apps_per_family=4), "feed-a")
    result = CorrelationEngine(platform.storage).run(EngineParams(holdout_reps=2))
    ev = result.stats["evaluation"]
    assert ev["status"] == "ok"
    assert set(ev["ablations"]) == {"root_only", "context", "context_temporal"}
    assert ev["ablations"]["context"]["precision"]["mean"] >= 0.9
    assert ev["ablations"]["context"]["recall"]["mean"] > ev["ablations"]["root_only"]["recall"]["mean"]


def test_temporal_feature_used_only_with_trustworthy_timestamps(platform):
    platform.importer.import_bytes(make_bundle(families=3, per_family=30), "bulk")
    snap = load_snapshot(platform.storage)
    assert not snap.indicators["ts_good"].any()
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    platform.importer.import_bytes(make_bundle(families=3, per_family=30, start=start, spread_days=200, prefix="tm"), "spread")
    snap = load_snapshot(platform.storage)
    assert snap.indicators["ts_good"].any()


def test_active_run_switches_only_after_completion(platform):
    platform.importer.import_bytes(make_bundle(families=2, per_family=4), "feed-a")
    engine = CorrelationEngine(platform.storage)
    first = engine.run(EngineParams(holdout_reps=0), evaluate=False)
    assert platform.storage.get_state("active_run") == first.run_id
    second = engine.run(EngineParams(holdout_reps=0), evaluate=False)
    assert platform.storage.get_state("active_run") == second.run_id
    runs = platform.storage.query("SELECT status FROM correlation_runs")
    assert all(r["status"] == "complete" for r in runs)


def test_concurrent_run_is_skipped(platform):
    engine = CorrelationEngine(platform.storage)
    engine._lock.acquire()
    try:
        assert engine.run() is None
    finally:
        engine._lock.release()


def test_engine_on_empty_database(platform):
    result = CorrelationEngine(platform.storage).run()
    assert result.stats["inferred_attributions"] == 0
    assert result.stats["evaluation"]["status"] == "insufficient-data"


def test_temporal_proximity_values_are_computed(platform):
    from mtip.correlate.engine import add_context
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    platform.importer.import_bytes(make_bundle(families=2, per_family=30, start=start, spread_days=400, prefix="tm"), "spread")
    snap = load_snapshot(platform.storage)
    ids = snap.indicators.sort_values("id")["id"].tolist()
    pairs = pd.DataFrame({"a": [ids[0], ids[0]], "b": [ids[1], ids[-1]], "same_root": [1.0, 0.0], "same_namespace": [0.0, 0.0],
                          "token_idf": [0.0, 0.0], "label_similarity": [0.0, 0.0]})
    out = add_context(pairs, snap.indicators, EngineParams(temporal_tau_days=180))
    assert out["temporal_known"].tolist() == [1.0, 1.0]
    near, far = out["temporal_proximity"].tolist()
    assert 0.98 < near <= 1.0
    assert far < near and far == pytest.approx(np.exp(-400.0 / 180), rel=0.05)
