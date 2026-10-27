import json

import pytest

from mtip.correlate.engine import REL_INFERRED_INDICATES, EngineParams
from mtip.metrics import compute_metrics
from mtip.reports import build_html_report, build_json_report, build_stix_bundle
from mtip.service import NotFound
from mtip.storage import MIGRATIONS, Storage
from tests.conftest import make_bundle, unattributed_bundle


def _setup(platform):
    platform.importer.import_bytes(make_bundle(families=4, per_family=6), "feed-a")
    platform.importer.import_bytes(unattributed_bundle([("domain-name:value", "fresh.fam1-cloudops.com"),
                                                        ("domain-name:value", "node0.fam0-cloudops.com")]), "feed-b")
    platform.engine.run(EngineParams(holdout_reps=1))
    return platform.storage.query_one("SELECT * FROM inferred_edges WHERE rel_type=?", (REL_INFERRED_INDICATES,))


def test_confirm_feedback_promotes_to_documented_and_updates_reliability(platform):
    edge = _setup(platform)
    before = platform.storage.query_one("SELECT alpha FROM sources WHERE name='feed-a'")[0]
    out = platform.submit_feedback("indicator", edge["src_id"], edge["dst_type"], edge["dst_id"], REL_INFERRED_INDICATES, "confirm")
    assert out["sources_updated"] == 1
    assert platform.storage.query_one("SELECT alpha FROM sources WHERE name='feed-a'")[0] == before + 1
    doc = platform.storage.query_one(
        "SELECT s.name FROM documented_edges d JOIN sources s ON s.id=d.source_id WHERE d.src_id=? AND d.rel_type='indicates'", (edge["src_id"],))
    assert doc["name"] == "analyst"
    assert compute_metrics(platform.storage)["confirmation"]["analyst_confirmed"] == 1


def test_reject_feedback_lowers_reliability(platform):
    edge = _setup(platform)
    before = platform.storage.query_one("SELECT beta FROM sources WHERE name='feed-a'")[0]
    platform.submit_feedback("indicator", edge["src_id"], edge["dst_type"], edge["dst_id"], REL_INFERRED_INDICATES, "reject")
    assert platform.storage.query_one("SELECT beta FROM sources WHERE name='feed-a'")[0] == before + 1


def test_feedback_on_unknown_edge(platform):
    _setup(platform)
    with pytest.raises(NotFound):
        platform.submit_feedback("indicator", 999999, "malware", 1, REL_INFERRED_INDICATES, "confirm")


def test_feedback_is_learned_by_next_model(platform):
    edge = _setup(platform)
    platform.submit_feedback("indicator", edge["src_id"], edge["dst_type"], edge["dst_id"], REL_INFERRED_INDICATES, "reject")
    result = platform.engine.run(EngineParams(holdout_reps=0), evaluate=False)
    assert result.stats["model"]["trained_on"] >= 1
    assert platform.storage.query_one("SELECT COUNT(*) FROM feedback")[0] == 1


def test_metrics(platform):
    _setup(platform)
    m = compute_metrics(platform.storage)
    assert m["duplicates"]["eliminated"] == 1
    assert m["coverage"]["sources"] == 2
    assert m["coverage"]["indicators_in_multiple_sources"] == 1
    assert m["confirmation"]["confirmed"] == 1
    assert 0 < m["accuracy"]["holdout_precision"] <= 1
    assert m["associations"]["inferred"][REL_INFERRED_INDICATES] >= 1


def test_listing_filters(platform):
    _setup(platform)
    inferred = platform.list_indicators(None, None, "inferred", None, 0, 50)
    assert inferred["total"] == 1 and inferred["items"][0]["value"] == "fresh.fam1-cloudops.com"
    assert inferred["items"][0]["inferred"]["entity"] == "FamFamily1"
    confirmed = platform.list_indicators(None, None, "confirmed", None, 0, 50)
    assert confirmed["items"][0]["value"] == "node0.fam0-cloudops.com"
    search = platform.list_indicators("domain", "fresh", None, None, 0, 50)
    assert search["total"] == 1
    assert platform.list_indicators(None, "%", None, None, 0, 50)["total"] == 0
    detail = platform.indicator_detail(inferred["items"][0]["id"])
    assert detail["inferred"][0]["basis"]["via_indicator"]["value"].endswith("fam1-cloudops.com")


def test_graph_contains_documented_and_inferred_kinds(platform):
    _setup(platform)
    graph = platform.campaign_graph(None, True, 300)
    kinds = {e["kind"] for e in graph["edges"]}
    assert "inferred" in kinds
    focus = platform.campaign_graph(int(platform.storage.query_one("SELECT id FROM entities LIMIT 1")[0]), True, 300)
    assert focus["nodes"]
    with pytest.raises(NotFound):
        platform.campaign_graph(10**9, True, 300)


def test_reports_keep_documented_and_inferred_separate(platform):
    _setup(platform)
    js = build_json_report(platform.storage)
    assert js["statistical_inferences"]["items"]
    assert all(i["relation"] for i in js["statistical_inferences"]["items"])
    html = build_html_report(platform.storage)
    assert "Statistical inferences" in html and "Documented associations" in html
    bundle = json.loads(build_stix_bundle(platform.storage))
    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    assert rels and all(r["x_mtip_association"] == "inferred" for r in rels)


def test_migrations_are_idempotent_and_backed_up(tmp_path):
    storage = Storage(tmp_path / "db.sqlite3")
    assert storage.migrate(tmp_path / "bk") == len(MIGRATIONS)
    with storage.transaction() as tx:
        tx.execute("PRAGMA user_version=1")
    storage.migrate(tmp_path / "bk")
    assert storage.schema_version() == len(MIGRATIONS)
    assert list((tmp_path / "bk").glob("*.sqlite3"))
    storage.close()


def test_newer_schema_refused(tmp_path):
    storage = Storage(tmp_path / "db.sqlite3")
    storage.migrate()
    with storage.transaction() as tx:
        tx.execute(f"PRAGMA user_version={len(MIGRATIONS) + 5}")
    with pytest.raises(RuntimeError):
        storage.migrate()
    storage.close()


def test_confirmed_conflict_records_analyst_attribution_and_penalises_source(platform):
    import stix2
    from mtip.correlate.engine import REL_CONFLICT
    platform.importer.import_bytes(make_bundle(families=3, per_family=8), "feed-a")
    wrong = stix2.Malware(name="FamFamily0", is_family=True)
    ind = stix2.Indicator(pattern="[domain-name:value='mislabelled.fam2-cloudops.com']", pattern_type="stix", valid_from="2025-01-01T00:00:00Z")
    platform.importer.import_bytes(stix2.Bundle(objects=[wrong, ind, stix2.Relationship(ind, "indicates", wrong)]).serialize().encode(), "feed-x")
    platform.engine.run(EngineParams(holdout_reps=0), evaluate=False)
    edge = platform.storage.query_one("SELECT * FROM inferred_edges WHERE rel_type=?", (REL_CONFLICT,))
    beta_before = platform.storage.query_one("SELECT beta FROM sources WHERE name='feed-x'")[0]
    platform.submit_feedback("indicator", edge["src_id"], edge["dst_type"], edge["dst_id"], REL_CONFLICT, "confirm")
    assert platform.storage.query_one("SELECT beta FROM sources WHERE name='feed-x'")[0] == beta_before + 1
    names = {r[0] for r in platform.storage.query(
        "SELECT s.name FROM documented_edges d JOIN sources s ON s.id=d.source_id WHERE d.src_id=? AND d.rel_type='indicates'", (edge["src_id"],))}
    assert names == {"feed-x", "analyst"}


def test_stix_export_handles_android_package_patterns(platform):
    platform.importer.import_bytes(make_bundle(families=3, per_family=4, apps_per_family=4), "feed-a")
    platform.importer.import_bytes(unattributed_bundle([("app:id", "com.fam1vendor.release"),
                                                        ("url:value", "http://x.fam0-cloudops.com/it's\\here")]), "feed-b")
    assert platform.storage.query_one("SELECT value FROM indicators WHERE kind='url'")[0] == "http://x.fam0-cloudops.com/it's\\here"
    platform.engine.run(EngineParams(holdout_reps=0), evaluate=False)
    bundle = json.loads(build_stix_bundle(platform.storage))
    patterns = [o["pattern"] for o in bundle["objects"] if o["type"] == "indicator"]
    assert "[app:id = 'com.fam1vendor.release']" in patterns
    assert "[url:value = 'http://x.fam0-cloudops.com/it\\'s\\\\here']" in patterns
