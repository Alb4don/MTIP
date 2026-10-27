from pytest_bdd import given, parsers, scenarios, then, when

from mtip.correlate.engine import REL_INFERRED_INDICATES, EngineParams
from tests.conftest import make_bundle, unattributed_bundle

scenarios("features/correlation.feature")


@given("a fresh platform", target_fixture="ctx")
def fresh(platform):
    return {"platform": platform}


@given(parsers.parse('the source "{source}" reports the family bundle'))
def family_bundle(ctx, source):
    ctx["platform"].importer.import_bytes(make_bundle(families=4, per_family=6), source)
    ctx["alpha_before"] = {r["name"]: r["alpha"] for r in ctx["platform"].storage.query("SELECT name, alpha FROM sources")}


@given(parsers.parse('the source "{source}" reports "{value}" without attribution'))
@when(parsers.parse('the source "{source}" reports "{value}" without attribution'))
def unattributed(ctx, source, value):
    ctx["report"] = ctx["platform"].importer.import_bytes(unattributed_bundle([("domain-name:value", value)]), source)
    ctx["value"] = value.lower()


@given("the analyst runs a correlation")
@when("the analyst runs a correlation")
def run(ctx):
    ctx["platform"].engine.run(EngineParams(holdout_reps=1))


@when(parsers.parse('the analyst confirms the inference for "{value}"'))
def confirm(ctx, value):
    p = ctx["platform"]
    edge = p.storage.query_one(
        "SELECT ie.* FROM inferred_edges ie JOIN indicators i ON i.id=ie.src_id WHERE i.value=? AND ie.rel_type=?", (value, REL_INFERRED_INDICATES))
    p.submit_feedback("indicator", edge["src_id"], edge["dst_type"], edge["dst_id"], REL_INFERRED_INDICATES, "confirm")


@then(parsers.parse("the platform holds {n:d} indicator with that value"))
def holds(ctx, n):
    assert ctx["platform"].storage.query_one("SELECT COUNT(*) FROM indicators WHERE value=?", (ctx["value"],))[0] == n


@then(parsers.parse("{n:d} duplicate observation was eliminated"))
def dup(ctx, n):
    assert ctx["report"].duplicates == n


@then(parsers.parse('"{value}" is inferred to belong to "{family}"'))
def inferred(ctx, value, family):
    row = ctx["platform"].storage.query_one(
        "SELECT e.display_name FROM inferred_edges ie JOIN indicators i ON i.id=ie.src_id JOIN entities e ON e.id=ie.dst_id "
        "WHERE i.value=? AND ie.rel_type=?", (value, REL_INFERRED_INDICATES))
    assert row is not None and row[0] == family


@then("no indicator documented by a source carries an inferred attribution")
def disjoint(ctx):
    assert ctx["platform"].storage.query_one(
        "SELECT COUNT(*) FROM inferred_edges ie WHERE ie.rel_type=? AND EXISTS (SELECT 1 FROM documented_edges d "
        "WHERE d.src_type='indicator' AND d.src_id=ie.src_id AND d.rel_type='indicates')", (REL_INFERRED_INDICATES,))[0] == 0


@then(parsers.parse('"{value}" is documented by "{source}" as "{family}"'))
def documented(ctx, value, source, family):
    row = ctx["platform"].storage.query_one(
        "SELECT s.name, e.display_name FROM documented_edges d JOIN indicators i ON i.id=d.src_id JOIN sources s ON s.id=d.source_id "
        "JOIN entities e ON e.id=d.dst_id WHERE i.value=? AND d.rel_type='indicates'", (value,))
    assert tuple(row) == (source, family)


@then(parsers.parse('the reliability of "{source}" increased'))
def reliability(ctx, source):
    now = ctx["platform"].storage.query_one("SELECT alpha FROM sources WHERE name=?", (source,))[0]
    assert now > ctx["alpha_before"][source]


@then(parsers.parse('"{value}" has no inferred attribution'))
def none(ctx, value):
    assert ctx["platform"].storage.query_one(
        "SELECT COUNT(*) FROM inferred_edges ie JOIN indicators i ON i.id=ie.src_id WHERE i.value=?", (value,))[0] == 0
