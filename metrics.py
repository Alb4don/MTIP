from __future__ import annotations

import json
from typing import Any

from .correlate.stats import beta_interval, beta_mean
from .storage import Storage


def _ratio(num: float, den: float) -> float:
    return round(num / den, 6) if den else 0.0


def active_run(storage: Storage) -> dict[str, Any] | None:
    run_id = storage.get_state("active_run")
    if run_id is None:
        return None
    row = storage.query_one("SELECT id, started_at, finished_at, status, stats FROM correlation_runs WHERE id=?", (int(run_id),))
    if row is None:
        return None
    try:
        stats = json.loads(row["stats"] or "{}")
    except ValueError:
        stats = {}
    return {"id": row["id"], "started_at": row["started_at"], "finished_at": row["finished_at"], "status": row["status"], "stats": stats}


def compute_metrics(storage: Storage) -> dict[str, Any]:
    q1 = storage.query_one
    total_obs = int(q1("SELECT COUNT(*) FROM observations")[0])
    distinct_ind = int(q1("SELECT COUNT(*) FROM indicators")[0])
    variant_merges = int(q1(
        "SELECT COUNT(*) FROM observations o JOIN indicators i ON i.id=o.indicator_id WHERE o.raw_value<>i.value"
    )[0])
    cross_source = int(q1(
        "SELECT COUNT(*) FROM (SELECT indicator_id FROM observations GROUP BY indicator_id HAVING COUNT(DISTINCT source_id)>=2)"
    )[0])
    analyst_confirmed = int(q1("SELECT COUNT(*) FROM indicators WHERE analyst_verdict='confirm'")[0])
    confirmed = int(q1(
        "SELECT COUNT(*) FROM indicators i WHERE i.analyst_verdict='confirm' OR "
        "(SELECT COUNT(DISTINCT source_id) FROM observations o WHERE o.indicator_id=i.id)>=2"
    )[0])
    documented_attr = int(q1(
        "SELECT COUNT(DISTINCT src_id) FROM documented_edges WHERE src_type='indicator' AND rel_type='indicates'"
    )[0])
    sources = []
    for row in storage.query(
        "SELECT s.id, s.name, s.kind, s.alpha, s.beta, s.ts_quality, s.last_import_at, "
        "(SELECT COUNT(DISTINCT indicator_id) FROM observations o WHERE o.source_id=s.id) AS indicators, "
        "(SELECT COUNT(*) FROM (SELECT o.indicator_id FROM observations o WHERE o.source_id=s.id GROUP BY o.indicator_id "
        " HAVING (SELECT COUNT(DISTINCT o2.source_id) FROM observations o2 WHERE o2.indicator_id=o.indicator_id)=1)) AS unique_indicators, "
        "(SELECT COUNT(DISTINCT dst_id) FROM documented_edges d WHERE d.source_id=s.id AND d.dst_type<>'indicator') AS entities, "
        "(SELECT COUNT(*) FROM imports im WHERE im.source_id=s.id) AS imports "
        "FROM sources s ORDER BY s.kind='analyst', s.name"
    ):
        lo, hi = beta_interval(row["alpha"], row["beta"])
        sources.append({
            "id": row["id"], "name": row["name"], "kind": row["kind"], "indicators": row["indicators"],
            "unique_indicators": row["unique_indicators"], "entities": row["entities"], "imports": row["imports"],
            "coverage": _ratio(row["indicators"], distinct_ind), "exclusive_share": _ratio(row["unique_indicators"], row["indicators"]),
            "reliability": round(beta_mean(row["alpha"], row["beta"]), 4), "reliability_ci": [round(lo, 4), round(hi, 4)],
            "timestamp_quality": row["ts_quality"], "last_import_at": row["last_import_at"],
        })
    feedback = {r["verdict"]: r["n"] for r in storage.query(
        "SELECT verdict, COUNT(*) AS n FROM feedback WHERE rel_type='inferred-indicates' GROUP BY verdict")}
    run = active_run(storage)
    stats = run["stats"] if run else {}
    evaluation = stats.get("evaluation") or {}
    full = (evaluation.get("ablations") or {}).get("context_temporal") or {}
    inferred_counts = {}
    if run:
        inferred_counts = {r["rel_type"]: r["n"] for r in storage.query(
            "SELECT rel_type, COUNT(*) AS n FROM inferred_edges WHERE run_id=? GROUP BY rel_type", (run["id"],))}
    families = int(q1("SELECT COUNT(*) FROM entities WHERE etype IN ('malware','tool')")[0])
    families_with_ind = int(q1(
        "SELECT COUNT(DISTINCT dst_id) FROM documented_edges WHERE src_type='indicator' AND rel_type='indicates'"
    )[0])
    return {
        "duplicates": {
            "observations": total_obs, "canonical_indicators": distinct_ind,
            "eliminated": total_obs - distinct_ind, "elimination_rate": _ratio(total_obs - distinct_ind, total_obs),
            "defanged_or_variant_forms_merged": variant_merges,
        },
        "coverage": {
            "sources": sum(1 for x in sources if x["kind"] != "analyst"), "indicators_in_multiple_sources": cross_source,
            "multi_source_share": _ratio(cross_source, distinct_ind),
            "families_with_indicators": families_with_ind, "families_total": families,
            "family_coverage": _ratio(families_with_ind, families), "per_source": sources,
        },
        "confirmation": {
            "confirmed": confirmed, "analyst_confirmed": analyst_confirmed, "multi_source_confirmed": cross_source,
            "confirmed_share": _ratio(confirmed, distinct_ind),
            "documented_attribution_share": _ratio(documented_attr, distinct_ind),
            "rule": "confirmed = asserted by at least two independent sources, or confirmed by an analyst",
        },
        "accuracy": {
            "holdout_precision": (full.get("precision") or {}).get("mean"),
            "holdout_recall": (full.get("recall") or {}).get("mean"),
            "holdout_f1": (full.get("f1") or {}).get("mean"),
            "holdout_status": evaluation.get("status"),
            "lift_context_over_root_f1": evaluation.get("lift_context_over_root_f1"),
            "lift_temporal_over_context_f1": evaluation.get("lift_temporal_over_context_f1"),
            "temporal_coverage": evaluation.get("temporal_coverage"),
            "analyst_confirmed": int(feedback.get("confirm", 0)), "analyst_rejected": int(feedback.get("reject", 0)),
            "analyst_precision": _ratio(feedback.get("confirm", 0), feedback.get("confirm", 0) + feedback.get("reject", 0)) if feedback else None,
        },
        "associations": {
            "documented": int(q1("SELECT COUNT(*) FROM documented_edges")[0]),
            "inferred": inferred_counts,
        },
        "run": {k: run[k] for k in ("id", "finished_at", "status")} if run else None,
    }
