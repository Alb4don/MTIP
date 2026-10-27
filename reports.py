from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any

import stix2

from . import __version__
from .correlate.engine import REL_CONFLICT, REL_INFERRED_INDICATES
from .metrics import active_run, compute_metrics
from .normalize import (
    KIND_APP, KIND_CERT, KIND_CERT_SHA1, KIND_DOMAIN, KIND_EMAIL, KIND_IPV4, KIND_IPV6, KIND_MD5, KIND_SHA1, KIND_SHA256, KIND_URL,
)
from .storage import Storage

MAX_EXPORT_INFERRED = 20_000

_PATTERNS = {
    KIND_DOMAIN: "domain-name:value", KIND_URL: "url:value", KIND_IPV4: "ipv4-addr:value", KIND_IPV6: "ipv6-addr:value",
    KIND_SHA256: "file:hashes.'SHA-256'", KIND_SHA1: "file:hashes.'SHA-1'", KIND_MD5: "file:hashes.MD5",
    KIND_EMAIL: "email-addr:value", KIND_APP: "app:id", KIND_CERT: "x509-certificate:hashes.'SHA-256'",
    KIND_CERT_SHA1: "x509-certificate:hashes.'SHA-1'",
}


def _stix_literal(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _report_rows(storage: Storage, limit: int) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    run = active_run(storage)
    if run is None:
        return None, []
    rows = storage.query(
        "SELECT ie.*, CASE WHEN ie.src_type='indicator' THEN (SELECT kind || ':' || value FROM indicators WHERE id=ie.src_id) "
        "ELSE (SELECT display_name FROM entities WHERE id=ie.src_id) END AS src_label, "
        "(SELECT display_name FROM entities WHERE id=ie.dst_id) AS dst_label FROM inferred_edges ie WHERE ie.run_id=? "
        "ORDER BY ie.rel_type, ie.score DESC LIMIT ?", (run["id"], limit))
    return run, [{
        "relation": r["rel_type"], "source": r["src_label"], "target": r["dst_label"], "score": round(float(r["score"]), 4),
        "p_value": r["p_value"], "q_value": r["q_value"], "basis": json.loads(r["basis"]),
    } for r in rows]


def build_json_report(storage: Storage, limit: int = 2000) -> dict[str, Any]:
    run, inferred = _report_rows(storage, limit)
    documented = [dict(r) for r in storage.query(
        "SELECT d.rel_type AS relation, s.name AS source, COUNT(*) AS edges FROM documented_edges d JOIN sources s ON s.id=d.source_id "
        "GROUP BY d.rel_type, s.name ORDER BY edges DESC")]
    return {
        "generator": f"mtip {__version__}",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "metrics": compute_metrics(storage),
        "evaluation": ((run or {}).get("stats") or {}).get("evaluation"),
        "model": ((run or {}).get("stats") or {}).get("model"),
        "documented_associations": {
            "definition": "asserted explicitly by a source as a STIX relationship or by an analyst confirmation",
            "summary": documented,
        },
        "statistical_inferences": {
            "definition": "derived by this platform from structural, contextual and temporal evidence; never asserted by a source",
            "items": inferred,
        },
    }


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    head = "".join(f"<th>{html.escape(str(h))}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{html.escape('' if c is None else str(c))}</td>" for c in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def build_html_report(storage: Storage, limit: int = 500) -> str:
    data = build_json_report(storage, limit)
    m = data["metrics"]
    acc = m["accuracy"]
    evaluation = data.get("evaluation") or {}
    abl_rows = []
    for name, vals in (evaluation.get("ablations") or {}).items():
        abl_rows.append([name] + [f"{vals[k]['mean']:.4f} ± {vals[k]['sd']:.4f}" for k in ("precision", "recall", "f1", "coverage")])
    src_rows = [[s["name"], s["indicators"], s["exclusive_share"], s["reliability"], s["timestamp_quality"], s["last_import_at"]]
                for s in m["coverage"]["per_source"]]
    inf_rows = [[i["relation"], i["source"], i["target"], i["score"], i["q_value"], ", ".join(i["basis"].get("reasons", [])) or i["basis"].get("method")]
                for i in data["statistical_inferences"]["items"]]
    doc_rows = [[d["relation"], d["source"], d["edges"]] for d in data["documented_associations"]["summary"]]
    summary = [
        ["Duplicates eliminated", f"{m['duplicates']['eliminated']} ({m['duplicates']['elimination_rate']:.2%})"],
        ["Confirmed indicators", f"{m['confirmation']['confirmed']} ({m['confirmation']['confirmed_share']:.2%})"],
        ["Multi-source indicators", f"{m['coverage']['indicators_in_multiple_sources']} ({m['coverage']['multi_source_share']:.2%})"],
        ["Hold-out precision / recall / F1", f"{acc['holdout_precision']} / {acc['holdout_recall']} / {acc['holdout_f1']}"],
        ["Context lift over root-only (F1)", acc["lift_context_over_root_f1"]],
        ["Temporal lift over context (F1)", acc["lift_temporal_over_context_f1"]],
        ["Indicators with usable timestamps", acc["temporal_coverage"]],
        ["Analyst precision", acc["analyst_precision"]],
    ]
    css = (
        "body{font:14px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:1100px;color:#1b2733;padding:0 1rem}"
        "h1{font-size:1.6rem}h2{font-size:1.15rem;margin-top:2rem;border-bottom:2px solid #1b2733}"
        "table{border-collapse:collapse;width:100%;font-size:12.5px}th,td{text-align:left;padding:4px 6px;border-bottom:1px solid #d5dde5;vertical-align:top}"
        "td{word-break:break-all}.doc{border-left:4px solid #1b2733;padding-left:.8rem}.inf{border-left:4px dashed #b7791f;padding-left:.8rem}"
    )
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Mobile threat correlation report</title>"
        f"<style>{css}</style></head><body>"
        f"<h1>Mobile threat correlation report</h1><p>{html.escape(data['generator'])} · {html.escape(data['generated_at'])}</p>"
        f"<h2>Summary</h2>{_table(['Metric', 'Value'], summary)}"
        f"<h2>Hold-out evaluation</h2><p>Each row hides {html.escape(str(evaluation.get('fraction')))} of documented attributions "
        f"{html.escape(str(evaluation.get('reps')))} times and measures recovery.</p>"
        f"{_table(['Configuration', 'Precision', 'Recall', 'F1', 'Coverage'], abl_rows)}"
        f"<h2>Sources</h2>{_table(['Source', 'Indicators', 'Exclusive share', 'Reliability', 'Timestamps', 'Last import'], src_rows)}"
        f"<div class=\"doc\"><h2>Documented associations</h2><p>{html.escape(data['documented_associations']['definition'])}</p>"
        f"{_table(['Relation', 'Source', 'Edges'], doc_rows)}</div>"
        f"<div class=\"inf\"><h2>Statistical inferences</h2><p>{html.escape(data['statistical_inferences']['definition'])}</p>"
        f"{_table(['Relation', 'From', 'To', 'Score', 'q-value', 'Basis'], inf_rows)}</div>"
        "</body></html>"
    )


def build_stix_bundle(storage: Storage) -> str:
    run = active_run(storage)
    identity = stix2.Identity(name="MTIP correlation engine", identity_class="system", allow_custom=True)
    objects: list[Any] = [identity]
    entity_ids: dict[int, str] = {}
    indicator_ids: dict[int, str] = {}

    def entity_ref(eid: int) -> str | None:
        if eid in entity_ids:
            return entity_ids[eid]
        row = storage.query_one("SELECT etype, display_name FROM entities WHERE id=?", (eid,))
        if row is None:
            return None
        if row["etype"] == "malware":
            obj = stix2.Malware(name=row["display_name"], is_family=True)
        elif row["etype"] == "campaign":
            obj = stix2.Campaign(name=row["display_name"])
        elif row["etype"] == "intrusion-set":
            obj = stix2.IntrusionSet(name=row["display_name"])
        elif row["etype"] == "tool":
            obj = stix2.Tool(name=row["display_name"])
        else:
            return None
        objects.append(obj)
        entity_ids[eid] = obj.id
        return obj.id

    def indicator_ref(iid: int) -> str | None:
        if iid in indicator_ids:
            return indicator_ids[iid]
        row = storage.query_one("SELECT kind, value, first_seen FROM indicators WHERE id=?", (iid,))
        if row is None or row["kind"] not in _PATTERNS:
            return None
        pattern = f"[{_PATTERNS[row['kind']]} = {_stix_literal(row['value'])}]"
        obj = stix2.Indicator(pattern=pattern, pattern_type="stix", valid_from=row["first_seen"] or datetime.now(timezone.utc),
                              indicator_types=["malicious-activity"], allow_custom=True)
        objects.append(obj)
        indicator_ids[iid] = obj.id
        return obj.id

    if run is not None:
        for r in storage.query(
            "SELECT * FROM inferred_edges WHERE run_id=? AND rel_type<>? ORDER BY score DESC LIMIT ?", (run["id"], REL_CONFLICT, MAX_EXPORT_INFERRED)):
            src = indicator_ref(r["src_id"]) if r["src_type"] == "indicator" else entity_ref(r["src_id"])
            dst = entity_ref(r["dst_id"])
            if not src or not dst:
                continue
            rel_type = "indicates" if r["rel_type"] == REL_INFERRED_INDICATES else "related-to"
            objects.append(stix2.Relationship(
                relationship_type=rel_type, source_ref=src, target_ref=dst, created_by_ref=identity.id,
                confidence=max(0, min(100, int(round(float(r["score"]) * 100)))),
                description=f"Statistical inference ({r['rel_type']}); not asserted by any source.",
                allow_custom=True,
                x_mtip_association="inferred", x_mtip_relation=r["rel_type"], x_mtip_score=float(r["score"]),
                x_mtip_q_value=r["q_value"], x_mtip_basis=json.loads(r["basis"]),
            ))
    bundle = stix2.Bundle(objects=objects, allow_custom=True)
    return bundle.serialize(pretty=False)
