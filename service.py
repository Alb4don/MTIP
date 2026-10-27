from __future__ import annotations

import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable

import networkx as nx

from .config import Settings
from .correlate.engine import (
    ATTRIBUTABLE_TYPES, REL_ALIAS, REL_CONFLICT, REL_INFERRED_INDICATES, REL_SHARED_INFRA, REL_SHARED_TTP,
    CorrelationEngine, EngineParams,
)
from .ingest.stix_import import ImportReport, StixImporter
from .ingest.taxii import TaxiiError, discover, fetch_collection
from .logging_setup import get_logger
from .metrics import active_run, compute_metrics
from .normalize import load_suffix_list
from .security import InputRejected, escape_like
from .storage import Storage, utcnow

log = get_logger("service")

INFERRED_RELS = (REL_INFERRED_INDICATES, REL_CONFLICT, REL_SHARED_INFRA, REL_SHARED_TTP, REL_ALIAS)
ENTITY_REL_TYPES = (REL_SHARED_INFRA, REL_SHARED_TTP, REL_ALIAS)


class NotFound(LookupError):
    pass


@dataclass
class Job:
    id: str
    kind: str
    status: str = "queued"
    created_at: str = field(default_factory=utcnow)
    finished_at: str | None = None
    result: dict[str, Any] | None = None
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


class JobManager:
    def __init__(self, workers: int = 2):
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="mtip-job")
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def submit(self, kind: str, fn: Callable[[], dict[str, Any]]) -> Job:
        job = Job(uuid.uuid4().hex, kind)
        with self._lock:
            self._jobs[job.id] = job
            if len(self._jobs) > 500:
                for key in sorted(self._jobs, key=lambda k: self._jobs[k].created_at)[:100]:
                    if self._jobs[key].status in ("complete", "failed"):
                        del self._jobs[key]

        def runner() -> None:
            job.status = "running"
            try:
                job.result = fn()
                job.status = "complete"
            except (InputRejected, TaxiiError) as exc:
                job.status = "failed"
                job.error = exc.public_message
            except Exception as exc:
                job.status = "failed"
                job.error = "the job could not be completed; see the application log"
                log.error("job failed kind=%s error=%s", kind, type(exc).__name__)
            finally:
                job.finished_at = utcnow()

        self._pool.submit(runner)
        return job

    def get(self, job_id: str) -> Job:
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            raise NotFound("job not found")
        return job

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)[:limit]
        return [j.as_dict() for j in jobs]

    def shutdown(self) -> None:
        self._pool.shutdown(wait=True, cancel_futures=True)


class Platform:
    def __init__(self, settings: Settings):
        self.settings = settings
        settings.ensure_dirs()
        load_suffix_list(settings.psl_path)
        self.storage = Storage(settings.db_path)
        self.storage.migrate(settings.backup_dir)
        self._ensure_analyst_source()
        self.importer = StixImporter(self.storage, settings.max_json_depth, settings.max_objects_per_bundle)
        self.engine = CorrelationEngine(self.storage)
        self.jobs = JobManager()
        self._correlate_pending = threading.Event()

    def close(self) -> None:
        self.jobs.shutdown()
        self.storage.close()

    def _ensure_analyst_source(self) -> None:
        with self.storage.transaction() as tx:
            tx.execute(
                "INSERT OR IGNORE INTO sources(name,kind,created_at,alpha,beta,ts_quality) VALUES('analyst','analyst',?,20,1,'observed')",
                (utcnow(),),
            )

    def health(self) -> dict[str, Any]:
        self.storage.query_one("SELECT 1")
        return {"status": "ok", "schema": self.storage.schema_version(), "engine": self.engine.state}

    def submit_import(self, data: bytes, source_name: str) -> Job:
        def work() -> dict[str, Any]:
            report = self.importer.import_bytes(data, source_name)
            self.storage.record_episode("import", {"source": source_name, "status": report.status, "objects": report.objects_total}, report.status)
            self._schedule_correlation(report)
            return report.as_dict()
        return self.jobs.submit("import", work)

    def submit_taxii_import(self, collection_url: str, source_name: str, added_after: str | None,
                            user: str | None, password: str | None) -> Job:
        def work() -> dict[str, Any]:
            data = fetch_collection(collection_url, self.settings.taxii_timeout_seconds, self.settings.allow_private_taxii,
                                    self.settings.taxii_max_pages, added_after, user, password)
            report = self.importer.import_bytes(data, source_name, "taxii", collection_url)
            self.storage.record_episode("taxii-import", {"source": source_name, "status": report.status}, report.status)
            self._schedule_correlation(report)
            return report.as_dict()
        return self.jobs.submit("taxii-import", work)

    def taxii_discover(self, url: str, user: str | None, password: str | None) -> list[dict[str, Any]]:
        found = discover(url, self.settings.taxii_timeout_seconds, self.settings.allow_private_taxii, user, password)
        return [c.as_dict() for c in found]

    def _schedule_correlation(self, report: ImportReport) -> None:
        if report.status == "complete":
            self.submit_correlation()

    def submit_correlation(self, params: EngineParams | None = None, evaluate: bool = True) -> Job:
        def work() -> dict[str, Any]:
            result = self.engine.run(params, evaluate=evaluate)
            if result is None:
                return {"status": "skipped", "reason": "a correlation run is already in progress"}
            self.storage.record_episode("metrics", {"run_id": result.run_id}, "snapshot")
            with self.storage.transaction() as tx:
                tx.execute("INSERT INTO metrics_history(created_at,run_id,metrics) VALUES(?,?,?)",
                           (utcnow(), result.run_id, json.dumps(compute_metrics(self.storage))))
                tx.execute("DELETE FROM metrics_history WHERE id <= (SELECT MAX(id) FROM metrics_history) - 1000")
            return {"run_id": result.run_id, "stats": {k: v for k, v in result.stats.items() if k != "evaluation"}}
        return self.jobs.submit("correlation", work)

    def overview(self) -> dict[str, Any]:
        metrics = compute_metrics(self.storage)
        run = active_run(self.storage)
        counts = {
            "indicators_by_kind": {r["kind"]: r["n"] for r in self.storage.query("SELECT kind, COUNT(*) AS n FROM indicators GROUP BY kind ORDER BY n DESC")},
            "entities_by_type": {r["etype"]: r["n"] for r in self.storage.query("SELECT etype, COUNT(*) AS n FROM entities GROUP BY etype ORDER BY n DESC")},
        }
        return {"metrics": metrics, "counts": counts, "evaluation": (run or {}).get("stats", {}).get("evaluation"),
                "model": (run or {}).get("stats", {}).get("model"), "engine": self.engine.state,
                "run_stats": {k: v for k, v in ((run or {}).get("stats") or {}).items() if k not in ("evaluation", "model")}}

    def metrics_history(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.storage.query("SELECT created_at, run_id, metrics FROM metrics_history ORDER BY id DESC LIMIT ?", (limit,))
        out = []
        for r in rows:
            try:
                m = json.loads(r["metrics"])
            except ValueError:
                continue
            out.append({
                "created_at": r["created_at"], "run_id": r["run_id"],
                "elimination_rate": m["duplicates"]["elimination_rate"], "confirmed_share": m["confirmation"]["confirmed_share"],
                "holdout_f1": m["accuracy"]["holdout_f1"], "holdout_precision": m["accuracy"]["holdout_precision"],
                "analyst_precision": m["accuracy"]["analyst_precision"], "sources": m["coverage"]["sources"],
            })
        return list(reversed(out))

    def _run_id(self) -> int | None:
        value = self.storage.get_state("active_run")
        return int(value) if value is not None else None

    def list_indicators(self, kind: str | None, search: str | None, status: str | None, source_id: int | None,
                        offset: int, limit: int) -> dict[str, Any]:
        run_id = self._run_id() or -1
        where = ["1=1"]
        params: list[Any] = []
        if kind:
            where.append("i.kind=?")
            params.append(kind)
        if search:
            where.append("i.value LIKE ? ESCAPE '\\'")
            params.append(f"%{escape_like(search)}%")
        if source_id is not None:
            where.append("EXISTS (SELECT 1 FROM observations o WHERE o.indicator_id=i.id AND o.source_id=?)")
            params.append(source_id)
        documented = "EXISTS (SELECT 1 FROM documented_edges d WHERE d.src_type='indicator' AND d.src_id=i.id AND d.rel_type='indicates')"
        inferred = "EXISTS (SELECT 1 FROM inferred_edges ie WHERE ie.run_id=? AND ie.src_type='indicator' AND ie.src_id=i.id AND ie.rel_type=?)"
        if status == "documented":
            where.append(documented)
        elif status == "inferred":
            where.append(inferred)
            params += [run_id, REL_INFERRED_INDICATES]
        elif status == "conflict":
            where.append(inferred)
            params += [run_id, REL_CONFLICT]
        elif status == "unattributed":
            where.append(f"NOT {documented} AND NOT {inferred}")
            params += [run_id, REL_INFERRED_INDICATES]
        elif status == "confirmed":
            where.append("(i.analyst_verdict='confirm' OR (SELECT COUNT(DISTINCT source_id) FROM observations o WHERE o.indicator_id=i.id)>=2)")
        clause = " AND ".join(where)
        total = int(self.storage.query_one(f"SELECT COUNT(*) FROM indicators i WHERE {clause}", params)[0])
        rows = self.storage.query(
            f"SELECT i.id, i.kind, i.value, i.root, i.shared_root, i.first_seen, i.analyst_verdict, "
            f"(SELECT COUNT(DISTINCT source_id) FROM observations o WHERE o.indicator_id=i.id) AS sources, "
            f"(SELECT GROUP_CONCAT(DISTINCT e.display_name) FROM documented_edges d JOIN entities e ON e.id=d.dst_id "
            f" WHERE d.src_type='indicator' AND d.src_id=i.id AND d.rel_type='indicates') AS documented, "
            f"(SELECT e.display_name || '|' || ie.score FROM inferred_edges ie JOIN entities e ON e.id=ie.dst_id "
            f" WHERE ie.run_id=? AND ie.src_type='indicator' AND ie.src_id=i.id AND ie.rel_type IN (?,?) ORDER BY ie.score DESC LIMIT 1) AS inferred, "
            f"(SELECT ie.rel_type FROM inferred_edges ie WHERE ie.run_id=? AND ie.src_type='indicator' AND ie.src_id=i.id "
            f" AND ie.rel_type IN (?,?) ORDER BY ie.score DESC LIMIT 1) AS inferred_rel "
            f"FROM indicators i WHERE {clause} ORDER BY i.id LIMIT ? OFFSET ?",
            [run_id, REL_INFERRED_INDICATES, REL_CONFLICT, run_id, REL_INFERRED_INDICATES, REL_CONFLICT, *params, limit, offset],
        )
        items = []
        for r in rows:
            inferred_name, inferred_score = None, None
            if r["inferred"]:
                name, _, score = r["inferred"].rpartition("|")
                inferred_name, inferred_score = name, round(float(score), 4)
            items.append({
                "id": r["id"], "kind": r["kind"], "value": r["value"], "root": r["root"], "shared_root": bool(r["shared_root"]),
                "first_seen": r["first_seen"], "sources": r["sources"], "verdict": r["analyst_verdict"],
                "documented": sorted(set((r["documented"] or "").split(","))) if r["documented"] else [],
                "inferred": {"entity": inferred_name, "score": inferred_score, "relation": r["inferred_rel"]} if inferred_name else None,
                "confirmed": (r["sources"] or 0) >= 2 or r["analyst_verdict"] == "confirm",
            })
        return {"total": total, "offset": offset, "limit": limit, "items": items}

    def indicator_detail(self, indicator_id: int) -> dict[str, Any]:
        row = self.storage.query_one("SELECT * FROM indicators WHERE id=?", (indicator_id,))
        if row is None:
            raise NotFound("indicator not found")
        run_id = self._run_id() or -1
        observations = [dict(r) for r in self.storage.query(
            "SELECT s.name AS source, s.ts_quality AS timestamp_quality, o.observed_at, o.raw_value, im.received_at "
            "FROM observations o JOIN sources s ON s.id=o.source_id JOIN imports im ON im.id=o.import_id WHERE o.indicator_id=? ORDER BY o.id LIMIT 200",
            (indicator_id,))]
        documented = [dict(r) for r in self.storage.query(
            "SELECT d.rel_type, d.dst_type AS target_type, d.dst_id AS target_id, "
            "COALESCE(e.display_name, (SELECT value FROM indicators x WHERE x.id=d.dst_id AND d.dst_type='indicator')) AS target, "
            "s.name AS source, d.observed_at, d.stix_rel_id FROM documented_edges d JOIN sources s ON s.id=d.source_id "
            "LEFT JOIN entities e ON e.id=d.dst_id AND d.dst_type<>'indicator' "
            "WHERE d.src_type='indicator' AND d.src_id=? ORDER BY d.id LIMIT 200", (indicator_id,))]
        inferred = []
        for r in self.storage.query(
            "SELECT ie.rel_type, ie.dst_type, ie.dst_id, e.display_name AS target, ie.score, ie.basis, ie.features "
            "FROM inferred_edges ie JOIN entities e ON e.id=ie.dst_id WHERE ie.run_id=? AND ie.src_type='indicator' AND ie.src_id=?",
            (run_id, indicator_id)):
            inferred.append({
                "relation": r["rel_type"], "target_type": r["dst_type"], "target_id": r["dst_id"], "target": r["target"],
                "score": r["score"], "basis": json.loads(r["basis"]), "features": json.loads(r["features"]),
            })
        siblings = []
        if row["root"] and not row["shared_root"]:
            siblings = [dict(r) for r in self.storage.query(
                "SELECT id, kind, value FROM indicators WHERE root=? AND id<>? ORDER BY id LIMIT 25", (row["root"], indicator_id))]
        return {"indicator": dict(row), "observations": observations, "documented": documented, "inferred": inferred,
                "same_root": siblings}

    def list_inferences(self, relation: str | None, min_score: float, offset: int, limit: int) -> dict[str, Any]:
        run_id = self._run_id()
        if run_id is None:
            return {"total": 0, "items": [], "offset": offset, "limit": limit}
        where = ["ie.run_id=?", "ie.score>=?"]
        params: list[Any] = [run_id, min_score]
        if relation:
            where.append("ie.rel_type=?")
            params.append(relation)
        clause = " AND ".join(where)
        total = int(self.storage.query_one(f"SELECT COUNT(*) FROM inferred_edges ie WHERE {clause}", params)[0])
        rows = self.storage.query(
            "SELECT ie.*, CASE WHEN ie.src_type='indicator' THEN (SELECT value FROM indicators WHERE id=ie.src_id) "
            "ELSE (SELECT display_name FROM entities WHERE id=ie.src_id) END AS src_label, "
            "(SELECT display_name FROM entities WHERE id=ie.dst_id) AS dst_label, "
            "(SELECT f.verdict FROM feedback f WHERE f.src_type=ie.src_type AND f.src_id=ie.src_id AND f.dst_type=ie.dst_type "
            " AND f.dst_id=ie.dst_id AND f.rel_type=ie.rel_type ORDER BY f.id DESC LIMIT 1) AS verdict "
            f"FROM inferred_edges ie WHERE {clause} ORDER BY ie.score DESC, ie.src_id LIMIT ? OFFSET ?",
            [*params, limit, offset],
        )
        items = [{
            "src_type": r["src_type"], "src_id": r["src_id"], "src": r["src_label"], "dst_type": r["dst_type"], "dst_id": r["dst_id"],
            "dst": r["dst_label"], "relation": r["rel_type"], "score": r["score"], "p_value": r["p_value"], "q_value": r["q_value"],
            "basis": json.loads(r["basis"]), "features": json.loads(r["features"]), "verdict": r["verdict"],
        } for r in rows]
        return {"total": total, "offset": offset, "limit": limit, "items": items}

    def submit_feedback(self, src_type: str, src_id: int, dst_type: str, dst_id: int, relation: str, verdict: str) -> dict[str, Any]:
        run_id = self._run_id()
        edge = self.storage.query_one(
            "SELECT * FROM inferred_edges WHERE run_id=? AND src_type=? AND src_id=? AND dst_type=? AND dst_id=? AND rel_type=?",
            (run_id or -1, src_type, src_id, dst_type, dst_id, relation),
        )
        if edge is None:
            raise NotFound("inference not found in the active correlation run")
        basis = json.loads(edge["basis"])
        supporting_sources: list[int] = []
        if relation in (REL_INFERRED_INDICATES, REL_CONFLICT):
            via = (basis.get("via_indicator") or {}).get("id")
            target_entity = dst_id
            if relation == REL_CONFLICT:
                supporting_sources = [r[0] for r in self.storage.query(
                    "SELECT DISTINCT source_id FROM documented_edges WHERE src_type='indicator' AND src_id=? AND rel_type='indicates'", (src_id,))]
            elif via is not None:
                supporting_sources = [r[0] for r in self.storage.query(
                    "SELECT DISTINCT source_id FROM documented_edges WHERE src_type='indicator' AND src_id=? AND dst_id=? AND rel_type='indicates'",
                    (int(via), target_entity))]
        with self.storage.transaction() as tx:
            tx.execute(
                "INSERT INTO feedback(created_at,src_type,src_id,dst_type,dst_id,rel_type,verdict,features,sources) VALUES(?,?,?,?,?,?,?,?,?)",
                (utcnow(), src_type, src_id, dst_type, dst_id, relation, verdict, edge["features"], json.dumps(supporting_sources)),
            )
            analyst = tx.execute("SELECT id FROM sources WHERE name='analyst'").fetchone()[0]
            positive = (verdict == "confirm") != (relation == REL_CONFLICT)
            for sid in supporting_sources:
                if sid == analyst:
                    continue
                column = "alpha" if positive else "beta"
                tx.execute(f"UPDATE sources SET {column}={column}+1 WHERE id=?", (sid,))
            if relation in (REL_INFERRED_INDICATES, REL_CONFLICT) and src_type == "indicator":
                if relation == REL_INFERRED_INDICATES:
                    tx.execute("UPDATE indicators SET analyst_verdict=? WHERE id=?", (verdict, src_id))
                if verdict == "confirm":
                    import_id = self._analyst_import(tx, analyst)
                    tx.execute(
                        "INSERT OR IGNORE INTO documented_edges(src_type,src_id,dst_type,dst_id,rel_type,source_id,import_id,stix_rel_id,observed_at) "
                        "VALUES('indicator',?,?,?,'indicates',?,?,NULL,?)",
                        (src_id, dst_type, dst_id, analyst, import_id, utcnow()),
                    )
        self.storage.record_episode("feedback", {"relation": relation, "verdict": verdict}, "stored")
        return {"stored": True, "sources_updated": len(supporting_sources)}

    @staticmethod
    def _analyst_import(tx, analyst_id: int) -> int:
        row = tx.execute("SELECT id FROM imports WHERE source_id=? AND content_sha256='analyst-feedback'", (analyst_id,)).fetchone()
        if row:
            return int(row[0])
        return int(tx.execute(
            "INSERT INTO imports(source_id,received_at,content_sha256,status) VALUES(?,?,'analyst-feedback','complete')",
            (analyst_id, utcnow()),
        ).lastrowid)

    def sources(self) -> list[dict[str, Any]]:
        per_source = {s["id"]: s for s in compute_metrics(self.storage)["coverage"]["per_source"]}
        out = []
        for sid, info in per_source.items():
            history = [dict(r) for r in self.storage.query(
                "SELECT received_at, objects_total, accepted, rejected, duplicates, ts_quality, status FROM imports "
                "WHERE source_id=? ORDER BY id DESC LIMIT 50", (sid,))]
            out.append({**info, "history": history})
        return out

    def entities(self, search: str | None, etype: str | None, limit: int) -> list[dict[str, Any]]:
        where, params = ["etype IN (?,?,?,?)"], list(ATTRIBUTABLE_TYPES)
        if etype:
            where.append("etype=?")
            params.append(etype)
        if search:
            where.append("display_name LIKE ? ESCAPE '\\'")
            params.append(f"%{escape_like(search)}%")
        rows = self.storage.query(
            "SELECT e.id, e.etype, e.display_name, e.first_seen, e.last_seen, "
            "(SELECT COUNT(*) FROM documented_edges d WHERE d.dst_id=e.id AND d.src_type='indicator' AND d.rel_type='indicates') AS indicators "
            f"FROM entities e WHERE {' AND '.join(where)} ORDER BY indicators DESC, display_name LIMIT ?", [*params, limit])
        return [dict(r) for r in rows]

    def campaign_graph(self, focus: int | None, include_inferred: bool, max_nodes: int) -> dict[str, Any]:
        run_id = self._run_id() or -1
        G = nx.Graph()
        ent_rows = {r["id"]: dict(r) for r in self.storage.query(
            "SELECT id, etype, display_name FROM entities WHERE etype IN (?,?,?,?)", ATTRIBUTABLE_TYPES)}
        ind_counts = {r[0]: r[1] for r in self.storage.query(
            "SELECT dst_id, COUNT(*) FROM documented_edges WHERE src_type='indicator' AND rel_type='indicates' GROUP BY dst_id")}

        def add_entity(eid: int) -> str:
            key = f"e{eid}"
            if key not in G:
                info = ent_rows.get(eid, {"etype": "malware", "display_name": str(eid)})
                G.add_node(key, label=info["display_name"], type=info["etype"], indicators=int(ind_counts.get(eid, 0)), ref=eid)
            return key

        for r in self.storage.query(
            "SELECT src_type, src_id, dst_type, dst_id, rel_type, COUNT(DISTINCT source_id) AS sources FROM documented_edges "
            "WHERE src_type IN (?,?,?,?) AND dst_type IN (?,?,?,?) GROUP BY src_type, src_id, dst_type, dst_id, rel_type",
            (*ATTRIBUTABLE_TYPES, *ATTRIBUTABLE_TYPES)):
            a, b = add_entity(r["src_id"]), add_entity(r["dst_id"])
            G.add_edge(a, b, kind="documented", relation=r["rel_type"], weight=1.0, sources=r["sources"])
        for r in self.storage.query(
            "SELECT i.root, d.dst_id, COUNT(*) AS n FROM documented_edges d JOIN indicators i ON i.id=d.src_id "
            "WHERE d.src_type='indicator' AND d.rel_type='indicates' AND i.root IS NOT NULL AND i.shared_root=0 "
            "AND i.root IN (SELECT i2.root FROM documented_edges d2 JOIN indicators i2 ON i2.id=d2.src_id "
            "WHERE d2.src_type='indicator' AND d2.rel_type='indicates' AND i2.root IS NOT NULL AND i2.shared_root=0 "
            "GROUP BY i2.root HAVING COUNT(DISTINCT d2.dst_id)=2) "
            "GROUP BY i.root, d.dst_id"):
            root_key = f"r:{r['root']}"
            G.add_node(root_key, label=r["root"], type="infrastructure", indicators=0, ref=r["root"])
            G.add_edge(root_key, add_entity(r["dst_id"]), kind="documented", relation="indicates", weight=1.0, count=r["n"])
        if include_inferred:
            for r in self.storage.query(
                "SELECT src_id, dst_id, rel_type, score, q_value FROM inferred_edges WHERE run_id=? AND rel_type IN (?,?,?)",
                (run_id, *ENTITY_REL_TYPES)):
                a, b = add_entity(r["src_id"]), add_entity(r["dst_id"])
                if not G.has_edge(a, b):
                    G.add_edge(a, b, kind="inferred", relation=r["rel_type"], weight=0.5 * float(r["score"]), score=r["score"], q=r["q_value"])
            for r in self.storage.query(
                "SELECT i.root, ie.dst_id, COUNT(*) AS n, MAX(ie.score) AS score FROM inferred_edges ie JOIN indicators i ON i.id=ie.src_id "
                "WHERE ie.run_id=? AND ie.rel_type=? AND i.root IS NOT NULL GROUP BY i.root, ie.dst_id",
                (run_id, REL_INFERRED_INDICATES)):
                root_key = f"r:{r['root']}"
                if root_key not in G:
                    G.add_node(root_key, label=r["root"], type="infrastructure", indicators=0, ref=r["root"])
                b = add_entity(r["dst_id"])
                if not G.has_edge(root_key, b):
                    G.add_edge(root_key, b, kind="inferred", relation=REL_INFERRED_INDICATES, weight=0.5 * float(r["score"]), score=r["score"], count=r["n"])
        if focus is not None:
            key = f"e{focus}"
            if key not in G:
                if focus not in ent_rows:
                    raise NotFound("entity not found")
                add_entity(focus)
            G = G.subgraph(nx.ego_graph(G, key, radius=2).nodes).copy()
        if G.number_of_nodes() > max_nodes:
            ranked = sorted(G.degree(weight="weight"), key=lambda kv: kv[1], reverse=True)[:max_nodes]
            G = G.subgraph([n for n, _ in ranked]).copy()
        if G.number_of_nodes() == 0:
            return {"nodes": [], "edges": [], "communities": 0}
        communities = nx.community.louvain_communities(G, weight="weight", seed=42) if G.number_of_edges() else [{n} for n in G]
        membership = {n: i for i, group in enumerate(sorted(communities, key=len, reverse=True)) for n in group}
        rank = nx.pagerank(G, weight="weight") if G.number_of_edges() else {n: 1.0 / G.number_of_nodes() for n in G}
        n_nodes = G.number_of_nodes()
        layout = nx.spring_layout(G, seed=7, weight=None, k=2.2 / (n_nodes ** 0.5), iterations=120) if n_nodes > 1 else {n: (0.0, 0.0) for n in G}
        nodes = [{
            "id": n, "label": d["label"], "type": d["type"], "ref": d["ref"], "indicators": d.get("indicators", 0),
            "community": membership.get(n, 0), "rank": round(rank.get(n, 0.0), 6),
            "x": round(float(layout[n][0]), 4), "y": round(float(layout[n][1]), 4),
        } for n, d in G.nodes(data=True)]
        edges = [{"source": a, "target": b, **{k: v for k, v in d.items() if k != "weight"}} for a, b, d in G.edges(data=True)]
        return {"nodes": nodes, "edges": edges, "communities": len(communities)}
