from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

import stix2
from stix2.exceptions import STIXError
from stix2patterns.v21.pattern import Pattern
from stix2patterns.exceptions import ParseException

from ..logging_setup import get_logger
from ..normalize import (
    NormalizationError, NormalizedIndicator, is_shared_infrastructure, normalize,
    normalize_family_name, root_of, stix_path_to_kind,
)
from ..security import InputRejected, check_json_depth
from ..storage import Storage, utcnow

log = get_logger("ingest")

ENTITY_TYPES = frozenset({"malware", "campaign", "intrusion-set", "tool", "threat-actor", "attack-pattern"})
KEPT_RELATIONSHIPS = frozenset({"indicates", "uses", "attributed-to", "variant-of", "related-to", "derived-from", "communicates-with"})

TS_OBSERVED = "observed"
TS_PUBLICATION = "publication"
TS_BULK = "bulk-export"
TS_UNKNOWN = "unknown"


@dataclass
class ImportReport:
    source: str
    status: str
    objects_total: int = 0
    accepted: int = 0
    rejected: int = 0
    duplicates: int = 0
    indicators_new: int = 0
    entities_new: int = 0
    documented_edges: int = 0
    non_atomic_comparisons: int = 0
    unresolved_relationships: int = 0
    ts_quality: str = TS_UNKNOWN
    reject_reasons: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


def _parse_ts(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or len(value) > 40:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def _unquote(literal: Any) -> str | None:
    if not isinstance(literal, str):
        return None
    text = literal.strip()
    if len(text) < 2 or text[0] != "'" or text[-1] != "'":
        return None
    body = text[1:-1]
    out: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            out.append(body[i + 1])
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def extract_pattern_indicators(pattern: str) -> tuple[list[tuple[NormalizedIndicator, str]], int]:
    if not isinstance(pattern, str) or len(pattern) > 20_000:
        return [], 1
    try:
        comparisons = Pattern(pattern).inspect().comparisons
    except (ParseException, Exception):
        return [], 1
    found: list[tuple[NormalizedIndicator, str]] = []
    skipped = 0
    for object_type, items in comparisons.items():
        for path, operator, literal in items:
            if operator not in ("=", "IN"):
                skipped += 1
                continue
            path_tuple = tuple(str(p) for p in path)
            kind = stix_path_to_kind(object_type, path_tuple)
            values: list[str] = []
            if operator == "IN" and isinstance(literal, str) and literal.startswith("("):
                inner = literal.strip("()")
                values = [v for v in (_unquote(part.strip()) for part in inner.split(",")) if v]
            else:
                value = _unquote(literal)
                values = [value] if value else []
            if not values:
                skipped += 1
                continue
            for raw in values:
                if kind is None:
                    kind_used = "other"
                    raw_used = f"{object_type}:{'.'.join(path_tuple)}={raw}"
                else:
                    kind_used, raw_used = kind, raw
                try:
                    found.append((normalize(kind_used, raw_used), raw))
                except NormalizationError:
                    skipped += 1
    return found, skipped


def load_objects(data: bytes, max_depth: int, max_objects: int) -> list[dict[str, Any]]:
    check_json_depth(data, max_depth)
    try:
        doc = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise InputRejected("file is not valid STIX JSON") from exc
    if isinstance(doc, dict) and isinstance(doc.get("objects"), list):
        objects = doc["objects"]
    elif isinstance(doc, list):
        objects = doc
    elif isinstance(doc, dict) and isinstance(doc.get("type"), str):
        objects = [doc]
    else:
        raise InputRejected("file is not a STIX bundle")
    if len(objects) > max_objects:
        raise InputRejected("bundle contains too many objects", "resource")
    return [o for o in objects if isinstance(o, dict)]


def assess_timestamp_quality(indicator_times: list[datetime], has_observations: bool) -> str:
    if has_observations:
        return TS_OBSERVED
    if len(indicator_times) < 20:
        return TS_PUBLICATION if indicator_times else TS_UNKNOWN
    ordered = sorted(indicator_times)
    window = max(1, int(len(ordered) * 0.95))
    tightest = min(
        (ordered[i + window - 1] - ordered[i]).total_seconds()
        for i in range(0, len(ordered) - window + 1)
    )
    return TS_BULK if tightest <= 86_400 else TS_PUBLICATION


class StixImporter:
    def __init__(self, storage: Storage, max_depth: int = 64, max_objects: int = 250_000):
        self.storage = storage
        self.max_depth = max_depth
        self.max_objects = max_objects

    def import_bytes(self, data: bytes, source_name: str, source_kind: str = "file", source_url: str | None = None) -> ImportReport:
        source_name = source_name.strip()[:120] or "unnamed"
        digest = hashlib.sha256(data).hexdigest()
        report = ImportReport(source=source_name, status="pending")
        objects = load_objects(data, self.max_depth, self.max_objects)
        report.objects_total = len(objects)
        parsed = self._validate(objects, report)
        with self.storage.transaction() as tx:
            source_id = self._upsert_source(tx, source_name, source_kind, source_url)
            existing = tx.execute(
                "SELECT id FROM imports WHERE source_id=? AND content_sha256=?", (source_id, digest)
            ).fetchone()
            if existing is not None:
                report.status = "already-imported"
                return report
            import_id = tx.execute(
                "INSERT INTO imports(source_id,received_at,content_sha256,objects_total,status) VALUES(?,?,?,?,?)",
                (source_id, utcnow(), digest, report.objects_total, "processing"),
            ).lastrowid
            self._store(tx, parsed, source_id, import_id, report)
            tx.execute(
                "UPDATE imports SET accepted=?, rejected=?, duplicates=?, ts_quality=?, status=? WHERE id=?",
                (report.accepted, report.rejected, report.duplicates, report.ts_quality, "complete", import_id),
            )
            tx.execute(
                "UPDATE sources SET last_import_at=?, ts_quality=? WHERE id=?",
                (utcnow(), self._merge_quality(tx, source_id), source_id),
            )
        report.status = "complete"
        log.info(
            "import complete source_id=%s objects=%s accepted=%s rejected=%s duplicates=%s ts=%s",
            source_id, report.objects_total, report.accepted, report.rejected, report.duplicates, report.ts_quality,
        )
        return report

    def _validate(self, objects: Iterable[dict[str, Any]], report: ImportReport) -> list[Any]:
        parsed: list[Any] = []
        reasons: Counter[str] = Counter()
        for obj in objects:
            otype = obj.get("type")
            if not isinstance(otype, str):
                reasons["missing-type"] += 1
                continue
            if obj.get("revoked") is True or obj.get("x_mitre_deprecated") is True:
                reasons["revoked-or-deprecated"] += 1
                continue
            if otype not in ENTITY_TYPES and otype not in ("indicator", "relationship", "sighting", "observed-data"):
                reasons["unused-type"] += 1
                continue
            try:
                parsed.append(stix2.parse(obj, allow_custom=True))
            except (STIXError, ValueError, TypeError, KeyError) as exc:
                reasons[f"invalid-{otype}"] += 1
                log.debug("object rejected type=%s reason=%s", otype, type(exc).__name__)
        report.rejected = sum(v for k, v in reasons.items() if k.startswith("invalid") or k == "missing-type")
        report.reject_reasons = dict(reasons)
        return parsed

    @staticmethod
    def _upsert_source(tx, name: str, kind: str, url: str | None) -> int:
        row = tx.execute(
            "INSERT INTO sources(name,kind,url,created_at) VALUES(?,?,?,?) "
            "ON CONFLICT(name) DO UPDATE SET url=COALESCE(excluded.url, sources.url) RETURNING id",
            (name, kind, url, utcnow()),
        ).fetchone()
        return int(row[0])

    @staticmethod
    def _merge_quality(tx, source_id: int) -> str:
        rows = tx.execute("SELECT ts_quality, COUNT(*) FROM imports WHERE source_id=? GROUP BY ts_quality", (source_id,)).fetchall()
        qualities = {r[0] for r in rows}
        for q in (TS_OBSERVED, TS_PUBLICATION, TS_BULK):
            if q in qualities:
                return q
        return TS_UNKNOWN

    def _resolve_entity(self, tx, obj: Any, source_id: int, report: ImportReport) -> int | None:
        name = obj.get("name")
        if not isinstance(name, str) or not name.strip():
            return None
        try:
            norm = normalize_family_name(name)
        except NormalizationError:
            return None
        etype = "intrusion-set" if obj["type"] == "threat-actor" else obj["type"]
        aliases: set[str] = set()
        for key in ("aliases", "x_mitre_aliases"):
            values = obj.get(key) or []
            if isinstance(values, list):
                for alias in values[:100]:
                    if isinstance(alias, str):
                        try:
                            aliases.add(normalize_family_name(alias))
                        except NormalizationError:
                            continue
        aliases.add(norm)
        first = _iso(_parse_ts(obj.get("first_seen")))
        last = _iso(_parse_ts(obj.get("last_seen")))
        row = tx.execute("SELECT id FROM entities WHERE etype=? AND norm_name=?", (etype, norm)).fetchone()
        if row is None:
            placeholders = ",".join("?" for _ in aliases)
            row = tx.execute(
                f"SELECT e.id FROM entities e JOIN entity_aliases a ON a.entity_id=e.id "
                f"WHERE e.etype=? AND a.alias_norm IN ({placeholders}) ORDER BY e.id LIMIT 1",
                (etype, *sorted(aliases)),
            ).fetchone()
        if row is None:
            entity_id = tx.execute(
                "INSERT INTO entities(etype,norm_name,display_name,first_seen,last_seen) VALUES(?,?,?,?,?)",
                (etype, norm, name.strip()[:200], first, last),
            ).lastrowid
            report.entities_new += 1
        else:
            entity_id = int(row[0])
            tx.execute(
                "UPDATE entities SET first_seen=CASE WHEN ? IS NOT NULL AND (first_seen IS NULL OR ? < first_seen) THEN ? ELSE first_seen END, "
                "last_seen=CASE WHEN ? IS NOT NULL AND (last_seen IS NULL OR ? > last_seen) THEN ? ELSE last_seen END WHERE id=?",
                (first, first, first, last, last, last, entity_id),
            )
        tx.executemany(
            "INSERT OR IGNORE INTO entity_aliases(entity_id,alias_norm,source_id) VALUES(?,?,?)",
            [(entity_id, a, source_id) for a in sorted(aliases)],
        )
        return entity_id

    def _store(self, tx, parsed: list[Any], source_id: int, import_id: int, report: ImportReport) -> None:
        local_map: dict[str, list[tuple[str, int]]] = {}
        indicator_times: list[datetime] = []
        has_observations = False
        sighting_times: dict[str, datetime] = {}
        for obj in parsed:
            if obj["type"] == "sighting":
                ref = obj.get("sighting_of_ref")
                ts = _parse_ts(obj.get("first_seen")) or _parse_ts(obj.get("last_seen"))
                if isinstance(ref, str) and ts:
                    has_observations = True
                    prev = sighting_times.get(ref)
                    sighting_times[ref] = ts if prev is None or ts < prev else prev
            elif obj["type"] == "observed-data" and obj.get("first_observed"):
                has_observations = True
        for obj in parsed:
            if obj["type"] in ENTITY_TYPES:
                entity_id = self._resolve_entity(tx, obj, source_id, report)
                if entity_id is not None:
                    etype = "intrusion-set" if obj["type"] == "threat-actor" else obj["type"]
                    local_map[obj["id"]] = [(etype, entity_id)]
                    tx.execute("INSERT OR IGNORE INTO stix_map(stix_id,node_type,node_id) VALUES(?,?,?)", (obj["id"], etype, entity_id))
                    report.accepted += 1
        seen_in_import: set[int] = set()
        for obj in parsed:
            if obj["type"] != "indicator":
                continue
            found, skipped = extract_pattern_indicators(obj.get("pattern", ""))
            report.non_atomic_comparisons += skipped
            if not found:
                continue
            ts = sighting_times.get(obj["id"]) or _parse_ts(obj.get("valid_from")) or _parse_ts(obj.get("created"))
            if ts:
                indicator_times.append(ts)
            observed = _iso(ts)
            nodes: list[tuple[str, int]] = []
            for ind, raw in found:
                root = root_of(ind)
                row = tx.execute(
                    "INSERT INTO indicators(kind,value,root,shared_root,first_seen,last_seen) VALUES(?,?,?,?,?,?) "
                    "ON CONFLICT(kind,value) DO UPDATE SET "
                    "first_seen=CASE WHEN excluded.first_seen IS NOT NULL AND (indicators.first_seen IS NULL OR excluded.first_seen < indicators.first_seen) THEN excluded.first_seen ELSE indicators.first_seen END, "
                    "last_seen=CASE WHEN excluded.last_seen IS NOT NULL AND (indicators.last_seen IS NULL OR excluded.last_seen > indicators.last_seen) THEN excluded.last_seen ELSE indicators.last_seen END "
                    "RETURNING id, (SELECT COUNT(*) FROM observations o WHERE o.indicator_id=indicators.id)",
                    (ind.kind, ind.value, root, 1 if (root is not None and is_shared_infrastructure(root)) else 0, observed, observed),
                ).fetchone()
                indicator_id, prior_obs = int(row[0]), int(row[1])
                if prior_obs == 0 and indicator_id not in seen_in_import:
                    report.indicators_new += 1
                else:
                    report.duplicates += 1
                seen_in_import.add(indicator_id)
                tx.execute(
                    "INSERT INTO observations(indicator_id,source_id,import_id,stix_id,observed_at,raw_value) VALUES(?,?,?,?,?,?)",
                    (indicator_id, source_id, import_id, obj["id"], observed, raw[:2048]),
                )
                nodes.append(("indicator", indicator_id))
            unique_nodes = list(dict.fromkeys(nodes))
            local_map[obj["id"]] = unique_nodes
            if len(unique_nodes) > 1:
                anchor = unique_nodes[0]
                for other in unique_nodes[1:12]:
                    report.documented_edges += self._edge(tx, anchor, other, "same-indicator", source_id, import_id, obj["id"], observed)
            report.accepted += 1
        for obj in parsed:
            if obj["type"] != "relationship":
                continue
            rel = obj.get("relationship_type")
            if rel not in KEPT_RELATIONSHIPS:
                continue
            srcs = local_map.get(obj["source_ref"]) or self._lookup(tx, obj["source_ref"])
            dsts = local_map.get(obj["target_ref"]) or self._lookup(tx, obj["target_ref"])
            if not srcs or not dsts:
                report.unresolved_relationships += 1
                continue
            observed = _iso(_parse_ts(obj.get("start_time")) or _parse_ts(obj.get("created")))
            for src in srcs:
                for dst in dsts:
                    if src != dst:
                        report.documented_edges += self._edge(tx, src, dst, rel, source_id, import_id, obj["id"], observed)
            report.accepted += 1
        report.ts_quality = assess_timestamp_quality(indicator_times, has_observations)

    @staticmethod
    def _lookup(tx, stix_id: Any) -> list[tuple[str, int]]:
        if not isinstance(stix_id, str):
            return []
        row = tx.execute("SELECT node_type,node_id FROM stix_map WHERE stix_id=?", (stix_id,)).fetchone()
        return [(row[0], int(row[1]))] if row else []

    @staticmethod
    def _edge(tx, src: tuple[str, int], dst: tuple[str, int], rel: str, source_id: int, import_id: int, rel_id: str, observed: str | None) -> int:
        cur = tx.execute(
            "INSERT OR IGNORE INTO documented_edges(src_type,src_id,dst_type,dst_id,rel_type,source_id,import_id,stix_rel_id,observed_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (src[0], src[1], dst[0], dst[1], rel, source_id, import_id, rel_id, observed),
        )
        return cur.rowcount
