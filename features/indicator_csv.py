from __future__ import annotations

import csv
import io

from fastapi import APIRouter
from fastapi.responses import Response

from ..correlate.engine import REL_INFERRED_INDICATES
from ..service import Platform

VERSION = "1"
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _cell(value: object) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA_PREFIXES) else text


def build_router(platform: Platform) -> APIRouter:
    router = APIRouter()

    @router.get("/export")
    def export() -> Response:
        run_id = platform.storage.get_state("active_run") or -1
        rows = platform.storage.query(
            "SELECT i.kind, i.value, i.root, "
            "(SELECT GROUP_CONCAT(DISTINCT e.display_name) FROM documented_edges d JOIN entities e ON e.id=d.dst_id "
            " WHERE d.src_type='indicator' AND d.src_id=i.id AND d.rel_type='indicates') AS documented, "
            "(SELECT e.display_name FROM inferred_edges ie JOIN entities e ON e.id=ie.dst_id WHERE ie.run_id=? AND ie.src_id=i.id "
            " AND ie.src_type='indicator' AND ie.rel_type=? ORDER BY ie.score DESC LIMIT 1) AS inferred, "
            "(SELECT MAX(ie.score) FROM inferred_edges ie WHERE ie.run_id=? AND ie.src_id=i.id AND ie.src_type='indicator' AND ie.rel_type=?) AS score, "
            "(SELECT COUNT(DISTINCT source_id) FROM observations o WHERE o.indicator_id=i.id) AS sources "
            "FROM indicators i ORDER BY i.id",
            (int(run_id), REL_INFERRED_INDICATES, int(run_id), REL_INFERRED_INDICATES),
        )
        buffer = io.StringIO()
        writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(["kind", "value", "registered_domain", "documented_families", "inferred_family", "inferred_score", "sources", "association"])
        for r in rows:
            association = "documented" if r["documented"] else ("inferred" if r["inferred"] else "none")
            writer.writerow([_cell(r["kind"]), _cell(r["value"]), _cell(r["root"]), _cell(r["documented"]), _cell(r["inferred"]),
                             "" if r["score"] is None else f"{r['score']:.4f}", r["sources"], association])
        return Response(buffer.getvalue(), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": 'attachment; filename="mtip-indicators.csv"'})

    return router
