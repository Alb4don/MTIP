from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, Response

from ..config import Settings
from ..correlate.engine import ATTRIBUTABLE_TYPES, EngineParams
from ..normalize import ALL_KINDS
from ..reports import build_html_report, build_json_report, build_stix_bundle
from ..security import InputRejected, validate_search_text
from ..service import INFERRED_RELS, Platform
from .schemas import CorrelationIn, FeedbackIn, TaxiiDiscoverIn, TaxiiImportIn, check_source_name

KindParam = Literal[ALL_KINDS]
StatusParam = Literal["documented", "inferred", "conflict", "unattributed", "confirmed"]
RelationParam = Literal[INFERRED_RELS]
EntityTypeParam = Literal[ATTRIBUTABLE_TYPES]


def _search(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    return validate_search_text(value)


def build_router(platform: Platform, settings: Settings) -> APIRouter:
    router = APIRouter()

    @router.get("/health")
    def health() -> dict:
        return platform.health()

    @router.get("/overview")
    def overview() -> dict:
        return platform.overview()

    @router.get("/metrics/history")
    def metrics_history(limit: int = Query(50, ge=1, le=500)) -> list:
        return platform.metrics_history(limit)

    @router.get("/indicators")
    def indicators(
        kind: KindParam | None = None,
        search: str | None = Query(None, max_length=200),
        status: StatusParam | None = None,
        source_id: int | None = Query(None, ge=1, le=2**31),
        offset: int = Query(0, ge=0, le=10_000_000),
        limit: int = Query(50, ge=1, le=500),
    ) -> dict:
        return platform.list_indicators(kind, _search(search), status, source_id, offset, limit)

    @router.get("/indicators/{indicator_id}")
    def indicator(indicator_id: int) -> dict:
        if not 1 <= indicator_id <= 2**53:
            raise InputRejected("indicator id is out of range")
        return platform.indicator_detail(indicator_id)

    @router.get("/inferences")
    def inferences(
        relation: RelationParam | None = None,
        min_score: float = Query(0.0, ge=0.0, le=1.0),
        offset: int = Query(0, ge=0, le=10_000_000),
        limit: int = Query(50, ge=1, le=500),
    ) -> dict:
        return platform.list_inferences(relation, min_score, offset, limit)

    @router.post("/feedback")
    def feedback(body: FeedbackIn) -> dict:
        return platform.submit_feedback(body.src_type, body.src_id, body.dst_type, body.dst_id, body.relation, body.verdict)

    @router.get("/sources")
    def sources() -> list:
        return platform.sources()

    @router.get("/entities")
    def entities(
        search: str | None = Query(None, max_length=200),
        etype: EntityTypeParam | None = None,
        limit: int = Query(100, ge=1, le=1000),
    ) -> list:
        return platform.entities(_search(search), etype, limit)

    @router.get("/graph")
    def graph(
        focus: int | None = Query(None, ge=1, le=2**53),
        inferred: bool = True,
        max_nodes: int = Query(300, ge=10, le=1500),
    ) -> dict:
        return platform.campaign_graph(focus, inferred, max_nodes)

    @router.post("/imports/file", status_code=202)
    async def import_file(request: Request, source: str = Query(..., min_length=1, max_length=80)) -> dict:
        name = check_source_name(source)
        content_type = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
        if content_type not in ("application/json", "application/stix+json", "application/taxii+json", "application/octet-stream"):
            raise InputRejected("upload must be a JSON file")
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > settings.max_upload_bytes:
                raise InputRejected("file is larger than the configured limit", "resource")
        if not body:
            raise InputRejected("file is empty")
        job = platform.submit_import(bytes(body), name)
        return {"job": job.as_dict()}

    @router.post("/taxii/discover")
    def taxii_discover(body: TaxiiDiscoverIn) -> dict:
        return {"collections": platform.taxii_discover(body.url, body.username, body.password)}

    @router.post("/taxii/import", status_code=202)
    def taxii_import(body: TaxiiImportIn) -> dict:
        job = platform.submit_taxii_import(body.collection_url, body.source_name, body.added_after, body.username, body.password)
        return {"job": job.as_dict()}

    @router.post("/correlation/run", status_code=202)
    def correlation_run(body: CorrelationIn) -> dict:
        params = EngineParams(min_attribution=body.min_attribution, ambiguity_ratio=body.ambiguity_ratio,
                              fdr_alpha=body.fdr_alpha, temporal_tau_days=body.temporal_tau_days)
        job = platform.submit_correlation(params, evaluate=body.evaluate)
        return {"job": job.as_dict()}

    @router.get("/jobs")
    def jobs() -> list:
        return platform.jobs.recent()

    @router.get("/jobs/{job_id}")
    def job(job_id: str) -> dict:
        if not (len(job_id) == 32 and all(c in "0123456789abcdef" for c in job_id)):
            raise InputRejected("job id is invalid")
        return platform.jobs.get(job_id).as_dict()

    @router.get("/features")
    def features(request: Request) -> list:
        return request.app.state.features

    @router.get("/reports/{fmt}")
    def report(fmt: Literal["json", "html", "stix"]) -> Response:
        if fmt == "json":
            return JSONResponse(build_json_report(platform.storage), headers={"Content-Disposition": 'attachment; filename="mtip-report.json"'})
        if fmt == "html":
            return Response(build_html_report(platform.storage), media_type="text/html; charset=utf-8",
                            headers={"Content-Disposition": 'attachment; filename="mtip-report.html"'})
        return Response(build_stix_bundle(platform.storage), media_type="application/stix+json",
                        headers={"Content-Disposition": 'attachment; filename="mtip-inferences.stix.json"'})

    return router
