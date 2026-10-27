from __future__ import annotations

import hmac
import importlib
import pkgutil
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .. import __version__
from ..config import Settings
from ..ingest.taxii import TaxiiError
from ..logging_setup import configure_logging, get_logger
from ..security import InputRejected, RateLimiter, StrikeTracker, client_fingerprint, detect_attack
from ..service import NotFound, Platform
from ..storage import utcnow
from .routes import build_router

log = get_logger("api")
sec_log = get_logger("security")
STATIC_DIR = Path(__file__).resolve().parent / "static"
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
FREE_TEXT_PARAMS = frozenset({"search"})

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
        "font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
}


def _error(status: int, message: str, error_id: str | None = None) -> JSONResponse:
    body: dict[str, Any] = {"error": message}
    if error_id:
        body["error_id"] = error_id
    return JSONResponse(body, status_code=status, headers=SECURITY_HEADERS)


def load_feature_routers(app: FastAPI, platform: Platform) -> list[dict[str, str]]:
    from .. import features

    loaded = []
    for module_info in pkgutil.iter_modules(features.__path__):
        name = module_info.name
        if name.startswith("_"):
            continue
        try:
            module = importlib.import_module(f"{features.__name__}.{name}")
            router = module.build_router(platform)
            app.include_router(router, prefix=f"/api/v1/features/{name}")
            loaded.append({"name": name, "status": "loaded", "version": str(getattr(module, "VERSION", "1"))})
        except Exception as exc:
            log.error("feature failed to load name=%s error=%s", name, type(exc).__name__)
            loaded.append({"name": name, "status": "disabled"})
    return loaded


def create_app(settings: Settings | None = None, platform: Platform | None = None) -> FastAPI:
    settings = settings or Settings()
    settings.ensure_dirs()
    configure_logging(settings.log_dir)
    platform = platform or Platform(settings)
    limiter = RateLimiter(settings.rate_limit_per_minute)
    strikes = StrikeTracker(settings.strike_threshold, settings.block_seconds)
    allowed_origins = {f"http://{h}:{settings.port}" for h in ("127.0.0.1", "localhost")}

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        platform.close()

    app = FastAPI(title="MTIP", version=__version__, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.platform = platform
    app.state.settings = settings
    app.state.strikes = strikes

    def client_key(request: Request) -> str:
        host = request.client.host if request.client else "unknown"
        return client_fingerprint(host, settings.session_token)

    def record_attack(request: Request, category: str) -> None:
        key = client_key(request)
        blocked = strikes.strike(key, 2 if category in ("sqli", "command_injection", "path_traversal", "ssrf") else 1)
        sec_log.warning("suspicious input category=%s route=%s client=%s blocked=%s", category, request.url.path, key, blocked)
        try:
            with platform.storage.transaction() as tx:
                tx.execute("INSERT INTO security_events(created_at,client_hash,category,route) VALUES(?,?,?,?)",
                           (utcnow(), key, category[:32], request.url.path[:200]))
                tx.execute("DELETE FROM security_events WHERE id <= (SELECT MAX(id) FROM security_events) - 10000")
        except Exception as exc:
            log.warning("security event not persisted error=%s", type(exc).__name__)

    app.state.record_attack = record_attack

    @app.middleware("http")
    async def guard(request: Request, call_next):
        key = client_key(request)
        path = request.url.path
        if strikes.is_blocked(key):
            return _error(403, "access temporarily blocked after repeated invalid requests")
        if path.startswith("/api/"):
            if not limiter.allow(key):
                return _error(429, "too many requests; slow down")
            inspected = [request.url.path] + [f"{k}={v}" for k, v in request.query_params.multi_items() if k not in FREE_TEXT_PARAMS]
            category = detect_attack(_unquote("&".join(inspected)))
            if category:
                record_attack(request, category)
                return _error(400, "request rejected by input validation")
            if request.method in STATE_CHANGING:
                token = request.headers.get("x-mtip-token", "")
                if not hmac.compare_digest(token.encode(), settings.session_token.encode()):
                    sec_log.warning("missing or invalid session token route=%s client=%s", path, key)
                    return _error(403, "session token missing or invalid; reload the page")
                origin = request.headers.get("origin")
                if origin is not None and origin not in allowed_origins:
                    record_attack(request, "csrf")
                    return _error(403, "cross-origin request rejected")
                length = request.headers.get("content-length")
                if length is not None and (not length.isdigit() or int(length) > settings.max_upload_bytes):
                    return _error(413, "request body is too large")
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        if "server" in response.headers:
            del response.headers["server"]
        return response

    @app.exception_handler(InputRejected)
    async def rejected_handler(request: Request, exc: InputRejected):
        if exc.category not in ("validation", "resource"):
            record_attack(request, exc.category)
        return _error(400 if exc.category != "resource" else 413, exc.public_message)

    @app.exception_handler(TaxiiError)
    async def taxii_handler(_: Request, exc: TaxiiError):
        return _error(502, exc.public_message)

    @app.exception_handler(NotFound)
    async def not_found_handler(_: Request, exc: NotFound):
        return _error(404, str(exc))

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        fields = []
        for err in exc.errors()[:10]:
            ctx_error = (err.get("ctx") or {}).get("error")
            if isinstance(ctx_error, InputRejected):
                if ctx_error.category not in ("validation", "resource"):
                    record_attack(request, ctx_error.category)
                return _error(400, ctx_error.public_message)
            loc = [str(p) for p in err.get("loc", ()) if p not in ("body", "query", "path")]
            fields.append(".".join(loc)[:64] or "request")
        return _error(422, "invalid value for: " + ", ".join(sorted(set(fields))))

    @app.exception_handler(StarletteHTTPException)
    async def http_handler(_: Request, exc: StarletteHTTPException):
        messages = {404: "not found", 405: "method not allowed", 413: "request body is too large"}
        return _error(exc.status_code, messages.get(exc.status_code, "request could not be processed"))

    @app.exception_handler(Exception)
    async def fallback_handler(request: Request, exc: Exception):
        error_id = uuid.uuid4().hex[:12]
        log.error("unhandled error id=%s route=%s type=%s", error_id, request.url.path, type(exc).__name__)
        return _error(500, "internal error; the incident was logged", error_id)

    app.include_router(build_router(platform, settings), prefix="/api/v1")
    app.state.features = load_feature_routers(app, platform)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    index_template = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    index_html = index_template.replace("__MTIP_TOKEN__", settings.session_token).replace("__MTIP_VERSION__", __version__)

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def index() -> HTMLResponse:
        return HTMLResponse(index_html, headers=SECURITY_HEADERS)

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon() -> Response:
        return Response(status_code=204)

    allowed_hosts = ["127.0.0.1", "localhost", *settings.extra_trusted_hosts]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
    return app


def _unquote(text: str) -> str:
    from urllib.parse import unquote_plus
    previous = text
    for _ in range(3):
        current = unquote_plus(previous)
        if current == previous:
            break
        previous = current
    return previous
