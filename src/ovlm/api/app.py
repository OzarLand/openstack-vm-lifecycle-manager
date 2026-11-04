"""FastAPI application factory."""

from __future__ import annotations

import logging
import re
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from ovlm import __version__
from ovlm.api.health import DbReadinessProbe, ReadinessProbe
from ovlm.config import Settings
from ovlm.db.engine import make_engine
from ovlm.observability.context import bind_context
from ovlm.observability.metrics import BUILD_INFO, HTTP_REQUESTS, InternalServer
from ovlm.ui import STATIC_DIR
from ovlm.ui.routes import router as ui_router

log = logging.getLogger("ovlm.api")

_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
)


def create_app(
    settings: Settings,
    *,
    probe: ReadinessProbe | None = None,
    start_metrics_server: bool = True,
) -> FastAPI:
    """Build the app. ``probe`` is injectable for tests; by default it checks the real database."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = None
        server = None
        if probe is None:
            engine = make_engine(settings)
            app.state.probe = DbReadinessProbe(engine, settings.migrations_dir)
        else:
            app.state.probe = probe
        BUILD_INFO.labels(__version__, "api").set(1)
        if start_metrics_server:
            server = InternalServer(settings.http.metrics_host, settings.http.metrics_port)
            server.start()
        log.info("api started")
        try:
            yield
        finally:
            if server:
                server.stop()
            if engine:
                engine.dispose()
            log.info("api stopped")

    app = FastAPI(
        title="OVLM",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,  # re-enabled with the authenticated API in E3
    )
    app.state.settings = settings
    if probe is not None:
        app.state.probe = (
            probe  # also available without running the lifespan (TestClient without `with`)
        )

    @app.middleware("http")
    async def request_context(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        inbound = request.headers.get("x-request-id", "")
        request_id = inbound if _REQUEST_ID.match(inbound) else uuid.uuid4().hex
        started = time.perf_counter()
        with bind_context(request_id=request_id):
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            response.headers["Content-Security-Policy"] = _CSP
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["Referrer-Policy"] = "no-referrer"
            HTTP_REQUESTS.labels(request.method, str(response.status_code)).inc()
            log.info(
                "request",
                extra={
                    "http_method": request.method,
                    "path": request.url.path,
                    "status": response.status_code,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                },
            )
            return response

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    def readyz(request: Request) -> JSONResponse:
        results = request.app.state.probe.check()
        ok = all(r.ok for r in results)
        body = {
            "status": "ready" if ok else "not_ready",
            "checks": {r.name: ("ok" if r.ok else r.detail or "failed") for r in results},
        }
        return JSONResponse(body, status_code=200 if ok else 503)

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(ui_router)
    return app
