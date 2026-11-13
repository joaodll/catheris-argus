from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from sqlalchemy.exc import IntegrityError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from argus.api.routes import (
    auth,
    compliance,
    connection_tests,
    connections,
    findings,
    health,
    overview,
    reports,
    resources,
    risk,
    runs,
    schedules,
    settings,
    users,
    vulnerabilities,
)
from argus.auth import UserRuleError
from argus.connections import ConnectionError as ConnectionValueError
from argus.core.db import ServiceBusyError
from argus.scheduling import InvalidScheduleError
from argus.settings import SettingsBoundError

API_PREFIX = "/api/v1"
BUSY_RETRY_AFTER_SECONDS = 5
SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}


class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response


def _unprocessable(_: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": str(exc)})


def _invalid_request(_: Request, exc: Exception) -> JSONResponse:
    """A request the contract refuses: where and why, never what was sent. FastAPI's own answer
    carries each error's "input" (and "ctx"), so a connection body with a missing field echoed
    its secret access key (reviews/8c306e53, 2026-11-10)."""
    errors = exc.errors() if isinstance(exc, RequestValidationError) else []
    return JSONResponse(
        status_code=422,
        content={
            "detail": [
                {"type": e.get("type"), "loc": list(e.get("loc", ())), "msg": e.get("msg")}
                for e in errors
            ]
        },
    )


def _not_found(_: Request, __: Exception) -> JSONResponse:
    return JSONResponse(status_code=404, content={"detail": "not found"})


def _conflict(_: Request, __: Exception) -> JSONResponse:
    # Never echo the database message: it names constraints and values.
    return JSONResponse(status_code=409, content={"detail": "conflicts with an existing item"})


def _busy(_: Request, __: Exception) -> JSONResponse:
    # Every pooled connection, or every password check, stayed in use: a load problem, not the
    # request's fault. The client may try again; the caps protect Postgres and the API's memory.
    return JSONResponse(
        status_code=503,
        content={"detail": "the service is busy; try again shortly"},
        headers={"Retry-After": str(BUSY_RETRY_AFTER_SECONDS)},
    )


def create_app() -> FastAPI:
    app = FastAPI(
        title="CatherIs Argus API",
        version="0.2.0",
        # The OpenAPI document is a build-time contract (entrypoints/openapi.py renders it from
        # the routes), never served: unauthenticated, it would map every endpoint and field.
        openapi_url=None,
        docs_url=None,
        redoc_url=None,
    )
    app.add_middleware(SecurityHeaders)
    for exc in (ConnectionValueError, InvalidScheduleError, SettingsBoundError, ValueError):
        app.add_exception_handler(exc, _unprocessable)
    app.add_exception_handler(RequestValidationError, _invalid_request)
    app.add_exception_handler(LookupError, _not_found)
    app.add_exception_handler(IntegrityError, _conflict)
    app.add_exception_handler(PoolTimeoutError, _busy)
    app.add_exception_handler(ServiceBusyError, _busy)
    app.add_exception_handler(UserRuleError, users.refused)
    for router in (
        health.router,
        auth.router,
        overview.router,
        connections.router,
        connection_tests.router,
        schedules.router,
        runs.router,
        settings.router,
        findings.router,
        vulnerabilities.router,
        compliance.router,
        resources.router,
        risk.router,
        reports.router,
        users.router,
    ):
        app.include_router(router, prefix=API_PREFIX)
    return app
