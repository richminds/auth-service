"""Request-ID propagation and access logging.

Every response carries a request ID (echoed from the caller's header when
present, otherwise minted here), attached to ``request.state`` so error
responses can quote it. The same ID is bound to ``features.log_context`` for
the lifetime of the request, so it appears automatically as ``request_id`` on
every structured log line emitted while handling this request — no parameter
threading needed.
"""
from __future__ import annotations

import logging
import time
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from features.log_context import bind_request_id, reset_request_id

from ..config import service_settings

logger = logging.getLogger("features.access")


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        header = service_settings.request_id_header
        request_id = request.headers.get(header) or uuid4().hex[:16]
        request.state.request_id = request_id

        token = bind_request_id(request_id)
        started = time.perf_counter()
        try:
            response = await call_next(request)
            elapsed_ms = (time.perf_counter() - started) * 1000
            response.headers[header] = request_id
            # Health probes fire constantly — keep them out of the access log.
            if not request.url.path.startswith("/health"):
                logger.info(
                    "%s %s → %d (%.0fms)",
                    request.method,
                    request.url.path,
                    response.status_code,
                    elapsed_ms,
                    extra={
                        "method": request.method,
                        "path": request.url.path,
                        "status": response.status_code,
                        "latency_ms": round(elapsed_ms, 1),
                    },
                )
            return response
        finally:
            reset_request_id(token)
