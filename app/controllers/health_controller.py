"""Health endpoints — always public, no credential required.

    GET /health         readiness (alias of /health/ready)
    GET /health/live     liveness — process is up, no I/O
    GET /health/ready    readiness — MongoDB reachable (when configured)

Liveness must never touch a dependency: a Mongo blip should not get the
container killed. Readiness may, because that is exactly the signal a load
balancer needs.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Request, Response

from features import __version__
from features.config import auth_settings
from features.mongo_connection import get_connection

from ..models.health_model import DependencyStatus, LivenessResponse, ReadinessResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/health", tags=["health"])


async def _readiness(request: Request) -> ReadinessResponse:
    deps: list[DependencyStatus] = []

    if auth_settings.mongo_uri:
        try:
            conn = await get_connection()
            reachable = await conn.ping()
            deps.append(
                DependencyStatus(
                    name="mongodb",
                    status="ok" if reachable else "degraded",
                    detail=(
                        f"db={conn.db_name}"
                        if reachable
                        else "Unreachable — requests fall back to in-memory storage."
                    ),
                )
            )
        except Exception as exc:  # noqa: BLE001
            deps.append(
                DependencyStatus(name="mongodb", status="degraded", detail=str(exc))
            )
    else:
        deps.append(
            DependencyStatus(
                name="mongodb",
                status="disabled",
                detail="No AUTH_MONGO_URI set — using in-memory storage (no persistence).",
            )
        )

    overall = "degraded" if any(d.status == "degraded" for d in deps) else "ready"

    return ReadinessResponse(
        status=overall,
        version=request.app.version,
        dependencies=deps,
    )


@router.get("/live", response_model=LivenessResponse, summary="Liveness probe")
async def live(request: Request) -> LivenessResponse:
    return LivenessResponse(version=request.app.version)


@router.get("/ready", response_model=ReadinessResponse, summary="Readiness probe")
async def ready(request: Request, response: Response) -> ReadinessResponse:
    result = await _readiness(request)
    if result.status == "not_ready":
        response.status_code = 503
    return result


@router.get("", response_model=ReadinessResponse, summary="Health (alias of /health/ready)")
async def health(request: Request, response: Response) -> ReadinessResponse:
    return await ready(request, response)
