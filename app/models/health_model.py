"""Health / readiness schemas.

``/health/live`` answers "is the process up" (no I/O). ``/health/ready``
answers "can it actually serve traffic": MongoDB reachable when configured
(in-memory storage always reports ready — there's nothing to be unreachable).
Container orchestrators should probe liveness frequently and readiness on a
slower cadence.
"""
from __future__ import annotations

from pydantic import BaseModel


class LivenessResponse(BaseModel):
    status: str = "ok"
    service: str = "auth-service"
    version: str = ""


class DependencyStatus(BaseModel):
    name: str
    status: str          # "ok" | "degraded" | "unavailable" | "disabled"
    detail: str = ""


class ReadinessResponse(BaseModel):
    status: str          # "ready" | "degraded" | "not_ready"
    service: str = "auth-service"
    version: str = ""
    dependencies: list[DependencyStatus] = []
