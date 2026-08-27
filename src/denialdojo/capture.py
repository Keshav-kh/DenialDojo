"""Acyclic raw-capture primitives shared by the adapter and trusted interposer."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

_SECRET_KEYS = frozenset(
    {"api_key", "apikey", "authorization", "cookie", "password", "secret", "token"}
)
_SECRET_PATTERNS = (
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)(api[_-]?key|password|secret|token)\s*[=:]\s*[^\s,;]+"),
    re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{16,}"),
)


class StrictCaptureModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CapturedExchange(StrictCaptureModel):
    provenance: Literal["raw_capture"] = "raw_capture"
    sequence: int = Field(ge=0)
    requested_at: str
    received_at: str
    request: dict[str, Any]
    response: dict[str, Any]


class MediatedToolEvent(StrictCaptureModel):
    provenance: Literal["raw_capture"] = "raw_capture"
    sequence: int = Field(ge=0)
    call_id: str | None
    tool_name: str
    classification: Literal["protected_probe", "registered_nonsink", "external_sink"]
    arguments: dict[str, Any]
    result: Any | None
    error: str | None
    started_at: str
    finished_at: str
    mediated: Literal[True] = True


def redact_capture_value(value: Any, *, key: str | None = None) -> Any:
    """Redact secrets before immutable capture without importing higher layers."""

    normalized_key = (key or "").lower().replace("-", "_")
    if normalized_key in _SECRET_KEYS or any(secret in normalized_key for secret in _SECRET_KEYS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {
            str(item_key): redact_capture_value(item_value, key=str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, list | tuple):
        return [redact_capture_value(item) for item in value]
    if isinstance(value, str):
        redacted = value
        for pattern in _SECRET_PATTERNS:
            redacted = pattern.sub("[REDACTED]", redacted)
        return redacted
    return value


__all__ = ["CapturedExchange", "MediatedToolEvent", "redact_capture_value"]
