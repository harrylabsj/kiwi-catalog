"""Transport-only error envelope helpers for catalog API stacks."""

from __future__ import annotations

from typing import Any


def error_body(error: Any) -> dict[str, Any]:
    """Return the stable fallback/FastAPI error body without exposing secrets."""
    return {"ok": False, "error": str(error)}


def error_result(status: int, error: Any) -> tuple[int, dict[str, Any]]:
    """Return the stable status/body pair used by fallback request handling."""
    return status, error_body(error)
