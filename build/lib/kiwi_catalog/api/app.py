"""kiwi-catalog standalone API app (阶段 2 独立库).

Route-level cut of the Agent Catalog domain extracted from shopping-cli
api/app.py: only /v1/agent-catalog/* (registration/verification/search/
governance), /v1/hosted/* (Agent Card / UCP publication) and /health are
served; the hosted negotiation endpoint and all marketplace routes are
excluded (切割分水岭).  Fallback-ASGI only; FastAPI dual-stack is phase 3.

Extraction date: 2026-08-06.  Keep handler semantics in sync with the
shopping-cli repo until the repos diverge intentionally.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kiwi_catalog import VERSION
from kiwi_catalog.api.limits import max_request_body_bytes, validate_payload
from kiwi_catalog.api.fallback_asgi import MarketplaceASGIApp
from kiwi_catalog.api.handlers import agent_catalog as agent_catalog_handlers
from kiwi_catalog.api.handlers import hosted_publication as hosted_publication_handlers
from kiwi_catalog.core.errors import (
    AuthError,
    ConflictError,
    IdempotencyConflict,
    MethodNotAllowedError,
    NotFoundError,
    PayloadTooLargeError,
    PermissionDenied,
    RateLimitError,
    ShoppingCliError,
    ValidationError,
)


def _health(db_path: str | Path) -> dict[str, Any]:
    return {"ok": True, "service": "kiwi-catalog", "db": str(db_path)}


@dataclass(frozen=True)
class RouteEntry:
    methods: set[str]
    path_template: str
    handler: Any


_ROUTE_TABLE: tuple[RouteEntry, ...] = (
RouteEntry({"GET"}, "/health", lambda db_path, payload, query, **kw: _health(db_path)),
RouteEntry(
        {"GET"},
        "/v1/agent-catalog/agents",
        lambda db_path, payload, query, **kw: _list_catalog_agents(db_path, payload, query),
    ),
RouteEntry(
        {"GET"},
        "/v1/agent-catalog/agents/search",
        lambda db_path, payload, query, **kw: _search_agent_catalog(db_path, payload, query),
    ),
RouteEntry(
        {"GET"},
        "/v1/agent-catalog/agents/{catalog_agent_id}",
        lambda db_path, payload, query, catalog_agent_id: _get_catalog_agent(
            db_path, payload, query, catalog_agent_id
        ),
    ),
RouteEntry(
        {"GET"},
        "/v1/agent-catalog/merchants/{merchant_id}/agents",
        lambda db_path, payload, query, merchant_id: _list_merchant_catalog_agents(
            db_path, payload, query, merchant_id
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/agent-catalog/agents/register",
        lambda db_path, payload, query, **kw: _register_catalog_agent(db_path, payload),
    ),
RouteEntry(
        {"POST"},
        "/v1/agent-catalog/agents/{catalog_agent_id}/refresh",
        lambda db_path, payload, query, catalog_agent_id: _refresh_catalog_agent(
            db_path, catalog_agent_id, payload
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/agent-catalog/agents/{catalog_agent_id}/verify",
        lambda db_path, payload, query, catalog_agent_id: _verify_catalog_agent(
            db_path, catalog_agent_id, payload
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/agent-catalog/agents/{catalog_agent_id}/claim",
        lambda db_path, payload, query, catalog_agent_id: _claim_catalog_agent(
            db_path, catalog_agent_id, payload
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/agent-catalog/agents/{catalog_agent_id}/suspend",
        lambda db_path, payload, query, catalog_agent_id: _suspend_catalog_agent(
            db_path, catalog_agent_id, payload
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/agent-catalog/agents/{catalog_agent_id}/reinstate",
        lambda db_path, payload, query, catalog_agent_id: _reinstate_catalog_agent(
            db_path, catalog_agent_id, payload
        ),
    ),
RouteEntry(
        {"GET"},
        "/v1/hosted/agents/{catalog_agent_id}/agent-card.json",
        lambda db_path, payload, query, catalog_agent_id: _hosted_agent_card_document(
            db_path, catalog_agent_id
        ),
    ),
RouteEntry(
        {"GET"},
        "/v1/hosted/agents/{catalog_agent_id}/ucp",
        lambda db_path, payload, query, catalog_agent_id: _hosted_ucp_profile_document(
            db_path, catalog_agent_id
        ),
    ),
)

def _match_path(template: str, path: str) -> dict[str, str] | None:
    parts = template.split("/")
    regex_parts = []
    for part in parts:
        if part.startswith("{") and part.endswith("}"):
            param_name = part[1:-1]
            regex_parts.append(f"(?P<{param_name}>[^/]+)")
        else:
            regex_parts.append(re.escape(part))
    match = re.match("^" + "/".join(regex_parts) + "$", path)
    return match.groupdict() if match else None


def _list_catalog_agents(db_path, payload, query):
    return agent_catalog_handlers.list_catalog_agents(db_path, query)


def _search_agent_catalog(db_path, payload, query):
    return agent_catalog_handlers.search_agent_catalog(db_path, query)


def _get_catalog_agent(db_path, catalog_agent_id, payload=None, query=None):
    return agent_catalog_handlers.get_catalog_agent(db_path, catalog_agent_id)


def _list_merchant_catalog_agents(db_path, merchant_id, payload=None, query=None):
    return agent_catalog_handlers.list_merchant_catalog_agents(db_path, merchant_id, query or {})


def _register_catalog_agent(db_path, payload):
    return agent_catalog_handlers.register_catalog_agent(db_path, payload)


def _refresh_catalog_agent(db_path, catalog_agent_id, payload=None, query=None):
    return agent_catalog_handlers.refresh_catalog_agent(db_path, catalog_agent_id, payload or {})


def _verify_catalog_agent(db_path, catalog_agent_id, payload=None, query=None):
    return agent_catalog_handlers.verify_catalog_agent(db_path, catalog_agent_id, payload or {})


def _claim_catalog_agent(db_path, catalog_agent_id, payload=None, query=None):
    return agent_catalog_handlers.claim_catalog_agent(db_path, catalog_agent_id, payload or {})


def _suspend_catalog_agent(db_path, catalog_agent_id, payload=None, query=None):
    return agent_catalog_handlers.suspend_catalog_agent(db_path, catalog_agent_id, payload or {})


def _reinstate_catalog_agent(db_path, catalog_agent_id, payload=None, query=None):
    return agent_catalog_handlers.reinstate_catalog_agent(db_path, catalog_agent_id, payload or {})


def _hosted_agent_card_document(db_path, catalog_agent_id, payload=None, query=None):
    return hosted_publication_handlers.hosted_agent_card(db_path, catalog_agent_id)


def _hosted_ucp_profile_document(db_path, catalog_agent_id, payload=None, query=None):
    return hosted_publication_handlers.hosted_ucp_profile(db_path, catalog_agent_id)


def _is_status_body_pair(result: Any) -> bool:
    return (
        isinstance(result, tuple)
        and len(result) == 2
        and isinstance(result[0], int)
        and not isinstance(result[0], bool)
    )


def resolve_route(
    method: str, path: str, routes: tuple[RouteEntry, ...] | list[Any] | None = None
) -> tuple[bool, bool]:
    """Return (path_known, method_allowed) without parsing the request body."""
    table = _ROUTE_TABLE if routes is None else tuple(routes)
    path_known = False
    for route in table:
        template = getattr(route, "path_template", None) or getattr(route, "path", "")
        if _match_path(template, path) is None:
            continue
        path_known = True
        if method.upper() in route.methods:
            return True, True
    return path_known, False


def handle_request(
    db_path: str | Path,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    query: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    payload = payload or {}
    query = query or {}
    try:
        validate_payload(payload)
        path_matched = False
        for route in _ROUTE_TABLE:
            path_params = _match_path(route.path_template, path)
            if path_params is None:
                continue
            path_matched = True
            if method.upper() in route.methods:
                result = route.handler(db_path, payload, query, **path_params)
                if _is_status_body_pair(result):
                    return result
                return 200, result
        if path_matched:
            raise MethodNotAllowedError(f"Method not allowed for {method} {path}")
        raise NotFoundError(f"No route for {method} {path}")
    except AuthError as exc:
        return 403, {"ok": False, "error": str(exc)}
    except PermissionDenied as exc:
        return 403, {"ok": False, "error": str(exc)}
    except IdempotencyConflict as exc:
        return 409, {"ok": False, "error": str(exc)}
    except ConflictError as exc:
        return 409, {"ok": False, "error": str(exc)}
    except NotFoundError as exc:
        return 404, {"ok": False, "error": str(exc)}
    except RateLimitError as exc:
        return 429, {"ok": False, "error": str(exc)}
    except PayloadTooLargeError as exc:
        return 413, {"ok": False, "error": str(exc)}
    except MethodNotAllowedError as exc:
        return 405, {"ok": False, "error": str(exc)}
    except ValidationError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except ShoppingCliError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except Exception:
        return 500, {"ok": False, "error": "internal server error"}




# ── FastAPI dual-stack (phase 3 follow-up) ─────────────────────────────────
# FastAPI 可用时 create_catalog_app 返回 FastAPI app（13 条 catalog 路由，
# 与 fallback ASGI 共用 wrapper）；不可用时回退 fallback。

try:
    from fastapi import FastAPI
    from fastapi import Header as _Header
except ImportError:
    FastAPI = None  # type: ignore[assignment,misc]
    _Header = None  # type: ignore[assignment,misc]


def _auth_header_default() -> Any:
    if _Header is None:
        return ""
    return _Header(default="")


def _idempotency_key_header_default() -> Any:
    if _Header is None:
        return ""
    return _Header(default="", alias="Idempotency-Key")


AUTHORIZATION_HEADER = _auth_header_default()
IDEMPOTENCY_KEY_HEADER = _idempotency_key_header_default()


def _register_fastapi_routes(app: Any, db_path: str | Path) -> None:
    """Register the 13 catalog routes on a FastAPI app.

    Exception mapping mirrors the fallback handle_request (403/404/409/429/
    400) so both stacks behave identically on the wire.
    """
    from fastapi.responses import JSONResponse
    from kiwi_catalog.api import auth as api_auth

    def _error_response(status: int, exc: Exception) -> JSONResponse:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=status)

    @app.exception_handler(AuthError)
    def _auth_error(_request: Any, exc: AuthError) -> JSONResponse:
        return _error_response(403, exc)

    @app.exception_handler(PermissionDenied)
    def _permission_error(_request: Any, exc: PermissionDenied) -> JSONResponse:
        return _error_response(403, exc)

    @app.exception_handler(NotFoundError)
    def _not_found_error(_request: Any, exc: NotFoundError) -> JSONResponse:
        return _error_response(404, exc)

    @app.exception_handler(ConflictError)
    def _conflict_error(_request: Any, exc: ConflictError) -> JSONResponse:
        return _error_response(409, exc)

    @app.exception_handler(IdempotencyConflict)
    def _idempotency_error(_request: Any, exc: IdempotencyConflict) -> JSONResponse:
        return _error_response(409, exc)

    @app.exception_handler(RateLimitError)
    def _rate_limit_error(_request: Any, exc: RateLimitError) -> JSONResponse:
        return _error_response(429, exc)

    @app.exception_handler(ValidationError)
    def _validation_error(_request: Any, exc: ValidationError) -> JSONResponse:
        return _error_response(400, exc)

    @app.exception_handler(ShoppingCliError)
    def _shopping_error(_request: Any, exc: ShoppingCliError) -> JSONResponse:
        return _error_response(400, exc)

    @app.get("/health")
    def health() -> dict[str, Any]:
        return _health(db_path)

    @app.get("/v1/agent-catalog/agents")
    def list_catalog_agents(limit: str = "", cursor: str = "") -> dict[str, Any]:
        return _list_catalog_agents(db_path, {}, {"limit": limit, "cursor": cursor})

    @app.get("/v1/agent-catalog/agents/search")
    def search_agent_catalog(
        q: str = "",
        category: str = "",
        skill: str = "",
        capability: str = "",
        protocol: str = "",
        hosting_mode: str = "",
        verification_status: str = "",
        verified_after: str = "",
        limit: str = "",
        cursor: str = "",
    ) -> dict[str, Any]:
        return _search_agent_catalog(
            db_path,
            {},
            {
                "q": q,
                "category": category,
                "skill": skill,
                "capability": capability,
                "protocol": protocol,
                "hosting_mode": hosting_mode,
                "verification_status": verification_status,
                "verified_after": verified_after,
                "limit": limit,
                "cursor": cursor,
            },
        )

    @app.get("/v1/agent-catalog/agents/{catalog_agent_id}")
    def get_catalog_agent(catalog_agent_id: str) -> dict[str, Any]:
        return _get_catalog_agent(db_path, catalog_agent_id)

    @app.get("/v1/agent-catalog/merchants/{merchant_id}/agents")
    def list_merchant_catalog_agents(
        merchant_id: str, limit: str = "", cursor: str = ""
    ) -> dict[str, Any]:
        return _list_merchant_catalog_agents(
            db_path, merchant_id, {}, {"limit": limit, "cursor": cursor}
        )

    @app.post("/v1/agent-catalog/agents/register")
    def register_catalog_agent(
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _register_catalog_agent(
            db_path, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/agent-catalog/agents/{catalog_agent_id}/refresh")
    def refresh_catalog_agent(
        catalog_agent_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _refresh_catalog_agent(
            db_path, catalog_agent_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/agent-catalog/agents/{catalog_agent_id}/verify")
    def verify_catalog_agent(
        catalog_agent_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _verify_catalog_agent(
            db_path, catalog_agent_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/agent-catalog/agents/{catalog_agent_id}/claim")
    def claim_catalog_agent(
        catalog_agent_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _claim_catalog_agent(
            db_path, catalog_agent_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/agent-catalog/agents/{catalog_agent_id}/suspend")
    def suspend_catalog_agent(
        catalog_agent_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _suspend_catalog_agent(
            db_path, catalog_agent_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/agent-catalog/agents/{catalog_agent_id}/reinstate")
    def reinstate_catalog_agent(
        catalog_agent_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _reinstate_catalog_agent(
            db_path, catalog_agent_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.get("/v1/hosted/agents/{catalog_agent_id}/agent-card.json")
    def hosted_agent_card_route(catalog_agent_id: str) -> Any:
        return _hosted_agent_card_document(db_path, catalog_agent_id)

    @app.get("/v1/hosted/agents/{catalog_agent_id}/ucp")
    def hosted_ucp_profile_route(catalog_agent_id: str) -> Any:
        return _hosted_ucp_profile_document(db_path, catalog_agent_id)


def create_catalog_app(db_path: str | Path = "kiwi-catalog.sqlite") -> Any:
    """kiwi-catalog standalone service (FastAPI dual-stack).

    FastAPI 可用时返回 FastAPI app（13 条 catalog 路由）；否则回退 fallback
    ASGI（同一 wrapper 与路由表）。  FastAPI 端点与 fallback 共用 handler，
    auth/idempotency header 经 payload_with_auth 合并进 payload。
    """
    if FastAPI is None:
        return MarketplaceASGIApp(
            db_path,
            route_provider=lambda: list(_ROUTE_TABLE),
            route_resolver=lambda method, path: resolve_route(method, path),
        )

    app = FastAPI(
        title="kiwi-catalog API",
        version=VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.db_path = str(db_path)
    _register_fastapi_routes(app, db_path)
    return app
