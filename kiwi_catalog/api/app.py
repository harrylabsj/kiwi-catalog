# Copyright 2026 harrylabsj
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kiwi_catalog import VERSION
from kiwi_catalog.api.fallback_asgi import MarketplaceASGIApp
from kiwi_catalog.api.handlers import agent_catalog as agent_catalog_handlers
from kiwi_catalog.api.handlers import hosted_publication as hosted_publication_handlers
from kiwi_catalog.api.handlers import listings as listings_handlers
from kiwi_catalog.api.handlers import merchants as merchants_handlers
from kiwi_catalog.api.handlers import portal as portal_handlers
from kiwi_catalog.api.limits import max_request_body_bytes, validate_payload
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
            db_path, catalog_agent_id=catalog_agent_id
        ),
    ),
RouteEntry(
        {"GET"},
        "/v1/agent-catalog/merchants/{merchant_id}/agents",
        lambda db_path, payload, query, merchant_id: _list_merchant_catalog_agents(
            db_path, merchant_id=merchant_id, query=query or {}
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
        "/v1/agents",
        lambda db_path, payload, query, **kw: _v1_list_agents(db_path, payload, query),
    ),
RouteEntry(
        {"GET"},
        "/v1/agents/search",
        lambda db_path, payload, query, **kw: _v1_search_agents(db_path, payload, query),
    ),
RouteEntry(
        {"GET"},
        "/v1/agents/{catalog_agent_id}",
        lambda db_path, payload, query, catalog_agent_id: _v1_get_agent(
            db_path, catalog_agent_id=catalog_agent_id
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/agents/register",
        lambda db_path, payload, query, **kw: _v1_register_agent(db_path, payload),
    ),
RouteEntry(
        {"POST"},
        "/v1/agents/{catalog_agent_id}/refresh",
        lambda db_path, payload, query, catalog_agent_id: _v1_refresh_agent(
            db_path, catalog_agent_id, payload
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/agents/{catalog_agent_id}/verify",
        lambda db_path, payload, query, catalog_agent_id: _v1_verify_agent(
            db_path, catalog_agent_id, payload
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/agents/{catalog_agent_id}/claim",
        lambda db_path, payload, query, catalog_agent_id: _v1_claim_agent(
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
# ── /v1/listings（v0.4 新 API：Product-first Commerce Discovery）────────────
# 顺序约束：/v1/listings/search 必须先于 /v1/listings/{listing_id}
#（_match_path 顺序匹配；与 /v1/agents/search 先例一致）。
RouteEntry(
        {"GET"},
        "/v1/listings/search",
        lambda db_path, payload, query, **kw: _v1_search_listings(db_path, payload, query),
    ),
RouteEntry(
        {"GET"},
        "/v1/listings/{listing_id}",
        lambda db_path, payload, query, listing_id: _v1_get_listing(
            db_path, listing_id=listing_id
        ),
    ),
RouteEntry(
        {"GET"},
        "/v1/agents/{catalog_agent_id}/listings",
        lambda db_path, payload, query, catalog_agent_id: _v1_list_agent_listings(
            db_path, catalog_agent_id, query or {}
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/listings/publish",
        lambda db_path, payload, query, **kw: _v1_publish_listing(db_path, payload),
    ),
RouteEntry(
        {"POST"},
        "/v1/listings/{listing_id}/withdraw",
        lambda db_path, payload, query, listing_id: _v1_withdraw_listing(
            db_path, listing_id, payload
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/listings/{listing_id}/reinstate",
        lambda db_path, payload, query, listing_id: _v1_reinstate_listing(
            db_path, listing_id, payload
        ),
    ),
# ── /v1/merchants（token 分发，docs/kiwi-catalog-token-portal-design-v0.1 §4）──
# 顺序约束：/v1/merchants/applications 先于 /v1/merchants/{merchant_id}/rotate
#（_match_path 顺序匹配，全路径正则无参数冲突；method 也不同）。
RouteEntry(
        {"POST"},
        "/v1/merchants/applications",
        lambda db_path, payload, query, **kw: _v1_submit_application(db_path, payload),
    ),
RouteEntry(
        {"GET"},
        "/v1/merchants/applications",
        lambda db_path, payload, query, **kw: _v1_list_applications(db_path, payload, query),
    ),
RouteEntry(
        {"POST"},
        "/v1/merchants/applications/{application_id}/approve",
        lambda db_path, payload, query, application_id: _v1_approve_application(
            db_path, application_id, payload
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/merchants/applications/{application_id}/reject",
        lambda db_path, payload, query, application_id: _v1_reject_application(
            db_path, application_id, payload
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/merchants/{merchant_id}/rotate",
        lambda db_path, payload, query, merchant_id: _v1_rotate_token(
            db_path, merchant_id, payload
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/merchants/{merchant_id}/revoke",
        lambda db_path, payload, query, merchant_id: _v1_revoke_token(
            db_path, merchant_id, payload
        ),
    ),
RouteEntry(
        {"GET"},
        "/v1/merchants/self",
        lambda db_path, payload, query, **kw: _v1_merchant_self(db_path, payload, query),
    ),
# ── /portal（门户页面，docs §6；fallback 栈渲染 HTML）────────────────────
RouteEntry(
        {"GET"},
        "/portal",
        lambda db_path, payload, query, **kw: _portal_home(),
    ),
RouteEntry(
        {"GET"},
        "/portal/apply",
        lambda db_path, payload, query, **kw: _portal_apply(),
    ),
RouteEntry(
        {"GET"},
        "/portal/admin",
        lambda db_path, payload, query, **kw: _portal_admin(),
    ),
RouteEntry(
        {"GET"},
        "/portal/status",
        lambda db_path, payload, query, **kw: _portal_status(),
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


# ── /v1/agents（v0.3 新 API：三正交状态域 record）──────────────────────────


def _v1_list_agents(db_path, payload, query):
    return agent_catalog_handlers.v1_list_agents(db_path, query)


def _v1_search_agents(db_path, payload, query):
    return agent_catalog_handlers.v1_search_agents(db_path, query)


def _v1_get_agent(db_path, catalog_agent_id, payload=None, query=None):
    return agent_catalog_handlers.v1_get_agent(db_path, catalog_agent_id)


def _v1_register_agent(db_path, payload):
    return agent_catalog_handlers.v1_register_agent(db_path, payload)


def _v1_refresh_agent(db_path, catalog_agent_id, payload=None, query=None):
    return agent_catalog_handlers.v1_refresh_agent(db_path, catalog_agent_id, payload or {})


def _v1_verify_agent(db_path, catalog_agent_id, payload=None, query=None):
    return agent_catalog_handlers.v1_verify_agent(db_path, catalog_agent_id, payload or {})


def _v1_claim_agent(db_path, catalog_agent_id, payload=None, query=None):
    return agent_catalog_handlers.v1_claim_agent(db_path, catalog_agent_id, payload or {})


# ── /v1/listings wrapper（v0.4）────────────────────────────────────────────


def _v1_search_listings(db_path, payload, query):
    return listings_handlers.v1_search_listings(db_path, query or {})


# ── /v1/merchants wrapper（token 分发）────────────────────────────────────


def _v1_submit_application(db_path, payload):
    return merchants_handlers.submit_application(db_path, payload)


def _v1_list_applications(db_path, payload, query):
    return merchants_handlers.list_applications(db_path, payload, query or {})


def _v1_approve_application(db_path, application_id, payload):
    return merchants_handlers.approve_application(db_path, application_id, payload)


def _v1_reject_application(db_path, application_id, payload):
    return merchants_handlers.reject_application(db_path, application_id, payload)


def _v1_rotate_token(db_path, merchant_id, payload):
    return merchants_handlers.rotate_token(db_path, merchant_id, payload)


def _v1_revoke_token(db_path, merchant_id, payload):
    return merchants_handlers.revoke_token(db_path, merchant_id, payload)


def _v1_merchant_self(db_path, payload, query):
    return merchants_handlers.self_status(db_path, payload, query or {})


# ── /portal wrapper（门户页面）────────────────────────────────────────────


def _portal_home():
    return portal_handlers.portal_home()


def _portal_apply():
    return portal_handlers.portal_apply()


def _portal_admin():
    return portal_handlers.portal_admin()


def _portal_status():
    return portal_handlers.portal_status()


def _v1_get_listing(db_path, listing_id, payload=None, query=None):
    return listings_handlers.v1_get_listing(db_path, listing_id)


def _v1_list_agent_listings(db_path, catalog_agent_id, query):
    return listings_handlers.v1_list_agent_listings(db_path, catalog_agent_id, query)


def _v1_publish_listing(db_path, payload):
    return listings_handlers.v1_publish_listing(db_path, payload)


def _v1_withdraw_listing(db_path, listing_id, payload=None, query=None):
    return listings_handlers.v1_withdraw_listing(db_path, listing_id, payload or {})


def _v1_reinstate_listing(db_path, listing_id, payload=None, query=None):
    return listings_handlers.v1_reinstate_listing(db_path, listing_id, payload or {})


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
                # handler 统一返回响应体 dict（13 条路由皆然）；旧
                # _is_status_body_pair 分支（handler 返回 (status, body) 对）
                # 无任何路由使用，已删。
                result = route.handler(db_path, payload, query, **path_params)
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
    except Exception as exc:
        # 错误（如 schema 漂移/遗留表引用）无法定位。
        logging.getLogger(__name__).exception("unhandled request error: %r", exc)
        return 500, {"ok": False, "error": "internal server error"}




# ── FastAPI dual-stack (phase 3 follow-up) ─────────────────────────────────
# FastAPI 可用时 create_catalog_app 返回 FastAPI app（13 条 catalog 路由，
# 与 fallback ASGI 共用 wrapper）；不可用时回退 fallback。

try:
    from fastapi import FastAPI
    from fastapi import Header as _Header
    from fastapi import Request as _FastAPIRequest
except ImportError:
    FastAPI = None  # type: ignore[assignment,misc]
    _Header = None  # type: ignore[assignment,misc]
    _FastAPIRequest = None  # type: ignore[assignment,misc]


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
    from fastapi.responses import JSONResponse, Response

    from kiwi_catalog.api import auth as api_auth
    from kiwi_catalog.discovery.cache import compute_etag, etag_matches

    @app.middleware("http")
    async def _parity_middleware(request: _FastAPIRequest, call_next: Any) -> Any:
        """审查 P2：FastAPI 栈补齐 fallback 的传输/JSON 资源上限与 GET 304 语义。

        - body 大小上限（413）、JSON 解析失败（400）、非对象 body（400）、
          validate_payload 深度/节点/字符串上限（400/413）——此前 FastAPI 栈
          无任何限制（任意大/深 body 直入内存）；
        - 空 body 视为 {}（与 fallback ``json.loads(... or "{}")`` 一致）；
        - GET 200 响应带 etag，显式 If-None-Match 匹配 → 304（fallback §18）。
        """
        if request.method in ("POST", "PUT", "PATCH"):
            maximum = max_request_body_bytes()
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    if int(content_length) > maximum:
                        return JSONResponse(
                            {"ok": False, "error": "request body is too large"},
                            status_code=413,
                        )
                except ValueError:
                    pass
            chunks: list[bytes] = []
            total = 0
            async for chunk in request.stream():
                total += len(chunk)
                if total > maximum:
                    return JSONResponse(
                        {"ok": False, "error": "request body is too large"},
                        status_code=413,
                    )
                chunks.append(chunk)
            body = b"".join(chunks) or b"{}"
            try:
                parsed = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return JSONResponse(
                    {"ok": False, "error": "invalid JSON request body"}, status_code=400
                )
            if not isinstance(parsed, dict):
                return JSONResponse(
                    {"ok": False, "error": "JSON request body must be an object"},
                    status_code=400,
                )
            try:
                validate_payload(parsed)
            except PayloadTooLargeError as exc:
                return JSONResponse({"ok": False, "error": str(exc)}, status_code=413)
            except ValidationError as exc:
                return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
            # stream() 已消费——把缓存 body 塞回 receive，让 FastAPI 依赖正常解析
            async def _receive() -> dict[str, Any]:
                return {"type": "http.request", "body": body, "more_body": False}

            request._receive = _receive  # type: ignore[attr-defined]
            request._stream_consumed = False  # type: ignore[attr-defined]

        response = await call_next(request)

        # GET 条件请求（fallback §18：仅成功表示 + 显式 If-None-Match）
        if request.method == "GET" and response.status_code == 200:
            body = b"".join([chunk async for chunk in response.body_iterator])
            etag = compute_etag(body)
            headers = dict(response.headers)
            headers["etag"] = etag
            if_none_match = request.headers.get("if-none-match", "")
            if if_none_match and etag_matches(if_none_match, etag):
                return Response(status_code=304, headers=headers)
            return Response(
                content=body, status_code=200, headers=headers, media_type=response.media_type
            )
        return response

    def _query_params_from_request(request: _FastAPIRequest) -> dict[str, str]:
        """Mirror fallback parse_qs(keep_blank_values=True) + last-value-wins.

        FastAPI 只识别声明过的 query 参数、静默丢弃其余键（含 attribute.* 动态键
        与未知键），与 fallback 全量透传语义分裂（审查 P2-3）。共享 handler 自带
        键白名单校验，路由层不做参数裁剪。

        注意：必须用模块级导入的 _FastAPIRequest（from __future__ import
        annotations 会把函数内导入的注解变成字符串，FastAPI 无法解析 → 参数被
        误判为 query 字段）。
        """
        return {key: value for key, value in request.query_params.multi_items()}


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

    # ── 审查 P2：错误形状与 fallback 对齐 ───────────────────────────────
    # fallback 的 404/405/400/500 都是 {"ok": false, "error": ...} 信封 +
    # 明确文案；FastAPI 默认的 {"detail": ...} / 纯文本 500 让依赖 ok/error
    # 信封的客户端在双栈切换后解析失败。

    from fastapi.exceptions import RequestValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException

    @app.exception_handler(RequestValidationError)
    def _request_validation_error(
        _request: Any, exc: RequestValidationError
    ) -> JSONResponse:
        # fallback 语义：请求体/参数不符合契约 → 400 信封（FastAPI 默认 422 detail）
        first = exc.errors()[:3]
        # 非 JSON body（如 form 编码）时 FastAPI 的 input 字段是 bytes——
        # 不 default=str 会在错误信封序列化时二次抛错变 500（冒烟实测）
        return JSONResponse(
            {
                "ok": False,
                "error": "invalid request: "
                + json.dumps(
                    first,
                    default=lambda o: o.decode("utf-8", "replace")
                    if isinstance(o, bytes)
                    else str(o),
                ),
            },
            status_code=400,
        )

    @app.exception_handler(StarletteHTTPException)
    def _http_exception(
        request: _FastAPIRequest, exc: StarletteHTTPException
    ) -> JSONResponse:
        if exc.status_code == 404:
            message = f"No route for {request.method} {request.url.path}"
        elif exc.status_code == 405:
            message = f"Method not allowed for {request.method} {request.url.path}"
        else:
            message = str(exc.detail)
        return JSONResponse({"ok": False, "error": message}, status_code=exc.status_code)

    @app.exception_handler(Exception)
    def _unhandled_exception(request: Any, exc: Exception) -> JSONResponse:
        logging.getLogger(__name__).exception("unhandled request error: %r", exc)
        return JSONResponse(
            {"ok": False, "error": "internal server error"}, status_code=500
        )

    @app.get("/health")
    def health() -> dict[str, Any]:
        return _health(db_path)

    @app.get("/v1/agent-catalog/agents")
    def list_catalog_agents(request: _FastAPIRequest) -> dict[str, Any]:
        return _list_catalog_agents(db_path, {}, _query_params_from_request(request))

    @app.get("/v1/agent-catalog/agents/search")
    def search_agent_catalog(request: _FastAPIRequest) -> dict[str, Any]:
        return _search_agent_catalog(db_path, {}, _query_params_from_request(request))

    @app.get("/v1/agent-catalog/agents/{catalog_agent_id}")
    def get_catalog_agent(catalog_agent_id: str) -> dict[str, Any]:
        return _get_catalog_agent(db_path, catalog_agent_id)

    @app.get("/v1/agent-catalog/merchants/{merchant_id}/agents")
    def list_merchant_catalog_agents(
        merchant_id: str, request: _FastAPIRequest
    ) -> dict[str, Any]:
        return _list_merchant_catalog_agents(
            db_path, merchant_id, {}, _query_params_from_request(request)
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

    @app.get("/v1/agents")
    def v1_list_agents(request: _FastAPIRequest) -> dict[str, Any]:
        return _v1_list_agents(db_path, {}, _query_params_from_request(request))

    @app.get("/v1/agents/search")
    def v1_search_agents(request: _FastAPIRequest) -> dict[str, Any]:
        return _v1_search_agents(db_path, {}, _query_params_from_request(request))

    @app.get("/v1/agents/{catalog_agent_id}")
    def v1_get_agent(catalog_agent_id: str) -> dict[str, Any]:
        return _v1_get_agent(db_path, catalog_agent_id)

    @app.post("/v1/agents/register")
    def v1_register_agent(
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _v1_register_agent(
            db_path, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/agents/{catalog_agent_id}/refresh")
    def v1_refresh_agent(
        catalog_agent_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _v1_refresh_agent(
            db_path, catalog_agent_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/agents/{catalog_agent_id}/verify")
    def v1_verify_agent(
        catalog_agent_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _v1_verify_agent(
            db_path, catalog_agent_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/agents/{catalog_agent_id}/claim")
    def v1_claim_agent(
        catalog_agent_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _v1_claim_agent(
            db_path, catalog_agent_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.get("/v1/hosted/agents/{catalog_agent_id}/agent-card.json")
    def hosted_agent_card_route(catalog_agent_id: str) -> Any:
        return _hosted_agent_card_document(db_path, catalog_agent_id)

    @app.get("/v1/hosted/agents/{catalog_agent_id}/ucp")
    def hosted_ucp_profile_route(catalog_agent_id: str) -> Any:
        return _hosted_ucp_profile_document(db_path, catalog_agent_id)

    @app.get("/v1/listings/search")
    def v1_search_listings(request: _FastAPIRequest) -> dict[str, Any]:
        return _v1_search_listings(db_path, {}, _query_params_from_request(request))

    @app.get("/v1/listings/{listing_id}")
    def v1_get_listing(listing_id: str) -> dict[str, Any]:
        return _v1_get_listing(db_path, listing_id)

    @app.get("/v1/agents/{catalog_agent_id}/listings")
    def v1_list_agent_listings(
        catalog_agent_id: str, request: _FastAPIRequest
    ) -> dict[str, Any]:
        return _v1_list_agent_listings(
            db_path, catalog_agent_id, _query_params_from_request(request)
        )

    @app.post("/v1/listings/publish")
    def v1_publish_listing(
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _v1_publish_listing(
            db_path, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/listings/{listing_id}/withdraw")
    def v1_withdraw_listing(
        listing_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _v1_withdraw_listing(
            db_path, listing_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/listings/{listing_id}/reinstate")
    def v1_reinstate_listing(
        listing_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _v1_reinstate_listing(
            db_path, listing_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    # ── /v1/merchants（token 分发，docs §4；门户 HTML 页 fallback-only）────

    @app.post("/v1/merchants/applications")
    def v1_submit_application(
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _v1_submit_application(
            db_path, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.get("/v1/merchants/applications")
    def v1_list_applications(request: _FastAPIRequest) -> dict[str, Any]:
        return _v1_list_applications(db_path, {}, _query_params_from_request(request))

    @app.post("/v1/merchants/applications/{application_id}/approve")
    def v1_approve_application(
        application_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _v1_approve_application(
            db_path, application_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/merchants/applications/{application_id}/reject")
    def v1_reject_application(
        application_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _v1_reject_application(
            db_path, application_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/merchants/{merchant_id}/rotate")
    def v1_rotate_token(
        merchant_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _v1_rotate_token(
            db_path, merchant_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/merchants/{merchant_id}/revoke")
    def v1_revoke_token(
        merchant_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _v1_revoke_token(
            db_path, merchant_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.get("/v1/merchants/self")
    def v1_merchant_self(request: _FastAPIRequest) -> dict[str, Any]:
        return _v1_merchant_self(db_path, {}, _query_params_from_request(request))

    # ── /portal（门户 HTML 页；双栈都注册以保持 route 覆盖 parity）────────
    from fastapi.responses import HTMLResponse

    _PORTAL_HTML_HEADERS = {"Cache-Control": "no-store"}  # 一次性令牌页防缓存

    @app.get("/portal")
    def portal_home_page() -> HTMLResponse:
        return HTMLResponse(
            portal_handlers.portal_home()["__html__"], headers=_PORTAL_HTML_HEADERS
        )

    @app.get("/portal/apply")
    def portal_apply_page() -> HTMLResponse:
        return HTMLResponse(
            portal_handlers.portal_apply()["__html__"], headers=_PORTAL_HTML_HEADERS
        )

    @app.get("/portal/admin")
    def portal_admin_page() -> HTMLResponse:
        return HTMLResponse(
            portal_handlers.portal_admin()["__html__"], headers=_PORTAL_HTML_HEADERS
        )

    @app.get("/portal/status")
    def portal_status_page() -> HTMLResponse:
        return HTMLResponse(
            portal_handlers.portal_status()["__html__"], headers=_PORTAL_HTML_HEADERS
        )


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
