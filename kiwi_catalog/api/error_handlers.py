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

"""FastAPI exception handlers for the catalog stacks (transport-injected).

Registers the error mappings that make the FastAPI stack behave like the
fallback ``handle_request``: business exceptions become the stable
``{"ok": false, "error": ...}`` envelope with the same status codes, and
RequestValidationError / Starlette HTTPException / unexpected Exception are
rewritten to that envelope instead of FastAPI's default shapes.

The module must stay importable in a non-FastAPI environment, so it never
imports FastAPI or Starlette at module level: ``json_response`` (the
JSONResponse class), ``request_type`` (the Request class) and the optional
framework exception types are injected by the caller.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from kiwi_catalog.core.errors import (
    AuthError,
    ConflictError,
    IdempotencyConflict,
    NotFoundError,
    PermissionDenied,
    RateLimitError,
    ShoppingCliError,
    ValidationError,
)

__all__ = ["register_exception_handlers"]


def register_exception_handlers(
    app: Any,
    *,
    json_response: Any,
    request_type: Any,
    request_validation_error: Any = None,
    http_exception: Any = None,
    logger_name: str | None = None,
) -> None:
    """Register the shared error mapping on ``app``.

    ``json_response`` must be the FastAPI ``JSONResponse`` class and
    ``request_type`` the FastAPI ``Request`` class; ``request_validation_error``
    and ``http_exception`` are the optional framework exception types
    (``RequestValidationError`` / Starlette ``HTTPException``) — pass None to
    skip those handlers.  ``logger_name`` keeps the unexpected-500 log on the
    caller's logger (app.py passes ``__name__`` so the name is unchanged).
    """

    def _error_response(status: int, exc: Exception) -> Any:
        return json_response({"ok": False, "error": str(exc)}, status_code=status)

    @app.exception_handler(AuthError)
    def _auth_error(_request: Any, exc: AuthError) -> Any:
        return _error_response(403, exc)

    @app.exception_handler(PermissionDenied)
    def _permission_error(_request: Any, exc: PermissionDenied) -> Any:
        return _error_response(403, exc)

    @app.exception_handler(NotFoundError)
    def _not_found_error(_request: Any, exc: NotFoundError) -> Any:
        return _error_response(404, exc)

    @app.exception_handler(ConflictError)
    def _conflict_error(_request: Any, exc: ConflictError) -> Any:
        return _error_response(409, exc)

    @app.exception_handler(IdempotencyConflict)
    def _idempotency_error(_request: Any, exc: IdempotencyConflict) -> Any:
        return _error_response(409, exc)

    @app.exception_handler(RateLimitError)
    def _rate_limit_error(_request: Any, exc: RateLimitError) -> Any:
        return _error_response(429, exc)

    @app.exception_handler(ValidationError)
    def _validation_error(_request: Any, exc: ValidationError) -> Any:
        return _error_response(400, exc)

    @app.exception_handler(ShoppingCliError)
    def _shopping_error(_request: Any, exc: ShoppingCliError) -> Any:
        return _error_response(400, exc)

    # ── 审查 P2：错误形状与 fallback 对齐 ───────────────────────────────
    # fallback 的 404/405/400/500 都是 {"ok": false, "error": ...} 信封 +
    # 明确文案；FastAPI 默认的 {"detail": ...} / 纯文本 500 让依赖 ok/error
    # 信封的客户端在双栈切换后解析失败。

    if request_validation_error is not None:
        @app.exception_handler(request_validation_error)
        def _request_validation_error(_request: Any, exc: Any) -> Any:
            # fallback 语义：请求体/参数不符合契约 → 400 信封（FastAPI 默认 422 detail）
            first = exc.errors()[:3]
            # 非 JSON body（如 form 编码）时 FastAPI 的 input 字段是 bytes——
            # 不 default=str 会在错误信封序列化时二次抛错变 500（冒烟实测）
            return json_response(
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

    if http_exception is not None:
        @app.exception_handler(http_exception)
        def _http_exception(request: request_type, exc: http_exception) -> Any:
            if exc.status_code == 404:
                message = f"No route for {request.method} {request.url.path}"
            elif exc.status_code == 405:
                message = f"Method not allowed for {request.method} {request.url.path}"
            else:
                message = str(exc.detail)
            return json_response(
                {"ok": False, "error": message}, status_code=exc.status_code
            )

    @app.exception_handler(Exception)
    def _unhandled_exception(request: Any, exc: Exception) -> Any:
        logging.getLogger(logger_name or "kiwi_catalog.api.app").exception(
            "unhandled request error: %r", exc
        )
        return json_response(
            {"ok": False, "error": "internal server error"}, status_code=500
        )
