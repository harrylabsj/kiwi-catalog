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

装配拆分（move-only，行为不变）：可执行路由表与 handler wrapper 在
``api.route_table``（RouteEntry / _ROUTE_TABLE / resolve_route），FastAPI
路由安装与 header 默认值在 ``api.fastapi_routes``（register_fastapi_routes）。
本模块保留公共门面——create_catalog_app / handle_request / resolve_route /
_ROUTE_TABLE / RouteEntry / FastAPI——fallback ASGI 与既有导入方不变。
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from kiwi_catalog import VERSION
from kiwi_catalog.api.error_envelope import error_result
from kiwi_catalog.api.fallback_asgi import MarketplaceASGIApp
from kiwi_catalog.api.fastapi_routes import FastAPI, register_fastapi_routes
from kiwi_catalog.api.limits import validate_payload
from kiwi_catalog.api.request_dispatch import dispatch_request
from kiwi_catalog.api.route_matching import match_path as _match_path
from kiwi_catalog.api.route_table import _ROUTE_TABLE, RouteEntry, resolve_route
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

# 公共导入兼容：_ROUTE_TABLE / RouteEntry / resolve_route / FastAPI 从拆分后
# 的模块再导出（route_registry、fallback_asgi、scripts/kiwi_catalog_conformance
# 及 tests 从本模块读取这些名字）。

__all__ = [
    "_ROUTE_TABLE",
    "FastAPI",
    "RouteEntry",
    "create_catalog_app",
    "handle_request",
    "resolve_route",
]


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
        # 纯路由分发循环已提取到 request_dispatch.dispatch_request：
        # 顺序匹配路径模板、命中即调 handler，路径已知但方法不符抛 405，
        # 未知路径抛 404（与内联实现逐字一致）。
        result = dispatch_request(
            _ROUTE_TABLE,
            method,
            path,
            db_path,
            payload,
            query,
            _match_path,
        )
        return 200, result
    except AuthError as exc:
        return error_result(403, exc)
    except PermissionDenied as exc:
        return error_result(403, exc)
    except IdempotencyConflict as exc:
        return error_result(409, exc)
    except ConflictError as exc:
        return error_result(409, exc)
    except NotFoundError as exc:
        return error_result(404, exc)
    except RateLimitError as exc:
        return error_result(429, exc)
    except PayloadTooLargeError as exc:
        return error_result(413, exc)
    except MethodNotAllowedError as exc:
        return error_result(405, exc)
    except ValidationError as exc:
        return error_result(400, exc)
    except ShoppingCliError as exc:
        return error_result(400, exc)
    except Exception:
        # 错误（如 schema 漂移/遗留表引用）无法定位。
        logging.getLogger(__name__).exception("unhandled request error")
        return error_result(500, "internal server error")


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
    register_fastapi_routes(app, db_path)
    return app

