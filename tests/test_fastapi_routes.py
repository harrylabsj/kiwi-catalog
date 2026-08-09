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

"""Characterization tests for the extracted FastAPI route installation.

``kiwi_catalog/api/fastapi_routes.py`` owns the FastAPI branch of the dual
stack: the module-level availability guard, the Authorization /
Idempotency-Key header defaults, and ``register_fastapi_routes``.  These tests
pin that the module imports cleanly with or without fastapi, that its route
registration covers every fallback route-table path, and that the facade app
builds the same route set through it.
"""

from __future__ import annotations

import pytest

from kiwi_catalog.api import app as app_module
from kiwi_catalog.api.fastapi_routes import (
    AUTHORIZATION_HEADER,
    IDEMPOTENCY_KEY_HEADER,
    FastAPI,
    register_fastapi_routes,
)
from kiwi_catalog.api.route_table import _ROUTE_TABLE

_HAS_FASTAPI = FastAPI is not None


def test_module_imports_and_exposes_registration() -> None:
    """模块在无 fastapi 环境下也必须可导入（try/except guard → FastAPI=None）。"""
    assert callable(register_fastapi_routes)
    assert FastAPI is None or callable(FastAPI)


@pytest.mark.skipif(not _HAS_FASTAPI, reason="fastapi not installed")
def test_register_fastapi_routes_covers_all_fallback_paths() -> None:
    """FastAPI 栈必须覆盖 fallback 路由表的每一条路径（双栈 route parity）。"""
    from fastapi import FastAPI as _FA

    app = _FA()
    register_fastapi_routes(app, ":db:")
    fastapi_paths = {route.path for route in app.routes if hasattr(route, "path")}
    fallback_paths = {entry.path_template for entry in _ROUTE_TABLE}
    assert fallback_paths <= fastapi_paths


@pytest.mark.skipif(not _HAS_FASTAPI, reason="fastapi not installed")
def test_header_defaults_are_fastapi_header() -> None:
    from fastapi.params import Header

    assert isinstance(AUTHORIZATION_HEADER, Header)
    assert isinstance(IDEMPOTENCY_KEY_HEADER, Header)
    # 幂等键走 Idempotency-Key 别名（与 fallback header 名一致）
    assert IDEMPOTENCY_KEY_HEADER.alias == "Idempotency-Key"


@pytest.mark.skipif(not _HAS_FASTAPI, reason="fastapi not installed")
def test_facade_app_uses_extracted_registration() -> None:
    """create_catalog_app 与直接 register_fastapi_routes 产出同一路由集。"""
    from fastapi import FastAPI as _FA

    # 与 create_catalog_app 相同的 docs/redoc/openapi 关闭项，只比 catalog 路由
    direct = _FA(docs_url=None, redoc_url=None, openapi_url=None)
    register_fastapi_routes(direct, ":db:")
    direct_paths = {route.path for route in direct.routes if hasattr(route, "path")}

    facade = app_module.create_catalog_app(":db:")
    facade_paths = {route.path for route in facade.routes if hasattr(route, "path")}

    assert direct_paths == facade_paths
    # 双栈 parity 的静态段仍由 facade 表驱动
    assert "/v1/listings/search" in facade_paths
    assert "/v1/listings/{listing_id}" in facade_paths
