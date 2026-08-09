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

"""Characterization tests for the extracted fallback route table.

``kiwi_catalog/api/route_table.py`` owns the executable route table, its
handler wrappers and ``resolve_route``.  These tests pin the table's shape,
its static-before-parameter ordering constraints and the route resolution
behavior, so future structural moves cannot silently drop, reorder or
dereference a route.  All tests are pure (no DB, no FastAPI), so they also run
under ``python3 -m unittest discover`` in a no-fastapi environment.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from typing import ClassVar

import pytest

from kiwi_catalog.api import app as app_module
from kiwi_catalog.api import fastapi_routes as fastapi_routes_module
from kiwi_catalog.api.route_table import _ROUTE_TABLE, RouteEntry, resolve_route


def _path_index(path: str) -> int:
    for i, entry in enumerate(_ROUTE_TABLE):
        if entry.path_template == path:
            return i
    raise AssertionError(f"route {path!r} not found in _ROUTE_TABLE")


def test_every_route_entry_is_well_formed() -> None:
    # 软上限 600 行不适用此处——路由表是声明式数据；断言其规模与形状稳定。
    assert len(_ROUTE_TABLE) >= 50
    for entry in _ROUTE_TABLE:
        assert isinstance(entry, RouteEntry)
        assert isinstance(entry.path_template, str)
        assert entry.path_template.startswith("/")
        assert isinstance(entry.methods, set) and len(entry.methods) >= 1
        assert all(isinstance(m, str) and m.isupper() for m in entry.methods)
        assert callable(entry.handler)


def test_route_table_covers_expected_route_groups() -> None:
    paths = {entry.path_template for entry in _ROUTE_TABLE}
    for expected in (
        "/health",
        "/v1/agent-catalog/agents",
        "/v1/agent-catalog/agents/search",
        "/v1/agent-catalog/agents/register",
        "/v1/agents",
        "/v1/agents/search",
        "/v1/agents/register",
        "/v1/hosted/agents/{catalog_agent_id}/agent-card.json",
        "/v1/hosted/agents/{catalog_agent_id}/ucp",
        "/v1/listings/search",
        "/v1/listings/{listing_id}",
        "/v1/listings/publish",
        "/v1/listings/{listing_id}/withdraw",
        "/v1/merchants/applications",
        "/v1/merchants/self",
        "/v1/merchants/{merchant_id}/rotate",
        "/v1/accounts/register",
        "/v1/accounts/login",
        "/v1/accounts/me",
        "/v1/admin/dashboard",
        "/v1/admin/merchants/{merchant_id}/report",
        "/portal",
        "/portal/apply",
        "/portal/account",
    ):
        assert expected in paths, f"missing route {expected!r}"


def test_static_paths_precede_parameter_siblings() -> None:
    """顺序匹配约束：/search 与 /applications 静态段必须先于参数段声明。

    ``_match_path`` 顺序匹配；若参数段先声明，静态段会被当作参数值吞掉。
    """
    assert _path_index("/v1/agent-catalog/agents/search") < _path_index(
        "/v1/agent-catalog/agents/{catalog_agent_id}"
    )
    assert _path_index("/v1/agents/search") < _path_index("/v1/agents/{catalog_agent_id}")
    assert _path_index("/v1/listings/search") < _path_index("/v1/listings/{listing_id}")
    assert _path_index("/v1/merchants/applications") < _path_index(
        "/v1/merchants/{merchant_id}/rotate"
    )
    assert _path_index("/v1/merchants/applications") < _path_index(
        "/v1/merchants/{merchant_id}/revoke"
    )


def test_route_methods_are_pinned() -> None:
    by_path = {entry.path_template: entry for entry in _ROUTE_TABLE}
    assert by_path["/health"].methods == {"GET"}
    assert by_path["/v1/agents/register"].methods == {"POST"}
    assert by_path["/v1/listings/search"].methods == {"GET"}
    # /v1/merchants/applications 拆成 POST 与 GET 两条 RouteEntry（方法不同）
    applications = [
        entry.methods
        for entry in _ROUTE_TABLE
        if entry.path_template == "/v1/merchants/applications"
    ]
    assert applications == [{"POST"}, {"GET"}]


def test_resolve_route_known_path_and_method() -> None:
    assert resolve_route("GET", "/health") == (True, True)
    assert resolve_route("get", "/health") == (True, True)  # 方法大小写不敏感


def test_resolve_route_known_path_wrong_method() -> None:
    assert resolve_route("DELETE", "/health") == (True, False)


def test_resolve_route_unknown_path() -> None:
    assert resolve_route("GET", "/v1/does-not-exist") == (False, False)


def test_resolve_route_accepts_explicit_route_list() -> None:
    table = [RouteEntry({"GET"}, "/custom", lambda db_path, payload, query, **kw: "ok")]
    assert resolve_route("GET", "/custom", table) == (True, True)
    assert resolve_route("POST", "/custom", table) == (True, False)
    assert resolve_route("GET", "/other", table) == (False, False)


def test_resolve_route_skips_non_str_template_fail_closed() -> None:
    """非 str route 模板 fail-closed：跳过而非强转，正常 str 模板仍匹配。"""

    class _WeirdTemplateRoute:
        def __init__(self, template: object) -> None:
            self.path_template = template
            self.methods = {"GET"}

    class _PathOnlyRoute:
        path = "/legacy"
        methods: ClassVar[set[str]] = {"GET"}

    table = [_WeirdTemplateRoute(42), _WeirdTemplateRoute(None), _PathOnlyRoute()]
    assert resolve_route("GET", "/legacy", table) == (True, True)
    assert resolve_route("GET", "/42", table) == (False, False)


def test_app_facade_reexports_extracted_symbols() -> None:
    assert app_module._ROUTE_TABLE is _ROUTE_TABLE
    assert app_module.RouteEntry is RouteEntry
    assert app_module.resolve_route is resolve_route
    assert app_module.FastAPI is fastapi_routes_module.FastAPI


def test_route_entry_is_frozen() -> None:
    entry = RouteEntry({"GET"}, "/x", lambda **kw: None)
    with pytest.raises(FrozenInstanceError):
        entry.path_template = "/y"  # type: ignore[misc]
