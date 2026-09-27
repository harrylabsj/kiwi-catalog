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

"""Characterization tests for the generic extension hook (docs/extensions.md).

扩展经 ``KIWI_CATALOG_EXTENSIONS`` env 声明，顶层暴露
``register_kiwi_extension(registry)``。这里用 ``types.ModuleType`` 伪造扩展
注册进 ``sys.modules``（importlib 直接命中缓存，无需 fixture 包），逐条钉住：
env 未设零变化、路由/FastAPI 双栈注册、fail-soft、基路由优先、缓存语义。
"""

from __future__ import annotations

import sys
import types
from collections.abc import Iterator
from typing import Any

import pytest

from kiwi_catalog.api import extensions
from kiwi_catalog.api.app import create_catalog_app, handle_request
from kiwi_catalog.api.route_table import _ROUTE_TABLE, all_routes, resolve_route

DUMMY_EXT_NAME = "kiwi_test_dummy_extension"


def _install_dummy_extension(
    *,
    handler: Any = None,
    hook: Any = None,
    register_raises: bool = False,
) -> types.ModuleType:
    module = types.ModuleType(DUMMY_EXT_NAME)

    def register(reg: extensions.ExtensionRegistry) -> None:
        if register_raises:
            raise RuntimeError("boom")
        if handler is not None:
            reg.add_route({"GET"}, "/v1/ext/ping", handler)
        if hook is not None:
            reg.add_fastapi_hook(hook)

    module.register_kiwi_extension = register  # type: ignore[attr-defined]
    sys.modules[DUMMY_EXT_NAME] = module
    return module


@pytest.fixture(autouse=True)
def _clean_extensions_env(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    monkeypatch.delenv(extensions.KIWI_EXTENSIONS_ENV, raising=False)
    extensions.reset_extension_cache()
    yield
    sys.modules.pop(DUMMY_EXT_NAME, None)
    extensions.reset_extension_cache()


def _enable_dummy(monkeypatch: pytest.MonkeyPatch, name: str = DUMMY_EXT_NAME) -> None:
    monkeypatch.setenv(extensions.KIWI_EXTENSIONS_ENV, name)
    extensions.reset_extension_cache()


def _dummy_handler(db_path, payload=None, query=None, **kw):
    return {"ok": True, "ext": True}


def test_env_unset_means_zero_extensions() -> None:
    assert extensions.extension_route_specs() == ()
    assert extensions.load_extensions().fastapi_hooks == ()
    assert all_routes() is _ROUTE_TABLE
    assert resolve_route("GET", "/v1/ext/ping") == (False, False)


def test_extension_route_registers_into_fallback_stack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_dummy_extension(handler=_dummy_handler)
    _enable_dummy(monkeypatch)

    table = all_routes()
    assert table is not _ROUTE_TABLE
    assert len(table) == len(_ROUTE_TABLE) + 1
    assert resolve_route("GET", "/v1/ext/ping") == (True, True)
    assert resolve_route("POST", "/v1/ext/ping") == (True, False)

    status, result = handle_request("unused.sqlite", "GET", "/v1/ext/ping", {}, {})
    assert status == 200
    assert result == {"ok": True, "ext": True}


def test_missing_extension_package_fails_soft(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_dummy(monkeypatch, "kiwi_no_such_extension_pkg")

    assert extensions.extension_route_specs() == ()
    assert extensions.load_extensions().fastapi_hooks == ()
    assert all_routes() is _ROUTE_TABLE


def test_register_exception_fails_soft(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_dummy_extension(register_raises=True)
    _enable_dummy(monkeypatch)

    assert extensions.extension_route_specs() == ()
    assert extensions.load_extensions().fastapi_hooks == ()


def test_extension_without_register_hook_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 有模块但没有 register_kiwi_extension：同样 fail-soft。
    sys.modules[DUMMY_EXT_NAME] = types.ModuleType(DUMMY_EXT_NAME)
    _enable_dummy(monkeypatch)

    assert extensions.extension_route_specs() == ()


def test_base_route_wins_on_template_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _install_dummy_extension(handler=_dummy_handler)
    original_register = module.register_kiwi_extension

    def register_with_conflict(reg: extensions.ExtensionRegistry) -> None:
        reg.add_route({"GET"}, "/health", _dummy_handler)
        original_register(reg)

    module.register_kiwi_extension = register_with_conflict  # type: ignore[attr-defined]
    _enable_dummy(monkeypatch)

    status, result = handle_request("unused.sqlite", "GET", "/health", {}, {})
    assert status == 200
    assert result.get("service") == "kiwi-catalog"  # 基路由的 _health 结果
    assert "ext" not in result


def test_fastapi_hook_registers_route_on_app(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def hook(app: Any, db_path: Any) -> None:
        captured["db_path"] = db_path

        @app.get("/v1/ext/fastapi-only")
        def ext_route() -> dict[str, Any]:  # pragma: no cover - 走 TestClient 才触发
            return {"ok": True, "via": "fastapi"}

    _install_dummy_extension(hook=hook)
    _enable_dummy(monkeypatch)

    app = create_catalog_app("unused.sqlite")
    routes = {getattr(route, "path", None) for route in app.routes}
    assert "/v1/ext/fastapi-only" in routes
    assert captured["db_path"] == "unused.sqlite"


def test_broken_fastapi_hook_does_not_break_app(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken_hook(app: Any, db_path: Any) -> None:
        raise RuntimeError("hook boom")

    _install_dummy_extension(hook=broken_hook)
    _enable_dummy(monkeypatch)

    app = create_catalog_app("unused.sqlite")  # 不抛
    assert app is not None


def test_cache_is_rebuilt_after_reset(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_dummy_extension(handler=_dummy_handler)
    _enable_dummy(monkeypatch)

    first = extensions.extension_route_specs()
    second = extensions.extension_route_specs()
    assert first is second  # 命中缓存

    extensions.reset_extension_cache()
    third = extensions.extension_route_specs()
    assert third == first
    assert third is not second  # 重新装载
