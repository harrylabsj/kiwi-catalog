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

"""Generic extension hook: out-of-package route providers (docs/extensions.md).

环境变量 ``KIWI_CATALOG_EXTENSIONS`` 列出逗号分隔的 import path；每个扩展
包在顶层暴露 ``register_kiwi_extension(registry)``，通过 registry 声明：

- fallback 栈路由（RouteEntry 约定：``handler(db_path, payload, query,
  **path_params)``，返回 dict 或 ``{"__html__": ...}``）；
- FastAPI 栈挂钩（``hook(app, db_path)``，自行 @app.get/@app.post）。

设计约束：

- 本模块不 import route_table（registry 只存原始三元组，RouteEntry 由
  route_table.all_routes() 单向构造），避免 route_table → extensions →
  route_table 导入环。
- fail-soft：扩展缺失或注册抛异常只记 warning 并跳过，绝不阻塞服务启动
  （缺扩展 = 对应路由 404，与路由未注册不可区分）。
- 结果进程级缓存（broken 扩展不在每请求重试）；测试用
  reset_extension_cache() 清缓存。
"""

from __future__ import annotations

import importlib
import logging
import os
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from kiwi_catalog.api.route_matching import paths_overlap, route_shape

KIWI_EXTENSIONS_ENV = "KIWI_CATALOG_EXTENSIONS"

logger = logging.getLogger(__name__)

#: FastAPI 栈挂钩签名：hook(app, db_path)，扩展自行注册 FastAPI 路由。
ExtensionFastAPIHook = Callable[[Any, "str | Path"], None]


@dataclass(frozen=True)
class ExtensionRouteSpec:
    """fallback 栈路由声明（route_table 负责包装成 RouteEntry）。"""

    methods: frozenset[str]
    path_template: str
    handler: Any
    extension_name: str = ""


@dataclass
class ExtensionRegistry:
    """ handed to each extension's register_kiwi_extension(). """

    routes: list[ExtensionRouteSpec] = field(default_factory=list)
    fastapi_hooks: list[ExtensionFastAPIHook] = field(default_factory=list)

    def add_route(
        self, methods: Iterable[str], path_template: str, handler: Any
    ) -> None:
        normalized = frozenset(m.upper() for m in methods)
        if not normalized or not path_template:
            raise ValueError("extension route needs methods and path_template")
        if re.search(r"\{[^{}]*:[^{}]*\}", path_template):
            raise ValueError(
                f"shared extension route {path_template!r} must use {{name}} parameters; "
                "converters require a FastAPI hook"
            )
        self.routes.append(
            ExtensionRouteSpec(normalized, path_template, handler)
        )

    def add_fastapi_hook(self, hook: ExtensionFastAPIHook) -> None:
        if not callable(hook):
            raise ValueError("fastapi hook must be callable: hook(app, db_path)")
        self.fastapi_hooks.append(hook)


@dataclass(frozen=True)
class _LoadedExtensions:
    routes: tuple[ExtensionRouteSpec, ...]
    fastapi_hooks: tuple[tuple[str, ExtensionFastAPIHook], ...]


_cache: _LoadedExtensions | None = None


def _load_uncached() -> _LoadedExtensions:
    raw = os.environ.get(KIWI_EXTENSIONS_ENV, "")
    names = [name.strip() for name in raw.split(",") if name.strip()]
    routes: list[ExtensionRouteSpec] = []
    hooks: list[tuple[str, ExtensionFastAPIHook]] = []
    for name in names:
        local = ExtensionRegistry()
        try:
            module = importlib.import_module(name)
            register = getattr(module, "register_kiwi_extension", None)
            if not callable(register):
                raise AttributeError(
                    f"extension {name!r} has no callable register_kiwi_extension()"
                )
            register(local)
        except Exception:
            # fail-soft：坏扩展只降级为"路由不存在"，不影响 catalog 启动。
            logger.warning(
                "kiwi-catalog extension %r failed to load; skipped", name, exc_info=True
            )
        else:
            routes.extend(replace(route, extension_name=name) for route in local.routes)
            hooks.extend((name, hook) for hook in local.fastapi_hooks)
    return _LoadedExtensions(tuple(routes), tuple(hooks))


def load_extensions() -> _LoadedExtensions:
    """Env 驱动的扩展装载（进程级缓存；env 未设 = 空集，零开销）。"""
    global _cache
    if _cache is None:
        _cache = _load_uncached()
    return _cache


def extension_route_specs() -> tuple[ExtensionRouteSpec, ...]:
    return load_extensions().routes


def run_fastapi_hooks(
    app: Any, db_path: str | Path, shared: tuple[Any, ...],
) -> set[tuple[str, str]]:
    """Install native routes without shadowing core or shared declarations."""
    from fastapi.routing import iter_route_contexts
    from starlette.routing import Mount, WebSocketRoute

    def paths(routes: Iterable[Any]) -> Iterable[tuple[str | None, set[str] | None]]:
        for context in iter_route_contexts(list(routes)):
            if isinstance(context.original_route, WebSocketRoute):
                continue
            path = context.path
            if isinstance(context.original_route, Mount) and path is not None:
                path = path.rstrip("/") + "/{rest:path}"
            yield path, context.methods

    def allowed_methods(
        path: str, methods: set[str] | None, extension_name: str,
        occupied: list[tuple[str | None, set[str] | None]],
    ) -> tuple[set[str], set[tuple[str, str]]]:
        allowed: set[str] = set()
        overrides: set[tuple[str, str]] = set()
        for method in sorted(methods) if methods else ["*"]:
            conflict = next((
                other for other, reserved in occupied
                if other is not None and (not reserved or method == "*" or method in reserved)
                and paths_overlap(path, other)
            ), None)
            own_override = False
            if conflict is None:
                for entry in shared:
                    if (method != "*" and method not in entry.methods) or not paths_overlap(path, entry.path_template):
                        continue
                    if (extension_name == entry.extension_name and method != "*"
                            and route_shape(path) == route_shape(entry.path_template)):
                        own_override = True
                    else:
                        conflict = entry.path_template
                        break
            if conflict is not None:
                logger.warning(
                    "ignoring overlapping FastAPI extension route: %s %s conflicts with %s",
                    method, path, conflict,
                )
                continue
            allowed.add(method)
            if own_override:
                overrides.add((route_shape(path), method))
        return allowed, overrides

    occupied = list(paths(app.router.routes))
    overrides: set[tuple[str, str]] = set()
    for extension_name, hook in load_extensions().fastapi_hooks:
        routes = app.router.routes
        start = len(routes)
        try:
            hook(app, db_path)
        except Exception:
            del routes[start:]
            logger.warning(
                "kiwi-catalog extension fastapi hook %r failed; skipped",
                hook,
                exc_info=True,
            )
            continue
        added = routes[start:]
        del routes[start:]
        for route in added:
            examined = list(paths([route]))
            if not examined:
                routes.append(route)
                continue
            # Included routers keep their FastAPI dependency and prefix
            # context intact. Validate their leaf routes as an atomic group.
            grouped = not isinstance(getattr(route, "path", None), str)
            pending: list[tuple[str | None, set[str] | None]] = []
            route_overrides: set[tuple[str, str]] = set()
            for path, methods in examined:
                if path is None:
                    logger.warning("ignoring FastAPI extension %s route without an auditable path", extension_name)
                    break
                allowed, replacements = allowed_methods(path, methods, extension_name, occupied + pending)
                if not allowed or (grouped and allowed != (methods or {"*"})):
                    break
                pending.append((path, allowed if methods else None))
                route_overrides.update(replacements)
            else:
                if not grouped and getattr(route, "methods", None):
                    route.methods = pending[0][1]
                overrides.update(route_overrides)
                occupied.extend(pending)
                routes.append(route)
    return overrides


def reset_extension_cache() -> None:
    """测试专用：丢弃缓存，下次访问重新读 env。"""
    global _cache
    _cache = None
