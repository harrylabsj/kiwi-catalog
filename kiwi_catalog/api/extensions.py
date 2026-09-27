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
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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
    fastapi_hooks: tuple[ExtensionFastAPIHook, ...]


_cache: _LoadedExtensions | None = None


def _load_uncached() -> _LoadedExtensions:
    raw = os.environ.get(KIWI_EXTENSIONS_ENV, "")
    names = [name.strip() for name in raw.split(",") if name.strip()]
    registry = ExtensionRegistry()
    for name in names:
        try:
            module = importlib.import_module(name)
            register = getattr(module, "register_kiwi_extension", None)
            if not callable(register):
                raise AttributeError(
                    f"extension {name!r} has no callable register_kiwi_extension()"
                )
            register(registry)
        except Exception:
            # fail-soft：坏扩展只降级为"路由不存在"，不影响 catalog 启动。
            logger.warning(
                "kiwi-catalog extension %r failed to load; skipped", name, exc_info=True
            )
    return _LoadedExtensions(tuple(registry.routes), tuple(registry.fastapi_hooks))


def load_extensions() -> _LoadedExtensions:
    """Env 驱动的扩展装载（进程级缓存；env 未设 = 空集，零开销）。"""
    global _cache
    if _cache is None:
        _cache = _load_uncached()
    return _cache


def extension_route_specs() -> tuple[ExtensionRouteSpec, ...]:
    return load_extensions().routes


def run_fastapi_hooks(app: Any, db_path: str | Path) -> None:
    """register_fastapi_routes 末尾调用：让扩展往 FastAPI app 挂路由。"""
    for hook in load_extensions().fastapi_hooks:
        try:
            hook(app, db_path)
        except Exception:
            logger.warning(
                "kiwi-catalog extension fastapi hook %r failed; skipped",
                hook,
                exc_info=True,
            )


def reset_extension_cache() -> None:
    """测试专用：丢弃缓存，下次访问重新读 env。"""
    global _cache
    _cache = None
