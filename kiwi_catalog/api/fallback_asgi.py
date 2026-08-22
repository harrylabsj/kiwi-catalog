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

"""Lightweight ASGI fallback used when FastAPI is unavailable."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs

from kiwi_catalog.api import auth as api_auth
from kiwi_catalog.api.ip_trust import resolve_client_ip
from kiwi_catalog.api.limits import max_request_body_bytes
from kiwi_catalog.discovery.cache import compute_etag, etag_matches
from kiwi_catalog.services import access_log

HandleRequest = Callable[[str | Path, str, str, dict[str, Any] | None, dict[str, Any] | None], tuple[int, dict[str, Any]]]
RouteProvider = Callable[[], list[Any]]
RouteResolver = Callable[[str, str], tuple[bool, bool]]


class MarketplaceASGIApp:
    title = "kiwi-catalog Agent Catalog API"

    def __init__(
        self,
        db_path: str | Path,
        handle_request_fn: HandleRequest | None = None,
        route_provider: RouteProvider | None = None,
        route_resolver: RouteResolver | None = None,
    ):
        self.state = SimpleNamespace(db_path=str(db_path), fastapi_available=False)
        self._handle_request = handle_request_fn
        self._route_provider = route_provider
        self._route_resolver = route_resolver
        self.routes = self._routes()

    def _routes(self) -> list[Any]:
        provider = self._route_provider
        if provider is None:
            from kiwi_catalog.api.route_registry import catalog_route_info

            provider = catalog_route_info
        return provider()

    def _handler(self) -> HandleRequest:
        if self._handle_request is None:
            from kiwi_catalog.api.app import handle_request

            self._handle_request = handle_request
        return self._handle_request

    def _resolver(self) -> RouteResolver:
        if self._route_resolver is None:
            if self._handle_request is not None:
                # Custom handlers own their routing; stay permissive for them.
                return lambda _method, _path: (True, True)
            from kiwi_catalog.api.app import resolve_route

            self._route_resolver = resolve_route
        return self._route_resolver

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await send({"type": "http.response.start", "status": 404, "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": b'{"ok":false,"error":"unsupported scope"}'})
            return
        headers = {
            key.decode("latin1").lower(): value.decode("latin1")
            for key, value in scope.get("headers", [])
        }
        method = str(scope.get("method") or "GET").upper()
        path = str(scope.get("path") or "/")
        client = scope.get("client")
        direct_peer = str(client[0] or "") if client else None
        # 客户端 IP（访问日志 ip_prefix 与 payload._client_ip 共用同一解析——
        # 仅可信代理采信 XFF，直连对端非可信代理则忽略 XFF）。
        client_ip = resolve_client_ip(headers.get("x-forwarded-for", ""), direct_peer)
        # 访问日志（v28）：捕获响应 status/body 用于 result_count 提取，测
        # latency；record 失败绝不抛错（services/access_log.py）。
        started = time.perf_counter()
        captured: dict[str, Any] = {"status": None, "chunks": []}

        async def _capture_send(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                captured["status"] = int(message.get("status", 500))
            elif message["type"] == "http.response.body":
                captured["chunks"].append(message.get("body", b""))
            await send(message)

        def _record_access_log() -> None:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            status = captured["status"] if captured["status"] is not None else 500
            result_count = access_log.result_count_from_body(b"".join(captured["chunks"]))
            try:
                raw_query = scope.get("query_string", b"").decode("utf-8")
            except UnicodeDecodeError:
                raw_query = ""
            query_dict = {
                key: values[-1] if values else ""
                for key, values in parse_qs(raw_query, keep_blank_values=True).items()
            }
            access_log.record_http_access(
                self.state.db_path,
                method=method,
                path=path,
                query=query_dict,
                headers=headers,
                client_ip=client_ip,
                status=status,
                latency_ms=elapsed_ms,
                result_count=result_count,
            )

        try:
            maximum = max_request_body_bytes()
            try:
                content_length = int(headers.get("content-length", "0") or 0)
            except ValueError:
                content_length = 0
            if content_length > maximum:
                await self._send_json(_capture_send, 413, {"ok": False, "error": "request body is too large"})
                return
            path_known, method_allowed = self._resolver()(method, path)
            if not path_known:
                await self._send_json(_capture_send, 404, {"ok": False, "error": f"No route for {method} {path}"})
                return
            if not method_allowed:
                await self._send_json(_capture_send, 405, {"ok": False, "error": f"Method not allowed for {method} {path}"})
                return
            chunks: list[bytes] = []
            body_size = 0
            while True:
                message = await receive()
                chunk = message.get("body", b"")
                body_size += len(chunk)
                if body_size > maximum:
                    await self._send_json(_capture_send, 413, {"ok": False, "error": "request body is too large"})
                    return
                chunks.append(chunk)
                if not message.get("more_body", False):
                    break
            try:
                decoded_payload = json.loads(b"".join(chunks).decode("utf-8") or "{}")
            except (UnicodeDecodeError, json.JSONDecodeError):
                body = json.dumps(
                    {"ok": False, "error": "invalid JSON request body"},
                    ensure_ascii=False,
                    sort_keys=True,
                ).encode("utf-8")
                await _capture_send({"type": "http.response.start", "status": 400, "headers": [(b"content-type", b"application/json")]})
                await _capture_send({"type": "http.response.body", "body": body})
                return
            if not isinstance(decoded_payload, dict):
                body = json.dumps(
                    {"ok": False, "error": "JSON request body must be an object"},
                    ensure_ascii=False,
                    sort_keys=True,
                ).encode("utf-8")
                await _capture_send({"type": "http.response.start", "status": 400, "headers": [(b"content-type", b"application/json")]})
                await _capture_send({"type": "http.response.body", "body": body})
                return
            payload = decoded_payload
            payload = api_auth.payload_with_auth(
                payload,
                authorization=headers.get("authorization", ""),
                idempotency_key=headers.get("idempotency-key", ""),
            )
            # 会话 cookie（账号体系）：透传给 handler（auth 头之外的最小传输面）
            cookie = headers.get("cookie", "")
            if cookie:
                payload["_cookie"] = cookie
            # 买家身份头（每日去重买家统计，services/buyer_stats.py）：buyer agent
            # 自选标识；只以日作用域 HMAC hash 落库，原始值不出传输层。
            buyer_id = headers.get("x-buyer-id", "")
            if buyer_id:
                payload["_buyer_id"] = buyer_id
            # 客户端 IP（/v1/discovery/search 限流 per-IP 分桶，审查 P3-06 / C-M2）：
            # 仅可信代理（默认回环）时采信 XFF；直连对端非可信代理则忽略 XFF，
            # 用直连对端——直连客户端伪造 XFF 无法轮换 IP 绕过限流。
            if client_ip:
                payload["_client_ip"] = client_ip
            try:
                raw_query = scope.get("query_string", b"").decode("utf-8")
            except UnicodeDecodeError:
                raw_query = ""
            query = parse_qs(raw_query, keep_blank_values=True)
            status, response = await asyncio.to_thread(
                self._handler(),
                self.state.db_path,
                method,
                path,
                payload,
                {key: values[-1] if values else "" for key, values in query.items()},
            )
            await self._send_json(
                _capture_send,
                status,
                response,
                if_none_match=headers.get("if-none-match", ""),
                allow_304=method == "GET",
            )
        finally:
            _record_access_log()

    @staticmethod
    async def _send_json(
        send: Any,
        status: int,
        response: dict[str, Any],
        *,
        if_none_match: str = "",
        allow_304: bool = False,
    ) -> None:
        """Serialize *response* with a §18 server-side ETag.

        When the caller allows conditional GET and the client's
        ``If-None-Match`` matches the computed ETag, a body-less 304 is sent.

        ``{"__html__": "..."}`` 标记响应（/portal/* 门户页，docs §6）改发
        text/html；门户页含一次性令牌展示，响应带 no-store 防缓存。
        ``__status__`` 键覆盖状态码（如审核后台关闭时发真实 404）；
        ``__redirect__`` 键发 302 + Location（门户旧路径合并跳转）；
        ``__cookies__`` 列表下发 Set-Cookie（账号会话，docs/accounts.md）。
        """
        html = response.get("__html__") if isinstance(response, dict) else None
        redirect_to = response.get("__redirect__") if isinstance(response, dict) else None
        if redirect_to is not None:
            # 门户旧路径跳转（如 /portal/admin/buyer-stats 并入 /portal/dashboard）：
            # 302 + Location，no-store 防缓存（与门户 HTML 页一致）。
            await send(
                {
                    "type": "http.response.start",
                    "status": 302,
                    "headers": [
                        (b"location", str(redirect_to).encode("utf-8")),
                        (b"cache-control", b"no-store"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": b""})
            return
        override_status = (
            response.get("__status__") if isinstance(response, dict) else None
        )
        if override_status is not None:
            status = int(override_status)
        if html is not None:
            body = str(html).encode("utf-8")
            content_type = b"text/html; charset=utf-8"
            extra_headers = [(b"cache-control", b"no-store")]
        else:
            body = json.dumps(response, ensure_ascii=False, sort_keys=True).encode("utf-8")
            content_type = b"application/json"
            extra_headers = []
        # 安全响应头（KC-SEC-01 硬化）：凭据页/JSON API 一律 nosniff + 禁
        # Referrer 泄漏（admin token 已改 header-only，referrer 兜底防
        # 凭据随导航外泄）；frame-ancestors 只能经响应头传递（meta 忽略）。
        extra_headers.extend(
            [
                (b"x-content-type-options", b"nosniff"),
                (b"referrer-policy", b"no-referrer"),
                (b"content-security-policy", b"frame-ancestors 'none'"),
            ]
        )
        cookies = response.get("__cookies__") if isinstance(response, dict) else None
        if cookies:
            extra_headers.extend(
                (b"set-cookie", str(cookie).encode("utf-8")) for cookie in cookies
            )
        if html is None and isinstance(response, dict) and "__cookies__" in response:
            # 元键不进响应体（JSON 分支）：只用于下发 Set-Cookie
            body = json.dumps(
                {k: v for k, v in response.items() if k != "__cookies__"},
                ensure_ascii=False,
                sort_keys=True,
            ).encode("utf-8")
        etag = compute_etag(body)
        # A conditional GET only revalidates a *successful* representation:
        # never 304 an error body (e.g. a 404 for If-None-Match: *).
        if allow_304 and status == 200 and if_none_match and etag_matches(if_none_match, etag):
            await send(
                {
                    "type": "http.response.start",
                    "status": 304,
                    "headers": [(b"etag", etag.encode("ascii"))],
                }
            )
            await send({"type": "http.response.body", "body": b""})
            return
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", content_type),
                    (b"etag", etag.encode("ascii")),
                    (b"content-length", str(len(body)).encode("ascii")),
                    *extra_headers,
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
