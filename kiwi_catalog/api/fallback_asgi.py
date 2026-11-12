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

from kiwi_catalog.a2a import card_store
from kiwi_catalog.api import auth as api_auth
from kiwi_catalog.api.ip_trust import resolve_client_ip
from kiwi_catalog.services.buyer_origin import derive_buyer_source
from kiwi_catalog.api.limits import (
    INQUIRY_TRANSPORT_KEYS,
    JSON_DEPTH_ERROR,
    max_request_body_bytes,
    validate_payload,
)
from kiwi_catalog.core.errors import PayloadTooLargeError, ValidationError
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
            except RecursionError:
                # 超深嵌套在解析阶段就触发 RecursionError，必须在 json.loads
                # 边界安全返回 400（FastAPI 中间件同口径），不能逃逸成 500。
                body = json.dumps(
                    {"ok": False, "error": JSON_DEPTH_ERROR},
                    ensure_ascii=False,
                    sort_keys=True,
                ).encode("utf-8")
                await _capture_send({"type": "http.response.start", "status": 400, "headers": [(b"content-type", b"application/json")]})
                await _capture_send({"type": "http.response.body", "body": body})
                return
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
            is_inquiry = (
                method == "POST"
                and path.startswith("/v1/agents/")
                and path.endswith("/public-inquiry")
            )
            # 先在未经任何传输层修改的客户端 JSON 上执行与 FastAPI 中间件相同
            # 的通用限制（大小/深度/项目数/字符串/节点数）。此前把同名键整体
            # 跳过，客户端可在自己的 JSON 里伪造 `_raw_inquiry_body_b64` 等键，
            # 绕过这些限制。
            try:
                validate_payload(decoded_payload)
            except PayloadTooLargeError as exc:
                await self._send_json(_capture_send, 413, {"ok": False, "error": str(exc)})
                return
            except ValidationError as exc:
                await self._send_json(_capture_send, 400, {"ok": False, "error": str(exc)})
                return
            payload = decoded_payload
            if is_inquiry:
                # 原始 body 已校验；删掉客户端自带的传输层同名键，后续只注入
                # 由 HTTP 头/原始字节派生的可信值。这样 handle_request 跳过这些
                # 键时不会跳过任何客户端 JSON。
                for key in INQUIRY_TRANSPORT_KEYS:
                    payload.pop(key, None)
            # 传输层元数据永远不是客户端字段：先剥除客户端 JSON 里的同名键
            # （_auth_token/_binding_jws/_origin/_referer 由 payload_with_auth 统一
            # 剥除，这里补齐 cookie / 买家标识 / 客户端 IP），之后只注入由 HTTP 头
            # 与真实对端派生的可信值。否则客户端可用 body 冒充 IP 选限流桶、
            # 冒充买家标识或会话 cookie。
            for key in ("_cookie", "_buyer_id", "_buyer_source", "_client_ip"):
                payload.pop(key, None)
            payload = api_auth.payload_with_auth(
                payload,
                authorization=headers.get("authorization", ""),
                idempotency_key=headers.get("idempotency-key", ""),
                binding_jws=headers.get("x-kiwi-binding-jws", ""),
            )
            # 会话 cookie（账号体系）：透传给 handler（auth 头之外的最小传输面）
            cookie = headers.get("cookie", "")
            if cookie:
                payload["_cookie"] = cookie
            payload["_origin"] = headers.get("origin", "")
            payload["_referer"] = headers.get("referer", "")
            # 买家身份头（每日去重买家统计，services/buyer_stats.py）：buyer agent
            # 自选标识；只以日作用域 HMAC hash 落库，原始值不出传输层。
            buyer_id = headers.get("x-buyer-id", "")
            if buyer_id:
                payload["_buyer_id"] = buyer_id
            # 渠道来源（运营归因，schema v53）：只落归一化标签，原始头不出传输层。
            payload["_buyer_source"] = derive_buyer_source(headers)
            # 客户端 IP（公开读与账号/设备限流的 per-IP 分桶，审查 P3-06 / C-M2）：
            # 仅可信代理（默认回环）时采信 XFF；直连对端非可信代理则忽略 XFF，
            # 用直连对端——直连客户端伪造 XFF 无法轮换 IP 绕过限流。
            # 无论解析结果是否为空，都先剥除客户端 JSON 里的同名键再注入 server
            # 侧解析值：ASGI 未提供对端（client_ip == ""）时也不能让 body 冒充
            # 传输 IP 去选择限流桶（F-7）；与 FastAPI 的 _client_payload /
            # _rate_limit_ip_payload “先剥除再注入”同口径。
            payload.pop("_client_ip", None)
            payload["_client_ip"] = client_ip or ""
            if is_inquiry:
                # Never trust a JSON-RPC field as the transport's source IP,
                # including when the ASGI server did not supply a peer.
                # （_client_ip 已在上方按传输层解析值统一注入。）
                allowed = {"content-type", "content-digest", "signature", "signature-input", "a2a-version", "a2a-extensions"}
                forwarded: dict[str, str] = {}
                for raw_name, raw_value in scope.get("headers", []):
                    name = raw_name.decode("latin-1").lower()
                    if name in allowed:
                        if name in forwarded:
                            await self._send_json(_capture_send, 400, {"ok": False, "error": "duplicate inquiry header"})
                            return
                        forwarded[name] = raw_value.decode("latin-1")
                import base64
                payload["_raw_inquiry_body_b64"] = base64.b64encode(b"".join(chunks)).decode("ascii")
                payload["_inquiry_headers"] = forwarded
            try:
                raw_query = scope.get("query_string", b"").decode("utf-8")
            except UnicodeDecodeError:
                raw_query = ""
            query = parse_qs(raw_query, keep_blank_values=True)
            handler = self._handler()
            handler_kwargs: dict[str, Any] = {}
            if is_inquiry:
                # 只有默认 handle_request 接受可信键名集合；自定义 handler 仍按
                # 原五参数调用（它们自行负责 payload 校验）。
                from kiwi_catalog.api.app import handle_request as _default_handle_request

                if handler is _default_handle_request:
                    handler_kwargs["trusted_transport_keys"] = INQUIRY_TRANSPORT_KEYS
            status, response = await asyncio.to_thread(
                handler,
                self.state.db_path,
                method,
                path,
                payload,
                {key: values[-1] if values else "" for key, values in query.items()},
                **handler_kwargs,
            )
            await self._send_json(
                _capture_send,
                status,
                response,
                if_none_match=headers.get("if-none-match", ""),
                allow_304=method == "GET",
                request_method=method,
                request_path=path,
            )
        finally:
            await asyncio.to_thread(_record_access_log)

    @staticmethod
    async def _send_json(
        send: Any,
        status: int,
        response: dict[str, Any],
        *,
        if_none_match: str = "",
        allow_304: bool = False,
        request_method: str = "",
        request_path: str = "",
    ) -> None:
        """Serialize *response* with a §18 server-side ETag.

        When the caller allows conditional GET and the client's
        ``If-None-Match`` matches the computed ETag, a body-less 304 is sent.

        ``{"__html__": "..."}`` 标记响应改发 text/html 并带 no-store；
        ``__status__`` 键覆盖状态码；``__redirect__`` 键发 302 + Location。
        ``__cookies__`` 列表下发 Set-Cookie（账号会话，docs/accounts.md）。
        这些 ``__*`` 元键只用于传输控制，绝不进入响应体。
        """
        html = response.get("__html__") if isinstance(response, dict) else None
        redirect_to = response.get("__redirect__") if isinstance(response, dict) else None
        if redirect_to is not None:
            # 扩展返回的页面跳转：302 + Location，no-store 防缓存。
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
        # 元键只用于传输控制（覆盖状态码 / no-store / Set-Cookie），绝不进入
        # 响应体。FastAPI 栈在路由层逐个 pop；fallback 在这里统一剥除，保证
        # 双栈错误响应体形状一致（F-2：502 曾把 "__status__":502 序列化出去）。
        no_store = bool(response.get("__no_store__")) if isinstance(response, dict) else False
        cookies = response.get("__cookies__") if isinstance(response, dict) else None
        if isinstance(response, dict):
            response = {
                k: v
                for k, v in response.items()
                if k not in {"__status__", "__no_store__", "__cookies__"}
            }
        if html is not None:
            body = str(html).encode("utf-8")
            content_type = b"text/html; charset=utf-8"
            extra_headers = [(b"cache-control", b"no-store")]
        else:
            body = json.dumps(response, ensure_ascii=False, sort_keys=True).encode("utf-8")
            content_type = b"application/json"
            extra_headers = [(b"cache-control", b"no-store")] if no_store else []
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
        # 稳定读地址（M3 §11.3 / 计划 A3）：公开只读 + ETag ⇒ 允许中间缓存但必须回源
        # 重验证。**只在成功响应上**加；404/410 不得带缓存头（错误不可缓存）。
        if status == 200 and card_store.is_stable_card_read(request_method, request_path):
            extra_headers.append((b"cache-control", card_store.CARD_CACHE_CONTROL.encode("ascii")))
        if cookies:
            extra_headers.extend(
                (b"set-cookie", str(cookie).encode("utf-8")) for cookie in cookies
            )
        etag = compute_etag(body)
        # A conditional GET only revalidates a *successful* representation:
        # never 304 an error body (e.g. a 404 for If-None-Match: *).
        # ``__no_store__`` 响应不参与条件请求：受控凭据分发既不能 304，也不能
        # 下发内容指纹 ETag（两栈一致；FastAPI 分支同样跳过）。
        if (
            allow_304
            and status == 200
            and not no_store
            and if_none_match
            and etag_matches(if_none_match, etag)
        ):
            await send(
                {
                    "type": "http.response.start",
                    "status": 304,
                    "headers": [(b"etag", etag.encode("ascii"))],
                }
            )
            await send({"type": "http.response.body", "body": b""})
            return
        # ETag 是成功表示的指纹：错误体（404/410 等）不下发，与上方 cache-control
        # 及 FastAPI 栈的 status == 200 门禁一致（错误不可缓存）。
        identity_headers = [] if no_store or status != 200 else [(b"etag", etag.encode("ascii"))]
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", content_type),
                    *identity_headers,
                    (b"content-length", str(len(body)).encode("ascii")),
                    *extra_headers,
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
