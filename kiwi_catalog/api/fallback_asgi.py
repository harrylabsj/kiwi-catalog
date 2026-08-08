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
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs

from kiwi_catalog.api import auth as api_auth
from kiwi_catalog.api.limits import max_request_body_bytes
from kiwi_catalog.discovery.cache import compute_etag, etag_matches

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
            from kiwi_catalog.api.route_registry import route_info

            provider = route_info
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
        maximum = max_request_body_bytes()
        try:
            content_length = int(headers.get("content-length", "0") or 0)
        except ValueError:
            content_length = 0
        if content_length > maximum:
            await self._send_json(send, 413, {"ok": False, "error": "request body is too large"})
            return
        method = str(scope.get("method") or "GET").upper()
        path = str(scope.get("path") or "/")
        path_known, method_allowed = self._resolver()(method, path)
        if not path_known:
            await self._send_json(send, 404, {"ok": False, "error": f"No route for {method} {path}"})
            return
        if not method_allowed:
            await self._send_json(send, 405, {"ok": False, "error": f"Method not allowed for {method} {path}"})
            return
        chunks: list[bytes] = []
        body_size = 0
        while True:
            message = await receive()
            chunk = message.get("body", b"")
            body_size += len(chunk)
            if body_size > maximum:
                await self._send_json(send, 413, {"ok": False, "error": "request body is too large"})
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
            await send({"type": "http.response.start", "status": 400, "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": body})
            return
        if not isinstance(decoded_payload, dict):
            body = json.dumps(
                {"ok": False, "error": "JSON request body must be an object"},
                ensure_ascii=False,
                sort_keys=True,
            ).encode("utf-8")
            await send({"type": "http.response.start", "status": 400, "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": body})
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
            send,
            status,
            response,
            if_none_match=headers.get("if-none-match", ""),
            allow_304=method == "GET",
        )

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
        ``__cookies__`` 列表下发 Set-Cookie（账号会话，docs/accounts.md）。
        """
        html = response.get("__html__") if isinstance(response, dict) else None
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
