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

"""FastAPI route installation for the kiwi-catalog dual stack.

Move-only extraction of the route registration that app.py used to perform
inside ``register_fastapi_routes``.  Keeps the same module-level FastAPI
availability guard (so the module imports cleanly without fastapi and
``FastAPI`` is ``None``), the same ``Authorization``/``Idempotency-Key``
header defaults, the same body-limit / etag / security-header middleware, and
the same route table registration.  The fallback stack is untouched; both
stacks continue to share the wrappers in ``api.route_table``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from kiwi_catalog.api.handlers import accounts as accounts_handlers
from kiwi_catalog.api.handlers import portal as portal_handlers
from kiwi_catalog.api.limits import max_request_body_bytes, validate_payload
from kiwi_catalog.api.route_table import (
    _claim_catalog_agent,
    _get_catalog_agent,
    _health,
    _hosted_agent_card_document,
    _hosted_ucp_profile_document,
    _list_catalog_agents,
    _list_merchant_catalog_agents,
    _refresh_catalog_agent,
    _register_catalog_agent,
    _reinstate_catalog_agent,
    _search_agent_catalog,
    _suspend_catalog_agent,
    _v1_admin_dashboard,
    _v1_admin_merchant_report,
    _v1_admin_merchants,
    _v1_admin_searches,
    _v1_approve_application,
    _v1_claim_agent,
    _v1_get_agent,
    _v1_get_listing,
    _v1_list_agent_listings,
    _v1_list_agents,
    _v1_list_applications,
    _v1_merchant_self,
    _v1_publish_listing,
    _v1_refresh_agent,
    _v1_register_agent,
    _v1_reinstate_listing,
    _v1_reject_application,
    _v1_revoke_token,
    _v1_rotate_token,
    _v1_search_agents,
    _v1_search_listings,
    _v1_submit_application,
    _v1_verify_agent,
    _v1_withdraw_listing,
    _verify_catalog_agent,
    resolve_route,
)
from kiwi_catalog.core.errors import PayloadTooLargeError, ValidationError

# ── FastAPI dual-stack (phase 3 follow-up) ─────────────────────────────────
# FastAPI 可用时 create_catalog_app 返回 FastAPI app（13 条 catalog 路由，
# 与 fallback ASGI 共用 wrapper）；不可用时回退 fallback。

try:
    from fastapi import FastAPI
    from fastapi import Header as _Header
    from fastapi import Request as _FastAPIRequest
except ImportError:
    FastAPI = None  # type: ignore[assignment,misc]
    _Header = None  # type: ignore[assignment,misc]
    _FastAPIRequest = None  # type: ignore[assignment,misc]


def _auth_header_default() -> Any:
    if _Header is None:
        return ""
    return _Header(default="")


def _idempotency_key_header_default() -> Any:
    if _Header is None:
        return ""
    return _Header(default="", alias="Idempotency-Key")


AUTHORIZATION_HEADER = _auth_header_default()
IDEMPOTENCY_KEY_HEADER = _idempotency_key_header_default()


def register_fastapi_routes(app: Any, db_path: str | Path) -> None:
    """Register the 13 catalog routes on a FastAPI app.

    Exception mapping mirrors the fallback handle_request (403/404/409/429/
    400) so both stacks behave identically on the wire.
    """
    from fastapi.responses import JSONResponse, Response

    from kiwi_catalog.api import auth as api_auth
    from kiwi_catalog.discovery.cache import compute_etag, etag_matches

    @app.middleware("http")
    async def _parity_middleware(request: _FastAPIRequest, call_next: Any) -> Any:
        """审查 P2：FastAPI 栈补齐 fallback 的传输/JSON 资源上限与 GET 304 语义。

        - body 大小上限（413）、JSON 解析失败（400）、非对象 body（400）、
          validate_payload 深度/节点/字符串上限（400/413）——此前 FastAPI 栈
          无任何限制（任意大/深 body 直入内存）；
        - 空 body 视为 {}（与 fallback ``json.loads(... or "{}")`` 一致）；
        - GET 200 响应带 etag，显式 If-None-Match 匹配 → 304（fallback §18）。
        """
        # Match fallback routing order: unknown paths and disallowed methods
        # must resolve to 404/405 before attempting to parse an untrusted body.
        # Otherwise a malformed body can mask the route error on only one stack.
        path_known, method_allowed = resolve_route(request.method, request.url.path)
        if request.method in ("POST", "PUT", "PATCH") and path_known and method_allowed:
            maximum = max_request_body_bytes()
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    if int(content_length) > maximum:
                        return JSONResponse(
                            {"ok": False, "error": "request body is too large"},
                            status_code=413,
                        )
                except ValueError:
                    pass
            chunks: list[bytes] = []
            total = 0
            async for chunk in request.stream():
                total += len(chunk)
                if total > maximum:
                    return JSONResponse(
                        {"ok": False, "error": "request body is too large"},
                        status_code=413,
                    )
                chunks.append(chunk)
            body = b"".join(chunks) or b"{}"
            try:
                parsed = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return JSONResponse(
                    {"ok": False, "error": "invalid JSON request body"}, status_code=400
                )
            if not isinstance(parsed, dict):
                return JSONResponse(
                    {"ok": False, "error": "JSON request body must be an object"},
                    status_code=400,
                )
            try:
                validate_payload(parsed)
            except PayloadTooLargeError as exc:
                return JSONResponse({"ok": False, "error": str(exc)}, status_code=413)
            except ValidationError as exc:
                return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
            # stream() 已消费——把缓存 body 塞回 receive，让 FastAPI 依赖正常解析
            async def _receive() -> dict[str, Any]:
                return {"type": "http.request", "body": body, "more_body": False}

            request._receive = _receive  # type: ignore[attr-defined]
            request._stream_consumed = False  # type: ignore[attr-defined]

        response = await call_next(request)

        # 安全响应头（KC-SEC-01 硬化，与 fallback _send_json 对齐）
        response.headers["x-content-type-options"] = "nosniff"
        response.headers["referrer-policy"] = "no-referrer"
        response.headers["content-security-policy"] = "frame-ancestors 'none'"

        # GET 条件请求（fallback §18：仅成功表示 + 显式 If-None-Match）
        if request.method == "GET" and response.status_code == 200:
            body = b"".join([chunk async for chunk in response.body_iterator])
            etag = compute_etag(body)
            headers = dict(response.headers)
            headers["etag"] = etag
            if_none_match = request.headers.get("if-none-match", "")
            if if_none_match and etag_matches(if_none_match, etag):
                return Response(status_code=304, headers=headers)
            return Response(
                content=body, status_code=200, headers=headers, media_type=response.media_type
            )
        return response

    def _query_params_from_request(request: _FastAPIRequest) -> dict[str, str]:
        """Mirror fallback parse_qs(keep_blank_values=True) + last-value-wins.

        FastAPI 只识别声明过的 query 参数、静默丢弃其余键（含 attribute.* 动态键
        与未知键），与 fallback 全量透传语义分裂（审查 P2-3）。共享 handler 自带
        键白名单校验，路由层不做参数裁剪。

        注意：必须用模块级导入的 _FastAPIRequest（from __future__ import
        annotations 会把函数内导入的注解变成字符串，FastAPI 无法解析 → 参数被
        误判为 query 字段）。
        """
        return {key: value for key, value in request.query_params.multi_items()}


    # ── 审查 P2：错误形状与 fallback 对齐 ───────────────────────────────
    # fallback 的 404/405/400/500 都是 {"ok": false, "error": ...} 信封 +
    # 明确文案；FastAPI 默认的 {"detail": ...} / 纯文本 500 让依赖 ok/error
    # 信封的客户端在双栈切换后解析失败。错误映射提取到 error_handlers
    #（transport 类型注入，模块本身不硬依赖 FastAPI/Starlette）。

    from fastapi.exceptions import RequestValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException

    from kiwi_catalog.api.error_handlers import register_exception_handlers

    register_exception_handlers(
        app,
        json_response=JSONResponse,
        request_type=_FastAPIRequest,
        request_validation_error=RequestValidationError,
        http_exception=StarletteHTTPException,
        logger_name=__name__,
    )

    @app.get("/health")
    def health() -> dict[str, Any]:
        return _health(db_path)

    @app.get("/v1/agent-catalog/agents")
    def list_catalog_agents(request: _FastAPIRequest) -> dict[str, Any]:
        return _list_catalog_agents(db_path, {}, _query_params_from_request(request))

    @app.get("/v1/agent-catalog/agents/search")
    def search_agent_catalog(request: _FastAPIRequest) -> dict[str, Any]:
        return _search_agent_catalog(db_path, {}, _query_params_from_request(request))

    @app.get("/v1/agent-catalog/agents/{catalog_agent_id}")
    def get_catalog_agent(catalog_agent_id: str) -> dict[str, Any]:
        return _get_catalog_agent(db_path, catalog_agent_id)

    @app.get("/v1/agent-catalog/merchants/{merchant_id}/agents")
    def list_merchant_catalog_agents(
        merchant_id: str, request: _FastAPIRequest
    ) -> dict[str, Any]:
        return _list_merchant_catalog_agents(
            db_path, merchant_id, {}, _query_params_from_request(request)
        )

    @app.post("/v1/agent-catalog/agents/register")
    def register_catalog_agent(
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _register_catalog_agent(
            db_path, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/agent-catalog/agents/{catalog_agent_id}/refresh")
    def refresh_catalog_agent(
        catalog_agent_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _refresh_catalog_agent(
            db_path, catalog_agent_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/agent-catalog/agents/{catalog_agent_id}/verify")
    def verify_catalog_agent(
        catalog_agent_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _verify_catalog_agent(
            db_path, catalog_agent_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/agent-catalog/agents/{catalog_agent_id}/claim")
    def claim_catalog_agent(
        catalog_agent_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _claim_catalog_agent(
            db_path, catalog_agent_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/agent-catalog/agents/{catalog_agent_id}/suspend")
    def suspend_catalog_agent(
        catalog_agent_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _suspend_catalog_agent(
            db_path, catalog_agent_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/agent-catalog/agents/{catalog_agent_id}/reinstate")
    def reinstate_catalog_agent(
        catalog_agent_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _reinstate_catalog_agent(
            db_path, catalog_agent_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.get("/v1/agents")
    def v1_list_agents(request: _FastAPIRequest) -> dict[str, Any]:
        return _v1_list_agents(db_path, {}, _query_params_from_request(request))

    @app.get("/v1/agents/search")
    def v1_search_agents(request: _FastAPIRequest) -> dict[str, Any]:
        return _v1_search_agents(db_path, {}, _query_params_from_request(request))

    @app.get("/v1/agents/{catalog_agent_id}")
    def v1_get_agent(catalog_agent_id: str) -> dict[str, Any]:
        return _v1_get_agent(db_path, catalog_agent_id)

    @app.post("/v1/agents/register")
    def v1_register_agent(
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _v1_register_agent(
            db_path, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/agents/{catalog_agent_id}/refresh")
    def v1_refresh_agent(
        catalog_agent_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _v1_refresh_agent(
            db_path, catalog_agent_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/agents/{catalog_agent_id}/verify")
    def v1_verify_agent(
        catalog_agent_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _v1_verify_agent(
            db_path, catalog_agent_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/agents/{catalog_agent_id}/claim")
    def v1_claim_agent(
        catalog_agent_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _v1_claim_agent(
            db_path, catalog_agent_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.get("/v1/hosted/agents/{catalog_agent_id}/agent-card.json")
    def hosted_agent_card_route(catalog_agent_id: str) -> Any:
        return _hosted_agent_card_document(db_path, catalog_agent_id)

    @app.get("/v1/hosted/agents/{catalog_agent_id}/ucp")
    def hosted_ucp_profile_route(catalog_agent_id: str) -> Any:
        return _hosted_ucp_profile_document(db_path, catalog_agent_id)

    @app.get("/v1/listings/search")
    def v1_search_listings(request: _FastAPIRequest) -> dict[str, Any]:
        return _v1_search_listings(db_path, {}, _query_params_from_request(request))

    @app.get("/v1/listings/{listing_id}")
    def v1_get_listing(listing_id: str) -> dict[str, Any]:
        return _v1_get_listing(db_path, listing_id)

    @app.get("/v1/agents/{catalog_agent_id}/listings")
    def v1_list_agent_listings(
        catalog_agent_id: str, request: _FastAPIRequest
    ) -> dict[str, Any]:
        # admin token 只经 Authorization header（KC-SEC-02，与 fallback 一致）；
        # owner_token 自查仍走 query。payload_with_auth 把 Bearer 合并为
        # _auth_token 供 handler 做 admin 校验。
        return _v1_list_agent_listings(
            db_path,
            catalog_agent_id,
            _query_params_from_request(request),
            api_auth.payload_with_auth({}, request.headers.get("authorization", ""), ""),
        )

    @app.post("/v1/listings/publish")
    def v1_publish_listing(
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _v1_publish_listing(
            db_path, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/listings/{listing_id}/withdraw")
    def v1_withdraw_listing(
        listing_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _v1_withdraw_listing(
            db_path, listing_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/listings/{listing_id}/reinstate")
    def v1_reinstate_listing(
        listing_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _v1_reinstate_listing(
            db_path, listing_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    # ── /v1/merchants（token 分发，docs §4；门户 HTML 页 fallback-only）────

    @app.post("/v1/merchants/applications")
    def v1_submit_application(
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _v1_submit_application(
            db_path, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.get("/v1/merchants/applications")
    def v1_list_applications(request: _FastAPIRequest) -> dict[str, Any]:
        # admin token 只经 Authorization header（KC-SEC-02，与 fallback 一致）
        return _v1_list_applications(
            db_path,
            api_auth.payload_with_auth({}, request.headers.get("authorization", ""), ""),
            _query_params_from_request(request),
        )

    @app.post("/v1/merchants/applications/{application_id}/approve")
    def v1_approve_application(
        application_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _v1_approve_application(
            db_path, application_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/merchants/applications/{application_id}/reject")
    def v1_reject_application(
        application_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _v1_reject_application(
            db_path, application_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/merchants/{merchant_id}/rotate")
    def v1_rotate_token(
        merchant_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _v1_rotate_token(
            db_path, merchant_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.post("/v1/merchants/{merchant_id}/revoke")
    def v1_revoke_token(
        merchant_id: str,
        payload: dict[str, Any],
        authorization: str = AUTHORIZATION_HEADER,
        idempotency_key: str = IDEMPOTENCY_KEY_HEADER,
    ) -> dict[str, Any]:
        return _v1_revoke_token(
            db_path, merchant_id, api_auth.payload_with_auth(payload, authorization, idempotency_key)
        )

    @app.get("/v1/merchants/self")
    def v1_merchant_self(request: _FastAPIRequest) -> dict[str, Any]:
        return _v1_merchant_self(
            db_path,
            api_auth.payload_with_auth({}, request.headers.get("authorization", ""), ""),
            _query_params_from_request(request),
        )

    # ── /v1/accounts（商家账号；cookie 会话经 request 透传）───────────────
    from fastapi.responses import JSONResponse as _JSONResponse

    def _account_response(result: dict[str, Any]) -> _JSONResponse:
        """账号 handler 结果 → JSONResponse；__cookies__ 下发 Set-Cookie。"""
        cookies = result.pop("__cookies__", None) or []
        headers = {"set-cookie": str(cookies[0])} if cookies else None
        return _JSONResponse(result, headers=headers)

    def _account_payload(request: _FastAPIRequest, body: dict[str, Any]) -> dict[str, Any]:
        cookie = request.headers.get("cookie", "")
        if cookie:
            body = dict(body or {})
            body["_cookie"] = cookie
        return body

    @app.post("/v1/accounts/register")
    def v1_account_register(payload: dict[str, Any]) -> _JSONResponse:
        return _account_response(accounts_handlers.register(db_path, payload))

    @app.post("/v1/accounts/login")
    def v1_account_login(payload: dict[str, Any]) -> _JSONResponse:
        return _account_response(accounts_handlers.login(db_path, payload))

    @app.post("/v1/accounts/logout")
    def v1_account_logout(request: _FastAPIRequest, payload: dict[str, Any]) -> dict[str, Any]:
        return accounts_handlers.logout(db_path, _account_payload(request, payload))

    @app.post("/v1/accounts/verify-email")
    def v1_account_verify_email(payload: dict[str, Any]) -> _JSONResponse:
        return _account_response(accounts_handlers.verify_email(db_path, payload))

    @app.post("/v1/accounts/resend-code")
    def v1_account_resend_code(payload: dict[str, Any]) -> dict[str, Any]:
        return accounts_handlers.resend_code(db_path, payload)

    @app.get("/v1/accounts/me")
    def v1_account_me(request: _FastAPIRequest) -> dict[str, Any]:
        return accounts_handlers.me(db_path, _account_payload(request, {}), {})

    @app.post("/v1/accounts/token-request")
    def v1_account_token_request(
        request: _FastAPIRequest, payload: dict[str, Any]
    ) -> dict[str, Any]:
        return accounts_handlers.token_request(db_path, _account_payload(request, payload), {})

    @app.post("/v1/accounts/profile")
    def v1_account_profile(
        request: _FastAPIRequest, payload: dict[str, Any]
    ) -> dict[str, Any]:
        return accounts_handlers.profile(db_path, _account_payload(request, payload))

    # ── /v1/admin（运营 dashboard，admin token 保护）──────────────────────
    @app.get("/v1/admin/dashboard")
    def v1_admin_dashboard(request: _FastAPIRequest) -> dict[str, Any]:
        return _v1_admin_dashboard(
            db_path,
            api_auth.payload_with_auth({}, request.headers.get("authorization", ""), ""),
            _query_params_from_request(request),
        )

    @app.get("/v1/admin/merchants")
    def v1_admin_merchants(request: _FastAPIRequest) -> dict[str, Any]:
        return _v1_admin_merchants(
            db_path,
            api_auth.payload_with_auth({}, request.headers.get("authorization", ""), ""),
            _query_params_from_request(request),
        )

    @app.get("/v1/admin/merchants/{merchant_id}/report")
    def v1_admin_merchant_report(
        merchant_id: str, request: _FastAPIRequest
    ) -> dict[str, Any]:
        return _v1_admin_merchant_report(
            db_path,
            merchant_id,
            api_auth.payload_with_auth({}, request.headers.get("authorization", ""), ""),
            _query_params_from_request(request),
        )

    @app.get("/v1/admin/searches")
    def v1_admin_searches(request: _FastAPIRequest) -> dict[str, Any]:
        return _v1_admin_searches(
            db_path,
            api_auth.payload_with_auth({}, request.headers.get("authorization", ""), ""),
            _query_params_from_request(request),
        )

    # ── /portal（门户 HTML 页；双栈都注册以保持 route 覆盖 parity）────────
    from fastapi.responses import HTMLResponse

    _PORTAL_HTML_HEADERS = {"Cache-Control": "no-store"}  # 一次性令牌页防缓存

    def _portal_html(result: dict[str, Any]) -> HTMLResponse:
        """门户 handler 结果 → HTMLResponse；__status__ 键覆盖状态码
        （与 fallback _send_json 语义一致）。"""
        return HTMLResponse(
            result["__html__"],
            status_code=int(result.get("__status__") or 200),
            headers=_PORTAL_HTML_HEADERS,
        )

    @app.get("/portal")
    def portal_home_page() -> HTMLResponse:
        return _portal_html(portal_handlers.portal_home())

    @app.get("/portal/apply")
    def portal_apply_page() -> HTMLResponse:
        return _portal_html(portal_handlers.portal_apply())

    @app.get("/portal/admin")
    def portal_admin_page() -> HTMLResponse:
        return _portal_html(portal_handlers.portal_admin())

    @app.get("/portal/admin/searches")
    def portal_admin_searches_page() -> HTMLResponse:
        return _portal_html(portal_handlers.portal_admin_searches())

    @app.get("/portal/dashboard")
    def portal_dashboard_page() -> HTMLResponse:
        return _portal_html(portal_handlers.portal_dashboard())

    @app.get("/portal/register")
    def portal_register_page() -> HTMLResponse:
        return _portal_html(portal_handlers.portal_register())

    @app.get("/portal/login")
    def portal_login_page() -> HTMLResponse:
        return _portal_html(portal_handlers.portal_login())

    @app.get("/portal/account")
    def portal_account_page() -> HTMLResponse:
        return _portal_html(portal_handlers.portal_account())
