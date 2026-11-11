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

"""FastAPI dual-stack tests (phase 3 follow-up).

create_catalog_app returns a FastAPI app when fastapi is installed and
falls back to the fallback ASGI app otherwise — both serve the same 13
catalog routes through the same wrappers.  This module asserts the
FastAPI branch (skipped when fastapi is unavailable).
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kiwi_catalog.api import app as app_module


def _has_fastapi() -> bool:
    return app_module.FastAPI is not None


@unittest.skipUnless(_has_fastapi(), "fastapi not installed")
class FastApiDualStackTest(unittest.TestCase):
    def setUp(self) -> None:
        patcher = mock.patch.dict(os.environ, {"KIWI_CATALOG_ENABLE_LEGACY_LISTINGS": "on"})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.db_file = Path(self.tmp.name) / "catalog.sqlite"
        self.app = app_module.create_catalog_app(self.db_file)
        self.assertIsNotNone(self.app)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_returns_fastapi_app(self) -> None:
        self.assertEqual(type(self.app).__name__, "FastAPI")

    def test_no_portal_pages_in_fastapi_stack(self) -> None:
        """与 route_table 守卫对称：FastAPI 栈同样不得注册 /portal/* 页面。

        核心自带 /portal/* 会遮蔽私有扩展 kiwi-catalog-admin 的商家后台页面
        （2026-09-29 生产事故：状态码仍全是 200，只有页面内容被换回旧版）。
        """
        leaked = sorted(
            route.path for route in self.app.routes
            if str(getattr(route, "path", "")).startswith("/portal")
        )
        self.assertEqual([], leaked, f"FastAPI 栈仍有商家后台路由: {leaked}")

    def test_register_via_fastapi(self) -> None:
        from fastapi.testclient import TestClient

        with TestClient(self.app) as client:
            resp = client.post(
                "/v1/agent-catalog/agents/register",
                json={"domain": "merchant.example", "idempotency_key": "r1"},
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            cagt = resp.json()["catalog_agent"]["catalog_agent_id"]

            search = client.get("/v1/agent-catalog/agents/search")
            self.assertEqual(search.status_code, 200)
            self.assertEqual(len(search.json()["results"]), 1)

            stats = client.get("/v1/agent-catalog/agents", params={"limit": "10"})
            self.assertEqual(stats.status_code, 200)

            card = client.get(f"/v1/hosted/agents/{cagt}/agent-card.json")
            self.assertIn(card.status_code, (200, 404))  # hosted gate 语义

    def test_marketplace_routes_are_cut_in_fastapi(self) -> None:
        from fastapi.testclient import TestClient

        with TestClient(self.app) as client:
            for path in ("/merchants", "/products", "/negotiation/pending-messages"):
                resp = client.get(path)
                self.assertEqual(resp.status_code, 404, f"{path}")

    def test_hosted_negotiation_endpoint_is_cut_in_fastapi(self) -> None:
        from fastapi.testclient import TestClient

        with TestClient(self.app) as client:
            resp = client.post(
                "/a2a/agents/cagt_any",
                json={"jsonrpc": "2.0", "id": "1", "method": "message/send", "params": {}},
            )
            self.assertEqual(resp.status_code, 404)

    def test_route_count_matches_fallback(self) -> None:
        fastapi_paths = {route.path for route in self.app.routes if hasattr(route, "path")}
        fallback_paths = {entry.path_template for entry in app_module._ROUTE_TABLE}
        # FastAPI 追加 /openapi.json 等内置路由——只断言 catalog 路由被覆盖。
        self.assertTrue(fallback_paths <= fastapi_paths)

    def test_public_merchant_home_in_fastapi_stack(self) -> None:
        """公开主页 FastAPI 分支必须真实返回 HTML，而不是 500。"""
        from fastapi.testclient import TestClient

        from kiwi_catalog.db.session import db_session

        merchant_id = "mkt_fastapi_home_1"
        with db_session(self.db_file) as conn:
            conn.execute(
                "insert into merchant_publications (publication_id, merchant_id, status,"
                " source_kind, merchant_display_name, shop_platform, shop_url, title,"
                " category, summary, faq_json, published_at, expires_at, version,"
                " created_at, updated_at)"
                " values ('mpub_fastapi_home', ?, 'published', 'merchant_declared',"
                " 'FastAPI 主页商家', '', '', 'FastAPI 主页商品', '', '公开主页简介',"
                " '[]', '2026-01-01T00:00:00+00:00', '', 1,"
                " '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')",
                (merchant_id,),
            )
        with TestClient(self.app) as client:
            resp = client.get(f"/m/{merchant_id}")
            self.assertEqual(resp.status_code, 200, resp.text)
            self.assertIn("text/html", resp.headers.get("content-type", ""))
            self.assertIn("FastAPI 主页商品", resp.text)
            self.assertEqual(resp.headers.get("cache-control"), "no-store")
            # 兼容别名也必须走同一 FastAPI handler。
            alias = client.get(f"/merchants/{merchant_id}")
            self.assertEqual(alias.status_code, 200, alias.text)
            self.assertIn("FastAPI 主页商品", alias.text)

    def test_listings_routes_in_both_stacks(self) -> None:
        """6 条 listing 路由双栈覆盖（v0.4）；/v1/listings/search 不被 {listing_id} 吞掉。"""
        from fastapi.testclient import TestClient

        listing_paths = {
            "/v1/listings/search",
            "/v1/listings/{listing_id}",
            "/v1/agents/{catalog_agent_id}/listings",
            "/v1/listings/publish",
            "/v1/listings/{listing_id}/withdraw",
            "/v1/listings/{listing_id}/reinstate",
        }
        self.assertTrue(listing_paths <= {entry.path_template for entry in app_module._ROUTE_TABLE})
        with TestClient(self.app) as client:
            # search 静态段优先于参数段：不把 "search" 当 listing_id（404 而不是 400）
            resp = client.get("/v1/listings/search")
            self.assertEqual(resp.status_code, 200, resp.text)
            self.assertEqual(resp.json()["results"], [])
            # 未知 listing_id → 404（参数段正确解析）
            resp = client.get("/v1/listings/lst_doesnotexist")
            self.assertEqual(resp.status_code, 404, resp.text)
            # FastAPI 默认参数传空字符串：数值/布尔过滤视为未提供（不 400）
            resp = client.get("/v1/listings/search")
            self.assertEqual(resp.status_code, 200, resp.text)

    def test_list_agent_listings_fastapi_threads_admin_header(self) -> None:
        """KC-SEC-02：FastAPI 栈 listings 自查路由 admin 只经 Authorization header。

        fallback 栈经 payload_with_auth 把 Bearer 合并进 payload；FastAPI 路由
        同样必须透传 header，否则双栈切换后 admin 豁免 / 未绑定 agent 读取失效。
        owner_token query 自查为 legacy 兼容，保持不变。
        """
        import os
        from unittest import mock

        from fastapi.testclient import TestClient

        from kiwi_catalog.api.auth import owner_token

        owner_secret = "test-owner-secret"
        admin_token = "admin-tok"
        merchant_id = "mrc_fastapi"
        with mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_OWNER_TOKEN_SECRET": owner_secret,
                "KIWI_CATALOG_ADMIN_TOKEN": admin_token,
            },
            clear=False,
        ):
            token = owner_token(merchant_id)
            with TestClient(self.app) as client:
                reg = client.post(
                    "/v1/agents/register",
                    json={
                        "domain": "fastapi-admin.example",
                        "display_name": "FastAPI Admin",
                        "agent_card_url": "https://fastapi-admin.example/.well-known/agent-card.json",
                        "hosting_mode": "direct_only",
                        "handoff_destination_types": ["external_checkout_url"],
                        "merchant_id": merchant_id,
                        "owner_token": token,
                    },
                )
                self.assertEqual(reg.status_code, 200, reg.text)
                agent_id = reg.json()["agent"]["catalog_agent_id"]
                pub = client.post(
                    "/v1/listings/publish",
                    json={
                        "listing_type": "product",
                        "owner_agent_id": agent_id,
                        "merchant_id": merchant_id,
                        "owner_token": token,
                        "source_product_ref": "SKU-001",
                        "title": "FastAPI Admin Display",
                        "category": "industrial-display",
                        "handoff_destination_types": ["external_checkout_url"],
                    },
                )
                self.assertEqual(pub.status_code, 200, pub.text)
                # admin token 在 query、无 header → 403（fail-closed）
                resp = client.get(
                    f"/v1/agents/{agent_id}/listings?admin_token={admin_token}"
                )
                self.assertEqual(resp.status_code, 403, resp.text)
                # Authorization: Bearer admin → 200 豁免
                resp = client.get(
                    f"/v1/agents/{agent_id}/listings",
                    headers={"Authorization": f"Bearer {admin_token}"},
                )
                self.assertEqual(resp.status_code, 200, resp.text)
                self.assertEqual(len(resp.json()["results"]), 1)
                # legacy owner_token query 自查 → 200
                resp = client.get(f"/v1/agents/{agent_id}/listings?owner_token={token}")
                self.assertEqual(resp.status_code, 200, resp.text)
                self.assertEqual(len(resp.json()["results"]), 1)

    def test_error_shapes_match_fallback(self) -> None:
        """审查 P2：错误信封 {ok:false,error} + 状态码与 fallback 对齐。"""
        from fastapi.testclient import TestClient

        with TestClient(self.app) as client:
            # 未知路由 → 404 信封（fallback 文案）
            resp = client.get("/v1/does-not-exist")
            self.assertEqual(resp.status_code, 404, resp.text)
            self.assertEqual(resp.json(), {"ok": False, "error": "No route for GET /v1/does-not-exist"})
            # 方法不允许 → 405 信封
            resp = client.delete("/v1/agents/register")
            self.assertEqual(resp.status_code, 405, resp.text)
            self.assertIn("Method not allowed", resp.json()["error"])
            # 非法 JSON body → 400 信封（FastAPI 默认是 422 detail）
            resp = client.post(
                "/v1/agents/register",
                content=b"{not json",
                headers={"content-type": "application/json"},
            )
            self.assertEqual(resp.status_code, 400, resp.text)
            self.assertEqual(resp.json(), {"ok": False, "error": "invalid JSON request body"})

    def test_body_limits_match_fallback(self) -> None:
        """审查 P2：FastAPI 栈补齐 body 大小/深度上限（此前无限制）。"""
        from fastapi.testclient import TestClient

        with TestClient(self.app) as client:
            # 深嵌套 body → 400（validate_payload 深度上限 16；嵌套数组先被
            # 「must be an object」拦截，与 fallback 检查顺序一致）
            deep = '{"a":' * 20 + "1" + "}" * 20
            resp = client.post(
                "/v1/agents/register",
                content=deep,
                headers={"content-type": "application/json"},
            )
            self.assertEqual(resp.status_code, 400, resp.text)
            self.assertIn("nesting", resp.json()["error"])

    def test_get_etag_and_304_match_fallback(self) -> None:
        """审查 P2：GET 200 带 etag；显式 If-None-Match 匹配 → 304。"""
        from fastapi.testclient import TestClient

        with TestClient(self.app) as client:
            first = client.get("/v1/listings/search")
            self.assertEqual(first.status_code, 200, first.text)
            etag = first.headers.get("etag")
            self.assertTrue(etag, "GET 响应必须带 etag header")
            revalidated = client.get(
                "/v1/listings/search", headers={"if-none-match": etag}
            )
            self.assertEqual(revalidated.status_code, 304, revalidated.text)
            self.assertEqual(revalidated.text, "")

    def _register_detail_agent(self, client, domain: str) -> str:
        reg = client.post(
            "/v1/agent-catalog/agents/register",
            json={"domain": domain, "idempotency_key": f"detail-{domain}"},
        )
        self.assertEqual(reg.status_code, 200, reg.text)
        return str(reg.json()["catalog_agent"]["catalog_agent_id"])

    def test_get_agent_include_buyer_access_is_projected_with_no_store(self) -> None:
        """回归：详情路由必须把 query 传给 ``_v1_get_agent(query=...)``。

        线上验收：include=buyer_access 时 FastAPI 详情既没有 buyer_access 投影，
        也没有 Cache-Control: no-store——query dict 被放到 payload 位置后丢弃。
        """
        from fastapi.testclient import TestClient

        with TestClient(self.app) as client:
            agent_id = self._register_detail_agent(client, "detail-include.example")
            resp = client.get(
                f"/v1/agents/{agent_id}", params={"include": "buyer_access"}
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            payload = resp.json()
            self.assertTrue(payload["ok"])
            # __no_store__ 是传输层元数据，绝不能出现在 wire body。
            self.assertNotIn("__no_store__", payload)
            access = payload["agent"]["buyer_access"]
            self.assertEqual(access["state"], "direct")
            self.assertEqual(access["source"], "legacy_no_share_code")
            self.assertEqual(access["revision"], 0)
            self.assertEqual(access["platform_verification"], "unverified")
            self.assertEqual(resp.headers.get("cache-control"), "no-store")
            # no-store 响应不参与 etag/304 条件请求。
            self.assertFalse(resp.headers.get("etag"))

    def test_get_agent_default_shape_is_unchanged(self) -> None:
        """缺省详情保持旧形状：无 buyer_access / no-store，且与 fallback 一致。"""
        from fastapi.testclient import TestClient

        with TestClient(self.app) as client:
            agent_id = self._register_detail_agent(client, "detail-default.example")
            resp = client.get(f"/v1/agents/{agent_id}")
            self.assertEqual(resp.status_code, 200, resp.text)
            payload = resp.json()
            self.assertNotIn("buyer_access", payload["agent"])
            self.assertNotIn("__no_store__", payload)
            self.assertNotEqual(resp.headers.get("cache-control"), "no-store")
            self.assertTrue(resp.headers.get("etag"), "缺省公开详情仍应带 etag")
            status, fallback = app_module.handle_request(
                self.db_file, "GET", f"/v1/agents/{agent_id}", query={}
            )
            self.assertEqual(status, 200, fallback)
            self.assertEqual(payload, fallback)

    def test_get_agent_unknown_include_is_rejected(self) -> None:
        """未知 include 与 fallback 同口径 fail-closed 400（不能静默忽略）。"""
        from fastapi.testclient import TestClient

        with TestClient(self.app) as client:
            agent_id = self._register_detail_agent(client, "detail-unknown.example")
            resp = client.get(
                f"/v1/agents/{agent_id}", params={"include": "secret_stuff"}
            )
            self.assertEqual(resp.status_code, 400, resp.text)
            self.assertEqual(
                resp.json(),
                {"ok": False, "error": "unsupported include field: secret_stuff"},
            )

    def test_account_agents_routes_in_both_stacks(self) -> None:
        """P0 批次 B：接入记录 3 条 API + 「我的名片」页双栈注册（设计 §5.2）。

        无会话一律 403（与 /v1/accounts/me 同一会话约定）；页面 200 HTML。
        """
        from fastapi.testclient import TestClient

        new_paths = {
            "/v1/accounts/agents",
            "/v1/accounts/agents/{catalog_agent_id}/card",
            "/v1/accounts/agents/{catalog_agent_id}/card/pause",
            "/v1/accounts/agents/{catalog_agent_id}/card/resume",
            "/v1/accounts/agents/{catalog_agent_id}/card/withdraw",
            "/v1/accounts/agents/{catalog_agent_id}/bindings/pending",
            "/v1/accounts/agents/{catalog_agent_id}/bindings/{binding_request_id}/confirm",
            "/v1/accounts/agents/{catalog_agent_id}/bindings/{binding_request_id}/reject",
        }
        self.assertTrue(new_paths <= {entry.path_template for entry in app_module._ROUTE_TABLE})
        with TestClient(self.app) as client:
            resp = client.post("/v1/accounts/agents", json={})
            self.assertEqual(resp.status_code, 403, resp.text)
            resp = client.get("/v1/accounts/agents")
            self.assertEqual(resp.status_code, 403, resp.text)
            resp = client.get("/v1/accounts/agents/cagt_x/card")
            self.assertEqual(resp.status_code, 403, resp.text)
            for action in ("pause", "resume", "withdraw"):
                resp = client.post(
                    f"/v1/accounts/agents/cagt_x/card/{action}", json={"expected_revision": 1}
                )
                self.assertEqual(resp.status_code, 403, (action, resp.text))
            resp = client.get("/v1/accounts/agents/cagt_x/bindings/pending")
            self.assertEqual(resp.status_code, 403, resp.text)
            for action in ("confirm", "reject"):
                resp = client.post(
                    f"/v1/accounts/agents/cagt_x/bindings/breq_x/{action}", json={}
                )
                self.assertEqual(resp.status_code, 403, (action, resp.text))

    def test_login_rate_limit_in_fastapi_stack(self) -> None:
        """The persisted auth counter also works through the real FastAPI stack."""
        from fastapi.testclient import TestClient

        email = "fastapi-rate@example.test"
        with mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
                "KIWI_CATALOG_LOGIN_RATE_LIMIT_PER_15MIN": "10",
            },
            clear=False,
        ):
            with TestClient(self.app) as client:
                code = client.post(
                    "/v1/accounts/register/code", json={"email": email}
                ).json()["verification_code"]
                ticket = client.post(
                    "/v1/accounts/register/verify",
                    json={"email": email, "code": code},
                ).json()["verification_ticket"]
                registered = client.post(
                    "/v1/accounts/register",
                    json={
                        "merchant_name": "FastAPI Rate",
                        "email": email,
                        "password": "strong-pw-123",
                        "phone": "+86 138 0000 0000",
                        "verification_ticket": ticket,
                    },
                )
                self.assertEqual(registered.status_code, 200, registered.text)

        with mock.patch.dict(
            os.environ, {"KIWI_CATALOG_LOGIN_RATE_LIMIT_PER_15MIN": "3"}, clear=False
        ):
            with TestClient(self.app) as client:
                statuses = [
                    client.post(
                        "/v1/accounts/login",
                        json={"email": email, "password": "wrong-password"},
                    ).status_code
                    for _ in range(4)
                ]
        self.assertEqual(statuses, [403, 403, 403, 429])

    def test_auth_storage_failure_does_not_issue_session_in_fastapi(self) -> None:
        """A failed rate-limit write must fail closed without a session cookie."""
        from fastapi.testclient import TestClient

        from kiwi_catalog.db.session import db_session

        email = "fastapi-storage@example.test"
        with mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
                "KIWI_CATALOG_LOGIN_RATE_LIMIT_PER_15MIN": "10",
            },
            clear=False,
        ):
            with TestClient(self.app) as client:
                code = client.post(
                    "/v1/accounts/register/code", json={"email": email}
                ).json()["verification_code"]
                ticket = client.post(
                    "/v1/accounts/register/verify",
                    json={"email": email, "code": code},
                ).json()["verification_ticket"]
                registered = client.post(
                    "/v1/accounts/register",
                    json={
                        "merchant_name": "FastAPI Storage",
                        "email": email,
                        "password": "strong-pw-123",
                        "phone": "+86 138 0000 0000",
                        "verification_ticket": ticket,
                    },
                )
                self.assertEqual(registered.status_code, 200, registered.text)

        with db_session(self.db_file) as conn:
            conn.execute(
                "create trigger fail_rate_in_fastapi before insert on merchant_application_limits"
                " begin select raise(abort, 'forced rate-limit storage failure'); end"
            )
        try:
            with TestClient(self.app, raise_server_exceptions=False) as client:
                response = client.post(
                    "/v1/accounts/login",
                    json={"email": email, "password": "strong-pw-123"},
                )
            self.assertEqual(response.status_code, 500, response.text)
            self.assertNotIn("set-cookie", response.headers)
        finally:
            with db_session(self.db_file) as conn:
                conn.execute("drop trigger if exists fail_rate_in_fastapi")

    def test_heartbeat_accepts_binding_signature_in_fastapi(self) -> None:
        """D6：FastAPI 栈的心跳也必须透传 x-kiwi-binding-jws（fallback 在全路由
        统一合并该头，FastAPI 路由要显式取——漏了就是 500/403 的双栈漂移）。

        全链路：注册 → 门户建接入记录 → admin 直绑 → 绑定私钥签名心跳 → 200。
        """
        import base64 as _b64
        import json as _json
        import uuid as _uuid
        from datetime import datetime, timezone

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )
        from fastapi.testclient import TestClient

        from kiwi_catalog.a2a.binding_claims import jwk_thumbprint

        def b64url(raw: bytes) -> str:
            return _b64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
        jwk = {
            "kty": "OKP", "crv": "Ed25519",
            "x": b64url(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
        }

        def jws(kid: str, fields: dict) -> str:
            from cryptography.hazmat.primitives.serialization import load_pem_private_key

            header = {"alg": "EdDSA", "kid": kid}
            body = {
                **fields,
                "issued_at": datetime.now(timezone.utc).isoformat(),
                "nonce": f"nonce-{_uuid.uuid4().hex}",
            }
            h = b64url(_json.dumps(header, separators=(",", ":")).encode())
            p = b64url(_json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode())
            k = load_pem_private_key(pem.encode(), password=None)
            return f"{h}.{p}.{b64url(k.sign(f'{h}.{p}'.encode('ascii')))}"

        origin = "https://hb-fastapi.example.app.workbuddy.host"
        with mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_ADMIN_TOKEN": "admin-tok",
                "KIWI_CATALOG_OWNER_TOKEN_SECRET": "test-owner-secret",
                "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
            },
            clear=False,
        ):
            with TestClient(self.app) as client:
                resp = client.post(
                    "/v1/accounts/register/code", json={"email": "hb@acme.example"}
                )
                self.assertEqual(resp.status_code, 200, resp.text)
                resp = client.post("/v1/accounts/register/verify", json={
                    "email": "hb@acme.example", "code": resp.json()["verification_code"],
                })
                self.assertEqual(resp.status_code, 200, resp.text)
                resp = client.post("/v1/accounts/register", json={
                    "merchant_name": "HB 商贸", "email": "hb@acme.example",
                    "password": "strong-pw-123", "phone": "+86 138 0000 0000",
                    "verification_ticket": resp.json()["verification_ticket"],
                })
                self.assertEqual(resp.status_code, 200, resp.text)
                # TestClient 的 cookie jar 不会把 Secure cookie 回传给 http://testserver
                # ——手动从 Set-Cookie 提取并显式传递（与 fallback 测试同法）。
                session = resp.headers["set-cookie"].split(";")[0].split("=", 1)[1]
                cookie = {"cookie": f"kiwi_session={session}"}
                resp = client.post("/v1/accounts/agents", json={}, headers=cookie)
                self.assertEqual(resp.status_code, 200, resp.text)
                cagt = resp.json()["catalog_agent_id"]
                # admin 直绑（运维兜底路径）拿活动绑定
                bind_body = {
                    "binding": {
                        "runtime_origin": origin, "a2a_endpoint": f"{origin}/a2a",
                        "key_jwk": jwk, "key_id": origin, "generation": 1, "service_epoch": 7,
                    },
                    "admin_token": "admin-tok",
                }
                bind_sig = jws(origin, {
                    "agent_id": cagt, "key_id": origin,
                    "key_thumbprint": jwk_thumbprint(jwk),
                    "runtime_origin": origin, "a2a_endpoint": f"{origin}/a2a",
                    "generation": 1, "service_epoch": 7,
                })
                resp = client.post(
                    f"/v1/agents/{cagt}/runtime-bindings",
                    json=bind_body, headers={"x-kiwi-binding-jws": bind_sig},
                )
                self.assertEqual(resp.status_code, 200, resp.text)
                binding_id = resp.json()["binding_id"]
                # 绑定签名心跳（无 cookie、无 owner token——只带签名头）
                hb_sig = jws(origin, {"agent_id": cagt, "binding_id": binding_id})
                resp = client.post(
                    f"/v1/agent-catalog/agents/{cagt}/heartbeat",
                    json={}, headers={"x-kiwi-binding-jws": hb_sig},
                )
                self.assertEqual(resp.status_code, 200, resp.text)
                self.assertEqual(resp.json()["actor"], f"runtime:{binding_id}")
                self.assertEqual(resp.json()["freshness_state"], "fresh")


if __name__ == "__main__":
    unittest.main()
