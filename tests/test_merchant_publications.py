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

"""商家公开资料（M0 工作包 A）集成测试。

覆盖（对应任务验收用例）：
- 未登录不能发布（会话认证，非 owner token）；
- 账号 A 不能撤回/查看账号 B 的资料；
- 草稿不出现在搜索；发布后按商品词可搜到正确 merchant_id；
- 两商家同名商品都可搜到；同一商家同名重复发布 = 幂等更新（不产生重复主体）；
- 撤回/过期后不可搜；search 返回 inquiry_available=false；
- 私密字段（邮箱/手机号）写入被拒绝并留审计；shop_url 内网地址被拒绝；
- 公开投影不含注册账户的电话/邮箱；
- 双栈：fallback 路由表 + FastAPI 路由 parity，fallback 栈端到端冒烟。
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import tempfile
import unittest
from unittest import mock

from kiwi_catalog.api import app as app_module
from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.api.fallback_asgi import MarketplaceASGIApp
from kiwi_catalog.api.route_table import _ROUTE_TABLE, resolve_route

OWNER_SECRET = "test-owner-secret"


def _call_http(
    app,
    method: str,
    path: str,
    body: bytes = b"",
    cookie: str = "",
    query_string: bytes = b"",
) -> tuple[int, dict, dict]:
    headers = [(b"content-type", b"application/json")]
    if cookie:
        headers.append((b"cookie", cookie.encode()))
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers,
        "query_string": query_string,
        "http_version": "1.1",
        "scheme": "http",
    }
    received: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(msg: dict) -> None:
        received.append(msg)

    asyncio.run(app(scope, receive, send))
    start = next(m for m in received if m["type"] == "http.response.start")
    headers_out = {
        k.decode("latin1"): v.decode("latin1") for k, v in start.get("headers", [])
    }
    chunks = b"".join(m.get("body", b"") for m in received if m["type"] == "http.response.body")
    payload: dict = {}
    if chunks:
        try:
            payload = json.loads(chunks.decode())
        except json.JSONDecodeError:
            payload = {"_raw": chunks.decode()}
    return start.get("status", 500), payload, headers_out


def _register_and_login(app, email: str, merchant_name: str) -> str:
    """注册（console 模式）→ 验证邮箱 → 返回会话 cookie。"""
    status, payload, _ = _call_http(
        app,
        "POST",
        "/v1/accounts/register",
        json.dumps(
            {
                "merchant_name": merchant_name,
                "email": email,
                "password": "strong-pw-123",
                "phone": "+86 138 0000 0000",
            }
        ).encode(),
    )
    assert status == 200, payload
    status, payload, headers = _call_http(
        app,
        "POST",
        "/v1/accounts/verify-email",
        json.dumps({"email": email, "code": payload["verification_code"]}).encode(),
    )
    assert status == 200, payload
    return headers["set-cookie"].split(";")[0]


def _merchant_id(app, cookie: str) -> str:
    status, payload, _ = _call_http(app, "GET", "/v1/accounts/me", cookie=cookie)
    assert status == 200, payload
    return str(payload["merchant_id"])


def _publish_body(title: str, **overrides) -> dict:
    body = {
        "action": "publish",
        "merchant_display_name": "Acme 商贸",
        "title": title,
        "category": "茶叶",
        "summary": "公开简介",
    }
    body.update(overrides)
    return body


class MerchantPublicationsApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "catalog.sqlite")
        env_patch = mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET,
                "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
            },
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.app = create_catalog_app(self.db_path)
        self.cookie_a = _register_and_login(self.app, "a@acme.example", "Acme 商贸")
        self.cookie_b = _register_and_login(self.app, "b@rival.example", "Rival 商行")
        self.merchant_a = _merchant_id(self.app, self.cookie_a)
        self.merchant_b = _merchant_id(self.app, self.cookie_b)

    def _create(self, cookie: str, body: dict) -> tuple[int, dict]:
        status, payload, _ = _call_http(
            self.app, "POST", "/v1/merchant-publications", json.dumps(body).encode(), cookie=cookie
        )
        return status, payload

    def _search(self, params: str = "", cookie: str = "") -> tuple[int, dict]:
        # 查询参数必须 percent-encode（与真实客户端一致；raw UTF-8 字节在
        # FastAPI 栈按 latin-1 解码会失真——测试 helper 不应依赖栈的容错）。
        from urllib.parse import quote

        encoded = "&".join(
            f"{quote(k, safe='')}={quote(v, safe='')}"
            for k, v in (part.split("=", 1) for part in params.split("&") if part)
        )
        status, payload, _ = _call_http(
            self.app,
            "GET",
            "/v1/merchant-publications/search",
            cookie=cookie,
            query_string=encoded.encode(),
        )
        return status, payload

    def _get(self, publication_id: str, cookie: str = "") -> tuple[int, dict]:
        status, payload, _ = _call_http(
            self.app, "GET", f"/v1/merchant-publications/{publication_id}", cookie=cookie
        )
        return status, payload

    def _withdraw(self, cookie: str, publication_id: str) -> tuple[int, dict]:
        status, payload, _ = _call_http(
            self.app,
            "POST",
            f"/v1/merchant-publications/{publication_id}/withdraw",
            b"{}",
            cookie=cookie,
        )
        return status, payload

    def _audit_events(self) -> list[str]:
        conn = sqlite3.connect(self.db_path)
        try:
            rows = conn.execute("select event from audit_events").fetchall()
        finally:
            conn.close()
        return [r[0] for r in rows]

    # ── 认证与归属 ────────────────────────────────────────────────────────

    def test_unauthenticated_cannot_publish(self) -> None:
        status, payload = self._create("", _publish_body("明前龙井"))
        self.assertEqual(status, 403, payload)
        self.assertFalse(payload["ok"])

    def test_account_a_cannot_withdraw_account_b(self) -> None:
        status, payload = self._create(self.cookie_b, _publish_body(" rival 专属商品 "))
        self.assertEqual(status, 200, payload)
        publication_id = payload["publication"]["publication_id"]
        # 账号 A 撤回账号 B 的资料 → 403
        status, payload = self._withdraw(self.cookie_a, publication_id)
        self.assertEqual(status, 403, payload)
        # 商家 B 的草稿对账号 A 也不可见（404，不泄漏存在性）
        status, payload = self._create(
            self.cookie_b, _publish_body(" rival 草稿商品 ", action="draft")
        )
        draft_id = payload["publication"]["publication_id"]
        status, _ = self._get(draft_id, cookie=self.cookie_a)
        self.assertEqual(status, 404)

    def test_client_supplied_merchant_id_is_ignored(self) -> None:
        """merchant_id 一律取自服务端会话：客户端传别人的 merchant_id 无效。"""
        status, payload = self._create(
            self.cookie_a, _publish_body("归属校验商品", merchant_id=self.merchant_b)
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["publication"]["merchant_id"], self.merchant_a)

    # ── 草稿 / 发布 / 搜索 ────────────────────────────────────────────────

    def test_draft_not_in_search(self) -> None:
        status, payload = self._create(
            self.cookie_a, _publish_body("草稿态商品", action="draft")
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["publication"]["status"], "draft")
        draft_id = payload["publication"]["publication_id"]
        status, payload = self._search("q=草稿态商品")
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["results"], [])
        # 匿名不可见草稿详情（商家本人可见见 test_owner_can_view_own_draft）
        status, _ = self._get(draft_id)
        self.assertEqual(status, 404)

    def _last_id(self, payload: dict) -> str:
        return str(payload["publication"]["publication_id"])

    def test_owner_can_view_own_draft(self) -> None:
        status, payload = self._create(
            self.cookie_a, _publish_body("本人草稿", action="draft")
        )
        draft_id = payload["publication"]["publication_id"]
        status, payload = self._get(draft_id, cookie=self.cookie_a)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["publication"]["status"], "draft")

    def test_publish_then_searchable_by_product_word(self) -> None:
        status, payload = self._create(self.cookie_a, _publish_body("明前龙井 2026"))
        self.assertEqual(status, 200, payload)
        receipt = payload["publication"]
        self.assertEqual(receipt["status"], "published")
        self.assertTrue(receipt["publication_id"])
        self.assertEqual(receipt["version"], 1)
        self.assertTrue(receipt["published_at"])

        status, payload = self._search("q=明前龙井")
        self.assertEqual(status, 200, payload)
        self.assertEqual(len(payload["results"]), 1)
        hit = payload["results"][0]
        self.assertEqual(hit["merchant_id"], self.merchant_a)
        self.assertEqual(hit["merchant_display_name"], "Acme 商贸")
        self.assertEqual(hit["title"], "明前龙井 2026")
        self.assertEqual(hit["source_kind"], "merchant_declared")
        # 不生成虚假能力：恒为不可实时询价
        self.assertIs(hit["inquiry_available"], False)
        self.assertTrue(hit["published_at"])
        self.assertTrue(hit["updated_at"])

    def test_two_merchants_same_title_both_searchable(self) -> None:
        status, _ = self._create(self.cookie_a, _publish_body("同款保温杯"))
        self.assertEqual(status, 200)
        status, _ = self._create(self.cookie_b, _publish_body("同款保温杯"))
        self.assertEqual(status, 200)
        status, payload = self._search("q=同款保温杯")
        self.assertEqual(status, 200, payload)
        merchants = {r["merchant_id"] for r in payload["results"]}
        self.assertEqual(merchants, {self.merchant_a, self.merchant_b})

    def test_idempotent_republish_same_title_updates_in_place(self) -> None:
        status, first = self._create(self.cookie_a, _publish_body("幂等商品"))
        self.assertEqual(status, 200, first)
        status, second = self._create(
            self.cookie_a, _publish_body("幂等商品", summary="更新后的简介")
        )
        self.assertEqual(status, 200, second)
        # 可解释处理：同一 publication_id、版本递增、显式 idempotent 标记
        self.assertTrue(second["idempotent"])
        self.assertTrue(second["message"])
        self.assertEqual(
            second["publication"]["publication_id"], first["publication"]["publication_id"]
        )
        self.assertEqual(second["publication"]["version"], 2)
        # 搜索结果不产生重复主体
        status, payload = self._search("q=幂等商品")
        self.assertEqual(len(payload["results"]), 1)

    # ── 撤回 / 过期 ──────────────────────────────────────────────────────

    def test_withdraw_removes_from_search_and_detail(self) -> None:
        status, payload = self._create(self.cookie_a, _publish_body("待撤回商品"))
        publication_id = payload["publication"]["publication_id"]
        status, payload = self._withdraw(self.cookie_a, publication_id)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["publication"]["status"], "withdrawn")
        status, payload = self._search("q=待撤回商品")
        self.assertEqual(payload["results"], [])
        # 匿名详情 404；本人仍可见（withdrawn 状态）
        status, _ = self._get(publication_id)
        self.assertEqual(status, 404)
        status, payload = self._get(publication_id, cookie=self.cookie_a)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["publication"]["status"], "withdrawn")
        self.assertIn("merchant_publication_withdrawn", self._audit_events())

    def test_expired_publication_not_in_search(self) -> None:
        status, payload = self._create(
            self.cookie_a,
            _publish_body("已过期商品", expires_at="2020-01-01T00:00:00+00:00"),
        )
        self.assertEqual(status, 200, payload)
        publication_id = payload["publication"]["publication_id"]
        status, payload = self._search("q=已过期商品")
        self.assertEqual(payload["results"], [])
        # 匿名详情同样不可见（过期 ≈ 不公开）
        status, _ = self._get(publication_id)
        self.assertEqual(status, 404)

    def test_future_expiry_still_searchable(self) -> None:
        status, payload = self._create(
            self.cookie_a,
            _publish_body("限时商品", expires_at="2099-01-01T00:00:00+00:00"),
        )
        self.assertEqual(status, 200, payload)
        status, payload = self._search("q=限时商品")
        self.assertEqual(len(payload["results"]), 1)

    # ── 私密字段与链接安全 ────────────────────────────────────────────────

    def test_private_contact_fields_rejected_and_audited(self) -> None:
        status, payload = self._create(
            self.cookie_a, _publish_body("私密商品一", summary="联系我 buyer@acme.example")
        )
        self.assertEqual(status, 400, payload)
        status, payload = self._create(
            self.cookie_a, _publish_body("下单电话 13812345678 微信同号")
        )
        self.assertEqual(status, 400, payload)
        status, payload = self._create(
            self.cookie_a,
            _publish_body("私密商品三", faq=[{"question": "怎么联系", "answer": "发邮件到 a@b.com"}]),
        )
        self.assertEqual(status, 400, payload)
        self.assertIn("merchant_publication_private_field_rejected", self._audit_events())
        # 被拒绝的内容没有落库
        status, payload = self._search("q=私密商品")
        self.assertEqual(payload["results"], [])

    def test_public_projection_has_no_account_contact(self) -> None:
        status, _ = self._create(self.cookie_a, _publish_body("投影校验商品"))
        self.assertEqual(status, 200)
        status, payload = self._search("q=投影校验商品")
        hit = payload["results"][0]
        for forbidden in ("phone", "email", "password", "wechat", "account_id"):
            self.assertNotIn(forbidden, hit)
        status, payload = self._get(hit["publication_id"])
        self.assertEqual(status, 200, payload)
        for forbidden in ("phone", "email", "password", "wechat", "account_id"):
            self.assertNotIn(forbidden, payload["publication"])

    def test_shop_url_safety(self) -> None:
        for bad_url in (
            "http://127.0.0.1/admin",
            "http://192.168.1.1/shop",
            "https://10.0.0.8/internal",
            "http://[::1]/shop",
            "ftp://shop.example.com",
            "not-a-url",
        ):
            status, payload = self._create(
                self.cookie_a, _publish_body("链接校验商品", shop_url=bad_url)
            )
            self.assertEqual(status, 400, f"{bad_url}: {payload}")
        status, payload = self._create(
            self.cookie_a,
            _publish_body("链接校验商品", shop_url="https://shop.example.com/item/1"),
        )
        self.assertEqual(status, 200, payload)

    # ── 字段校验与限流 ────────────────────────────────────────────────────

    def test_required_fields_and_length_caps(self) -> None:
        status, payload = self._create(
            self.cookie_a, {"action": "publish", "merchant_display_name": "", "title": ""}
        )
        self.assertEqual(status, 400, payload)
        status, payload = self._create(
            self.cookie_a, _publish_body("x" * 201)
        )
        self.assertEqual(status, 400, payload)

    def test_search_rejects_unknown_query_keys(self) -> None:
        status, payload = self._search("q=x&admin=true")
        self.assertEqual(status, 400, payload)

    def test_per_merchant_rate_limit(self) -> None:
        with mock.patch.dict(
            os.environ, {"KIWI_CATALOG_PUBLICATION_RATE_LIMIT_PER_15MIN": "2"}, clear=False
        ):
            for i in range(2):
                status, payload = self._create(self.cookie_a, _publish_body(f"限流商品{i}"))
                self.assertEqual(status, 200, payload)
            status, payload = self._create(self.cookie_a, _publish_body("限流商品2"))
            self.assertEqual(status, 429, payload)

    def test_audit_events_for_publish_and_update(self) -> None:
        self._create(self.cookie_a, _publish_body("审计商品"))
        self._create(self.cookie_a, _publish_body("审计商品"))
        events = self._audit_events()
        self.assertIn("merchant_publication_published", events)
        self.assertIn("merchant_publication_republished", events)


class MerchantPublicationsFallbackStackTest(unittest.TestCase):
    """fallback 栈端到端冒烟（create_catalog_app 在有 fastapi 时返回 FastAPI——
    显式构造 fallback app 锁定双栈行为一致）。"""

    def test_publish_and_search_on_fallback_stack(self) -> None:
        tmp = tempfile.mkdtemp()
        db_path = os.path.join(tmp, "catalog.sqlite")
        with mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET,
                "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
            },
            clear=False,
        ):
            app = MarketplaceASGIApp(
                db_path,
                route_provider=lambda: list(_ROUTE_TABLE),
                route_resolver=lambda method, path: resolve_route(method, path),
            )
            cookie = _register_and_login(app, "fb@acme.example", "Fallback 商贸")
            status, payload, _ = _call_http(
                app,
                "POST",
                "/v1/merchant-publications",
                json.dumps(_publish_body("fallback 商品")).encode(),
                cookie=cookie,
            )
            self.assertEqual(status, 200, payload)
            status, payload, _ = _call_http(
                app,
                "GET",
                "/v1/merchant-publications/search",
                query_string=b"q=fallback",
            )
            self.assertEqual(status, 200, payload)
            self.assertEqual(len(payload["results"]), 1)
            self.assertIs(payload["results"][0]["inquiry_available"], False)


@unittest.skipUnless(app_module.FastAPI is not None, "fastapi not installed")
class MerchantPublicationsFastApiTest(unittest.TestCase):
    """FastAPI 栈：4 条新路由注册 + 会话 cookie 透传 + 公开搜索。"""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        env_patch = mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET,
                "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
            },
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.app = create_catalog_app(os.path.join(self.tmp, "catalog.sqlite"))

    def test_routes_registered_and_functional(self) -> None:
        from fastapi.testclient import TestClient

        fastapi_paths = {route.path for route in self.app.routes if hasattr(route, "path")}
        for expected in (
            "/v1/merchant-publications",
            "/v1/merchant-publications/search",
            "/v1/merchant-publications/{publication_id}",
            "/v1/merchant-publications/{publication_id}/withdraw",
            "/portal/publications",
        ):
            self.assertIn(expected, fastapi_paths)

        with TestClient(self.app) as client:
            resp = client.post(
                "/v1/accounts/register",
                json={
                    "merchant_name": "FastAPI 商贸",
                    "email": "fa@acme.example",
                    "password": "strong-pw-123",
                    "phone": "+86 138 0000 0000",
                },
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            code = resp.json()["verification_code"]
            resp = client.post(
                "/v1/accounts/verify-email", json={"email": "fa@acme.example", "code": code}
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            # Set-Cookie 带 Secure 属性，TestClient 的 http://testserver 不会回
            # 传——显式取 cookie 头（与 test_accounts_api 的 raw-ASGI 模式一致）。
            session_cookie = resp.headers["set-cookie"].split(";")[0]
            auth = {"cookie": session_cookie}
            # 会话 cookie 透传（_account_payload）：发布 → 搜索 → 撤回闭环
            resp = client.post(
                "/v1/merchant-publications",
                json=_publish_body("fastapi 双栈商品"),
                headers=auth,
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            publication_id = resp.json()["publication"]["publication_id"]
            resp = client.get("/v1/merchant-publications/search", params={"q": "双栈商品"})
            self.assertEqual(resp.status_code, 200, resp.text)
            self.assertEqual(len(resp.json()["results"]), 1)
            resp = client.post(
                f"/v1/merchant-publications/{publication_id}/withdraw", json={}, headers=auth
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            resp = client.get("/v1/merchant-publications/search", params={"q": "双栈商品"})
            self.assertEqual(resp.json()["results"], [])
            # 未登录发布 → 403
            resp = client.post("/v1/merchant-publications", json=_publish_body("x"))
            self.assertEqual(resp.status_code, 403, resp.text)


if __name__ == "__main__":
    unittest.main()
