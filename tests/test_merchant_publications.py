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
        "/v1/accounts/register/code",
        json.dumps({"email": email}).encode(),
    )
    assert status == 200, payload
    status, payload, _ = _call_http(
        app,
        "POST",
        "/v1/accounts/register/verify",
        json.dumps({"email": email, "code": payload["verification_code"]}).encode(),
    )
    assert status == 200, payload
    status, payload, headers = _call_http(
        app,
        "POST",
        "/v1/accounts/register",
        json.dumps(
            {
                "merchant_name": merchant_name,
                "email": email,
                "password": "strong-pw-123",
                "phone": "+86 138 0000 0000",
                "verification_ticket": payload["verification_ticket"],
            }
        ).encode(),
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
        # 公开主页/主页链接现在要求商家有活动绑定：测试商家默认各绑定一个
        # Runtime；需要验证断开语义的用例再单独 revoke。
        self._add_active_binding(self.merchant_a, "cagt_bind_a")
        self._add_active_binding(self.merchant_b, "cagt_bind_b")

    def _add_active_binding(self, merchant_id: str, agent_id: str) -> None:
        conn = sqlite3.connect(self.db_path)
        try:
            now = "2026-01-01T00:00:00+00:00"
            conn.execute(
                "insert into catalog_agents (catalog_agent_id, merchant_id, display_name,"
                " source_type, hosting_mode, first_seen_at, last_seen_at, created_at, updated_at)"
                " values (?, ?, '测试接入', 'self_registered', 'direct', ?, ?, ?, ?)",
                (agent_id, merchant_id, now, now, now, now),
            )
            conn.execute(
                "insert into runtime_bindings (binding_id, catalog_agent_id, merchant_id,"
                " runtime_origin, a2a_endpoint, key_id, key_thumbprint, key_jwk_json,"
                " binding_version, service_epoch, status, created_at, updated_at)"
                " values (?, ?, ?, 'https://bind.example', 'https://bind.example/a2a',"
                " 'key-1', 'thumb-1', '{}', 1, 1, 'active', ?, ?)",
                (f"bind-{agent_id}", agent_id, merchant_id, now, now),
            )
            conn.commit()
        finally:
            conn.close()

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
        # WorkBuddy 服务/门禁链接、Agent 端点与分享码参数不是公开店铺页：
        # 新写入 fail-closed（普通外部商品链接仍兼容）。
        for bad_url in (
            "https://acme.app.workbuddy.host/shop",
            "https://workbuddy.host/shop",
            "https://open.workbuddy.cn/shop?sharecode=FAKE-SHARE-CODE-1",
            "https://shop.example.com/acme?sharecode=FAKE-SHARE-CODE-1",
            "https://shop.example.com/acme?share_code=FAKE-SHARE-CODE-1",
            "https://shop.example.com/acme?share-code=FAKE-SHARE-CODE-1",
            "https://shop.example.com/acme#sharecode=FAKE-SHARE-CODE-1",
            "https://shop.example.com/sharecode/FAKE-SHARE-CODE-1",
            "https://shop.example.com/%73harecode/FAKE-SHARE-CODE-1",
            "https://shop.example.com/acme?share%5Fcode=FAKE-SHARE-CODE-1",
            "https://shop.example.com/acme?sharecode=FAKE-SHARE-CODE-1/a2a",
            "https://shop.example.com/a2a",
            "https://shop.example.com/.well-known/agent-card.json",
        ):
            status, payload = self._create(
                self.cookie_a, _publish_body("链接校验商品", shop_url=bad_url)
            )
            self.assertEqual(status, 400, f"{bad_url}: {payload}")
            self.assertNotIn("FAKE-SHARE-CODE-1", json.dumps(payload))
        # 普通商品链接保持兼容。
        status, payload = self._create(
            self.cookie_a,
            _publish_body("链接校验商品", shop_url="https://shop.example.com/item/1"),
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["publication"]["shop_url"], "https://shop.example.com/item/1")

    def test_public_text_links_reject_workbuddy_share_codes(self) -> None:
        for summary in (
            "看这里 https://acme.app.workbuddy.host/?sharecode=FAKE-SHARE-CODE-2",
            "门禁链接 https://shop.example.com/acme?share_code=FAKE-SHARE-CODE-2",
        ):
            status, payload = self._create(
                self.cookie_a, _publish_body("文本链接商品", summary=summary)
            )
            self.assertEqual(status, 400, payload)
            self.assertNotIn("FAKE-SHARE-CODE-2", json.dumps(payload))
        # 普通商品链接仍可作为公开文本内容。
        status, payload = self._create(
            self.cookie_a,
            _publish_body("文本链接商品", summary="详情见 https://shop.example.com/item/2"),
        )
        self.assertEqual(status, 200, payload)
        self.assertIn("https://shop.example.com/item/2", payload["publication"]["summary"])

    def test_historical_public_projection_redacts_share_code_links(self) -> None:
        """旧数据/手工写库绕过写入校验时，搜索/详情/事件仍不投影危险链接。"""
        status, payload = self._create(self.cookie_a, _publish_body("历史链接商品"))
        self.assertEqual(status, 200, payload)
        publication_id = payload["publication"]["publication_id"]
        secret = "FAKE-HISTORY-SHARE-CODE-9"
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "update merchant_publications set shop_url = ?, summary = ?"
                " where publication_id = ?",
                (
                    f"https://acme.app.workbuddy.host/?sharecode={secret}",
                    f"历史简介 https://shop.example.com/acme?sharecode={secret}",
                    publication_id,
                ),
            )
            conn.commit()
        finally:
            conn.close()

        status, payload = self._search("q=历史链接商品")
        self.assertEqual(status, 200, payload)
        hit = payload["results"][0]
        self.assertEqual(hit["shop_url"], "")
        self.assertNotIn(secret, json.dumps(payload))
        self.assertIn("[链接已移除]", hit["summary"])

        status, payload = self._get(publication_id)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["publication"]["shop_url"], "")
        self.assertNotIn(secret, json.dumps(payload))

    def test_public_merchant_home_without_external_shop_url(self) -> None:
        """没有外部 shop_url 也有有效公开主页；只展示已公开资料。"""
        status, payload = self._create(
            self.cookie_a,
            _publish_body("主页商品一", summary="公开主页简介"),
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["publication"]["shop_url"], "")

        status, page, headers = _call_http(
            self.app, "GET", f"/m/{self.merchant_a}"
        )
        self.assertEqual(status, 200, page)
        rendered = str(page.get("_raw") or "")
        self.assertIn("Acme 商贸", rendered)
        self.assertIn("主页商品一", rendered)
        self.assertIn("公开主页简介", rendered)
        self.assertIn(self.merchant_a, rendered)
        self.assertNotIn("a@acme.example", rendered)
        self.assertNotIn("138 0000 0000", rendered)
        self.assertNotIn("sharecode", rendered)
        self.assertIn("text/html", headers.get("content-type", ""))

        # 等价别名与未知商家 404
        status, page, _ = _call_http(
            self.app, "GET", f"/merchants/{self.merchant_a}"
        )
        self.assertEqual(status, 200, page)
        status, _page, _ = _call_http(self.app, "GET", "/m/mkt_missing")
        self.assertEqual(status, 404)

    def test_public_home_link_requires_active_binding(self) -> None:
        """断开后公开投影与公开主页都不再给入口。"""
        status, payload = self._create(self.cookie_a, _publish_body("绑定门禁商品"))
        self.assertEqual(status, 200, payload)
        publication_id = payload["publication"]["publication_id"]
        self.assertTrue(payload["publication"]["public_home_url"])

        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "update runtime_bindings set status = 'revoked' where merchant_id = ?",
                (self.merchant_a,),
            )
            conn.commit()
        finally:
            conn.close()

        status, detail = self._get(publication_id)
        self.assertEqual(status, 200, detail)
        self.assertEqual(detail["publication"]["public_home_url"], "")
        status, search = self._search("q=绑定门禁")
        self.assertEqual(status, 200, search)
        self.assertTrue(all(item["public_home_url"] == "" for item in search["results"]))
        status, _page, _ = _call_http(self.app, "GET", f"/m/{self.merchant_a}")
        self.assertEqual(status, 404)

    def test_public_merchant_home_shows_active_listings(self) -> None:
        """只有已发布 Listing 的商家也能打开主页；私有字段不进入页面。"""
        status, _ = self._create(self.cookie_a, _publish_body("占位商品"))
        self.assertEqual(status, 200)
        conn = sqlite3.connect(self.db_path)
        try:
            now = "2026-10-01T00:00:00+00:00"
            conn.execute(
                "insert into commerce_listings (listing_id, listing_type, owner_agent_id,"
                " merchant_id, source_product_ref, title, summary, category, brand,"
                " attributes_json, regions_json, tags_json, commercial_hints_json,"
                " handoff_destination_types_json, listing_digest, publication_state,"
                " listing_freshness_state, published_at, updated_at, fresh_until, created_at)"
                " values ('lst_home_1', 'product', 'cagt_home', ?, 'SKU-HOME-1',"
                " '主页 Listing 商品', 'Listing 公开简介', '个护', 'Acme', '{}', '[]', '[]',"
                " '{}', '[]', 'digest-home-1', 'ACTIVE', 'FRESH', ?, ?, ?, ?)",
                (self.merchant_a, now, now, now, now),
            )
            conn.commit()
        finally:
            conn.close()
        status, page, _ = _call_http(self.app, "GET", f"/m/{self.merchant_a}")
        self.assertEqual(status, 200, page)
        rendered = str(page.get("_raw") or "")
        self.assertIn("主页 Listing 商品", rendered)
        self.assertIn("Listing 公开简介", rendered)

    def test_public_merchant_home_is_rate_limited(self) -> None:
        """主页是匿名公开读：按客户端 IP 接入与名片读相同的公开读预算。"""
        status, _ = self._create(self.cookie_a, _publish_body("限流主页商品"))
        self.assertEqual(status, 200)
        with mock.patch.dict(
            os.environ,
            {"KIWI_CATALOG_PUBLIC_READ_RATE_LIMIT_PER_MINUTE": "1"},
            clear=False,
        ):
            status, _page, _ = _call_http(self.app, "GET", f"/m/{self.merchant_a}")
            self.assertEqual(status, 200)
            status, payload, _ = _call_http(self.app, "GET", f"/m/{self.merchant_a}")
            self.assertEqual(status, 429, payload)

    def test_public_merchant_home_paginates_beyond_fifty(self) -> None:
        """单页 50 件不是硬截断：第 51 件可通过 ?page=2 访问。"""
        now = "2026-10-01T00:00:00+00:00"
        conn = sqlite3.connect(self.db_path)
        try:
            for index in range(51):
                conn.execute(
                    "insert into merchant_publications (publication_id, merchant_id,"
                    " status, source_kind, merchant_display_name, title, category, summary,"
                    " faq_json, published_at, expires_at, version, created_at, updated_at)"
                    " values (?, ?, 'published', 'merchant_declared', 'Acme 商贸', ?,"
                    " '茶叶', '公开简介', '[]', ?, '', 1, ?, ?)",
                    (
                        f"mpub_page_{index:02d}",
                        self.merchant_a,
                        f"分页商品{index:02d}",
                        now,
                        now,
                        now,
                    ),
                )
            conn.commit()
        finally:
            conn.close()
        status, page, _ = _call_http(self.app, "GET", f"/m/{self.merchant_a}")
        self.assertEqual(status, 200, page)
        rendered = str(page.get("_raw") or "")
        self.assertIn("分页商品50", rendered)
        self.assertIn('href="?page=2"', rendered)
        self.assertNotIn("分页商品00", rendered)

        status, page, _ = _call_http(
            self.app, "GET", f"/m/{self.merchant_a}", query_string=b"page=2"
        )
        self.assertEqual(status, 200, page)
        rendered = str(page.get("_raw") or "")
        self.assertIn("分页商品00", rendered)
        self.assertNotIn("分页商品50", rendered)

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
        self.db_path = os.path.join(self.tmp, "catalog.sqlite")
        self.app = create_catalog_app(self.db_path)

    def test_routes_registered_and_functional(self) -> None:
        from fastapi.testclient import TestClient

        fastapi_paths = {route.path for route in self.app.routes if hasattr(route, "path")}
        for expected in (
            "/v1/merchant-publications",
            "/v1/merchant-publications/search",
            "/v1/merchant-publications/stats",
            "/v1/merchant-publications/{publication_id}",
            "/v1/merchant-publications/{publication_id}/withdraw",
            "/m/{merchant_id}",
            "/merchants/{merchant_id}",
            "/merchant/{merchant_id}",
        ):
            self.assertIn(expected, fastapi_paths)

        with TestClient(self.app) as client:
            resp = client.post(
                "/v1/accounts/register/code", json={"email": "fa@acme.example"}
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            code = resp.json()["verification_code"]
            resp = client.post(
                "/v1/accounts/register/verify",
                json={"email": "fa@acme.example", "code": code},
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            resp = client.post(
                "/v1/accounts/register",
                json={
                    "merchant_name": "FastAPI 商贸",
                    "email": "fa@acme.example",
                    "password": "strong-pw-123",
                    "phone": "+86 138 0000 0000",
                    "verification_ticket": resp.json()["verification_ticket"],
                },
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
            merchant_id = resp.json()["publication"]["merchant_id"]
            # 公开主页要求活动绑定；这里补一个最小绑定夹具。
            now = "2026-01-01T00:00:00+00:00"
            agent_id = f"cagt-fa-{merchant_id}"
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute(
                    "insert or ignore into catalog_agents (catalog_agent_id, merchant_id,"
                    " display_name, source_type, hosting_mode, first_seen_at, last_seen_at,"
                    " created_at, updated_at) values (?, ?, 'FastAPI 商贸',"
                    " 'self_registered', 'direct', ?, ?, ?, ?)",
                    (agent_id, merchant_id, now, now, now, now),
                )
                conn.execute(
                    "insert or ignore into runtime_bindings (binding_id, catalog_agent_id,"
                    " merchant_id, runtime_origin, a2a_endpoint, key_id, key_thumbprint,"
                    " key_jwk_json, binding_version, service_epoch, status, created_at,"
                    " updated_at) values (?, ?, ?, 'https://fa.example',"
                    " 'https://fa.example/a2a', 'key-1', 'thumb-1', '{}', 1, 1, 'active', ?, ?)",
                    (f"bind-fa-{merchant_id}", agent_id, merchant_id, now, now),
                )
                conn.commit()
            finally:
                conn.close()
            resp = client.get("/v1/merchant-publications/search", params={"q": "双栈商品"})
            self.assertEqual(resp.status_code, 200, resp.text)
            self.assertEqual(len(resp.json()["results"]), 1)
            # 公开商家主页（FastAPI 栈 HTML 响应）
            resp = client.get(f"/m/{merchant_id}")
            self.assertEqual(resp.status_code, 200, resp.text)
            self.assertIn("text/html", resp.headers.get("content-type", ""))
            self.assertIn("fastapi 双栈商品", resp.text)
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
