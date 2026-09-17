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

"""买家主动订阅（M4：MerchantPublicEvent + BuyerFollow）集成测试。

覆盖（对应任务验收用例）：
- 发布/更新/撤回产生对应事件，version 按商家单调递增（不同商家各自递增）；
- 草稿保存等内部操作不产生公开事件；仅 FAQ 变化产生 faq_updated；
- 关注幂等（重复关注不产生重复记录，可更新 category/consent_version）；
- 取消后不再收到更新；重新关注水位重置（不补历史）；
- updates 只返回 last_seen_at 之后的事件，不丢不重（同秒多事件）；
- 类目过滤：不匹配的事件不投递也不重复扫描；
- 买家 A 看不到买家 B 的关注；未登录不能关注/取消/拉取；
- 商家只能看到匿名汇总数字（stats 接口不含任何买家身份），浏览计数只计
  非本人浏览；
- 关注/取消限流；审计事件落表；双栈 parity。
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


class BuyerFollowsApiTest(unittest.TestCase):
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
        # 商家 A/B（发布方）与买家 C/D（关注方——任何已登录账号都可作买家）
        self.cookie_a = _register_and_login(self.app, "a@acme.example", "Acme 商贸")
        self.cookie_b = _register_and_login(self.app, "b@rival.example", "Rival 商行")
        self.cookie_c = _register_and_login(self.app, "c@buyer.example", "买家 C")
        self.cookie_d = _register_and_login(self.app, "d@buyer.example", "买家 D")
        self.merchant_a = self._merchant_id(self.cookie_a)
        self.merchant_b = self._merchant_id(self.cookie_b)

    def _merchant_id(self, cookie: str) -> str:
        status, payload, _ = _call_http(self.app, "GET", "/v1/accounts/me", cookie=cookie)
        assert status == 200, payload
        return str(payload["merchant_id"])

    def _account_id(self, cookie: str) -> int:
        status, payload, _ = _call_http(self.app, "GET", "/v1/accounts/me", cookie=cookie)
        assert status == 200, payload
        return int(payload["account_id"])

    def _publish(self, cookie: str, title: str, **overrides) -> tuple[int, dict]:
        body = {
            "action": "publish",
            "merchant_display_name": "Acme 商贸",
            "title": title,
            "category": "茶叶",
            "summary": "公开简介",
        }
        body.update(overrides)
        return self._raw("POST", "/v1/merchant-publications", body, cookie)

    def _save_draft(self, cookie: str, title: str, **overrides) -> tuple[int, dict]:
        body = {
            "action": "draft",
            "merchant_display_name": "Acme 商贸",
            "title": title,
        }
        body.update(overrides)
        return self._raw("POST", "/v1/merchant-publications", body, cookie)

    def _withdraw(self, cookie: str, publication_id: str) -> tuple[int, dict]:
        return self._raw(
            "POST", f"/v1/merchant-publications/{publication_id}/withdraw", {}, cookie
        )

    def _raw(self, method: str, path: str, body: dict, cookie: str) -> tuple[int, dict]:
        status, payload, _ = _call_http(
            self.app, method, path, json.dumps(body).encode(), cookie=cookie
        )
        return status, payload

    def _follow(
        self, cookie: str, merchant_id: str, **body
    ) -> tuple[int, dict]:
        return self._raw("PUT", f"/v1/me/follows/{merchant_id}", body, cookie)

    def _unfollow(self, cookie: str, merchant_id: str) -> tuple[int, dict]:
        return self._raw("DELETE", f"/v1/me/follows/{merchant_id}", {}, cookie)

    def _list_follows(self, cookie: str) -> tuple[int, dict]:
        status, payload, _ = _call_http(self.app, "GET", "/v1/me/follows", cookie=cookie)
        return status, payload

    def _updates(self, cookie: str) -> tuple[int, dict]:
        status, payload, _ = _call_http(
            self.app, "GET", "/v1/me/follows/updates", cookie=cookie
        )
        return status, payload

    def _stats(self, cookie: str) -> tuple[int, dict]:
        status, payload, _ = _call_http(
            self.app, "GET", "/v1/merchant-publications/stats", cookie=cookie
        )
        return status, payload

    def _events(self, merchant_id: str) -> list[dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "select event_type, version, publication_id, created_at"
                " from merchant_public_events where merchant_id = ? order by version",
                (merchant_id,),
            ).fetchall()
        finally:
            conn.close()
        return [dict(r) for r in rows]

    def _audit_events(self) -> list[str]:
        conn = sqlite3.connect(self.db_path)
        try:
            rows = conn.execute("select event from audit_events").fetchall()
        finally:
            conn.close()
        return [r[0] for r in rows]

    # ── 认证 ────────────────────────────────────────────────────────────────

    def test_unauthenticated_cannot_follow_or_pull(self) -> None:
        status, _ = self._follow("", self.merchant_a)
        self.assertEqual(status, 403)
        status, _ = self._unfollow("", self.merchant_a)
        self.assertEqual(status, 403)
        status, _ = self._list_follows("")
        self.assertEqual(status, 403)
        status, _ = self._updates("")
        self.assertEqual(status, 403)
        status, _ = self._stats("")
        self.assertEqual(status, 403)

    def test_follow_unknown_merchant_404(self) -> None:
        status, payload = self._follow(self.cookie_c, "mkt_missing")
        self.assertEqual(status, 404, payload)

    # ── 事件生成与版本递增 ──────────────────────────────────────────────────

    def test_publish_update_withdraw_generate_events_per_merchant_version(self) -> None:
        status, payload = self._publish(self.cookie_a, "明前龙井")
        self.assertEqual(status, 200, payload)
        publication_id = payload["publication"]["publication_id"]
        # 更新（summary 变化）→ product_updated
        status, _ = self._publish(self.cookie_a, "明前龙井", summary="新简介")
        self.assertEqual(status, 200)
        # 撤回 → publication_withdrawn
        status, _ = self._withdraw(self.cookie_a, publication_id)
        self.assertEqual(status, 200)
        events = self._events(self.merchant_a)
        self.assertEqual(
            [e["event_type"] for e in events],
            ["product_added", "product_updated", "publication_withdrawn"],
        )
        self.assertEqual([e["version"] for e in events], [1, 2, 3])
        # created_at 严格递增（水位不丢不重的前提）
        created = [e["created_at"] for e in events]
        self.assertEqual(created, sorted(created))
        self.assertEqual(len(set(created)), 3)
        # 事件 payload 只含公开字段（复用 M0 公开投影）
        conn = sqlite3.connect(self.db_path)
        try:
            payload_json = conn.execute(
                "select payload_json from merchant_public_events where merchant_id = ?"
                " and version = 1",
                (self.merchant_a,),
            ).fetchone()[0]
        finally:
            conn.close()
        event_payload = json.loads(payload_json)
        self.assertEqual(event_payload["title"], "明前龙井")
        self.assertIs(event_payload["inquiry_available"], False)
        for forbidden in ("phone", "email", "password", "wechat", "account_id"):
            self.assertNotIn(forbidden, event_payload)
        # 另一个商家的版本序列独立从 1 开始
        status, _ = self._publish(self.cookie_b, " rival 商品 ")
        self.assertEqual(status, 200)
        b_events = self._events(self.merchant_b)
        self.assertEqual([e["version"] for e in b_events], [1])

    def test_faq_only_change_generates_faq_updated(self) -> None:
        status, _ = self._publish(self.cookie_a, "FAQ 商品")
        self.assertEqual(status, 200)
        status, _ = self._publish(
            self.cookie_a,
            "FAQ 商品",
            faq=[{"question": "保修多久", "answer": "一年"}],
        )
        self.assertEqual(status, 200)
        events = self._events(self.merchant_a)
        self.assertEqual(
            [e["event_type"] for e in events], ["product_added", "faq_updated"]
        )

    def test_internal_ops_do_not_generate_public_events(self) -> None:
        """草稿保存/草稿更新是内部操作，不进入公开事件流。"""
        status, _ = self._save_draft(self.cookie_a, "内部草稿商品")
        self.assertEqual(status, 200)
        status, _ = self._save_draft(self.cookie_a, "内部草稿商品", category="茶叶")
        self.assertEqual(status, 200)
        self.assertEqual(self._events(self.merchant_a), [])
        # 买家此时关注并拉取：无任何事件
        status, _ = self._follow(self.cookie_c, self.merchant_a)
        self.assertEqual(status, 200)
        status, payload = self._updates(self.cookie_c)
        self.assertEqual(payload["updates"], [])

    # ── 关注幂等 / 取消 / 重新关注 ─────────────────────────────────────────

    def test_follow_is_idempotent_and_updates_category(self) -> None:
        status, payload = self._follow(self.cookie_c, self.merchant_a)
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["created"])
        status, payload = self._follow(
            self.cookie_c, self.merchant_a, category="茶叶", consent_version="v1"
        )
        self.assertEqual(status, 200, payload)
        self.assertFalse(payload["created"])
        self.assertEqual(payload["follow"]["category"], "茶叶")
        self.assertEqual(payload["follow"]["consent_version"], "v1")
        # 不产生重复记录
        status, payload = self._list_follows(self.cookie_c)
        self.assertEqual(len(payload["follows"]), 1)
        self.assertIn("buyer_followed", self._audit_events())

    def test_unfollow_stops_updates_and_audit(self) -> None:
        status, _ = self._publish(self.cookie_a, "取消关注用商品")
        self.assertEqual(status, 200)
        status, _ = self._follow(self.cookie_c, self.merchant_a)
        self.assertEqual(status, 200)
        status, payload = self._unfollow(self.cookie_c, self.merchant_a)
        self.assertEqual(status, 200, payload)
        self.assertFalse(payload["following"])
        # 取消后新事件不再出现在更新里
        status, _ = self._publish(self.cookie_a, "取消后的新商品")
        self.assertEqual(status, 200)
        status, payload = self._updates(self.cookie_c)
        self.assertEqual(payload["updates"], [])
        # 关注列表也不再展示
        status, payload = self._list_follows(self.cookie_c)
        self.assertEqual(payload["follows"], [])
        self.assertIn("buyer_unfollowed", self._audit_events())
        # 幂等：重复取消同样 ok
        status, payload = self._unfollow(self.cookie_c, self.merchant_a)
        self.assertEqual(status, 200, payload)

    def test_refollow_resets_watermark(self) -> None:
        """取消后重新关注：水位重置到重新关注时刻，不补取消期间的历史。"""
        status, _ = self._follow(self.cookie_c, self.merchant_a)
        self.assertEqual(status, 200)
        status, _ = self._publish(self.cookie_a, "关注期商品一")
        self.assertEqual(status, 200)
        status, _ = self._unfollow(self.cookie_c, self.merchant_a)
        self.assertEqual(status, 200)
        status, _ = self._follow(self.cookie_c, self.merchant_a)
        self.assertEqual(status, 200)
        status, payload = self._updates(self.cookie_c)
        self.assertEqual(payload["updates"], [])
        # 重新关注后的新事件正常到达
        status, _ = self._publish(self.cookie_a, "关注期商品二")
        self.assertEqual(status, 200)
        status, payload = self._updates(self.cookie_c)
        titles = [
            e["payload"]["title"] for m in payload["updates"] for e in m["events"]
        ]
        self.assertEqual(titles, ["关注期商品二"])

    # ── 增量拉取：不丢不重 ──────────────────────────────────────────────────

    def test_updates_incremental_no_loss_no_dup(self) -> None:
        status, _ = self._follow(self.cookie_c, self.merchant_a)
        self.assertEqual(status, 200)
        # 同秒连续发布多个事件（考验水位精度）
        for title in ("增量商品一", "增量商品二", "增量商品三"):
            status, _ = self._publish(self.cookie_a, title)
            self.assertEqual(status, 200)
        status, payload = self._updates(self.cookie_c)
        self.assertEqual(status, 200, payload)
        self.assertEqual(len(payload["updates"]), 1)
        block = payload["updates"][0]
        self.assertEqual(block["merchant_id"], self.merchant_a)
        self.assertEqual(
            [e["payload"]["title"] for e in block["events"]],
            ["增量商品一", "增量商品二", "增量商品三"],
        )
        self.assertEqual([e["version"] for e in block["events"]], [1, 2, 3])
        # 再拉：空（不重）
        status, payload = self._updates(self.cookie_c)
        self.assertEqual(payload["updates"], [])
        # 新事件继续到达且只有新事件（不丢）
        status, _ = self._publish(self.cookie_a, "增量商品四")
        self.assertEqual(status, 200)
        status, payload = self._updates(self.cookie_c)
        self.assertEqual(
            [e["payload"]["title"] for m in payload["updates"] for e in m["events"]],
            ["增量商品四"],
        )

    def test_category_filter_scopes_updates(self) -> None:
        status, _ = self._follow(self.cookie_c, self.merchant_a, category="茶叶")
        self.assertEqual(status, 200)
        status, _ = self._publish(self.cookie_a, "茶叶商品", category="茶叶")
        self.assertEqual(status, 200)
        status, _ = self._publish(self.cookie_a, "咖啡商品", category="咖啡")
        self.assertEqual(status, 200)
        status, payload = self._updates(self.cookie_c)
        titles = [e["payload"]["title"] for m in payload["updates"] for e in m["events"]]
        self.assertEqual(titles, ["茶叶商品"])
        # 不匹配的事件随水位越过：下次拉取不重复出现
        status, payload = self._updates(self.cookie_c)
        self.assertEqual(payload["updates"], [])

    # ── 买家隔离 ────────────────────────────────────────────────────────────

    def test_buyers_are_isolated(self) -> None:
        status, _ = self._follow(self.cookie_c, self.merchant_a)
        self.assertEqual(status, 200)
        status, _ = self._follow(self.cookie_d, self.merchant_b)
        self.assertEqual(status, 200)
        status, payload = self._list_follows(self.cookie_c)
        self.assertEqual(
            [f["merchant_id"] for f in payload["follows"]], [self.merchant_a]
        )
        status, payload = self._list_follows(self.cookie_d)
        self.assertEqual(
            [f["merchant_id"] for f in payload["follows"]], [self.merchant_b]
        )
        # 买家 C 的更新只来自自己关注的商家
        status, _ = self._publish(self.cookie_b, "Rival 新品")
        self.assertEqual(status, 200)
        status, payload = self._updates(self.cookie_c)
        self.assertEqual(payload["updates"], [])

    # ── 商家匿名汇总 ────────────────────────────────────────────────────────

    def test_merchant_stats_are_anonymous_aggregate_only(self) -> None:
        status, payload = self._publish(self.cookie_a, "汇总商品")
        self.assertEqual(status, 200)
        publication_id = payload["publication"]["publication_id"]
        status, _ = self._follow(self.cookie_c, self.merchant_a)
        self.assertEqual(status, 200)
        status, _ = self._follow(self.cookie_d, self.merchant_a)
        self.assertEqual(status, 200)
        # 匿名浏览公开详情 → 计数；商家本人查看 → 不计
        status, _, _ = _call_http(
            self.app, "GET", f"/v1/merchant-publications/{publication_id}"
        )
        self.assertEqual(status, 200)
        status, _, _ = _call_http(
            self.app, "GET", f"/v1/merchant-publications/{publication_id}", cookie=self.cookie_c
        )
        self.assertEqual(status, 200)
        status, _, _ = _call_http(
            self.app, "GET", f"/v1/merchant-publications/{publication_id}", cookie=self.cookie_a
        )
        self.assertEqual(status, 200)
        status, payload = self._stats(self.cookie_a)
        self.assertEqual(status, 200, payload)
        stats = payload["stats"]
        self.assertEqual(stats["merchant_id"], self.merchant_a)
        self.assertEqual(stats["followers_total"], 2)
        self.assertEqual(stats["views_total"], 2)
        self.assertEqual(stats["publications"][0]["view_count"], 2)
        # 接口不返回任何买家身份
        raw = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("buyer_subject", raw)
        self.assertNotIn(f"account:{self._account_id(self.cookie_c)}", raw)
        self.assertNotIn(f"account:{self._account_id(self.cookie_d)}", raw)
        self.assertNotIn("c@buyer.example", raw)
        # 另一个商家只能看到自己的汇总（看不到 A 的关注数）
        status, payload = self._stats(self.cookie_b)
        self.assertEqual(payload["stats"]["followers_total"], 0)
        # 取消后汇总数字随之减一
        status, _ = self._unfollow(self.cookie_c, self.merchant_a)
        self.assertEqual(status, 200)
        status, payload = self._stats(self.cookie_a)
        self.assertEqual(payload["stats"]["followers_total"], 1)

    # ── 限流 ────────────────────────────────────────────────────────────────

    def test_follow_rate_limit(self) -> None:
        with mock.patch.dict(
            os.environ, {"KIWI_CATALOG_FOLLOW_RATE_LIMIT_PER_15MIN": "2"}, clear=False
        ):
            status, _ = self._follow(self.cookie_c, self.merchant_a)
            self.assertEqual(status, 200)
            status, _ = self._follow(self.cookie_c, self.merchant_b)
            self.assertEqual(status, 200)
            status, _ = self._unfollow(self.cookie_c, self.merchant_a)
            self.assertEqual(status, 429)

    def test_client_supplied_buyer_subject_is_ignored(self) -> None:
        """buyer_subject 一律取自服务端会话：客户端伪造无效。"""
        status, payload = self._follow(
            self.cookie_c, self.merchant_a, buyer_subject="account:1"
        )
        self.assertEqual(status, 200, payload)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute("select buyer_subject from buyer_follows").fetchall()
        finally:
            conn.close()
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0]["buyer_subject"], f"account:{self._account_id(self.cookie_c)}"
        )


class BuyerFollowsFallbackStackTest(unittest.TestCase):
    """fallback 栈端到端冒烟（关注 → 拉取 → 取消闭环）。"""

    def test_follow_and_updates_on_fallback_stack(self) -> None:
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
            cookie_m = _register_and_login(app, "fb-m@acme.example", "Fallback 商贸")
            cookie_b = _register_and_login(app, "fb-b@buyer.example", "Fallback 买家")
            status, payload, _ = _call_http(app, "GET", "/v1/accounts/me", cookie=cookie_m)
            merchant_id = str(payload["merchant_id"])
            status, payload, _ = _call_http(
                app, "PUT", f"/v1/me/follows/{merchant_id}", b"{}", cookie=cookie_b
            )
            self.assertEqual(status, 200, payload)
            self.assertTrue(payload["created"])
            status, payload, _ = _call_http(
                app,
                "POST",
                "/v1/merchant-publications",
                json.dumps(
                    {
                        "action": "publish",
                        "merchant_display_name": "Fallback 商贸",
                        "title": "fallback 订阅商品",
                    }
                ).encode(),
                cookie=cookie_m,
            )
            self.assertEqual(status, 200, payload)
            status, payload, _ = _call_http(
                app, "GET", "/v1/me/follows/updates", cookie=cookie_b
            )
            self.assertEqual(status, 200, payload)
            self.assertEqual(len(payload["updates"]), 1)
            self.assertEqual(payload["updates"][0]["events"][0]["event_type"], "product_added")
            status, payload, _ = _call_http(
                app, "DELETE", f"/v1/me/follows/{merchant_id}", b"{}", cookie=cookie_b
            )
            self.assertEqual(status, 200, payload)
            # 门户买家关注页（fallback HTML）
            status, payload, _ = _call_http(app, "GET", "/portal/follows")
            self.assertEqual(status, 200)
            self.assertIn("我的关注", payload["_raw"])


@unittest.skipUnless(app_module.FastAPI is not None, "fastapi not installed")
class BuyerFollowsFastApiTest(unittest.TestCase):
    """FastAPI 栈：新路由注册 + 会话 cookie 透传 + 关注/拉取/取消闭环。"""

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
            "/v1/me/follows",
            "/v1/me/follows/updates",
            "/v1/me/follows/{merchant_id}",
            "/v1/merchant-publications/stats",
            "/portal/follows",
        ):
            self.assertIn(expected, fastapi_paths)

        with TestClient(self.app) as client:
            def register(email: str, name: str) -> str:
                resp = client.post(
                    "/v1/accounts/register",
                    json={
                        "merchant_name": name,
                        "email": email,
                        "password": "strong-pw-123",
                        "phone": "+86 138 0000 0000",
                    },
                )
                self.assertEqual(resp.status_code, 200, resp.text)
                code = resp.json()["verification_code"]
                resp = client.post(
                    "/v1/accounts/verify-email", json={"email": email, "code": code}
                )
                self.assertEqual(resp.status_code, 200, resp.text)
                return resp.headers["set-cookie"].split(";")[0]

            cookie_m = register("fa-m@acme.example", "FastAPI 商贸")
            cookie_b = register("fa-b@buyer.example", "FastAPI 买家")
            merchant_id = client.get(
                "/v1/accounts/me", headers={"cookie": cookie_m}
            ).json()["merchant_id"]
            # 未登录关注 → 403
            resp = client.put(f"/v1/me/follows/{merchant_id}", json={})
            self.assertEqual(resp.status_code, 403, resp.text)
            # 关注 → 发布 → 拉取 → 统计 → 取消
            resp = client.put(
                f"/v1/me/follows/{merchant_id}", json={}, headers={"cookie": cookie_b}
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            resp = client.post(
                "/v1/merchant-publications",
                json={
                    "action": "publish",
                    "merchant_display_name": "FastAPI 商贸",
                    "title": "fastapi 订阅商品",
                },
                headers={"cookie": cookie_m},
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            resp = client.get("/v1/me/follows/updates", headers={"cookie": cookie_b})
            self.assertEqual(resp.status_code, 200, resp.text)
            self.assertEqual(len(resp.json()["updates"]), 1)
            resp = client.get(
                "/v1/merchant-publications/stats", headers={"cookie": cookie_m}
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            self.assertEqual(resp.json()["stats"]["followers_total"], 1)
            resp = client.delete(
                f"/v1/me/follows/{merchant_id}", headers={"cookie": cookie_b}
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            resp = client.get("/portal/follows")
            self.assertEqual(resp.status_code, 200, resp.text)
            self.assertIn("我的关注", resp.text)


if __name__ == "__main__":
    unittest.main()
