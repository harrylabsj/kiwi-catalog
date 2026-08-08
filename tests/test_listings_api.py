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

"""Listing publish/withdraw/reinstate API 集成测试（升级计划 §11；v0.4 §13）。

覆盖：
- owner token 校验（错误/缺失 token 拒绝）；
- 行级幂等 upsert：同 source_product_ref 更新而非新建；同内容重发不重复；
- 请求级幂等：同 idempotency_key 同内容 → replay；同 key 不同内容 → 409；
- capability 缺 publisher_listing_key → 每次新建（id 幂等语义）；
- withdraw / reinstate 生命周期（reinstate 仅 SUSPENDED）；
- agent suspend → owned Listings 置 SUSPENDED（DoD #12 联动）+ 搜索排除；
- 私有字段永不进入序列化输出（wire 形状）。
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from unittest import mock

from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.api.auth import owner_token
from kiwi_catalog.db.session import db_session

OWNER_SECRET = "test-owner-secret"
MERCHANT_ID = "mrc_01JABC"

REGISTER_BODY = {
    "domain": "acme.example",
    "display_name": "Acme Merchant",
    "agent_card_url": "https://acme.example/.well-known/agent-card.json",
    "hosting_mode": "direct_only",
    "handoff_destination_types": ["external_checkout_url"],
}

PRODUCT_PAYLOAD = {
    "listing_type": "product",
    "owner_agent_id": "CAGT_PLACEHOLDER",
    "merchant_id": MERCHANT_ID,
    "source_product_ref": "SKU-001",
    "title": "21.5 inch Industrial Touch Display",
    "category": "industrial-display",
    "brand": "Example Display Co.",
    "attributes": {"screen_size": "21.5"},
    "regions": ["CN"],
    "tags": ["touch"],
    "commercial_hints": {"moq": 50, "supports_bulk_quote": True},
    "handoff_destination_types": ["external_checkout_url"],
}


def _call_http(app, method: str, path: str, body: bytes = b"") -> tuple[int, dict]:
    path_only = path.split("?", 1)[0]
    query_bytes = path.split("?", 1)[1].encode() if "?" in path else b""
    scope = {
        "type": "http",
        "method": method,
        "path": path_only,
        "headers": [(b"content-type", b"application/json")],
        "query_string": query_bytes,
        "http_version": "1.1",
        "scheme": "http",
    }
    sent = {"body": body}
    received: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": sent["body"], "more_body": False}

    async def send(msg: dict) -> None:
        received.append(msg)

    async def run():
        await app(scope, receive, send)

    asyncio.run(run())
    status = next((m.get("status") for m in received if m["type"] == "http.response.start"), None)
    chunks = b"".join(m.get("body", b"") for m in received if m["type"] == "http.response.body")
    payload: dict = {}
    if chunks:
        payload = json.loads(chunks.decode())
    return status or 500, payload


class ListingsApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "catalog.sqlite")
        env_patch = mock.patch.dict(
            os.environ,
            {"KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET},
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.app = create_catalog_app(self.db_path)
        self.token = owner_token(MERCHANT_ID)
        self.agent_id = self._register_agent()

    def _register_agent(self) -> str:
        body = {**REGISTER_BODY, "merchant_id": MERCHANT_ID, "owner_token": self.token}
        status, payload = _call_http(
            self.app, "POST", "/v1/agents/register", json.dumps(body).encode()
        )
        self.assertEqual(status, 200, payload)
        return payload["agent"]["catalog_agent_id"]

    def _publish(self, overrides: dict | None = None, token: str | None = None) -> tuple[int, dict]:
        body = {
            **PRODUCT_PAYLOAD,
            "owner_agent_id": self.agent_id,
            "owner_token": self.token if token is None else token,
            **(overrides or {}),
        }
        return _call_http(self.app, "POST", "/v1/listings/publish", json.dumps(body).encode())

    # ── publish ─────────────────────────────────────────────────────────────

    def test_publish_creates_listing_with_wire_shape(self) -> None:
        status, payload = self._publish()
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["created"])
        listing = payload["listing"]
        self.assertTrue(listing["listing_id"].startswith("lst_"))
        self.assertEqual(listing["owner_agent_id"], self.agent_id)
        self.assertEqual(listing["source_product_ref"], "SKU-001")
        self.assertEqual(listing["publication_state"], "ACTIVE")
        self.assertEqual(listing["listing_freshness_state"], "FRESH")
        self.assertIn("listing_digest", listing)
        self.assertNotIn("floor_price", listing)
        self.assertNotIn("cost", listing)

    def test_publish_requires_owner_token(self) -> None:
        status, payload = self._publish(token="")
        self.assertEqual(status, 403, payload)
        status, payload = self._publish(token="wrong-token")
        self.assertEqual(status, 403, payload)

    def test_publish_unknown_owner_agent_rejected(self) -> None:
        status, payload = self._publish({"owner_agent_id": "cagt_unknown"})
        self.assertEqual(status, 404, payload)

    def test_same_source_ref_upserts_not_duplicates(self) -> None:
        _, first = self._publish()
        listing_id = first["listing"]["listing_id"]
        status, second = self._publish({"title": "Updated title"})
        self.assertEqual(status, 200, second)
        self.assertFalse(second["created"])
        self.assertEqual(second["listing"]["listing_id"], listing_id)
        self.assertEqual(second["listing"]["title"], "Updated title")
        # 库中只有一行
        with db_session(self.db_path) as conn:
            count = conn.execute("select count(*) from commerce_listings").fetchone()[0]
        self.assertEqual(count, 1)

    def test_capability_without_publisher_key_creates_new_rows(self) -> None:
        body = {
            "listing_type": "capability",
            "owner_agent_id": self.agent_id,
            "merchant_id": MERCHANT_ID,
            "title": "Touch Display Manufacturing",
            "category": "industrial-manufacturing",
            "owner_token": self.token,
        }
        status, first = _call_http(self.app, "POST", "/v1/listings/publish", json.dumps(body).encode())
        self.assertEqual(status, 200, first)
        status, second = _call_http(self.app, "POST", "/v1/listings/publish", json.dumps(body).encode())
        self.assertEqual(status, 200, second)
        self.assertNotEqual(first["listing"]["listing_id"], second["listing"]["listing_id"])

    def test_capability_with_publisher_key_upserts(self) -> None:
        body = {
            "listing_type": "capability",
            "owner_agent_id": self.agent_id,
            "merchant_id": MERCHANT_ID,
            "publisher_listing_key": "touch-mfg",
            "title": "Touch Display Manufacturing",
            "category": "industrial-manufacturing",
            "owner_token": self.token,
        }
        _, first = _call_http(self.app, "POST", "/v1/listings/publish", json.dumps(body).encode())
        status, second = _call_http(self.app, "POST", "/v1/listings/publish", json.dumps(body).encode())
        self.assertEqual(status, 200, second)
        self.assertEqual(first["listing"]["listing_id"], second["listing"]["listing_id"])

    # ── request-level idempotency ───────────────────────────────────────────

    def test_idempotency_key_replay_same_content(self) -> None:
        body = {**PRODUCT_PAYLOAD, "owner_agent_id": self.agent_id, "owner_token": self.token, "idempotency_key": "idem-1"}
        status, first = _call_http(self.app, "POST", "/v1/listings/publish", json.dumps(body).encode())
        self.assertEqual(status, 200, first)
        status, second = _call_http(self.app, "POST", "/v1/listings/publish", json.dumps(body).encode())
        self.assertEqual(status, 200, second)
        self.assertTrue(second["idempotent"])
        self.assertEqual(first["listing"]["listing_id"], second["listing"]["listing_id"])

    def test_idempotency_key_reused_with_different_content_conflicts(self) -> None:
        body = {**PRODUCT_PAYLOAD, "owner_agent_id": self.agent_id, "owner_token": self.token, "idempotency_key": "idem-2"}
        status, _ = _call_http(self.app, "POST", "/v1/listings/publish", json.dumps(body).encode())
        self.assertEqual(status, 200)
        body2 = {**PRODUCT_PAYLOAD, "owner_agent_id": self.agent_id, "title": "Different", "owner_token": self.token, "idempotency_key": "idem-2"}
        status, payload = _call_http(self.app, "POST", "/v1/listings/publish", json.dumps(body2).encode())
        self.assertEqual(status, 409, payload)

    def test_idempotency_key_isolated_per_owner(self) -> None:
        """跨商户幂等键隔离：商户 B 复用商户 A 的 key 发布不同内容不得 409
        （历史教训：匿名 actor 桶让合法写被其他商户的 key squat 永久打掉）。"""
        other_merchant = "mrc_OTHER"
        other_token = owner_token(other_merchant)
        body = {
            **REGISTER_BODY,
            "domain": "other.example",
            "display_name": "Other Merchant",
            "merchant_id": other_merchant,
            "owner_token": other_token,
        }
        status, payload = _call_http(self.app, "POST", "/v1/agents/register", json.dumps(body).encode())
        self.assertEqual(status, 200, payload)
        other_agent = payload["agent"]["catalog_agent_id"]

        # 商户 A 用 key "shared-key" 发布
        body_a = {
            **PRODUCT_PAYLOAD,
            "owner_agent_id": self.agent_id,
            "owner_token": self.token,
            "idempotency_key": "shared-key",
        }
        status, _ = _call_http(self.app, "POST", "/v1/listings/publish", json.dumps(body_a).encode())
        self.assertEqual(status, 200)
        # 商户 B 同 key、不同内容 → 必须成功（不同 actor 桶）
        body_b = {
            **PRODUCT_PAYLOAD,
            "owner_agent_id": other_agent,
            "merchant_id": other_merchant,
            "source_product_ref": "SKU-B",
            "title": "Other Item",
            "owner_token": other_token,
            "idempotency_key": "shared-key",
        }
        status, payload = _call_http(self.app, "POST", "/v1/listings/publish", json.dumps(body_b).encode())
        self.assertEqual(status, 200, payload)
        # 商户 B 同 key、同内容 → 幂等重放
        status, replay = _call_http(self.app, "POST", "/v1/listings/publish", json.dumps(body_b).encode())
        self.assertEqual(status, 200, replay)
        self.assertTrue(replay["idempotent"])

    def test_unauthenticated_spam_does_not_consume_rate_limit(self) -> None:
        """认证先于限流：无 token 请求 403 且不消耗写预算（历史教训：匿名桶
        被未认证 spam 耗尽后全体商户写 429）。"""
        with mock.patch.dict(
            os.environ, {"KIWI_CATALOG_WRITE_RATE_LIMIT_PER_MINUTE": "2"}, clear=False
        ):
            for _ in range(2):
                status, payload = _call_http(
                    self.app,
                    "POST",
                    "/v1/listings/publish",
                    json.dumps({**PRODUCT_PAYLOAD, "owner_agent_id": self.agent_id}).encode(),
                )
                self.assertEqual(status, 403, payload)
            # 预算未被 spam 消耗：合法发布仍成功
            status, payload = self._publish()
            self.assertEqual(status, 200, payload)

    # ── withdraw / reinstate ────────────────────────────────────────────────

    def test_withdraw_and_reinstate_flow(self) -> None:
        _, published = self._publish()
        listing_id = published["listing"]["listing_id"]
        status, payload = _call_http(
            self.app,
            "POST",
            f"/v1/listings/{listing_id}/withdraw",
            json.dumps({"owner_token": self.token}).encode(),
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["listing"]["publication_state"], "WITHDRAWN")
        # reinstate 只允许 SUSPENDED；WITHDRAWN 拒绝（PermissionDenied → 403）
        status, payload = _call_http(
            self.app,
            "POST",
            f"/v1/listings/{listing_id}/reinstate",
            json.dumps({"owner_token": self.token}).encode(),
        )
        self.assertEqual(status, 403, payload)

    def test_withdraw_requires_owner_token(self) -> None:
        _, published = self._publish()
        listing_id = published["listing"]["listing_id"]
        status, payload = _call_http(
            self.app,
            "POST",
            f"/v1/listings/{listing_id}/withdraw",
            json.dumps({}).encode(),
        )
        self.assertEqual(status, 403, payload)

    def test_withdraw_other_merchants_listing_rejected(self) -> None:
        other_merchant = "mrc_OTHER"
        other_token = owner_token(other_merchant)
        # 第二个 agent 属于 other merchant
        body = {
            **REGISTER_BODY,
            "domain": "other.example",
            "display_name": "Other Merchant",
            "merchant_id": other_merchant,
            "owner_token": other_token,
        }
        status, payload = _call_http(self.app, "POST", "/v1/agents/register", json.dumps(body).encode())
        self.assertEqual(status, 200, payload)
        _, published = self._publish()
        listing_id = published["listing"]["listing_id"]
        status, payload = _call_http(
            self.app,
            "POST",
            f"/v1/listings/{listing_id}/withdraw",
            json.dumps({"owner_token": other_token}).encode(),
        )
        self.assertEqual(status, 403, payload)

    # ── agent governance linkage (DoD #12) ─────────────────────────────────

    def test_agent_suspend_marks_owned_listings_suspended(self) -> None:
        self._publish()
        self._publish({"source_product_ref": "SKU-002", "title": "Second"})
        from kiwi_catalog.api.auth import configured_admin_token

        with mock.patch.dict(os.environ, {"KIWI_CATALOG_ADMIN_TOKEN": "admin-tok"}):
            status, payload = _call_http(
                self.app,
                "POST",
                f"/v1/agent-catalog/agents/{self.agent_id}/suspend",
                json.dumps({"admin_token": "admin-tok", "reason": "test"}).encode(),
            )
        self.assertEqual(status, 200, payload)
        with db_session(self.db_path) as conn:
            rows = conn.execute(
                "select listing_id, publication_state from commerce_listings"
            ).fetchall()
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(row["publication_state"], "SUSPENDED")
        # 搜索不再返回（suppress 半边）
        status, payload = _call_http(self.app, "GET", "/v1/listings/search")
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["results"], [])

    def test_agent_reinstate_does_not_auto_restore_listings(self) -> None:
        self.test_agent_suspend_marks_owned_listings_suspended()
        with mock.patch.dict(os.environ, {"KIWI_CATALOG_ADMIN_TOKEN": "admin-tok"}):
            status, payload = _call_http(
                self.app,
                "POST",
                f"/v1/agent-catalog/agents/{self.agent_id}/reinstate",
                json.dumps({"admin_token": "admin-tok"}).encode(),
            )
        self.assertEqual(status, 200, payload)
        with db_session(self.db_path) as conn:
            states = [
                row["publication_state"]
                for row in conn.execute("select publication_state from commerce_listings").fetchall()
            ]
        self.assertEqual(states, ["SUSPENDED", "SUSPENDED"])

    def test_publisher_can_reinstate_suspended_listing(self) -> None:
        self._publish()
        from kiwi_catalog.api.auth import configured_admin_token

        with mock.patch.dict(os.environ, {"KIWI_CATALOG_ADMIN_TOKEN": "admin-tok"}):
            _call_http(
                self.app,
                "POST",
                f"/v1/agent-catalog/agents/{self.agent_id}/suspend",
                json.dumps({"admin_token": "admin-tok", "reason": "test"}).encode(),
            )
            _call_http(
                self.app,
                "POST",
                f"/v1/agent-catalog/agents/{self.agent_id}/reinstate",
                json.dumps({"admin_token": "admin-tok"}).encode(),
            )
        with db_session(self.db_path) as conn:
            listing_id = conn.execute("select listing_id from commerce_listings").fetchone()[0]
        status, payload = _call_http(
            self.app,
            "POST",
            f"/v1/listings/{listing_id}/reinstate",
            json.dumps({"owner_token": self.token}).encode(),
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["listing"]["publication_state"], "ACTIVE")

    # ── publisher self-check ────────────────────────────────────────────────

    def test_list_agent_listings_requires_owner_token(self) -> None:
        """自查接口必须认证：无 token 不得枚举任意 agent 的 listing。"""
        self._publish()
        status, payload = _call_http(self.app, "GET", f"/v1/agents/{self.agent_id}/listings")
        self.assertEqual(status, 403, payload)
        # 审查 P3：认证失败文案统一模糊（不区分缺失/无效/未配置）
        self.assertIn("invalid owner token", payload.get("error", ""))

    def test_list_agent_listings_wrong_owner_rejected(self) -> None:
        self._publish()
        other = owner_token("other-merchant")
        status, payload = _call_http(
            self.app, "GET", f"/v1/agents/{self.agent_id}/listings?owner_token={other}"
        )
        self.assertEqual(status, 403, payload)
        self.assertIn("invalid owner token", payload.get("error", ""))

    def test_list_agent_listings_admin_exempt_for_bound_agent(self) -> None:
        """审查 P2：已绑定 merchant 的 agent 自查，admin token 必须豁免
        （此前只走 owner HMAC 校验，admin 恒 403——与 withdraw/reinstate 不一致）。"""
        self._publish()
        with mock.patch.dict(os.environ, {"KIWI_CATALOG_ADMIN_TOKEN": "admin-tok"}):
            status, payload = _call_http(
                self.app,
                "GET",
                f"/v1/agents/{self.agent_id}/listings?admin_token=admin-tok",
            )
        self.assertEqual(status, 200, payload)

    def test_list_agent_listings_unbound_agent_admin_only(self) -> None:
        """未绑定 merchant 的 agent 无 owner 可归属：仅 admin 可读（含治理状态面）。"""
        body = {
            **REGISTER_BODY,
            "domain": "unbound.example",  # 独立 domain：注册接口按 domain 去重
            "owner_token": self.token,
        }
        status, payload = _call_http(
            self.app, "POST", "/v1/agents/register", json.dumps(body).encode()
        )
        self.assertEqual(status, 200, payload)
        unbound = payload["agent"]["catalog_agent_id"]
        status, payload = _call_http(self.app, "GET", f"/v1/agents/{unbound}/listings")
        self.assertEqual(status, 403, payload)
        self.assertIn("no merchant binding", payload.get("error", ""))
        with mock.patch.dict(os.environ, {"KIWI_CATALOG_ADMIN_TOKEN": "admin-tok"}):
            status, payload = _call_http(
                self.app, "GET", f"/v1/agents/{unbound}/listings?admin_token=admin-tok"
            )
        self.assertEqual(status, 200, payload)

    def test_list_agent_listings_with_freshness_filter(self) -> None:
        self._publish()
        status, payload = _call_http(
            self.app, "GET", f"/v1/agents/{self.agent_id}/listings?owner_token={self.token}"
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(len(payload["results"]), 1)
        status, payload = _call_http(
            self.app,
            "GET",
            f"/v1/agents/{self.agent_id}/listings?freshness_state=STALE&owner_token={self.token}",
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["results"], [])

    # ── get single listing ──────────────────────────────────────────────────

    def test_get_listing_returns_record(self) -> None:
        _, published = self._publish()
        listing_id = published["listing"]["listing_id"]
        status, payload = _call_http(self.app, "GET", f"/v1/listings/{listing_id}")
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["listing"]["listing_id"], listing_id)
        status, payload = _call_http(self.app, "GET", "/v1/listings/lst_nope")
        self.assertEqual(status, 404, payload)


if __name__ == "__main__":
    unittest.main()
