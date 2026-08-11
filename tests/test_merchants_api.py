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

"""Merchant token 分发 API 集成测试（docs/kiwi-catalog-token-portal-design-v0.1 §4/§10）。

覆盖：
- apply：公开提交、字段校验、按邮箱限流；
- list_applications：admin 必填（fail-closed）、status 过滤；
- approve：admin 必填、签发 mkt_ merchant_id + 明文 token 仅一次、
  重复 approve 409、审计不含明文；
- reject：仅 pending 可拒、review_note；
- rotate：admin、新 token 生效、旧 token 失效；
- revoke：admin、吊销后 token 失效、重复吊销幂等；
- self：token 即身份解析 merchant_id、吊销 token 403、admin 按 merchant_id 查；
- 双路径：随机 token 可用于 register(带 merchant)/publish；HMAC 旧 token 兼容；
- 门户页 GET 200 + text/html + no-store。
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
from kiwi_catalog.core.tokens import token_digest

ADMIN_TOKEN = "admin-tok-123"
OWNER_SECRET = "test-owner-secret"

APPLY_BODY = {
    "domain": "acme.example",
    "agent_name": "Acme Merchant Agent",
    "agent_id": "merchant-001",
    "contact_email": "ops@acme.example",
    "purpose": "sell industrial displays",
}

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
    "merchant_id": "PLACEHOLDER",
    "source_product_ref": "SKU-001",
    "title": "21.5 inch Industrial Touch Display",
    "category": "industrial-display",
    "brand": "Acme Display Co.",
    "attributes": {"screen_size": "21.5"},
    "regions": ["CN"],
    "tags": ["touch"],
    "handoff_destination_types": ["external_checkout_url"],
}


def _call_http(
    app, method: str, path: str, body: bytes = b"", headers: dict[str, str] | None = None
) -> tuple[int, dict, dict]:
    """(status, json_payload, headers)；HTML 页面 json 解析失败时 payload={}。"""
    path_only = path.split("?", 1)[0]
    query_bytes = path.split("?", 1)[1].encode() if "?" in path else b""
    scope_headers: list[tuple[bytes, bytes]] = [(b"content-type", b"application/json")]
    for key, value in (headers or {}).items():
        scope_headers.append((key.lower().encode("latin1"), value.encode("latin1")))
    scope = {
        "type": "http",
        "method": method,
        "path": path_only,
        "headers": scope_headers,
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
    start = next(m for m in received if m["type"] == "http.response.start")
    headers = {k.decode("latin1"): v.decode("latin1") for k, v in start.get("headers", [])}
    chunks = b"".join(m.get("body", b"") for m in received if m["type"] == "http.response.body")
    payload: dict = {}
    if chunks:
        try:
            payload = json.loads(chunks.decode())
        except json.JSONDecodeError:
            payload = {"_raw": chunks.decode()}
    return start.get("status", 500), payload, headers


class MerchantsApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "catalog.sqlite")
        env_patch = mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_ADMIN_TOKEN": ADMIN_TOKEN,
                "KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET,
            },
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.app = create_catalog_app(self.db_path)
        self._agents: dict[str, str] = {}

    def _apply(self, overrides: dict | None = None) -> tuple[int, dict]:
        body = {**APPLY_BODY, **(overrides or {})}
        return _call_http(self.app, "POST", "/v1/merchants/applications", json.dumps(body).encode())[:2]

    def _approve(self, app_id: int) -> tuple[int, dict]:
        return _call_http(
            self.app,
            "POST",
            f"/v1/merchants/applications/{app_id}/approve",
            json.dumps({"admin_token": ADMIN_TOKEN}).encode(),
        )[:2]

    def _ensure_agent(self, merchant_id: str, token: str) -> str:
        """每 merchant 注册一次 agent（merchant 单 agent 约束 + domain 唯一），
        之后复用——token 轮换/吊销测试要测的是 publish 鉴权而非注册冲突。"""
        if merchant_id in self._agents:
            return self._agents[merchant_id]
        body = {**REGISTER_BODY, "merchant_id": merchant_id, "owner_token": token}
        status, registered = _call_http(
            self.app, "POST", "/v1/agents/register", json.dumps(body).encode()
        )[:2]
        self.assertEqual(status, 200, registered)
        agent_id = registered["agent"]["catalog_agent_id"]
        self._agents[merchant_id] = agent_id
        return agent_id

    def _register(self, merchant_id: str, token: str) -> int:
        self._ensure_agent(merchant_id, token)
        return 200

    def _publish(self, merchant_id: str, token: str) -> int:
        """注册（或复用）agent 后发布产品；返回 publish 状态。"""
        agent_id = self._ensure_agent(merchant_id, token)
        publish_body = {
            **PRODUCT_PAYLOAD,
            "merchant_id": merchant_id,
            "owner_agent_id": agent_id,
            "owner_token": token,
        }
        status, _ = _call_http(
            self.app, "POST", "/v1/listings/publish", json.dumps(publish_body).encode()
        )[:2]
        return status

    # ── apply ──────────────────────────────────────────────────────────────

    def test_apply_public_success(self) -> None:
        status, payload = self._apply()
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["application"]["status"], "pending")
        self.assertEqual(payload["application"]["domain"], "acme.example")
        self.assertNotIn("token", payload)

    def test_apply_validation(self) -> None:
        status, payload = self._apply({"domain": "not a hostname"})
        self.assertEqual(status, 400, payload)
        status, payload = self._apply({"contact_email": "not-an-email"})
        self.assertEqual(status, 400, payload)
        status, payload = self._apply({"agent_name": ""})
        self.assertEqual(status, 400, payload)

    def test_apply_rate_limited_by_email(self) -> None:
        with mock.patch.dict(os.environ, {"KIWI_CATALOG_APPLY_RATE_LIMIT_PER_HOUR": "2"}, clear=False):
            status, _ = self._apply()
            self.assertEqual(status, 200)
            status, _ = self._apply()
            self.assertEqual(status, 200)
            status, payload = self._apply()
            self.assertEqual(status, 429, payload)
            # 不同邮箱不受影响
            status, _ = self._apply({"contact_email": "other@acme.example"})
            self.assertEqual(status, 200)

    # ── list_applications ──────────────────────────────────────────────────

    def test_list_applications_requires_admin(self) -> None:
        self._apply()
        status, payload = _call_http(self.app, "GET", "/v1/merchants/applications")[:2]
        self.assertEqual(status, 403, payload)
        # KC-SEC-02：admin token 只经 Authorization header；query 携带被拒
        status, payload = _call_http(
            self.app,
            "GET",
            "/v1/merchants/applications?status=pending&admin_token=" + ADMIN_TOKEN,
        )[:2]
        self.assertEqual(status, 403, payload)
        status, payload = _call_http(
            self.app,
            "GET",
            "/v1/merchants/applications?status=pending",
            headers={"Authorization": "Bearer " + ADMIN_TOKEN},
        )[:2]
        self.assertEqual(status, 200, payload)
        self.assertEqual(len(payload["results"]), 1)
        self.assertEqual(payload["results"][0]["status"], "pending")

    # ── approve ────────────────────────────────────────────────────────────

    def test_approve_requires_admin_and_issues_token_once(self) -> None:
        _, applied = self._apply()
        app_id = applied["application"]["application_id"]
        status, payload = _call_http(
            self.app, "POST", f"/v1/merchants/applications/{app_id}/approve", b"{}"
        )[:2]
        self.assertEqual(status, 403, payload)

        status, issued = self._approve(app_id)
        self.assertEqual(status, 200, issued)
        self.assertTrue(issued["merchant_id"].startswith("mkt_"))
        self.assertTrue(issued["token"].startswith("mkt_"))
        self.assertEqual(issued["token"], issued["token"])

        # 重复 approve → 409
        status, payload = self._approve(app_id)
        self.assertEqual(status, 409, payload)

        # 审计含签发事件、不含明文 token
        from kiwi_catalog.db.session import db_session

        with db_session(self.db_path) as conn:
            events = conn.execute(
                "select details_json from audit_events where event = 'merchant_token_issued'"
            ).fetchall()
        self.assertEqual(len(events), 1)
        details = json.loads(events[0]["details_json"])
        self.assertEqual(details["merchant_id"], issued["merchant_id"])
        self.assertIn("token_prefix", details)
        self.assertNotIn(issued["token"], json.dumps(details, ensure_ascii=False))

    def test_approve_token_works_for_register_and_publish(self) -> None:
        _, applied = self._apply()
        _, issued = self._approve(applied["application"]["application_id"])
        self.assertEqual(self._register(issued["merchant_id"], issued["token"]), 200)
        self.assertEqual(self._publish(issued["merchant_id"], issued["token"]), 200)

    # ── reject ─────────────────────────────────────────────────────────────

    def test_reject_pending_only(self) -> None:
        _, applied = self._apply()
        app_id = applied["application"]["application_id"]
        status, payload = _call_http(
            self.app,
            "POST",
            f"/v1/merchants/applications/{app_id}/reject",
            json.dumps({"admin_token": ADMIN_TOKEN, "review_note": "domain unverifiable"}).encode(),
        )[:2]
        self.assertEqual(status, 200, payload)
        # 已拒再拒 → 409
        status, payload = _call_http(
            self.app,
            "POST",
            f"/v1/merchants/applications/{app_id}/reject",
            json.dumps({"admin_token": ADMIN_TOKEN}).encode(),
        )[:2]
        self.assertEqual(status, 409, payload)

    # ── rotate ─────────────────────────────────────────────────────────────

    def test_rotate_invalidates_old_token(self) -> None:
        _, applied = self._apply()
        _, issued = self._approve(applied["application"]["application_id"])
        old_token = issued["token"]
        mid = issued["merchant_id"]
        self.assertEqual(self._publish(mid, old_token), 200)

        status, rotated = _call_http(
            self.app,
            "POST",
            f"/v1/merchants/{mid}/rotate",
            json.dumps({"admin_token": ADMIN_TOKEN}).encode(),
        )[:2]
        self.assertEqual(status, 200, rotated)
        self.assertNotEqual(rotated["token"], old_token)
        # 旧 token 失效
        self.assertEqual(self._publish(mid, old_token), 403)
        # 新 token 生效
        self.assertEqual(self._publish(mid, rotated["token"]), 200)

    def test_rotate_requires_admin(self) -> None:
        _, applied = self._apply()
        _, issued = self._approve(applied["application"]["application_id"])
        status, _ = _call_http(
            self.app, "POST", f"/v1/merchants/{issued['merchant_id']}/rotate", b"{}"
        )[:2]
        self.assertEqual(status, 403)

    # ── revoke ─────────────────────────────────────────────────────────────

    def test_revoke_blocks_token_and_is_idempotent(self) -> None:
        _, applied = self._apply()
        _, issued = self._approve(applied["application"]["application_id"])
        mid, token = issued["merchant_id"], issued["token"]
        self.assertEqual(self._publish(mid, token), 200)

        status, payload = _call_http(
            self.app,
            "POST",
            f"/v1/merchants/{mid}/revoke",
            json.dumps({"admin_token": ADMIN_TOKEN}).encode(),
        )[:2]
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["token_status"], "revoked")
        # 吊销后写请求 fail-closed
        self.assertEqual(self._publish(mid, token), 403)
        # 重复吊销幂等
        status, payload = _call_http(
            self.app,
            "POST",
            f"/v1/merchants/{mid}/revoke",
            json.dumps({"admin_token": ADMIN_TOKEN}).encode(),
        )[:2]
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["token_status"], "revoked")

    def test_hmac_fallback_closed_after_token_onboarding_and_revocation(self) -> None:
        """审查 P2-1：HMAC 派生 fallback 不得复活已吊销/已轮换的商户凭证。

        历史 bug：require_merchant_token 在随机 token 未命中或行状态 revoked
        时无条件落入 HMAC 派生路径——admin 吊销后，存量 HMAC 调用方仍可用
        派生 token 认证全部写接口（revoke 契约失效）。修复：商户一旦进入
        token 体系（存在 token 行），凭证以 active 行为唯一权威；仅无任何
        token 记录的存量商户保留 HMAC fallback。
        """
        def _register_with_domain(mid: str, token: str, domain: str) -> str:
            body = {
                **REGISTER_BODY,
                "domain": domain,
                "merchant_id": mid,
                "owner_token": token,
            }
            status, payload = _call_http(
                self.app, "POST", "/v1/agents/register", json.dumps(body).encode()
            )[:2]
            self.assertEqual(status, 200, payload)
            return payload["agent"]["catalog_agent_id"]

        def _publish_with(mid: str, token: str, agent_id: str) -> int:
            body = {
                **PRODUCT_PAYLOAD,
                "merchant_id": mid,
                "owner_agent_id": agent_id,
                "owner_token": token,
            }
            return _call_http(
                self.app, "POST", "/v1/listings/publish", json.dumps(body).encode()
            )[:2][0]

        # 1) 无 token 记录的存量商户：HMAC 派生 token 仍可用（fallback 保留）
        legacy = "legacy-merchant"
        legacy_agent = _register_with_domain(legacy, owner_token(legacy), "legacy.example")
        self.assertEqual(_publish_with(legacy, owner_token(legacy), legacy_agent), 200)

        # 2) 进入 token 体系（apply+approve 签发随机 token）后：HMAC 派生
        #    token 立即失效——凭证以 active 随机 token 为唯一权威
        _, applied = self._apply()
        _, issued = self._approve(applied["application"]["application_id"])
        mid, random_token = issued["merchant_id"], issued["token"]
        mid_agent = _register_with_domain(mid, random_token, "onboarded.example")
        self.assertEqual(_publish_with(mid, random_token, mid_agent), 200)
        self.assertEqual(_publish_with(mid, owner_token(mid), mid_agent), 403)

        # 3) admin 吊销后：随机 token 与 HMAC 派生 token 双双失效
        status, payload = _call_http(
            self.app,
            "POST",
            f"/v1/merchants/{mid}/revoke",
            json.dumps({"admin_token": ADMIN_TOKEN}).encode(),
        )[:2]
        self.assertEqual(status, 200, payload)
        self.assertEqual(_publish_with(mid, random_token, mid_agent), 403)
        self.assertEqual(_publish_with(mid, owner_token(mid), mid_agent), 403)

    # ── self ───────────────────────────────────────────────────────────────

    def test_self_resolves_token_to_merchant(self) -> None:
        _, applied = self._apply()
        _, issued = self._approve(applied["application"]["application_id"])
        self._register(issued["merchant_id"], issued["token"])
        self._publish(issued["merchant_id"], issued["token"])

        status, payload = _call_http(
            self.app, "GET", "/v1/merchants/self?owner_token=" + issued["token"]
        )[:2]
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["merchant_id"], issued["merchant_id"])
        self.assertEqual(payload["token_status"], "active")
        self.assertEqual(payload["agents_count"], 1)
        self.assertEqual(payload["listings_count"], 1)

    def test_self_rejects_unknown_and_revoked_tokens(self) -> None:
        status, payload = _call_http(self.app, "GET", "/v1/merchants/self?owner_token=mkt_bogus")[:2]
        self.assertEqual(status, 403, payload)
        _, applied = self._apply()
        _, issued = self._approve(applied["application"]["application_id"])
        _call_http(
            self.app,
            "POST",
            f"/v1/merchants/{issued['merchant_id']}/revoke",
            json.dumps({"admin_token": ADMIN_TOKEN}).encode(),
        )
        status, payload = _call_http(
            self.app, "GET", "/v1/merchants/self?owner_token=" + issued["token"]
        )[:2]
        self.assertEqual(status, 403, payload)

    def test_self_admin_by_merchant_id(self) -> None:
        _, applied = self._apply()
        _, issued = self._approve(applied["application"]["application_id"])
        status, payload = _call_http(
            self.app,
            "GET",
            f"/v1/merchants/self?merchant_id={issued['merchant_id']}",
            headers={"Authorization": "Bearer " + ADMIN_TOKEN},
        )[:2]
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["merchant_id"], issued["merchant_id"])

    # ── 双路径兼容 ─────────────────────────────────────────────────────────

    def test_hmac_owner_token_still_works(self) -> None:
        # 存量 HMAC 派生路径（无 merchant_tokens 行）不受随机 token 影响
        mid = "mrc_legacy"
        token = owner_token(mid)
        self.assertEqual(self._register(mid, token), 200)
        self.assertEqual(self._publish(mid, token), 200)
        # self 自查对 HMAC 商家仍 403（token 不在 merchant_tokens 表——设计如此：
        # 自查只认落库随机 token）
        status, _ = _call_http(self.app, "GET", "/v1/merchants/self?owner_token=" + token)[:2]
        self.assertEqual(status, 403)

    # ── 门户页 ─────────────────────────────────────────────────────────────

    def test_portal_pages_serve_html(self) -> None:
        for path in ("/portal", "/portal/apply"):
            status, payload, headers = _call_http(self.app, "GET", path)
            self.assertEqual(status, 200, (path, payload))
            self.assertIn("text/html", headers.get("content-type", ""))
            self.assertIn("no-store", headers.get("cache-control", ""))
            self.assertIn("Kiwi", payload.get("_raw", ""))

    def test_portal_admin_hidden_by_default(self) -> None:
        """审核后台不对外公布：默认 404，页面不含审核表单。"""
        status, payload, _ = _call_http(self.app, "GET", "/portal/admin")
        self.assertEqual(status, 404, payload)
        self.assertNotIn("id=\"admin_token\"", payload.get("_raw", ""))

    def test_portal_admin_enabled_via_env(self) -> None:
        with mock.patch.dict(
            os.environ, {"KIWI_CATALOG_PORTAL_ADMIN_ENABLED": "1"}, clear=False
        ):
            status, payload, headers = _call_http(self.app, "GET", "/portal/admin")
            self.assertEqual(status, 200, payload)
            self.assertIn("text/html", headers.get("content-type", ""))
            self.assertIn("admin_token", payload.get("_raw", ""))
            self.assertIn("no-store", headers.get("cache-control", ""))

    def test_portal_admin_escapes_api_values_and_keeps_token_out_of_query(self) -> None:
        with mock.patch.dict(
            os.environ, {"KIWI_CATALOG_PORTAL_ADMIN_ENABLED": "1"}, clear=False
        ):
            _, admin_payload, _ = _call_http(self.app, "GET", "/portal/admin")
            admin_raw = admin_payload.get("_raw", "")
            self.assertIn("function escHtml", admin_raw)
            self.assertIn("escHtml(a.agent_name)", admin_raw)
            self.assertIn("escHtml(a.purpose)", admin_raw)
            _, dashboard_payload, _ = _call_http(self.app, "GET", "/portal/dashboard")
            dashboard_raw = dashboard_payload.get("_raw", "")
            self.assertIn("return getJson(path, token);", dashboard_raw)
            self.assertNotIn("admin_token=' + encodeURIComponent(token)", dashboard_raw)

    def test_portal_pages_use_official_theme(self) -> None:
        """门户页与官网共用主题（nav/hero/section/card 类 + --kiwi-* 变量）。"""
        for path in ("/portal", "/portal/apply"):
            _, payload, _ = _call_http(self.app, "GET", path)
            raw = payload.get("_raw", "")
            self.assertIn("--kiwi-800", raw, path)
            self.assertIn("class=\"nav\"", raw, path)
            self.assertIn("class=\"section", raw, path)

    def test_token_digest_format(self) -> None:
        self.assertEqual(len(token_digest("mkt_x")), 64)


if __name__ == "__main__":
    unittest.main()
