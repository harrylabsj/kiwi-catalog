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

"""运营 Dashboard API 集成测试（admin token 保护 + 埋点 + 报告）。

覆盖：
- dashboard / merchants / report 三端点 admin 必填（fail-closed 403）；
- dashboard KPI 计数与使用趋势（埋点后 series 有值、天数正确）；
- 埋点：agents/search、listings/search、merchants/self、listings/publish
  各 +1；幂等重放 publish 不重复计；
- merchant 列表聚合（agents/listings/token 计数）；
- 商家报告（资料/agents/listings/token 生命周期/审计）；
- /portal/dashboard 默认 404、env 开启 200。
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from unittest import mock

from kiwi_catalog.api.app import create_catalog_app

ADMIN_TOKEN = "admin-tok-123"
OWNER_SECRET = "test-owner-secret"

REGISTER_BODY = {
    "domain": "acme.example",
    "display_name": "Acme Merchant",
    "agent_card_url": "https://acme.example/.well-known/agent-card.json",
    "hosting_mode": "direct_only",
    "handoff_destination_types": ["external_checkout_url"],
}

PRODUCT_PAYLOAD = {
    "listing_type": "product",
    "source_product_ref": "SKU-001",
    "title": "Industrial Touch Display",
    "category": "industrial-display",
    "brand": "Acme",
    "attributes": {"screen_size": "21.5"},
    "regions": ["CN"],
    "handoff_destination_types": ["external_checkout_url"],
}


def _call_http(
    app, method: str, path: str, body: bytes = b"", headers: dict[str, str] | None = None
) -> tuple[int, dict]:
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
    chunks = b"".join(m.get("body", b"") for m in received if m["type"] == "http.response.body")
    payload: dict = {}
    if chunks:
        try:
            payload = json.loads(chunks.decode())
        except json.JSONDecodeError:
            payload = {"_raw": chunks.decode()}
    return start.get("status", 500), payload


class AdminApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "catalog.sqlite")
        env_patch = mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_ADMIN_TOKEN": ADMIN_TOKEN,
                "KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET,
                "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
            },
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.app = create_catalog_app(self.db_path)

    def _seed_merchant(self) -> dict:
        """走完整链路造一个商家：注册账号（console 验证）→ 会话申请 → approve → register → publish。"""
        from kiwi_catalog.db.session import db_session
        from kiwi_catalog.services import accounts as accounts_service

        email = "ops@acme.example"
        status, registered = _call_http(
            self.app,
            "POST",
            "/v1/accounts/register",
            json.dumps({"merchant_name": "Acme Merchant", "email": email, "password": "strong-pw-123", "phone": "+86 138 0000 0000"}).encode(),
        )
        self.assertEqual(status, 200, registered)
        status, verified = _call_http(
            self.app,
            "POST",
            "/v1/accounts/verify-email",
            json.dumps({"email": email, "code": registered["verification_code"]}).encode(),
        )
        self.assertEqual(status, 200, verified)
        # 申请需会话（2026-08-12 关闭匿名通道）；本文件 _call_http 不透传 cookie，
        # 直接建会话并经 body 的 kiwi_session 字段传递（handler 支持的备选通道）
        with db_session(self.db_path) as conn:
            account_id = conn.execute(
                "select account_id from merchant_accounts where email = ?", (email,)
            ).fetchone()["account_id"]
            session = accounts_service.create_session(conn, int(account_id))
        status, applied = _call_http(
            self.app,
            "POST",
            "/v1/merchants/applications",
            json.dumps(
                {
                    "domain": "acme.example",
                    "agent_name": "Acme Merchant",
                    "agent_id": "merchant-001",
                    "kiwi_session": session,
                }
            ).encode(),
        )
        self.assertEqual(status, 200, applied)
        app_id = applied["application_id"]
        status, issued = _call_http(
            self.app,
            "POST",
            f"/v1/merchants/applications/{app_id}/approve",
            json.dumps({"admin_token": ADMIN_TOKEN}).encode(),
        )
        self.assertEqual(status, 200, issued)
        mid, token = issued["merchant_id"], issued["token"]
        status, registered = _call_http(
            self.app,
            "POST",
            "/v1/agents/register",
            json.dumps({**REGISTER_BODY, "merchant_id": mid, "owner_token": token}).encode(),
        )
        self.assertEqual(status, 200, registered)
        agent_id = registered["agent"]["catalog_agent_id"]
        status, _ = _call_http(
            self.app,
            "POST",
            "/v1/listings/publish",
            json.dumps(
                {
                    **PRODUCT_PAYLOAD,
                    "merchant_id": mid,
                    "owner_agent_id": agent_id,
                    "owner_token": token,
                }
            ).encode(),
        )
        self.assertEqual(status, 200)
        return {"merchant_id": mid, "token": token, "agent_id": agent_id}

    # ── 鉴权 fail-closed ───────────────────────────────────────────────────

    def test_admin_endpoints_require_token(self) -> None:
        for path in (
            "/v1/admin/dashboard",
            "/v1/admin/merchants",
            "/v1/admin/merchants/mkt_x/report",
        ):
            status, payload = _call_http(self.app, "GET", path)
            self.assertEqual(status, 403, (path, payload))
            self.assertIn("admin token", payload.get("error", ""))

    # ── dashboard ──────────────────────────────────────────────────────────

    def test_dashboard_kpis_and_usage_series(self) -> None:
        self._seed_merchant()
        # 制造埋点：agent 搜索 ×2、listing 搜索 ×1、自查 ×1
        for _ in range(2):
            _call_http(self.app, "GET", "/v1/agents/search?q=display")
        _call_http(self.app, "GET", "/v1/listings/search?q=touch")
        status, payload = _call_http(
            self.app, "GET", "/v1/admin/dashboard?days=7",
            headers={"Authorization": "Bearer " + ADMIN_TOKEN},
        )
        self.assertEqual(status, 200, payload)
        counts = payload["counts"]
        self.assertEqual(counts["merchants"], 1)
        self.assertEqual(counts["agents"], 1)
        self.assertEqual(counts["listings"], 1)
        self.assertEqual(counts["pending_applications"], 0)
        self.assertEqual(counts["active_tokens"], 1)
        usage = payload["usage"]
        self.assertEqual(len(usage), 7)
        today = usage[-1]["counts"]
        self.assertEqual(today["buyer_agent_search"], 2)
        self.assertEqual(today["buyer_listing_search"], 1)
        self.assertEqual(today["listing_publish"], 1)

    def test_dashboard_non_numeric_query_is_400_not_500(self) -> None:
        """审查 P3：非数字 days/limit 此前 int() 抛 ValueError → 未类型化 500。"""
        status, payload = _call_http(
            self.app, "GET", "/v1/admin/dashboard?days=abc",
            headers={"Authorization": "Bearer " + ADMIN_TOKEN},
        )
        self.assertEqual(status, 400, payload)
        self.assertIn("days", payload.get("error", ""))

        status, payload = _call_http(
            self.app, "GET", "/v1/admin/merchants?limit=abc",
            headers={"Authorization": "Bearer " + ADMIN_TOKEN},
        )
        self.assertEqual(status, 400, payload)
        self.assertIn("limit", payload.get("error", ""))

        # 负数同样拒绝（非负整数语义）
        status, payload = _call_http(
            self.app, "GET", "/v1/admin/dashboard?days=-1",
            headers={"Authorization": "Bearer " + ADMIN_TOKEN},
        )
        self.assertEqual(status, 400, payload)

    def test_dashboard_self_check_metric(self) -> None:
        seeded = self._seed_merchant()
        _call_http(self.app, "GET", f"/v1/merchants/self?owner_token={seeded['token']}")
        status, payload = _call_http(
            self.app, "GET", "/v1/admin/dashboard?days=1",
            headers={"Authorization": "Bearer " + ADMIN_TOKEN},
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["usage"][-1]["counts"]["merchant_self_check"], 1)

    # ── merchant 列表 ──────────────────────────────────────────────────────

    def test_merchant_list_aggregates(self) -> None:
        seeded = self._seed_merchant()
        status, payload = _call_http(
            self.app, "GET", "/v1/admin/merchants",
            headers={"Authorization": "Bearer " + ADMIN_TOKEN},
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(len(payload["results"]), 1)
        row = payload["results"][0]
        self.assertEqual(row["merchant_id"], seeded["merchant_id"])
        self.assertEqual(row["agents_count"], 1)
        self.assertEqual(row["listings_count"], 1)
        self.assertEqual(row["token_status"], "active")

    def test_registered_merchant_visible_without_approval(self) -> None:
        """注册即商家（无需批准）：仅注册 + 验证邮箱即出现在 admin 商家列表。

        token_status 应为 none（注册种入的 revoked 占位行不算已签发），
        签发时间不显示占位行；令牌仍待申请/审批。
        """
        email = "newmerchant@example.com"
        status, registered = _call_http(
            self.app,
            "POST",
            "/v1/accounts/register",
            json.dumps({"merchant_name": "新晋商家", "email": email, "password": "strong-pw-123", "phone": "+86 138 0000 0000"}).encode(),
        )
        self.assertEqual(status, 200, registered)
        status, verified = _call_http(
            self.app,
            "POST",
            "/v1/accounts/verify-email",
            json.dumps({"email": email, "code": registered["verification_code"]}).encode(),
        )
        self.assertEqual(status, 200, verified)
        status, payload = _call_http(
            self.app, "GET", "/v1/admin/merchants",
            headers={"Authorization": "Bearer " + ADMIN_TOKEN},
        )
        self.assertEqual(status, 200, payload)
        rows = [r for r in payload["results"] if r["merchant_id"].startswith("mkt_")]
        self.assertEqual(len(rows), 1, payload)
        row = rows[0]
        self.assertEqual(row["name"], "新晋商家")
        self.assertEqual(row["token_status"], "none")
        self.assertEqual(row["token_issued_at"], "")
        self.assertEqual(row["agents_count"], 0)
        self.assertEqual(row["listings_count"], 0)

    # ── 商家报告 ───────────────────────────────────────────────────────────

    def test_merchant_report_full(self) -> None:
        seeded = self._seed_merchant()
        status, payload = _call_http(
            self.app,
            "GET",
            f"/v1/admin/merchants/{seeded['merchant_id']}/report",
            headers={"Authorization": "Bearer " + ADMIN_TOKEN},
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["merchant"]["name"], "Acme Merchant")
        self.assertEqual(len(payload["agents"]), 1)
        self.assertEqual(len(payload["listings"]), 1)
        self.assertEqual(payload["tokens"][0]["status"], "active")
        events = [e["event"] for e in payload["audit_events"]]
        self.assertIn("merchant_token_issued", events)

    def test_merchant_report_unknown_404(self) -> None:
        status, payload = _call_http(
            self.app, "GET", "/v1/admin/merchants/mkt_zzz/report",
            headers={"Authorization": "Bearer " + ADMIN_TOKEN},
        )
        self.assertEqual(status, 404, payload)

    # ── dashboard 页面 ─────────────────────────────────────────────────────

    def test_portal_dashboard_hidden_by_default(self) -> None:
        status, payload = _call_http(self.app, "GET", "/portal/dashboard")
        self.assertEqual(status, 404, payload)

    def test_portal_dashboard_enabled_via_env(self) -> None:
        with mock.patch.dict(
            os.environ, {"KIWI_CATALOG_PORTAL_ADMIN_ENABLED": "1"}, clear=False
        ):
            status, payload = _call_http(self.app, "GET", "/portal/dashboard")
            self.assertEqual(status, 200, payload)
            self.assertIn("运营 Dashboard", payload.get("_raw", ""))
            self.assertIn("admin_token", payload.get("_raw", ""))
            self.assertIn("拒绝理由", payload.get("_raw", ""))  # 拒绝必填理由（review_note）

    def test_admin_pages_have_no_merchant_portal_links(self) -> None:
        """运营后台页面不带商家门户导航：无 /portal/apply、/portal/status
        链接、无 nav-links 容器（官方找不到、无链接可到）。"""
        with mock.patch.dict(
            os.environ, {"KIWI_CATALOG_PORTAL_ADMIN_ENABLED": "1"}, clear=False
        ):
            for path in ("/portal/dashboard", "/portal/admin"):
                _, payload = _call_http(self.app, "GET", path)
                raw = payload.get("_raw", "")
                self.assertNotIn("/portal/apply", raw, path)
                self.assertNotIn("/portal/status", raw, path)
                self.assertNotIn('class="nav-links"', raw, path)
                self.assertIn("运营后台", raw, path)
                self.assertIn("拒绝理由", raw, path)  # 拒绝必填理由（review_note）


if __name__ == "__main__":
    unittest.main()
