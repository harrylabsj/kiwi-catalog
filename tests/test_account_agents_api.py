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

"""商家自助接入记录 API 测试（D3；设计 §4.3①/§5.2）。

覆盖：
- POST /v1/accounts/agents：创建幂等（重复调用返回同一条）、一商家一 agent、
  source_type/hosting_mode/canonical_domain 正确、审计 actor、限流按账号；
- GET /v1/accounts/agents：空列表 → 创建后一条（含名片状态/绑定摘要/稳定读地址）；
- GET /v1/accounts/agents/{cagt}/card：归属不一致 404（与不存在不可区分）、
  无名片/无绑定时诚实空态、有种子的发布/绑定/卡片时字段齐全；
- 无会话一律 403（与 /v1/accounts/me 同一会话约定）。
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import tempfile
import unittest
from unittest import mock

from kiwi_catalog.api.app import create_catalog_app

ADMIN_TOKEN = "admin-tok-123"
OWNER_SECRET = "test-owner-secret"

BASE_REGISTER_BODY = {
    "merchant_name": "Acme 商贸",
    "password": "strong-pw-123",
    "phone": "+86 138 0000 0000",
}


def _call_http(app, method: str, path: str, body: bytes = b"", cookie: str = "") -> tuple[int, dict, dict]:
    headers = [(b"content-type", b"application/json")]
    if cookie:
        headers.append((b"cookie", cookie.encode()))
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers,
        "query_string": b"",
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


class AccountAgentsApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "catalog.sqlite")
        env_patch = mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_ADMIN_TOKEN": ADMIN_TOKEN,
                "KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET,
                "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
                "KIWI_CATALOG_PUBLIC_BASE_URL": "https://catalog.example",
            },
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.app = create_catalog_app(self.db_path)

    def _register(self, email: str = "ops@acme.example") -> str:
        """邮箱先行注册（发码 → 验码换 ticket → 建号），返回会话 token。"""
        body = {**BASE_REGISTER_BODY, "email": email}
        status, payload, _ = _call_http(
            self.app, "POST", "/v1/accounts/register/code",
            json.dumps({"email": email}).encode(),
        )
        self.assertEqual(status, 200, payload)
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/register/verify",
            json.dumps({"email": email, "code": payload["verification_code"]}).encode(),
        )
        self.assertEqual(status, 200, payload)
        body["verification_ticket"] = payload["verification_ticket"]
        status, payload, headers = _call_http(
            self.app, "POST", "/v1/accounts/register", json.dumps(body).encode()
        )
        self.assertEqual(status, 200, payload)
        return headers["set-cookie"].split(";")[0].split("=", 1)[1]

    def _create_agent(self, session: str) -> dict:
        status, payload, _ = _call_http(
            self.app, "POST", "/v1/accounts/agents", b"{}", cookie=f"kiwi_session={session}"
        )
        self.assertEqual(status, 200, payload)
        return payload

    # ── 创建（POST /v1/accounts/agents）────────────────────────────────────

    def test_create_agent_idempotent_and_fields(self) -> None:
        """创建幂等：重复调用返回同一条（created=False），一商家一 agent。"""
        session = self._register()
        first = self._create_agent(session)
        self.assertTrue(first["created"])
        self.assertEqual(first["source_type"], "self_registered")
        self.assertEqual(first["hosting_mode"], "direct")
        self.assertEqual(first["canonical_domain"], "")
        self.assertEqual(first["display_name"], "Acme 商贸")
        cagt = first["catalog_agent_id"]
        self.assertTrue(cagt.startswith("cagt_"), first)
        # 预留稳定读地址 + 诚实标注（尚无内容、读会 404）
        self.assertEqual(
            first["card_url"],
            f"https://catalog.example/v1/agents/{cagt}/agent-card.json",
        )
        self.assertIn("404", first["card_url_note"])
        # 重复调用：同一条，不新建
        second = self._create_agent(session)
        self.assertFalse(second["created"])
        self.assertEqual(second["catalog_agent_id"], cagt)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "select * from catalog_agents where merchant_id != ''"
            ).fetchall()
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row["source_type"], "self_registered")
            self.assertEqual(row["hosting_mode"], "direct")
            self.assertEqual(row["canonical_domain"], "")
            self.assertEqual(row["verification_status"], "discovered")
            self.assertEqual(row["administrative_state"], "active")
            # 审计：事件名沿用 catalog_agent_registered，actor = merchant:<id>
            audit = conn.execute(
                "select actor, event, details_json from audit_events"
                " where event = 'catalog_agent_registered' order by rowid"
            ).fetchall()
            self.assertEqual(len(audit), 1)
            self.assertEqual(audit[0]["actor"], f"merchant:{row['merchant_id']}")
            details = json.loads(audit[0]["details_json"])
            self.assertEqual(details["catalog_agent_id"], cagt)
            self.assertEqual(details["source_type"], "self_registered")
            self.assertEqual(details["canonical_domain"], "")
        finally:
            conn.close()

    def test_create_agent_requires_session(self) -> None:
        for method, path in (
            ("POST", "/v1/accounts/agents"),
            ("GET", "/v1/accounts/agents"),
            ("GET", "/v1/accounts/agents/cagt_x/card"),
        ):
            status, payload, _ = _call_http(self.app, method, path, b"{}")
            self.assertEqual(status, 403, (method, path, payload))

    def test_create_agent_rate_limited_per_account(self) -> None:
        """限流按账号：复用登录限流 env 默认值（10 次/15min），第 11 次 429。"""
        session = self._register()
        cookie = f"kiwi_session={session}"
        for i in range(10):
            status, payload, _ = _call_http(
                self.app, "POST", "/v1/accounts/agents", b"{}", cookie=cookie
            )
            self.assertEqual(status, 200, (i, payload))
        status, payload, _ = _call_http(
            self.app, "POST", "/v1/accounts/agents", b"{}", cookie=cookie
        )
        self.assertEqual(status, 429, payload)

    # ── 列表（GET /v1/accounts/agents）─────────────────────────────────────

    def test_list_agents_empty_then_one(self) -> None:
        session = self._register()
        cookie = f"kiwi_session={session}"
        status, payload, _ = _call_http(self.app, "GET", "/v1/accounts/agents", cookie=cookie)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["results"], [])
        created = self._create_agent(session)
        status, payload, _ = _call_http(self.app, "GET", "/v1/accounts/agents", cookie=cookie)
        self.assertEqual(status, 200, payload)
        self.assertEqual(len(payload["results"]), 1)
        item = payload["results"][0]
        self.assertEqual(item["catalog_agent_id"], created["catalog_agent_id"])
        self.assertEqual(item["display_name"], "Acme 商贸")
        self.assertEqual(item["hosting_mode"], "direct")
        # 诚实空态：无名片、无绑定
        self.assertEqual(item["card_state"], "none")
        self.assertEqual(item["card_revision"], 0)
        self.assertEqual(item["card_digest"], "")
        self.assertIsNone(item["binding"])
        self.assertTrue(item["card_url"].endswith("/agent-card.json"))

    # ── 名片详情（GET /v1/accounts/agents/{cagt}/card）──────────────────────

    def test_card_detail_empty_states_and_ownership(self) -> None:
        """归属不一致 → 404（与不存在不可区分）；无名片/无绑定 → 诚实空态。"""
        session_a = self._register("a@acme.example")
        created = self._create_agent(session_a)
        cagt = created["catalog_agent_id"]
        # 他人 agent / 不存在的 agent：统一 404
        session_b = self._register("b@acme.example")
        for session, target in ((session_b, cagt), (session_a, "cagt_nonexistent")):
            status, payload, _ = _call_http(
                self.app,
                "GET",
                f"/v1/accounts/agents/{target}/card",
                cookie=f"kiwi_session={session}",
            )
            self.assertEqual(status, 404, (target, payload))
        # 本人：200，诚实空态
        status, payload, _ = _call_http(
            self.app,
            "GET",
            f"/v1/accounts/agents/{cagt}/card",
            cookie=f"kiwi_session={session_a}",
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["catalog_agent_id"], cagt)
        self.assertEqual(payload["publication"]["state"], "none")
        self.assertEqual(payload["publication"]["active_revision"], 0)
        self.assertIsNone(payload["binding"])
        self.assertIsNone(payload["card"])
        self.assertIsNone(payload["runtime_access"])
        self.assertEqual(payload["pending_bindings"], [])
        self.assertEqual(
            payload["card_url"],
            f"https://catalog.example/v1/agents/{cagt}/agent-card.json",
        )

    def test_card_detail_with_seeded_publication_and_binding(self) -> None:
        """有种子的发布/绑定/卡片：状态、版本、digest、绑定摘要、公开字段齐全。"""
        session = self._register()
        created = self._create_agent(session)
        cagt = created["catalog_agent_id"]
        card = {
            "name": "Acme Agent",
            "description": "Acme 的云端名片",
            "url": "https://acme.app.workbuddy.host",
            "supportedInterfaces": [{"url": "https://acme.app.workbuddy.host/a2a", "protocol": "a2a"}],
            "skills": [{"id": "catalog"}],
        }
        merchant_id = ""
        conn = sqlite3.connect(self.db_path)
        try:
            merchant_id = conn.execute(
                "select merchant_id from catalog_agents where catalog_agent_id = ?", (cagt,)
            ).fetchone()[0]
            now = "2026-09-26T00:00:00+00:00"
            conn.execute(
                "insert into agent_card_versions"
                " (catalog_agent_id, card_revision, wire_profile, canonical_bytes, digest, created_by, created_at)"
                " values (?, 1, '{}', ?, 'sha256:9f3cabc', 'runtime:bind-1', ?)",
                (cagt, json.dumps(card, ensure_ascii=False), now),
            )
            conn.execute(
                "insert into card_publications"
                " (catalog_agent_id, active_revision, publication_state, etag, updated_at)"
                " values (?, 1, 'ACTIVE', 'etag-1', ?)",
                (cagt, now),
            )
            conn.execute(
                "insert into runtime_bindings"
                " (binding_id, catalog_agent_id, merchant_id, runtime_origin, a2a_endpoint,"
                " key_id, key_thumbprint, key_jwk_json, binding_version, service_epoch,"
                " status, created_at, updated_at)"
                " values ('bind-1', ?, ?, 'https://acme.app.workbuddy.host',"
                " 'https://acme.app.workbuddy.host/a2a', 'key-1', 'thumb-1', '{}', 2, 1,"
                " 'active', ?, ?)",
                (cagt, merchant_id, now, now),
            )
            # 已生效的 WorkBuddy 分享码门禁：门户靠这份**公开投影**提示门禁存在，
            # 绝不能把密文/分享码带进响应。
            conn.execute(
                "insert into runtime_access_configs (catalog_agent_id, config_version, provider,"
                " access_mode, parameter_name, secret_ciphertext, key_id, adapter_version,"
                " auth_mode, status, validated_at, created_at, updated_at)"
                " values (?, 1, 'workbuddy', 'share_parameter', 'sharecode', 'cipher-secret',"
                " 'access-key-1', 'workbuddy-share-v1', 'signature', 'active', ?, ?, ?)",
                (cagt, now, now, now),
            )
            # 公开店铺页：只取 published 且未过期的公开资料里的 shop_url。
            # 这里同时放一条更新的 draft 和一条更新的过期 published，验证都不选。
            for publication_id, status, shop_url, expires_at, updated_at in (
                ("mpub_visible", "published", "https://shop.example.com/acme", "", now),
                ("mpub_draft", "draft", "https://draft.example.com/acme", "",
                 "2026-09-27T00:00:00+00:00"),
                ("mpub_expired", "published", "https://expired.example.com/acme",
                 "2026-01-01T00:00:00+00:00", "2026-09-28T00:00:00+00:00"),
            ):
                conn.execute(
                    "insert into merchant_publications (publication_id, merchant_id, status,"
                    " source_kind, merchant_display_name, shop_platform, shop_url, title, category,"
                    " summary, faq_json, published_at, expires_at, version, created_at, updated_at)"
                    " values (?, ?, ?, 'merchant_declared', 'Acme 商贸', '', ?, ?, '', '',"
                    " '[]', ?, ?, 1, ?, ?)",
                    (publication_id, merchant_id, status, shop_url, publication_id,
                     now, expires_at, now, updated_at),
                )
            conn.commit()
        finally:
            conn.close()
        status, payload, _ = _call_http(
            self.app,
            "GET",
            f"/v1/accounts/agents/{cagt}/card",
            cookie=f"kiwi_session={session}",
        )
        self.assertEqual(status, 200, payload)
        pub = payload["publication"]
        self.assertEqual(pub["state"], "ACTIVE")
        self.assertEqual(pub["active_revision"], 1)
        self.assertEqual(pub["digest"], "sha256:9f3cabc")
        self.assertEqual(pub["etag"], "etag-1")
        binding = payload["binding"]
        self.assertEqual(binding["runtime_origin"], "https://acme.app.workbuddy.host")
        self.assertEqual(binding["a2a_endpoint"], "https://acme.app.workbuddy.host/a2a")
        self.assertEqual(binding["binding_version"], 2)
        self.assertEqual(binding["status"], "active")
        self.assertEqual(payload["card"]["name"], "Acme Agent")
        self.assertEqual(payload["card"]["url"], "https://acme.app.workbuddy.host")
        self.assertEqual(len(payload["card"]["supportedInterfaces"]), 1)
        # 已生效的访问门禁只以公开投影出现（provider/模式/版本），不含分享码、
        # 密文、密钥 ID 或解密入口。
        access = payload["runtime_access"]
        self.assertEqual(access["provider"], "workbuddy")
        self.assertEqual(access["access_mode"], "share_parameter")
        self.assertEqual(access["parameter_name"], "sharecode")
        self.assertEqual(access["config_version"], 1)
        self.assertEqual(access["adapter_version"], "workbuddy-share-v1")
        self.assertEqual(access["auth_mode"], "signature")
        rendered = json.dumps(payload)
        self.assertNotIn("cipher-secret", rendered)
        self.assertNotIn("secret_ciphertext", rendered)
        self.assertNotIn("access-key-1", rendered)
        self.assertNotIn("secret_value", rendered)
        # 公开店铺页只取 published + 未过期的最新一条；draft/过期行不参与。
        self.assertEqual(payload["public_shop_url"], "https://shop.example.com/acme")
        self.assertEqual(
            payload["public_home_url"], f"https://catalog.example/m/{merchant_id}"
        )
        self.assertNotIn("draft.example", rendered)
        self.assertNotIn("expired.example", rendered)
        # 列表同步反映名片状态与 digest
        status, payload, _ = _call_http(
            self.app, "GET", "/v1/accounts/agents", cookie=f"kiwi_session={session}"
        )
        item = payload["results"][0]
        self.assertEqual(item["card_state"], "ACTIVE")
        self.assertEqual(item["card_revision"], 1)
        self.assertEqual(item["card_digest"], "sha256:9f3cabc")
        self.assertEqual(item["binding"]["binding_version"], 2)

    def test_card_detail_marks_quarantine_without_rewriting_digest(self) -> None:
        """已签名卡片污染：详情提示重新发布，digest/etag 保持原值。"""
        from kiwi_catalog.a2a.card_store import compute_etag

        session = self._register()
        cagt = self._create_agent(session)["catalog_agent_id"]
        secret = "FAKE-DETAIL-QUARANTINE-CODE-5"
        card = {
            "name": "Acme Agent",
            "description": f"门禁链接 https://shop.example.com/a?sharecode={secret}",
            "url": "https://acme.app.workbuddy.host",
            "supportedInterfaces": [
                {"url": "https://acme.app.workbuddy.host/a2a", "protocol": "a2a"}
            ],
        }
        now = "2026-09-26T00:00:00+00:00"
        etag = compute_etag(card)
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "insert into agent_card_versions"
                " (catalog_agent_id, card_revision, wire_profile, canonical_bytes,"
                " digest, created_by, created_at) values (?, 1, 'a2a-1.0', ?,"
                " 'sha256:" + "d" * 64 + "', 'runtime:bind-1', ?)",
                (cagt, json.dumps(card, ensure_ascii=False), now),
            )
            conn.execute(
                "insert into card_publications (catalog_agent_id, active_revision,"
                " publication_state, etag, updated_at) values (?, 1, 'ACTIVE', ?, ?)",
                (cagt, etag, now),
            )
            conn.commit()
        finally:
            conn.close()

        status, payload, _ = _call_http(
            self.app,
            "GET",
            f"/v1/accounts/agents/{cagt}/card",
            cookie=f"kiwi_session={session}",
        )
        self.assertEqual(status, 200, payload)
        pub = payload["publication"]
        self.assertTrue(pub["quarantined"])
        self.assertTrue(pub["republish_required"])
        self.assertEqual(pub["digest"], "sha256:" + "d" * 64)
        self.assertEqual(pub["etag"], etag)
        self.assertNotIn(secret, json.dumps(payload))

        # 公开稳定读地址拒绝返回被隔离的已签名内容，且不带 ETag/缓存头。
        status, _body, headers = _call_http(
            self.app, "GET", f"/v1/agents/{cagt}/agent-card.json"
        )
        self.assertEqual(status, 410)
        self.assertNotIn("etag", headers)

    def test_card_detail_only_projects_active_runtime_access(self) -> None:
        """待验证/已撤销的访问配置不属于门禁状态：门户只看到 None。"""
        session = self._register()
        cagt = self._create_agent(session)["catalog_agent_id"]
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "insert into runtime_access_configs (catalog_agent_id, config_version, provider,"
                " access_mode, parameter_name, secret_ciphertext, key_id, adapter_version,"
                " auth_mode, status, validated_at, created_at, updated_at)"
                " values (?, 1, 'workbuddy', 'share_parameter', 'sharecode', 'cipher-secret',"
                " 'access-key-1', 'workbuddy-share-v1', 'signature', 'pending', '', ?, ?)",
                (cagt, "2026-09-26T00:00:00+00:00", "2026-09-26T00:00:00+00:00"),
            )
            conn.commit()
        finally:
            conn.close()
        status, payload, _ = _call_http(
            self.app,
            "GET",
            f"/v1/accounts/agents/{cagt}/card",
            cookie=f"kiwi_session={session}",
        )
        self.assertEqual(status, 200, payload)
        self.assertIsNone(payload["runtime_access"])
        self.assertNotIn("cipher-secret", json.dumps(payload))

    def test_card_detail_read_side_rejects_unsafe_public_shop_url(self) -> None:
        """旧数据/手工写库绕过写入校验时，读侧仍不把危险链接交给门户。"""
        session = self._register()
        cagt = self._create_agent(session)["catalog_agent_id"]
        conn = sqlite3.connect(self.db_path)
        try:
            merchant_id = conn.execute(
                "select merchant_id from catalog_agents where catalog_agent_id = ?", (cagt,)
            ).fetchone()[0]
            now = "2026-09-26T00:00:00+00:00"
            conn.execute(
                "insert into merchant_publications (publication_id, merchant_id, status,"
                " source_kind, merchant_display_name, shop_platform, shop_url, title, category,"
                " summary, faq_json, published_at, expires_at, version, created_at, updated_at)"
                " values ('mpub_unsafe', ?, 'published', 'merchant_declared', 'Acme 商贸', '',"
                " 'http://192.168.1.5/shop', '商品', '', '', '[]', ?, '', 1, ?, ?)",
                (merchant_id, now, now, now),
            )
            conn.commit()
        finally:
            conn.close()

        def read_card() -> dict:
            status, payload, _ = _call_http(
                self.app,
                "GET",
                f"/v1/accounts/agents/{cagt}/card",
                cookie=f"kiwi_session={session}",
            )
            self.assertEqual(status, 200, payload)
            return payload

        unsafe_rows = (
            "http://192.168.1.5/shop",
            "https://user:pass@shop.example.com/acme",
            "javascript:alert(1)",
            # WorkBuddy 服务/门禁主机与目录自身基址都不是公开店铺页。
            "https://acme.app.workbuddy.host/shop",
            "https://workbuddy.host/shop",
            "https://open.workbuddy.cn/shop",
            "https://kiwi.harrylabsj.com/shop",
            "https://catalog.example/portal/account",
            "https://catalog.example/v1/agents/x",
            # Agent 服务端点与分享码参数/路径段不得当公开链接。
            "https://shop.example.com/a2a",
            "https://shop.example.com/.well-known/agent-card.json",
            "https://shop.example.com/acme?sharecode=abc",
            "https://shop.example.com/acme#sharecode=abc",
            "https://shop.example.com/sharecode/abc",
        )
        for raw in unsafe_rows:
            with self.subTest(url=raw):
                conn = sqlite3.connect(self.db_path)
                try:
                    conn.execute(
                        "update merchant_publications set shop_url = ?"
                        " where publication_id = 'mpub_unsafe'",
                        (raw,),
                    )
                    conn.commit()
                finally:
                    conn.close()
                payload = read_card()
                self.assertEqual(payload["public_shop_url"], "")
                # 外部链接被拒不妨碍目录托管的公开主页（只展示公开资料）。
                self.assertTrue(payload["public_home_url"])
                self.assertNotIn(raw, json.dumps(payload))

        # 精确等于服务地址/卡片地址的 URL 由 blocked_urls 拒绝；同主机的普通
        # 子路径仍可作为外部店铺页。
        from kiwi_catalog.services import merchant_publications as publications_service

        self.assertEqual(
            publications_service.safe_public_shop_url(
                "https://runtime.example/shop",
                blocked_urls=("https://runtime.example/shop",),
            ),
            "",
        )
        self.assertEqual(
            publications_service.safe_public_shop_url("https://runtime.example/shop"),
            "https://runtime.example/shop",
        )

        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "update merchant_publications set shop_url = 'https://shop.example.com/acme'"
                " where publication_id = 'mpub_unsafe'"
            )
            conn.commit()
        finally:
            conn.close()
        self.assertEqual(read_card()["public_shop_url"], "https://shop.example.com/acme")

    def test_disconnect_revokes_binding_and_is_idempotent(self) -> None:
        """门户取消连接：撤销绑定/下线端点/写审计；无会话 403；越权与未知绑定 404；重复幂等。"""
        session = self._register()
        cagt = self._create_agent(session)["catalog_agent_id"]
        conn = sqlite3.connect(self.db_path)
        try:
            merchant_id = conn.execute(
                "select merchant_id from catalog_agents where catalog_agent_id = ?", (cagt,)
            ).fetchone()[0]
            now = "2026-11-11T00:00:00+00:00"
            conn.execute(
                "insert into runtime_bindings"
                " (binding_id, catalog_agent_id, merchant_id, runtime_origin, a2a_endpoint,"
                " key_id, key_thumbprint, key_jwk_json, binding_version, service_epoch,"
                " status, created_at, updated_at)"
                " values ('bind-1', ?, ?, 'https://acme.app.workbuddy.host',"
                " 'https://acme.app.workbuddy.host/a2a', 'key-1', 'thumb-1', '{}', 1, 1,"
                " 'active', ?, ?)",
                (cagt, merchant_id, now, now),
            )
            conn.execute(
                "insert into agent_endpoints"
                " (catalog_agent_id, kind, url, protocol, protocol_version, preference, status)"
                " values (?, 'a2a', 'https://acme.app.workbuddy.host/a2a', 'a2a', '', 1, 'active')",
                (cagt,),
            )
            # 已发布的公开名片：解除连接后必须一并撤下（稳定读 410，门户不再投影）。
            card = {
                "name": "Acme Agent",
                "description": "公开介绍",
                "version": "1.0.0",
                "url": "https://acme.app.workbuddy.host",
                "supportedInterfaces": [
                    {
                        "url": "https://acme.app.workbuddy.host/a2a",
                        "protocolBinding": "JSONRPC",
                        "protocolVersion": "1.0",
                    }
                ],
            }
            conn.execute(
                "insert into agent_card_versions"
                " (catalog_agent_id, card_revision, wire_profile, canonical_bytes,"
                " digest, created_by, created_at) values (?, 1, 'a2a-1.0', ?, ?, 'runtime', ?)",
                (cagt, json.dumps(card, ensure_ascii=False, sort_keys=True), "sha256:" + "a" * 64, now),
            )
            conn.execute(
                "insert into card_publications"
                " (catalog_agent_id, active_revision, publication_state, etag, updated_at)"
                " values (?, 1, 'ACTIVE', 'etag-1', ?)",
                (cagt, now),
            )
            conn.commit()
        finally:
            conn.close()
        path = f"/v1/accounts/agents/{cagt}/disconnect"
        body = json.dumps({"binding_id": "bind-1"}).encode()
        # 无会话 → 403（与 /v1/accounts/me 同一会话约定）
        status, payload, _ = _call_http(self.app, "POST", path, body)
        self.assertEqual(status, 403, payload)
        # 越权（他人会话）→ 404，不可区分
        other = self._register("other@acme.example")
        status, payload, _ = _call_http(
            self.app, "POST", path, body, cookie=f"kiwi_session={other}"
        )
        self.assertEqual(status, 404, payload)
        # 未知绑定 → 404
        status, payload, _ = _call_http(
            self.app,
            "POST",
            path,
            json.dumps({"binding_id": "bind-x"}).encode(),
            cookie=f"kiwi_session={session}",
        )
        self.assertEqual(status, 404, payload)
        # 本人解除：撤销并下线 a2a 端点行
        status, payload, _ = _call_http(
            self.app, "POST", path, body, cookie=f"kiwi_session={session}"
        )
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["ok"], payload)
        self.assertEqual(payload["status"], "revoked")
        self.assertTrue(payload["changed"])
        # 重复解除幂等
        status, payload, _ = _call_http(
            self.app, "POST", path, body, cookie=f"kiwi_session={session}"
        )
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["ok"], payload)
        self.assertEqual(payload["status"], "revoked")
        self.assertFalse(payload["changed"])
        conn = sqlite3.connect(self.db_path)
        try:
            self.assertEqual(
                conn.execute(
                    "select status from runtime_bindings where binding_id = 'bind-1'"
                ).fetchone()[0],
                "revoked",
            )
            self.assertEqual(
                conn.execute(
                    "select count(*) from agent_endpoints"
                    " where catalog_agent_id = ? and kind = 'a2a'",
                    (cagt,),
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                conn.execute(
                    "select publication_state from card_publications"
                    " where catalog_agent_id = ?",
                    (cagt,),
                ).fetchone()[0],
                "WITHDRAWN",
            )
            self.assertEqual(
                conn.execute(
                    "select count(*) from agent_endpoints"
                    " where catalog_agent_id = ? and kind = 'agent_card'",
                    (cagt,),
                ).fetchone()[0],
                0,
            )
            actor, event = conn.execute(
                "select actor, event from audit_events"
                " where event = 'runtime_binding_revoked' order by id desc limit 1"
            ).fetchone()
            self.assertEqual(actor, f"merchant:{merchant_id}")
            self.assertEqual(event, "runtime_binding_revoked")
            withdrawn_audit = conn.execute(
                "select actor, details_json from audit_events"
                " where event = 'card_publication_withdrawn' order by id desc limit 1"
            ).fetchone()
            self.assertIsNotNone(withdrawn_audit)
            self.assertEqual(withdrawn_audit[0], f"merchant:{merchant_id}")
            self.assertEqual(json.loads(withdrawn_audit[1])["reason"], "binding_disconnected")
        finally:
            conn.close()
        # 公开稳定读地址随撤下返回 410，门户也不再投影旧应用的卡片内容。
        status, _body, _headers = _call_http(
            self.app, "GET", f"/v1/agents/{cagt}/agent-card.json"
        )
        self.assertEqual(status, 410)
        status, payload, _ = _call_http(
            self.app,
            "GET",
            f"/v1/accounts/agents/{cagt}/card",
            cookie=f"kiwi_session={session}",
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["publication"]["state"], "WITHDRAWN")
        self.assertIsNone(payload["card"])
        self.assertIsNone(payload["runtime_access"])

    def test_disconnect_without_binding_returns_404(self) -> None:
        """从未绑定过的商家：解除返回 404，不创建任何绑定/端点行。"""
        session = self._register("nobind@acme.example")
        cagt = self._create_agent(session)["catalog_agent_id"]
        status, payload, _ = _call_http(
            self.app,
            "POST",
            f"/v1/accounts/agents/{cagt}/disconnect",
            json.dumps({"binding_id": "bind-none"}).encode(),
            cookie=f"kiwi_session={session}",
        )
        self.assertEqual(status, 404, payload)
        conn = sqlite3.connect(self.db_path)
        try:
            self.assertEqual(
                conn.execute(
                    "select count(*) from runtime_bindings where catalog_agent_id = ?", (cagt,)
                ).fetchone()[0],
                0,
            )
        finally:
            conn.close()


class AccountCardGovernanceTest(unittest.TestCase):
    """门户名片治理端点（P1；设计 §5.2/§5.3）：pause/resume/withdraw。

    与运行时签名面同一状态转移核心（card_store）：CAS 409、撤回后公开读
    410、暂停后仍可读、恢复回 ACTIVE；审计 actor=merchant:<merchant_id>。
    """

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "catalog.sqlite")
        env_patch = mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_ADMIN_TOKEN": ADMIN_TOKEN,
                "KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET,
                "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
                "KIWI_CATALOG_PUBLIC_BASE_URL": "https://catalog.example",
            },
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.app = create_catalog_app(self.db_path)

    def _register(self, email: str = "ops@acme.example") -> str:
        body = {**BASE_REGISTER_BODY, "email": email}
        status, payload, _ = _call_http(
            self.app, "POST", "/v1/accounts/register/code",
            json.dumps({"email": email}).encode(),
        )
        self.assertEqual(status, 200, payload)
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/register/verify",
            json.dumps({"email": email, "code": payload["verification_code"]}).encode(),
        )
        self.assertEqual(status, 200, payload)
        body["verification_ticket"] = payload["verification_ticket"]
        status, payload, headers = _call_http(
            self.app, "POST", "/v1/accounts/register", json.dumps(body).encode()
        )
        self.assertEqual(status, 200, payload)
        return headers["set-cookie"].split(";")[0].split("=", 1)[1]

    def _create_agent(self, session: str) -> str:
        status, payload, _ = _call_http(
            self.app, "POST", "/v1/accounts/agents", b"{}", cookie=f"kiwi_session={session}"
        )
        self.assertEqual(status, 200, payload)
        return payload["catalog_agent_id"]

    def _seed_publication(self, cagt: str, state: str = "ACTIVE", revision: int = 1) -> None:
        """直接落一条发布（1..revision 版本行 + 状态行），绕开运行时签名发布通道。"""
        card = {"name": "Acme Agent", "description": "d", "url": "https://acme.example",
                "supportedInterfaces": [], "skills": []}
        now = "2026-09-26T00:00:00+00:00"
        conn = sqlite3.connect(self.db_path)
        try:
            for rev in range(1, revision + 1):
                conn.execute(
                    "insert into agent_card_versions"
                    " (catalog_agent_id, card_revision, wire_profile, canonical_bytes, digest, created_by, created_at)"
                    " values (?, ?, 'a2a-1.0', ?, ?, 'runtime:bind-1', ?)",
                    (cagt, rev, json.dumps(card, ensure_ascii=False), f"sha256:rev{rev}", now),
                )
            conn.execute(
                "insert into card_publications"
                " (catalog_agent_id, active_revision, publication_state, etag, updated_at)"
                " values (?, ?, ?, 'etag-1', ?)",
                (cagt, revision, state, now),
            )
            conn.commit()
        finally:
            conn.close()

    def _govern(self, session: str, cagt: str, action: str, expected) -> tuple[int, dict]:
        return _call_http(
            self.app,
            "POST",
            f"/v1/accounts/agents/{cagt}/card/{action}",
            json.dumps({"expected_revision": expected}).encode(),
            cookie=f"kiwi_session={session}",
        )[:2]

    def _read_public_card(self, cagt: str) -> int:
        return _call_http(self.app, "GET", f"/v1/agents/{cagt}/agent-card.json")[0]

    def _state_of(self, cagt: str) -> str:
        conn = sqlite3.connect(self.db_path)
        try:
            return conn.execute(
                "select publication_state from card_publications where catalog_agent_id = ?",
                (cagt,),
            ).fetchone()[0]
        finally:
            conn.close()

    # ── 生命周期 ──────────────────────────────────────────────────────────

    def test_pause_resume_withdraw_cycle(self) -> None:
        session = self._register()
        cagt = self._create_agent(session)
        self._seed_publication(cagt, "ACTIVE", 1)
        # 暂停：公开信息保留（仍可读 200），停止接待
        status, payload = self._govern(session, cagt, "pause", 1)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["publication_state"], "PAUSED")
        self.assertEqual(self._read_public_card(cagt), 200)
        # 恢复：回 ACTIVE
        status, payload = self._govern(session, cagt, "resume", 1)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["publication_state"], "ACTIVE")
        self.assertEqual(self._read_public_card(cagt), 200)
        # 撤回：稳定读地址 410（既有公开读语义，不重定向）
        status, payload = self._govern(session, cagt, "withdraw", 1)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["publication_state"], "WITHDRAWN")
        self.assertEqual(self._read_public_card(cagt), 410)
        # 审计：三个事件、actor=merchant:<merchant_id>
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "select actor, event, details_json from audit_events"
                " where event like 'card_publication_%' order by rowid"
            ).fetchall()
            merchant_id = conn.execute(
                "select merchant_id from catalog_agents where catalog_agent_id = ?", (cagt,)
            ).fetchone()["merchant_id"]
        finally:
            conn.close()
        self.assertEqual(
            [r["event"] for r in rows],
            ["card_publication_paused", "card_publication_resumed", "card_publication_withdrawn"],
        )
        for r in rows:
            self.assertEqual(r["actor"], f"merchant:{merchant_id}")
            details = json.loads(r["details_json"])
            self.assertEqual(details["active_revision"], 1)
            self.assertEqual(details["catalog_agent_id"], cagt)

    # ── CAS / 校验 / 归属 ─────────────────────────────────────────────────

    def test_cas_conflict_returns_409(self) -> None:
        session = self._register()
        cagt = self._create_agent(session)
        self._seed_publication(cagt, "ACTIVE", 2)
        status, payload = self._govern(session, cagt, "pause", 1)
        self.assertEqual(status, 409, payload)
        self.assertEqual(self._state_of(cagt), "ACTIVE")  # CAS 失败不动状态
        # resume 同样 CAS（用存在但已过期的 revision：核心先查版本存在，再比对 CAS）
        status, payload = self._govern(session, cagt, "resume", 1)
        self.assertEqual(status, 409, payload)

    def test_expected_revision_must_be_int(self) -> None:
        session = self._register()
        cagt = self._create_agent(session)
        self._seed_publication(cagt, "ACTIVE", 1)
        status, payload = self._govern(session, cagt, "pause", "1")
        self.assertEqual(status, 400, payload)

    def test_govern_requires_session_and_ownership(self) -> None:
        session_a = self._register("a@acme.example")
        cagt = self._create_agent(session_a)
        self._seed_publication(cagt, "ACTIVE", 1)
        # 无会话 → 403（仓库会话约定，与 /v1/accounts/me 一致）
        status, payload, _ = _call_http(
            self.app,
            "POST",
            f"/v1/accounts/agents/{cagt}/card/pause",
            json.dumps({"expected_revision": 1}).encode(),
        )
        self.assertEqual(status, 403, payload)
        # 非本商家 → 404（与不存在不可区分）
        session_b = self._register("b@acme.example")
        status, payload = self._govern(session_b, cagt, "pause", 1)
        self.assertEqual(status, 404, payload)
        self.assertEqual(self._state_of(cagt), "ACTIVE")

    def test_govern_without_publication_404(self) -> None:
        session = self._register()
        cagt = self._create_agent(session)
        status, payload = self._govern(session, cagt, "pause", 0)
        self.assertEqual(status, 404, payload)


class CardPublicFieldSafetyTest(unittest.TestCase):
    def test_card_service_urls_strip_share_codes(self) -> None:
        from kiwi_catalog.services import account_agents

        card = {
            "name": "Acme",
            "description": "服务介绍",
            "url": "https://acme.app.workbuddy.host/?sharecode=FAKE-CARD-CODE-1",
            "supportedInterfaces": [
                {
                    "url": "https://acme.app.workbuddy.host/a2a?share_code=FAKE-CARD-CODE-1",
                    "protocol": "a2a",
                },
                {"url": "https://acme.app.workbuddy.host/a2a", "protocol": "a2a"},
            ],
            "skills": [{"id": "catalog", "description": "普通描述"}],
        }
        cleaned = account_agents._card_public_fields(card)
        rendered = json.dumps(cleaned)
        self.assertNotIn("FAKE-CARD-CODE-1", rendered)
        self.assertEqual(cleaned["url"], "")
        self.assertEqual(cleaned["supportedInterfaces"][0]["url"], "")
        # 普通 WorkBuddy 服务地址（无分享码）保持不变。
        self.assertEqual(
            cleaned["supportedInterfaces"][1]["url"],
            "https://acme.app.workbuddy.host/a2a",
        )

    def test_public_card_payload_sanitizes_share_code_urls(self) -> None:
        from kiwi_catalog.services.merchant_publications import (
            sanitize_public_card_urls,
        )

        card = {
            "name": "Acme",
            "url": "https://acme.app.workbuddy.host/?sharecode=FAKE-CARD-CODE-2",
            "supportedInterfaces": [
                {"url": "https://acme.app.workbuddy.host/a2a?share_code=FAKE-CARD-CODE-2"}
            ],
            "skills": [{"id": "catalog"}],
        }
        cleaned = sanitize_public_card_urls(card)
        rendered = json.dumps(cleaned)
        self.assertNotIn("FAKE-CARD-CODE-2", rendered)
        self.assertEqual(cleaned["url"], "")
        self.assertEqual(cleaned["supportedInterfaces"][0]["url"], "")
        self.assertEqual(cleaned["skills"][0]["id"], "catalog")


if __name__ == "__main__":
    unittest.main()
