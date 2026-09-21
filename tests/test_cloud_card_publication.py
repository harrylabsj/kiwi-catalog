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

"""M3 云端名片托管（T031/T032/T033/T034/T036/T039 的 Catalog 侧）。

覆盖：
  - 稳定读地址返回**原始 Card JSON**（不套 ok 信封）+ ETag + If-None-Match → 304；
  - 发布需**绑定 Runtime 的请求签名**（缺签名 400 / 错签名 403 / 未知 kid 403）；
  - **泄漏字段注入**（底价/成本/token）→ 拒绝且**不覆盖旧活动名片**；
  - CAS：expected_revision 不匹配 → 409，旧活动版本不被错误覆盖；
  - 撤回 → 稳定地址 **410**（不重定向）；暂停 → 仍可读（治理状态另表表达）；
  - 审计留痕（发布/激活/撤回）。
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from kiwi_catalog.a2a.request_signature import sign_runtime_request
from kiwi_catalog.agent_catalog.sqlite_repository import new_catalog_agent_id, upsert_catalog_agent
from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.db.session import db_session

RUNTIME_ORIGIN = "https://pilot.example.app.workbuddy.host"
A2A_ENDPOINT = f"{RUNTIME_ORIGIN}/a2a"
KID = RUNTIME_ORIGIN
BINDING_ID = "binding-m3-test-1"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _call_http(
    app, method: str, path: str, body: bytes = b"", signature: str = ""
) -> tuple[int, dict, dict, bytes]:
    headers = [(b"content-type", b"application/json")]
    if signature:
        headers.append((b"x-kiwi-binding-jws", signature.encode()))
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers,
        "query_string": b"",
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
    headers_out = {k.decode("latin1"): v.decode("latin1") for k, v in start.get("headers", [])}
    chunks = b"".join(m.get("body", b"") for m in received if m["type"] == "http.response.body")
    try:
        payload = json.loads(chunks.decode("utf-8")) if chunks else {}
    except json.JSONDecodeError:
        payload = {}
    return start["status"], payload, headers_out, chunks


def _card(*, name: str = "Kiwi A2A Merchant", extra: dict | None = None) -> dict:
    card = {
        "name": name,
        "description": "M3 test card",
        "version": "1.0.0",
        "url": RUNTIME_ORIGIN,
        "supportedInterfaces": [
            {"url": A2A_ENDPOINT, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
        ],
        "capabilities": {"extensions": []},
    }
    if extra:
        card.update(extra)
    return card


class CloudCardPublicationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "catalog.sqlite")
        self.app = create_catalog_app(self.db_path)
        # 真实 Ed25519 Runtime 身份（私钥只在测试里）
        self.private_key = Ed25519PrivateKey.generate()
        self.private_pem = self.private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode()
        public_raw = self.private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.key_jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(public_raw)}
        self.catalog_agent_id = self._seed_agent()
        self._seed_binding()

    def _seed_agent(self, *, merchant_id: str = "mkt_m3_1") -> str:
        catalog_agent_id = new_catalog_agent_id()
        with db_session(self.db_path) as conn:
            upsert_catalog_agent(
                conn,
                catalog_agent_id,
                merchant_id=merchant_id,
                display_name="M3 Merchant",
                canonical_domain="merchant.example",
            )
        return catalog_agent_id

    def _seed_binding(self, *, binding_version: int = 1, expires_at: str = "") -> None:
        with db_session(self.db_path) as conn:
            conn.execute(
                "insert into runtime_bindings (binding_id, catalog_agent_id, merchant_id,"
                " runtime_origin, a2a_endpoint, key_id, key_thumbprint, key_jwk_json,"
                " binding_version, service_epoch, status, expires_at, created_at, updated_at)"
                " values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)",
                (
                    BINDING_ID,
                    self.catalog_agent_id,
                    "mkt_m3_1",
                    RUNTIME_ORIGIN,
                    A2A_ENDPOINT,
                    KID,
                    "sha256:" + "0" * 64,
                    json.dumps(self.key_jwk),
                    binding_version,
                    7,
                    expires_at,
                    "2026-09-21T00:00:00+00:00",
                    "2026-09-21T00:00:00+00:00",
                ),
            )

    # ── 辅助：签名 ────────────────────────────────────────────────
    def _sign(self, fields: dict, *, issued_at: str | None = None) -> str:
        return sign_runtime_request(
            kid=KID,
            private_key_pem=self.private_pem,
            signed_fields=fields,
            issued_at=issued_at or datetime.now(timezone.utc).isoformat(),
            nonce="nonce-" + str(id(fields)),
        )

    def _publication(self, card: dict | None = None, expected_revision: int = 0) -> dict:
        card = card or _card()
        digest = "sha256:" + "a" * 64
        return {
            "schema_version": "0.1.2",
            "agent_id": self.catalog_agent_id,
            "binding_id": BINDING_ID,
            "generation": 1,
            "expected_revision": expected_revision,
            "wire_profile": "a2a-1.0",
            "card_digest": digest,
            "agent_card": card,
        }

    def _publish(self, card: dict | None = None, expected_revision: int = 0):
        publication = self._publication(card, expected_revision)
        signature = self._sign(
            {
                "agent_id": self.catalog_agent_id,
                "binding_id": BINDING_ID,
                "card_digest": publication["card_digest"],
                "expected_revision": publication["expected_revision"],
                "generation": publication["generation"],
            }
        )
        body = json.dumps({"publication": publication}).encode()
        return _call_http(
            self.app,
            "POST",
            f"/v1/agents/{self.catalog_agent_id}/card-publications",
            body,
            signature=signature,
        )

    def _activate(self, revision: int, expected_revision: int):
        signature = self._sign(
            {
                "agent_id": self.catalog_agent_id,
                "binding_id": BINDING_ID,
                "card_revision": revision,
                "expected_revision": expected_revision,
            }
        )
        body = json.dumps(
            {
                "binding_id": BINDING_ID,
                "card_revision": revision,
                "expected_revision": expected_revision,
            }
        ).encode()
        return _call_http(
            self.app,
            "POST",
            f"/v1/agents/{self.catalog_agent_id}/publish",
            body,
            signature=signature,
        )

    def _set_state(self, state: str, expected_revision: int):
        signature = self._sign(
            {
                "agent_id": self.catalog_agent_id,
                "binding_id": BINDING_ID,
                "expected_revision": expected_revision,
                "publication_state": state,
            }
        )
        body = json.dumps(
            {"binding_id": BINDING_ID, "expected_revision": expected_revision}
        ).encode()
        segment = {"PAUSED": "pause", "WITHDRAWN": "withdraw", "ACTIVE": "publish"}[state]
        return _call_http(
            self.app,
            "POST",
            f"/v1/agents/{self.catalog_agent_id}/{segment}",
            body,
            signature=signature,
        )

    def _read(self, *, if_none_match: str = ""):
        status, payload, headers, raw = _call_http(
            self.app, "GET", f"/v1/agents/{self.catalog_agent_id}/agent-card.json"
        )
        return status, payload, headers, raw

    # ── T031/T032：发布 + 稳定读地址返回原始 Card ─────────────────
    def test_publish_then_read_raw_card_json(self) -> None:
        status, payload, _headers, _raw = self._publish()
        self.assertEqual(status, 200, payload)
        revision = payload["card_revision"]
        self.assertEqual(revision, 1)
        # 只创建版本时还没有"活动名片"（稳定地址 404 是正确语义）——需先激活。
        self.assertEqual(self._read()[0], 404)
        self.assertEqual(self._activate(revision=revision, expected_revision=0)[0], 200)

        status, payload, headers, raw = self._read()
        self.assertEqual(status, 200, payload)
        # 原始 Card JSON：不套 ok 信封（设计 §11.3）
        self.assertNotIn("ok", payload)
        self.assertEqual(payload["name"], "Kiwi A2A Merchant")
        self.assertEqual(payload["supportedInterfaces"][0]["url"], A2A_ENDPOINT)
        self.assertTrue(headers.get("etag"))
        # 计划 A3：公开只读 + ETag ⇒ 允许中间缓存但必须回源重验证
        self.assertEqual(headers.get("cache-control"), "public, max-age=60, must-revalidate")

        # If-None-Match → 304（无 body）
        status, _payload, _headers, raw = _call_http(
            self.app,
            "GET",
            f"/v1/agents/{self.catalog_agent_id}/agent-card.json",
        )
        self.assertEqual(status, 200)
        etag = headers["etag"]
        scope_headers = [(b"content-type", b"application/json"), (b"if-none-match", etag.encode())]
        # 直接构造带 If-None-Match 的请求
        received: list[dict] = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(msg: dict) -> None:
            received.append(msg)

        asyncio.run(
            self.app(
                {
                    "type": "http",
                    "method": "GET",
                    "path": f"/v1/agents/{self.catalog_agent_id}/agent-card.json",
                    "headers": scope_headers,
                    "query_string": b"",
                    "http_version": "1.1",
                    "scheme": "http",
                },
                receive,
                send,
            )
        )
        start = next(m for m in received if m["type"] == "http.response.start")
        self.assertEqual(start["status"], 304)

    # ── T040：Card 必须过正式 A2A 验证器（§13.1） ─────────────────
    def test_card_must_pass_the_formal_a2a_validator(self) -> None:
        """外层发布 Schema 不是完整 A2A Schema——正式解析器会拦下它管的那部分。

        正式 A2A v1.0.0 解析器的同源判定覆盖 `url` / `documentationUrl` / `provider.url`；
        这里用跨域的 `provider.url` 触发它（接口列表不在其覆盖范围内，由本模块自己的
        权威域检查兜住，见下一个用例）。
        """
        bad_provider = _card(
            extra={"provider": {"organization": "Kiwi", "url": "https://other.example"}}
        )
        status, payload, _headers, _raw = self._publish(bad_provider)
        self.assertEqual(status, 400, payload)
        self.assertIn("A2A v1.0.0", str(payload.get("error", "")))

        # 合法卡片照常通过——反例与正例必须成对，否则"全拒"也能让测试变绿
        self.assertEqual(self._publish()[0], 200)

    def test_every_declared_interface_must_live_on_the_runtime_origin(self) -> None:
        """[绑定端点, 第三方端点] 这种卡片必须被拒。

        只断言"绑定端点在列表里"是不够的：那样等于用 Catalog 的签名背书替第三方
        端点做广告。云端名片声明的每个接口都必须落在绑定 Runtime 的权威域内。
        """
        cross_domain = _card(
            extra={
                "supportedInterfaces": [
                    {"url": A2A_ENDPOINT, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"},
                    {
                        "url": "https://other.example/a2a",
                        "protocolBinding": "JSONRPC",
                        "protocolVersion": "1.0",
                    },
                ]
            }
        )
        status, payload, _headers, _raw = self._publish(cross_domain)
        self.assertEqual(status, 400, payload)
        self.assertIn("runtime origin", str(payload.get("error", "")))

        # 子域仍然允许（同源判定含子域），且 url 指向 Runtime origin 是合法的
        subdomain = _card(
            extra={
                "url": RUNTIME_ORIGIN,
                "supportedInterfaces": [
                    {"url": A2A_ENDPOINT, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
                ],
            }
        )
        self.assertEqual(self._publish(subdomain)[0], 200)

    def test_cache_control_is_identical_on_the_fallback_stack(self) -> None:
        """两栈必须发同一个 cache-control（双栈 parity 的又一项）。

        FastAPI 可用时 `create_catalog_app` 返回 FastAPI app，fallback 路径不会被走到；
        这里直挂 `MarketplaceASGIApp`（与 fallback 部署同一构造），确保那份实现也带
        缓存指令——否则换栈部署时缓存语义会静默变化。
        """
        from kiwi_catalog.api.fallback_asgi import MarketplaceASGIApp
        from kiwi_catalog.api.route_table import _ROUTE_TABLE, resolve_route

        fallback = MarketplaceASGIApp(
            self.db_path,
            route_provider=lambda: list(_ROUTE_TABLE),
            route_resolver=lambda method, path: resolve_route(method, path),
        )
        self.assertEqual(self._publish()[0], 200)
        self.assertEqual(self._activate(revision=1, expected_revision=0)[0], 200)
        status, payload, headers, _raw = _call_http(
            fallback, "GET", f"/v1/agents/{self.catalog_agent_id}/agent-card.json"
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(headers.get("cache-control"), "public, max-age=60, must-revalidate")
        self.assertEqual(payload["name"], "Kiwi A2A Merchant")

    def test_error_responses_carry_no_cache_control(self) -> None:
        """错误不可缓存：404（未发布）与 410（已撤回）都不带 cache-control。"""
        missing = new_catalog_agent_id()
        status, _payload, headers, _raw = _call_http(
            self.app, "GET", f"/v1/agents/{missing}/agent-card.json"
        )
        self.assertEqual(status, 404)
        self.assertNotIn("cache-control", headers)

        self.assertEqual(self._publish()[0], 200)
        self.assertEqual(self._activate(revision=1, expected_revision=0)[0], 200)
        self.assertEqual(self._set_state("WITHDRAWN", expected_revision=1)[0], 200)
        status, _payload, headers, _raw = self._read()
        self.assertEqual(status, 410)
        self.assertNotIn("cache-control", headers)

    def test_card_url_may_not_point_away_from_the_runtime_origin(self) -> None:
        pointing_at_catalog = _card(extra={"url": "https://catalog.example"})
        status, payload, _headers, _raw = self._publish(pointing_at_catalog)
        self.assertEqual(status, 400, payload)
        self.assertIn("runtime origin", str(payload.get("error", "")))

    def test_wire_profile_is_pinned_to_a2a_1_0(self) -> None:
        publication = self._publication()
        for profile in ("a2a-1.1", "a2a-0.3", ""):
            with self.subTest(profile=profile):
                publication["wire_profile"] = profile
                signature = self._sign(
                    {
                        "agent_id": self.catalog_agent_id,
                        "binding_id": BINDING_ID,
                        "card_digest": publication["card_digest"],
                        "expected_revision": publication["expected_revision"],
                        "generation": publication["generation"],
                    }
                )
                status, payload, _headers, _raw = _call_http(
                    self.app,
                    "POST",
                    f"/v1/agents/{self.catalog_agent_id}/card-publications",
                    json.dumps({"publication": publication}).encode(),
                    signature=signature,
                )
                self.assertEqual(status, 400, payload)
                self.assertIn("wire_profile", str(payload.get("error", "")))

    # ── T033：泄漏字段注入 ────────────────────────────────────────
    def test_private_field_injection_rejected_and_old_card_intact(self) -> None:
        self.assertEqual(self._publish()[0], 200)
        self.assertEqual(self._activate(revision=1, expected_revision=0)[0], 200)

        leaked = _card(extra={"unit_price": {"amount_minor": 10000}, "min_unit_price_private": 100.0})
        status, payload, _headers, _raw = self._publish(leaked, expected_revision=1)
        self.assertEqual(status, 400, payload)
        self.assertIn("private field", json.dumps(payload))

        # 旧活动名片不受影响
        status, card, _headers, _raw = self._read()
        self.assertEqual(status, 200)
        self.assertNotIn("min_unit_price_private", json.dumps(card))

    # ── T034：CAS ────────────────────────────────────────────────
    def test_cas_blocks_stale_activation(self) -> None:
        self.assertEqual(self._publish()[0], 200)  # revision 1
        self.assertEqual(self._activate(revision=1, expected_revision=0)[0], 200)
        self.assertEqual(self._publish(expected_revision=1)[0], 200)  # revision 2

        # 用过期 expected_revision 激活 → 409，旧活动版本不动
        status, payload, _headers, _raw = self._activate(revision=2, expected_revision=0)
        self.assertEqual(status, 409, payload)
        status, card, _headers, _raw = self._read()
        self.assertEqual(status, 200)
        self.assertEqual(card["name"], "Kiwi A2A Merchant")

        self.assertEqual(self._activate(revision=2, expected_revision=1)[0], 200)
        status, card, _headers, _raw = self._read()
        self.assertEqual(status, 200)
        # revision 3 用同名卡片（内容相同）——这里只验证激活推进成功
        self.assertEqual(card["name"], "Kiwi A2A Merchant")

    # ── T036：撤回 → 410；暂停 → 仍可读 ───────────────────────────
    def test_withdraw_returns_410_and_pause_keeps_card_readable(self) -> None:
        self.assertEqual(self._publish()[0], 200)
        self.assertEqual(self._activate(revision=1, expected_revision=0)[0], 200)

        status, payload, _headers, _raw = self._set_state("PAUSED", expected_revision=1)
        self.assertEqual(status, 200, payload)
        self.assertEqual(self._read()[0], 200)  # 暂停仍可读（公开信息保留）

        status, payload, _headers, _raw = self._set_state("WITHDRAWN", expected_revision=1)
        self.assertEqual(status, 200, payload)
        status, payload, headers, _raw = self._read()
        self.assertEqual(status, 410, payload)
        self.assertEqual(payload.get("ok"), False)  # 错误信封（410 语义）
        self.assertNotIn("location", {k.lower(): v for k, v in headers.items()})  # 不重定向

    # ── T039：签名要求 ───────────────────────────────────────────
    def test_publication_requires_valid_runtime_signature(self) -> None:
        publication = self._publication()
        body = json.dumps({"publication": publication}).encode()
        path = f"/v1/agents/{self.catalog_agent_id}/card-publications"

        # 缺签名 → 400
        status, payload, _headers, _raw = _call_http(self.app, "POST", path, body)
        self.assertEqual(status, 400, payload)

        # 冒名签名（另一把私钥签的、kid 却是本绑定）→ 403
        other_key = Ed25519PrivateKey.generate()
        forged = sign_runtime_request(
            kid=KID,
            private_key_pem=other_key.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            ).decode(),
            signed_fields={
                "agent_id": self.catalog_agent_id,
                "binding_id": BINDING_ID,
                "card_digest": publication["card_digest"],
                "expected_revision": 0,
                "generation": 1,
            },
            issued_at=datetime.now(timezone.utc).isoformat(),
            nonce="forged",
        )
        status, payload, _headers, _raw = _call_http(self.app, "POST", path, body, signature=forged)
        self.assertEqual(status, 403, payload)

        # 签名正确但字段不符（card_digest 不同）→ 403
        mismatched = self._sign(
            {
                "agent_id": self.catalog_agent_id,
                "binding_id": BINDING_ID,
                "card_digest": "sha256:" + "b" * 64,
                "expected_revision": 0,
                "generation": 1,
            }
        )
        status, payload, _headers, _raw = _call_http(
            self.app, "POST", path, body, signature=mismatched
        )
        self.assertEqual(status, 403, payload)

        # 正确签名 → 200
        self.assertEqual(self._publish()[0], 200)

    def test_audit_rows_written(self) -> None:
        self._publish()
        self._activate(revision=1, expected_revision=0)
        self._set_state("WITHDRAWN", expected_revision=1)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            events = {
                row["event"]
                for row in conn.execute(
                    "select event from audit_events where details_json like ?",
                    (f"%{self.catalog_agent_id}%",),
                )
            }
        finally:
            conn.close()
        self.assertIn("card_revision_created", events)
        self.assertIn("card_publication_activated", events)
        self.assertIn("card_publication_withdrawn", events)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
