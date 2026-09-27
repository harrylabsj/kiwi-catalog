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

"""端点行同步 + purge 豁免 + D5 阶梯短路测试（§4.5/D5；§8 验收对应条目）。

- 端点行同步：确认后有 a2a 行且无 agent_card 行；激活后 agent_card=稳定读
  地址；暂停后两行仍在；撤回后两行都没了；重复同步幂等；**买家侧发现性**
  断言（/v1/agent-catalog/agents/{id} 与 search 的 discovery.agent_card_url
  就是稳定读地址，不只断言表里有行）；
- purge 豁免：云商家重新注册（含换 canonical_domain）后稳定读地址行仍在，
  非云端点照旧被清；
- D5：有活动绑定的 agent 跑 verify/verify_profile 不抓卡、不降级、停在
  commerce_verified；证据过期后重算仍不降级；无绑定 agent 行为不变。
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sqlite3
import tempfile
import unittest
import unittest.mock
import uuid
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from kiwi_catalog.a2a.binding_claims import jwk_thumbprint
from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.db.session import db_session

ADMIN_TOKEN = "admin-token-m3"
OWNER_SECRET = "test-owner-secret"
RUNTIME_ORIGIN = "https://pilot.example.app.workbuddy.host"
A2A_ENDPOINT = f"{RUNTIME_ORIGIN}/a2a"
CATALOG_ORIGIN = "https://catalog.example"

BASE_REGISTER_BODY = {
    "merchant_name": "Acme 商贸",
    "password": "strong-pw-123",
    "phone": "+86 138 0000 0000",
}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _jws(private_pem: str, kid: str, fields: dict) -> str:
    """与 Runtime 侧同形状的 compact JWS（EdDSA）——测试用最小实现。"""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    header = {"alg": "EdDSA", "kid": kid}
    payload = {
        **fields,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "nonce": f"nonce-{uuid.uuid4().hex}",
    }
    header_segment = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_segment = _b64url(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode())
    key = load_pem_private_key(private_pem.encode(), password=None)
    signature = key.sign(f"{header_segment}.{payload_segment}".encode("ascii"))
    return f"{header_segment}.{payload_segment}.{_b64url(signature)}"


def _runtime_key() -> tuple[str, dict]:
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return pem, {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}


def _call(app, method: str, path: str, body: dict | None = None,
          signature: str = "", cookie: str = ""):
    raw = json.dumps(body).encode() if body is not None else b""
    headers = [(b"content-type", b"application/json")]
    if signature:
        headers.append((b"x-kiwi-binding-jws", signature.encode()))
    if cookie:
        headers.append((b"cookie", cookie.encode()))
    received: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": raw, "more_body": False}

    async def send(msg: dict) -> None:
        received.append(msg)

    asyncio.run(
        app(
            {
                "type": "http",
                "method": method,
                "path": path,
                "headers": headers,
                "query_string": b"",
                "http_version": "1.1",
                "scheme": "http",
            },
            receive,
            send,
        )
    )
    start = next(m for m in received if m["type"] == "http.response.start")
    resp_headers = {k.decode().lower(): v.decode() for k, v in start.get("headers", [])}
    chunks = b"".join(m.get("body", b"") for m in received if m["type"] == "http.response.body")
    try:
        payload = json.loads(chunks.decode("utf-8")) if chunks else {}
    except json.JSONDecodeError:
        payload = {}
    return start["status"], payload, resp_headers


class CloudEndpointSyncTest(unittest.TestCase):
    """§4.5 端点行同步（含买家侧发现性断言）+ purge 豁免。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "catalog.sqlite")
        self.app = create_catalog_app(self.db_path)
        env_patch = unittest.mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_ADMIN_TOKEN": ADMIN_TOKEN,
                "KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET,
                "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
                "KIWI_CATALOG_PUBLIC_BASE_URL": CATALOG_ORIGIN,
            },
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.runtime_pem, self.runtime_jwk = _runtime_key()

    # ── helpers ───────────────────────────────────────────────────────────

    def _register(self, email: str = "ops@acme.example") -> str:
        body = {**BASE_REGISTER_BODY, "email": email}
        status, payload, _ = _call(self.app, "POST", "/v1/accounts/register", body)
        self.assertEqual(status, 200, payload)
        status, payload, _ = _call(
            self.app, "POST", "/v1/accounts/verify-email",
            {"email": email, "code": payload["verification_code"]},
        )
        self.assertEqual(status, 200, payload)
        status, _payload, headers = _call(
            self.app, "POST", "/v1/accounts/login",
            {"email": email, "password": BASE_REGISTER_BODY["password"]},
        )
        self.assertEqual(status, 200)
        return headers["set-cookie"].split(";")[0].split("=", 1)[1]

    def _cookie(self) -> str:
        return f"kiwi_session={self.session}"

    def _create_agent(self) -> str:
        status, payload, _ = _call(
            self.app, "POST", "/v1/accounts/agents", {}, cookie=self._cookie()
        )
        self.assertEqual(status, 200, payload)
        return payload["catalog_agent_id"]

    def _request_binding(self, cagt: str, *, pem: str | None = None, jwk: dict | None = None,
                         origin: str = RUNTIME_ORIGIN, admin: bool = False):
        pem = pem or self.runtime_pem
        jwk = jwk or self.runtime_jwk
        kid = origin
        body: dict[str, Any] = {
            "binding": {
                "runtime_origin": origin,
                "a2a_endpoint": f"{origin}/a2a",
                "key_jwk": jwk,
                "key_id": kid,
                "generation": 1,
                "service_epoch": 7,
            }
        }
        if admin:
            body["admin_token"] = ADMIN_TOKEN
        sig = _jws(
            pem,
            kid,
            {
                "agent_id": cagt,
                "key_id": kid,
                "key_thumbprint": jwk_thumbprint(jwk),
                "runtime_origin": origin,
                "a2a_endpoint": f"{origin}/a2a",
                "generation": 1,
                "service_epoch": 7,
            },
        )
        return _call(self.app, "POST", f"/v1/agents/{cagt}/runtime-bindings", body, signature=sig)[:2]

    def _confirm(self, cagt: str, request_id: str):
        return _call(
            self.app, "POST", f"/v1/accounts/agents/{cagt}/bindings/{request_id}/confirm",
            {}, cookie=self._cookie(),
        )[:2]

    def _setup_confirmed(self) -> tuple[str, str]:
        """注册 → 建接入记录 → 首绑请求 → 门户确认；返回 (cagt, binding_id)。"""
        self.session = self._register()
        cagt = self._create_agent()
        status, payload = self._request_binding(cagt)
        self.assertEqual(status, 200, payload)
        status, payload = self._confirm(cagt, payload["binding_request_id"])
        self.assertEqual(status, 200, payload)
        return cagt, str(payload["binding_id"])

    def _publish_and_activate(self, cagt: str, binding_id: str) -> None:
        """用绑定私钥走真实发布 → 激活（触发 card_store 的同步挂接点）。"""
        publication = {
            "schema_version": "0.1.2",
            "agent_id": cagt,
            "binding_id": binding_id,
            "generation": 1,
            "expected_revision": 0,
            "wire_profile": "a2a-1.0",
            "card_digest": "sha256:" + "a" * 64,
            "agent_card": {
                "name": "Acme Cloud Agent",
                "version": "1.0.0",
                "url": RUNTIME_ORIGIN,
                "supportedInterfaces": [
                    {"url": A2A_ENDPOINT, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
                ],
            },
        }
        sig = _jws(
            self.runtime_pem,
            RUNTIME_ORIGIN,
            {
                "agent_id": cagt,
                "binding_id": binding_id,
                "card_digest": publication["card_digest"],
                "expected_revision": 0,
                "generation": 1,
            },
        )
        status, payload, _ = _call(
            self.app, "POST", f"/v1/agents/{cagt}/card-publications",
            {"publication": publication}, signature=sig,
        )
        self.assertEqual(status, 200, payload)
        revision = payload["card_revision"]
        sig = _jws(
            self.runtime_pem,
            RUNTIME_ORIGIN,
            {
                "agent_id": cagt,
                "binding_id": binding_id,
                "card_revision": revision,
                "expected_revision": 0,
            },
        )
        status, payload, _ = _call(
            self.app, "POST", f"/v1/agents/{cagt}/publish",
            {"binding_id": binding_id, "card_revision": revision, "expected_revision": 0},
            signature=sig,
        )
        self.assertEqual(status, 200, payload)

    def _govern(self, cagt: str, action: str, expected_revision: int):
        return _call(
            self.app, "POST", f"/v1/accounts/agents/{cagt}/card/{action}",
            {"expected_revision": expected_revision}, cookie=self._cookie(),
        )[:2]

    def _endpoint_rows(self, cagt: str) -> dict[str, list[str]]:
        """agent_endpoints 行按 kind 分组 → {kind: [url, ...]}。"""
        conn = sqlite3.connect(self.db_path)
        try:
            rows = conn.execute(
                "select kind, url from agent_endpoints where catalog_agent_id = ? order by kind",
                (cagt,),
            ).fetchall()
        finally:
            conn.close()
        grouped: dict[str, list[str]] = {}
        for kind, url in rows:
            grouped.setdefault(str(kind), []).append(str(url))
        return grouped

    def _stable_card_url(self, cagt: str) -> str:
        return f"{CATALOG_ORIGIN}/v1/agents/{cagt}/agent-card.json"

    def _discovery_block(self, cagt: str) -> dict:
        status, payload, _ = _call(self.app, "GET", f"/v1/agent-catalog/agents/{cagt}")
        self.assertEqual(status, 200, payload)
        return payload["catalog_agent"].get("discovery") or {}

    # ── 触发点与买家侧发现性 ──────────────────────────────────────────────

    def test_confirm_writes_a2a_row_not_card_row(self) -> None:
        """绑定确认 → 有 a2a 行、**无** agent_card 行（此时还没有卡）。"""
        cagt, _binding_id = self._setup_confirmed()
        rows = self._endpoint_rows(cagt)
        self.assertEqual(rows.get("a2a"), [A2A_ENDPOINT])
        self.assertNotIn("agent_card", rows)
        # 买家侧：detail 的 discovery 带 a2a_urls，还没有 agent_card_url
        discovery = self._discovery_block(cagt)
        self.assertEqual(discovery.get("a2a_urls"), [A2A_ENDPOINT])
        self.assertNotIn("agent_card_url", discovery)

    def test_activate_writes_card_row_and_buyer_discovers(self) -> None:
        """名片激活 → agent_card 行 = 稳定读地址；买家 detail/search 都能发现。"""
        cagt, binding_id = self._setup_confirmed()
        self._publish_and_activate(cagt, binding_id)
        stable = self._stable_card_url(cagt)
        rows = self._endpoint_rows(cagt)
        self.assertEqual(rows.get("agent_card"), [stable])
        self.assertEqual(rows.get("a2a"), [A2A_ENDPOINT])
        # 买家侧发现性断言：detail 与 search 的 discovery.agent_card_url 都是稳定读地址
        discovery = self._discovery_block(cagt)
        self.assertEqual(discovery.get("agent_card_url"), stable)
        self.assertEqual(discovery.get("a2a_urls"), [A2A_ENDPOINT])
        status, payload, _ = _call(self.app, "GET", "/v1/agent-catalog/agents/search")
        self.assertEqual(status, 200, payload)
        found = [r for r in payload["results"] if r["catalog_agent_id"] == cagt]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["discovery"]["agent_card_url"], stable)
        self.assertEqual(found[0]["discovery"]["a2a_urls"], [A2A_ENDPOINT])
        # 重复同步幂等（直接再跑两次，行数不变）
        from kiwi_catalog.services.agent_endpoints import sync_cloud_endpoints

        with db_session(self.db_path) as conn:
            sync_cloud_endpoints(conn, cagt, "2026-09-27T00:00:00+00:00")
            sync_cloud_endpoints(conn, cagt, "2026-09-27T00:00:01+00:00")
        rows = self._endpoint_rows(cagt)
        self.assertEqual(rows.get("agent_card"), [stable])
        self.assertEqual(rows.get("a2a"), [A2A_ENDPOINT])

    def test_pause_keeps_rows_withdraw_removes_both(self) -> None:
        """暂停 → 两行保留（公开信息保留）；撤回 → 两行皆删（不再可被发现）。"""
        cagt, binding_id = self._setup_confirmed()
        self._publish_and_activate(cagt, binding_id)
        # 暂停（门户治理，走同一 card_store 核心）
        status, payload = self._govern(cagt, "pause", 1)
        self.assertEqual(status, 200, payload)
        rows = self._endpoint_rows(cagt)
        self.assertEqual(rows.get("agent_card"), [self._stable_card_url(cagt)])
        self.assertEqual(rows.get("a2a"), [A2A_ENDPOINT])
        # 撤回 → 两行都没了；稳定读地址 410（既有语义）
        status, payload = self._govern(cagt, "withdraw", 1)
        self.assertEqual(status, 200, payload)
        self.assertEqual(self._endpoint_rows(cagt), {})
        status, _, _ = _call(self.app, "GET", f"/v1/agents/{cagt}/agent-card.json")
        self.assertEqual(status, 410)
        # 买家侧也消失
        self.assertNotIn("agent_card_url", self._discovery_block(cagt))

    def test_revoke_binding_removes_rows(self) -> None:
        """撤销绑定（admin 同路）→ 无其他活动绑定时 a2a 与 agent_card 行皆删。"""
        cagt, binding_id = self._setup_confirmed()
        self._publish_and_activate(cagt, binding_id)
        status, payload, _ = _call(
            self.app, "POST", f"/v1/agents/{cagt}/runtime-bindings/{binding_id}/revoke",
            {"admin_token": ADMIN_TOKEN},
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(self._endpoint_rows(cagt), {})

    def test_rotation_updates_a2a_row(self) -> None:
        """轮换 → a2a 行指向新绑定的端点（同事务更新）。"""
        cagt, _binding_id = self._setup_confirmed()
        new_pem, new_jwk = _runtime_key()
        new_origin = "https://pilot2.example.app.workbuddy.host"
        status, payload = self._request_binding(
            cagt, pem=new_pem, jwk=new_jwk, origin=new_origin, admin=True
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["binding_version"], 2)
        rows = self._endpoint_rows(cagt)
        self.assertEqual(rows.get("a2a"), [f"{new_origin}/a2a"])

    # ── purge 豁免 ────────────────────────────────────────────────────────

    def test_reregister_keeps_stable_card_row_and_purges_noncloud(self) -> None:
        """云商家重新注册（含换 canonical_domain）：稳定读地址行仍在，非云端点照旧被清。"""
        cagt, binding_id = self._setup_confirmed()
        self._publish_and_activate(cagt, binding_id)
        merchant_id = ""
        with db_session(self.db_path) as conn:
            merchant_id = conn.execute(
                "select merchant_id from catalog_agents where catalog_agent_id = ?", (cagt,)
            ).fetchone()["merchant_id"]
            # 种一个旧域名的非云端点（注册 purge 的既定清理对象）
            from kiwi_catalog.agent_catalog.sqlite_repository import upsert_profile_endpoints

            upsert_profile_endpoints(
                conn, cagt,
                [{"kind": "ucp_profile", "url": "https://old.example/ucp", "protocol": "ucp",
                  "protocol_version": "", "preference": 1}],
            )
        # 换域名重注册（服务层函数，与 API 同一路径）
        from kiwi_catalog.services.agent_catalog_writes import register_catalog_agent

        with db_session(self.db_path) as conn:
            register_catalog_agent(
                conn, domain="merchant-new.example", merchant_id=merchant_id, actor="test"
            )
        rows = self._endpoint_rows(cagt)
        # 豁免生效：云名片稳定读地址行仍在
        self.assertEqual(rows.get("agent_card"), [self._stable_card_url(cagt)])
        # 非云端点照旧被清
        self.assertNotIn("ucp_profile", rows)
        # a2a 行由注册末尾的同步兜底仍在
        self.assertEqual(rows.get("a2a"), [A2A_ENDPOINT])


class CloudBindingVerificationSkipTest(unittest.TestCase):
    """D5：有活动绑定的 agent 跳过验证阶梯（不抓卡、不降级）。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "catalog.sqlite")
        self.app = create_catalog_app(self.db_path)
        env_patch = unittest.mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_ADMIN_TOKEN": ADMIN_TOKEN,
                "KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET,
                "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
                "KIWI_CATALOG_PUBLIC_BASE_URL": CATALOG_ORIGIN,
            },
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.runtime_pem, self.runtime_jwk = _runtime_key()

    def _bound_agent(self) -> str:
        """注册 → 建接入记录 → 首绑请求 → 门户确认（带 D5 证据行）。返回 cagt。"""
        body = {**BASE_REGISTER_BODY, "email": "ops@acme.example"}
        status, payload, _ = _call(self.app, "POST", "/v1/accounts/register", body)
        self.assertEqual(status, 200, payload)
        status, payload, _ = _call(
            self.app, "POST", "/v1/accounts/verify-email",
            {"email": "ops@acme.example", "code": payload["verification_code"]},
        )
        self.assertEqual(status, 200, payload)
        status, _p, headers = _call(
            self.app, "POST", "/v1/accounts/login",
            {"email": "ops@acme.example", "password": BASE_REGISTER_BODY["password"]},
        )
        cookie = f"kiwi_session={headers['set-cookie'].split(';')[0].split('=', 1)[1]}"
        status, payload, _ = _call(self.app, "POST", "/v1/accounts/agents", {}, cookie=cookie)
        self.assertEqual(status, 200, payload)
        cagt = payload["catalog_agent_id"]
        kid = RUNTIME_ORIGIN
        sig = _jws(
            self.runtime_pem,
            kid,
            {
                "agent_id": cagt,
                "key_id": kid,
                "key_thumbprint": jwk_thumbprint(self.runtime_jwk),
                "runtime_origin": RUNTIME_ORIGIN,
                "a2a_endpoint": A2A_ENDPOINT,
                "generation": 1,
                "service_epoch": 7,
            },
        )
        status, payload, _ = _call(
            self.app, "POST", f"/v1/agents/{cagt}/runtime-bindings",
            {"binding": {
                "runtime_origin": RUNTIME_ORIGIN, "a2a_endpoint": A2A_ENDPOINT,
                "key_jwk": self.runtime_jwk, "key_id": kid, "generation": 1, "service_epoch": 7,
            }},
            signature=sig,
        )
        self.assertEqual(status, 200, payload)
        status, payload, _ = _call(
            self.app, "POST",
            f"/v1/accounts/agents/{cagt}/bindings/{payload['binding_request_id']}/confirm",
            {}, cookie=cookie,
        )
        self.assertEqual(status, 200, payload)
        return cagt

    def _agent_row(self, cagt: str) -> dict:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            return dict(
                conn.execute(
                    "select * from catalog_agents where catalog_agent_id = ?", (cagt,)
                ).fetchone()
            )
        finally:
            conn.close()

    def test_confirm_writes_d5_evidence_rows(self) -> None:
        """绑定确认写两条 passed 证据行（agent_identity + commerce_capability）。"""
        cagt = self._bound_agent()
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "select verification_type, result, evidence_json, expires_at"
                " from agent_verifications where catalog_agent_id = ? order by verification_id",
                (cagt,),
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual(
            [(r["verification_type"], r["result"]) for r in rows],
            [("agent_identity", "passed"), ("commerce_capability", "passed")],
        )
        evidence = json.loads(rows[0]["evidence_json"])
        for field in ("binding_id", "key_thumbprint", "runtime_origin", "a2a_endpoint", "issuer_kid", "exp"):
            self.assertIn(field, evidence)
        # 绑定无到期 → 90 天窗口
        self.assertTrue(rows[0]["expires_at"] > "2026-10-01", rows[0]["expires_at"])

    def test_bound_agent_verify_skips_ladder(self) -> None:
        """有活动绑定：verify/verify_profile 不抓卡、不降级，停在 commerce_verified。"""
        cagt = self._bound_agent()
        # 绑定确认已写入证据并晋升；后续阶梯验证不能抓卡或将其降级。
        self.assertEqual(self._agent_row(cagt)["verification_level"], "commerce_verified")

        class _ExplodingFetcher:
            def fetch(self, *args: Any, **kwargs: Any) -> Any:
                raise AssertionError("bound agent must not be fetched")

        from kiwi_catalog.services.agent_verification import VerificationService

        with db_session(self.db_path) as conn:
            service = VerificationService(conn, fetcher=_ExplodingFetcher())  # type: ignore[arg-type]
            result = service.verify(cagt, force=True)
        self.assertEqual(result.status, "commerce_verified")
        row = self._agent_row(cagt)
        self.assertEqual(row["verification_level"], "commerce_verified")
        self.assertEqual(row["verification_status"], "commerce_verified")
        self.assertEqual(row["freshness_state"], "fresh")
        # granular verify_profile 同样跳过
        with db_session(self.db_path) as conn:
            service = VerificationService(conn, fetcher=_ExplodingFetcher())  # type: ignore[arg-type]
            result = service.verify_profile(cagt)
        self.assertEqual(result.status, "commerce_verified")
        self.assertEqual(self._agent_row(cagt)["verification_level"], "commerce_verified")
        # 审计记 skipped: cloud binding
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            audits = conn.execute(
                "select details_json from audit_events"
                " where event = 'catalog_agent_verification_skipped' order by rowid"
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual(len(audits), 2)
        for a in audits:
            self.assertEqual(json.loads(a["details_json"])["reason"], "skipped: cloud binding")

    def test_expired_evidence_still_not_degraded(self) -> None:
        """证据过期后重算仍不降级（短路由活动绑定驱动，不依赖证据未过期）。"""
        cagt = self._bound_agent()
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "update agent_verifications set expires_at = '2020-01-01T00:00:00+00:00'"
                " where catalog_agent_id = ?",
                (cagt,),
            )
            conn.commit()
        finally:
            conn.close()

        class _ExplodingFetcher:
            def fetch(self, *args: Any, **kwargs: Any) -> Any:
                raise AssertionError("bound agent must not be fetched")

        from kiwi_catalog.services.agent_verification import VerificationService

        with db_session(self.db_path) as conn:
            service = VerificationService(conn, fetcher=_ExplodingFetcher())  # type: ignore[arg-type]
            service.verify(cagt, force=True)
        self.assertEqual(self._agent_row(cagt)["verification_level"], "commerce_verified")

    def test_unbound_agent_unchanged(self) -> None:
        """无绑定的普通 agent 行为与今天一致：缺端点 → REJECTED + 证据重算降级。"""
        from kiwi_catalog.agent_catalog.sqlite_repository import new_catalog_agent_id, upsert_catalog_agent
        from kiwi_catalog.services.agent_verification import VerificationService

        cagt = new_catalog_agent_id()
        with db_session(self.db_path) as conn:
            upsert_catalog_agent(
                conn, cagt, merchant_id="mkt_direct", display_name="Direct",
                canonical_domain="direct.example",
            )
        with db_session(self.db_path) as conn:
            result = VerificationService(conn).verify(cagt, force=True)
        # 缺 agent_card/ucp_profile 端点 → REJECTED 证据失效 → 证据重算降级 +
        # freshness STALE（折叠投影为 stale；与既有语义一致，不因 D5 改变）
        self.assertEqual(result.status, "stale")
        self.assertEqual(self._agent_row(cagt)["verification_level"], "discovered")


if __name__ == "__main__":
    unittest.main()
