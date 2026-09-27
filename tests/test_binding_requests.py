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

"""首次绑定两步闭环测试（D1/D2；设计 §4.3③/§8/§10）。

覆盖（§8 验收「未决绑定」「确认/拒绝」条目）：
- 未决绑定：危险目标拒、错签名拒、nonce 重放拒、超 TTL 视为不存在
  （读路径过滤 + 惰性标 expired）、超未决上限拒；未确认期间公开读 404；
- 确认/拒绝：无会话 403、非本商家 404、已决请求重复确认 409、确认后公开读
  出现且 binding_version 正确、canonical_domain 回填（D2）、审计 actor
  正确、确认后同行其他 pending 失效（§10）、拒绝带理由留痕。
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
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from kiwi_catalog.a2a.binding_claims import jwk_thumbprint
from kiwi_catalog.api.app import create_catalog_app

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
    chunks = b"".join(m.get("body", b"") for m in received if m["type"] == "http.response.body")
    try:
        payload = json.loads(chunks.decode("utf-8")) if chunks else {}
    except json.JSONDecodeError:
        payload = {}
    return start["status"], payload


def _runtime_key() -> tuple[str, dict]:
    """生成一对运行时 Ed25519 密钥：(pem, public_jwk)。"""
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return pem, {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}


class BindingRequestFlowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "catalog.sqlite")
        self.app = create_catalog_app(self.db_path)
        # 发行者身份（公开读 /runtime-binding 的声明签发需要）
        issuer_key = Ed25519PrivateKey.generate()
        issuer_path = Path(self.tmp.name) / "issuer.pem"
        issuer_path.write_bytes(
            issuer_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        )
        env_patch = unittest.mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_ADMIN_TOKEN": ADMIN_TOKEN,
                "KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET,
                "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
                "KIWI_CATALOG_PUBLIC_BASE_URL": CATALOG_ORIGIN,
                "KIWI_CATALOG_ISSUER_KEY_FILE": str(issuer_path),
                "KIWI_CATALOG_ISSUER_KID": "catalog-issuer-test",
                "KIWI_CATALOG_ISSUER_NAME": "catalog.kiwi.test",
                "KIWI_CATALOG_PUBLIC_ORIGIN": CATALOG_ORIGIN,
            },
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.runtime_pem, self.runtime_jwk = _runtime_key()

    # ── helpers ───────────────────────────────────────────────────────────

    def _register(self, email: str = "ops@acme.example") -> str:
        body = {**BASE_REGISTER_BODY, "email": email}
        status, payload = _call(self.app, "POST", "/v1/accounts/register", body)
        self.assertEqual(status, 200, payload)
        status, payload = _call(
            self.app, "POST", "/v1/accounts/verify-email",
            {"email": email, "code": payload["verification_code"]},
        )
        self.assertEqual(status, 200, payload)
        # verify-email 的 Set-Cookie 在响应头里（_call 不返回头）——登录拿会话
        return self._login(email)

    def _login(self, email: str) -> str:
        received: list[dict] = []
        raw = json.dumps({"email": email, "password": BASE_REGISTER_BODY["password"]}).encode()

        async def receive():
            return {"type": "http.request", "body": raw, "more_body": False}

        async def send(msg: dict) -> None:
            received.append(msg)

        asyncio.run(
            self.app(
                {
                    "type": "http",
                    "method": "POST",
                    "path": "/v1/accounts/login",
                    "headers": [(b"content-type", b"application/json")],
                    "query_string": b"",
                    "http_version": "1.1",
                    "scheme": "http",
                },
                receive,
                send,
            )
        )
        start = next(m for m in received if m["type"] == "http.response.start")
        headers = {k.decode().lower(): v.decode() for k, v in start.get("headers", [])}
        return headers["set-cookie"].split(";")[0].split("=", 1)[1]

    def _cookie(self, session: str) -> str:
        return f"kiwi_session={session}"

    def _create_agent(self, session: str) -> str:
        status, payload = _call(
            self.app, "POST", "/v1/accounts/agents", {}, cookie=self._cookie(session)
        )
        self.assertEqual(status, 200, payload)
        return payload["catalog_agent_id"]

    def _request_binding(self, cagt: str, *, pem: str | None = None, jwk: dict | None = None,
                         origin: str = RUNTIME_ORIGIN, signature: str = ""):
        pem = pem or self.runtime_pem
        jwk = jwk or self.runtime_jwk
        kid = origin
        body = {
            "binding": {
                "runtime_origin": origin,
                "a2a_endpoint": f"{origin}/a2a",
                "key_jwk": jwk,
                "key_id": kid,
                "generation": 1,
                "service_epoch": 7,
            }
        }
        sig = signature or _jws(
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
        return _call(self.app, "POST", f"/v1/agents/{cagt}/runtime-bindings", body, signature=sig)

    def _read_claims(self, cagt: str):
        return _call(self.app, "GET", f"/v1/agents/{cagt}/runtime-binding")

    def _pending(self, session: str, cagt: str):
        return _call(
            self.app, "GET", f"/v1/accounts/agents/{cagt}/bindings/pending",
            cookie=self._cookie(session),
        )

    def _confirm(self, session: str, cagt: str, request_id: str):
        return _call(
            self.app, "POST", f"/v1/accounts/agents/{cagt}/bindings/{request_id}/confirm",
            {}, cookie=self._cookie(session),
        )

    def _reject(self, session: str, cagt: str, request_id: str, note: str = ""):
        return _call(
            self.app, "POST", f"/v1/accounts/agents/{cagt}/bindings/{request_id}/reject",
            {"note": note}, cookie=self._cookie(session),
        )

    def _request_rows(self, cagt: str) -> list[sqlite3.Row]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            return conn.execute(
                "select * from runtime_binding_requests where catalog_agent_id = ?"
                " order by requested_at",
                (cagt,),
            ).fetchall()
        finally:
            conn.close()

    # ── 端到端：请求 → 确认 ───────────────────────────────────────────────

    def test_request_then_confirm_end_to_end(self) -> None:
        session = self._register()
        cagt = self._create_agent(session)
        # ① 运行时首绑（无 admin）→ 待确认请求，不落 active 绑定
        status, payload = self._request_binding(cagt)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["status"], "pending_confirmation")
        request_id = payload["binding_request_id"]
        self.assertTrue(request_id.startswith("breq_"), payload)
        rows = self._request_rows(cagt)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["status"], "pending")
        self.assertEqual(row["runtime_origin"], RUNTIME_ORIGIN)
        self.assertTrue(row["nonce"])  # nonce 落库（防重放留痕）
        self.assertTrue(row["expires_at"] > row["requested_at"])  # TTL
        # ② 未确认期间公开读不得出现（Catalog 不提前背书）
        status, _ = self._read_claims(cagt)
        self.assertEqual(status, 404)
        # ③ 门户待确认列表（含分辨信息）
        status, payload = self._pending(session, cagt)
        self.assertEqual(status, 200, payload)
        self.assertEqual(len(payload["results"]), 1)
        item = payload["results"][0]
        self.assertEqual(item["binding_request_id"], request_id)
        self.assertEqual(item["runtime_origin"], RUNTIME_ORIGIN)
        self.assertEqual(item["a2a_endpoint"], A2A_ENDPOINT)
        self.assertEqual(len(item["key_thumbprint_short"]), 16)
        self.assertTrue(item["requested_at"])
        # 名片详情的 pending_bindings 同数据
        status, payload = _call(
            self.app, "GET", f"/v1/accounts/agents/{cagt}/card", cookie=self._cookie(session)
        )
        self.assertEqual([q["binding_request_id"] for q in payload["pending_bindings"]], [request_id])
        # ④ 确认 → active 绑定（version 1）+ D2 回填 canonical_domain
        status, payload = self._confirm(session, cagt, request_id)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["status"], "active")
        self.assertEqual(payload["binding_version"], 1)
        self.assertEqual(payload["canonical_domain"], "pilot.example.app.workbuddy.host")
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            binding = conn.execute(
                "select * from runtime_bindings where catalog_agent_id = ?", (cagt,)
            ).fetchone()
            self.assertEqual(binding["status"], "active")
            self.assertEqual(binding["binding_version"], 1)
            agent = conn.execute(
                "select canonical_domain from catalog_agents where catalog_agent_id = ?", (cagt,)
            ).fetchone()
            self.assertEqual(agent["canonical_domain"], "pilot.example.app.workbuddy.host")
            audit = conn.execute(
                "select actor, event from audit_events"
                " where event like 'runtime_binding_%' order by rowid"
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual(
            [(r["event"], r["actor"]) for r in audit],
            [
                ("runtime_binding_requested", f"possession:{RUNTIME_ORIGIN}"),
                ("runtime_binding_confirmed", f"merchant:{binding['merchant_id']}"),
            ],
        )
        # ⑤ 确认后**立即**公开读可读（不需要先有名片——否则运行时拿不到
        # binding_id 无法签名首发，死锁）：200 + 声明，治理态给诚实值
        # UNPUBLISHED，无版本号/etag。
        status, payload = self._read_claims(cagt)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["claims"]["binding_version"], 1)
        self.assertEqual(payload["claims"]["runtime_origin"], RUNTIME_ORIGIN)
        self.assertEqual(payload["claims"]["status"], "active")
        self.assertEqual(payload["governance"]["publication_state"], "UNPUBLISHED")
        self.assertIsNone(payload["card_revision"])
        self.assertIsNone(payload["card_etag"])
        # ⑥ 已决请求重复确认 → 409；待确认列表已空
        status, payload = self._confirm(session, cagt, request_id)
        self.assertEqual(status, 409, payload)
        status, payload = self._pending(session, cagt)
        self.assertEqual(payload["results"], [])

    def test_confirm_to_first_publish_end_to_end(self) -> None:
        """§8 端到端最小闭环：确认 → 公开读拿 binding_id → 运行时签名首发
        （card-publications + publish）→ 激活后公开读 publication_state=ACTIVE。"""
        session = self._register()
        cagt = self._create_agent(session)
        status, payload = self._request_binding(cagt)
        self.assertEqual(status, 200, payload)
        status, payload = self._confirm(session, cagt, payload["binding_request_id"])
        self.assertEqual(status, 200, payload)
        # 公开读拿到 binding_id（未发布名片也可读）
        status, payload = self._read_claims(cagt)
        self.assertEqual(status, 200, payload)
        binding_id = payload["claims"]["binding_id"]
        # 运行时签名首发：创建版本（不激活）
        publication = {
            "schema_version": "0.1.2",
            "agent_id": cagt,
            "binding_id": binding_id,
            "generation": 1,
            "expected_revision": 0,
            "wire_profile": "a2a-1.0",
            "card_digest": "sha256:" + "b" * 64,
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
        status, payload = _call(
            self.app, "POST", f"/v1/agents/{cagt}/card-publications",
            {"publication": publication}, signature=sig,
        )
        self.assertEqual(status, 200, payload)
        revision = payload["card_revision"]
        # CAS 激活
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
        status, payload = _call(
            self.app, "POST", f"/v1/agents/{cagt}/publish",
            {"binding_id": binding_id, "card_revision": revision, "expected_revision": 0},
            signature=sig,
        )
        self.assertEqual(status, 200, payload)
        # 激活后公开读：publication_state=ACTIVE + 版本号/etag 就位
        status, payload = self._read_claims(cagt)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["governance"]["publication_state"], "ACTIVE")
        self.assertEqual(payload["card_revision"], 1)
        self.assertTrue(payload["card_etag"])
        # 撤回后公开读 403（SIG-02 拒签语义不变）
        sig = _jws(
            self.runtime_pem,
            RUNTIME_ORIGIN,
            {
                "agent_id": cagt,
                "binding_id": binding_id,
                "expected_revision": 1,
                "publication_state": "WITHDRAWN",
            },
        )
        status, payload = _call(
            self.app, "POST", f"/v1/agents/{cagt}/withdraw",
            {"binding_id": binding_id, "expected_revision": 1}, signature=sig,
        )
        self.assertEqual(status, 200, payload)
        status, _ = self._read_claims(cagt)
        self.assertEqual(status, 403)

    def test_confirm_supersedes_other_pending(self) -> None:
        """§10：确认后同行其他 pending 请求即失效（标 expired，视为不存在）。"""
        session = self._register()
        cagt = self._create_agent(session)
        pem2, jwk2 = _runtime_key()
        status, first = self._request_binding(cagt)
        self.assertEqual(status, 200, first)
        status, second = self._request_binding(cagt, pem=pem2, jwk=jwk2)
        self.assertEqual(status, 200, second)
        status, payload = self._confirm(session, cagt, first["binding_request_id"])
        self.assertEqual(status, 200, payload)
        rows = {str(r["binding_request_id"]): str(r["status"]) for r in self._request_rows(cagt)}
        self.assertEqual(rows[first["binding_request_id"]], "confirmed")
        self.assertEqual(rows[second["binding_request_id"]], "expired")
        # 被顶掉的请求再确认：expired 视为不存在 → 404
        status, payload = self._confirm(session, cagt, second["binding_request_id"])
        self.assertEqual(status, 404, payload)

    # ── 拒绝 ──────────────────────────────────────────────────────────────

    def test_reject_flow(self) -> None:
        session = self._register()
        cagt = self._create_agent(session)
        status, payload = self._request_binding(cagt)
        request_id = payload["binding_request_id"]
        # 理由必填
        status, payload = self._reject(session, cagt, request_id, note="  ")
        self.assertEqual(status, 400, payload)
        # 带理由拒绝 → rejected 留痕 + 审计
        status, payload = self._reject(session, cagt, request_id, note="不是我发起的")
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["status"], "rejected")
        rows = self._request_rows(cagt)
        self.assertEqual(rows[0]["status"], "rejected")
        self.assertEqual(rows[0]["decided_note"], "不是我发起的")
        self.assertTrue(rows[0]["decided_at"])
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            audit = conn.execute(
                "select actor, event from audit_events where event = 'runtime_binding_rejected'"
            ).fetchone()
            merchant_id = conn.execute(
                "select merchant_id from catalog_agents where catalog_agent_id = ?", (cagt,)
            ).fetchone()["merchant_id"]
        finally:
            conn.close()
        self.assertEqual(audit["actor"], f"merchant:{merchant_id}")
        # 已决重复决策 → 409；公开读仍 404；待确认列表空
        status, _ = self._reject(session, cagt, request_id, note="again")
        self.assertEqual(status, 409)
        status, _ = self._read_claims(cagt)
        self.assertEqual(status, 404)
        status, payload = self._pending(session, cagt)
        self.assertEqual(payload["results"], [])

    # ── 未决约束：TTL / 上限 / 重放 / 闸门 ────────────────────────────────

    def test_expired_request_invisible_and_lazy_marked(self) -> None:
        """超 TTL 视为不存在：读路径过滤 + 惰性标 expired。"""
        session = self._register()
        cagt = self._create_agent(session)
        status, payload = self._request_binding(cagt)
        request_id = payload["binding_request_id"]
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "update runtime_binding_requests set expires_at = '2020-01-01T00:00:00+00:00'"
                " where binding_request_id = ?",
                (request_id,),
            )
            conn.commit()
        finally:
            conn.close()
        status, payload = self._pending(session, cagt)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["results"], [])
        rows = self._request_rows(cagt)
        self.assertEqual(rows[0]["status"], "expired")  # 惰性标记
        status, payload = self._confirm(session, cagt, request_id)
        self.assertEqual(status, 404, payload)

    def test_pending_cap_rejects_overflow(self) -> None:
        """每 agent 未决上限（默认 3）：第 4 条拒绝。"""
        session = self._register()
        cagt = self._create_agent(session)
        for i in range(3):
            status, payload = self._request_binding(cagt)
            self.assertEqual(status, 200, (i, payload))
        status, payload = self._request_binding(cagt)
        self.assertEqual(status, 409, payload)
        self.assertEqual(len(self._request_rows(cagt)), 3)

    def test_nonce_replay_rejected(self) -> None:
        """同一签名重放 → 第二次 403（nonce 已消费）。"""
        session = self._register()
        cagt = self._create_agent(session)
        signature = _jws(
            self.runtime_pem,
            RUNTIME_ORIGIN,
            {
                "agent_id": cagt,
                "key_id": RUNTIME_ORIGIN,
                "key_thumbprint": jwk_thumbprint(self.runtime_jwk),
                "runtime_origin": RUNTIME_ORIGIN,
                "a2a_endpoint": A2A_ENDPOINT,
                "generation": 1,
                "service_epoch": 7,
            },
        )
        status, payload = self._request_binding(cagt, signature=signature)
        self.assertEqual(status, 200, payload)
        status, payload = self._request_binding(cagt, signature=signature)
        self.assertEqual(status, 403, payload)
        self.assertEqual(len(self._request_rows(cagt)), 1)

    def test_bad_signature_and_unsafe_target_rejected(self) -> None:
        """错签名 → 403；危险目标 → 拒（不落请求行）。"""
        session = self._register()
        cagt = self._create_agent(session)
        # 冒名公钥：用 runtime 私钥签但提交另一把公钥
        other_pem, other_jwk = _runtime_key()
        status, payload = self._request_binding(cagt, pem=self.runtime_pem, jwk=other_jwk)
        self.assertEqual(status, 403, payload)
        # 危险目标（cloud metadata）
        status, payload = self._request_binding(cagt, origin="http://169.254.169.254")
        self.assertIn(status, (400, 403), payload)
        self.assertEqual(self._request_rows(cagt), [])

    # ── 门户端点鉴权与归属 ────────────────────────────────────────────────

    def test_portal_endpoints_auth_and_ownership(self) -> None:
        session_a = self._register("a@acme.example")
        cagt = self._create_agent(session_a)
        status, payload = self._request_binding(cagt)
        request_id = payload["binding_request_id"]
        paths = (
            ("GET", f"/v1/accounts/agents/{cagt}/bindings/pending"),
            ("POST", f"/v1/accounts/agents/{cagt}/bindings/{request_id}/confirm"),
            ("POST", f"/v1/accounts/agents/{cagt}/bindings/{request_id}/reject"),
        )
        # 无会话 → 403（仓库会话约定）
        for method, path in paths:
            status, payload = _call(self.app, method, path, {} if method == "POST" else None)
            self.assertEqual(status, 403, (method, path, payload))
        # 非本商家 → 404（与不存在不可区分）
        session_b = self._register("b@acme.example")
        for method, path in paths:
            status, payload = _call(
                self.app, method, path, {} if method == "POST" else None,
                cookie=self._cookie(session_b),
            )
            self.assertEqual(status, 404, (method, path, payload))
        # 未知请求 id → 404
        status, payload = self._confirm(session_a, cagt, "breq_nonexistent")
        self.assertEqual(status, 404, payload)


if __name__ == "__main__":
    unittest.main()
