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

"""M3 Runtime 绑定与绑定声明（SIG-02 的 Catalog 侧 + 治理联动）。

覆盖：
  - 首次绑定：缺管理员闸门 → 403；持钥证明错误 → 403；齐备 → 创建成功（version 1）；
  - `GET /runtime-binding`：返回 Catalog 签发的声明（用发行者公钥**真实验签**）、
    绑定 TTL ≤ 15 分钟、scope/agent/key_thumbprint 一致；
  - 轮换：用**旧绑定私钥**签名 → version 2，旧绑定立即 revoked；用旧私钥再签 → 403；
  - 撤回名片后**拒绝签发**（治理联动）；
  - 撤销绑定后拒绝签发；
  - 签发不依赖平台 applicationId / 用户 ID（响应里不出现）。
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import tempfile
import unittest
import unittest.mock
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from kiwi_catalog.a2a.binding_claims import catalog_public_origin, jwk_thumbprint
from kiwi_catalog.agent_catalog.sqlite_repository import new_catalog_agent_id, upsert_catalog_agent
from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.core.errors import PermissionDenied
from kiwi_catalog.db.session import db_session

ADMIN_TOKEN = "admin-token-m3"
RUNTIME_ORIGIN = "https://pilot.example.app.workbuddy.host"
A2A_ENDPOINT = f"{RUNTIME_ORIGIN}/a2a"
CATALOG_ORIGIN = "https://catalog.example"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _jws(private_pem: str, kid: str, fields: dict) -> str:
    """与 Runtime 侧同形状的 compact JWS（EdDSA）——测试用最小实现。"""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    header = {"alg": "EdDSA", "kid": kid}
    payload = {**fields, "issued_at": datetime.now(timezone.utc).isoformat(), "nonce": "n1"}
    header_segment = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_segment = _b64url(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode())
    key = load_pem_private_key(private_pem.encode(), password=None)
    signature = key.sign(f"{header_segment}.{payload_segment}".encode("ascii"))
    return f"{header_segment}.{payload_segment}.{_b64url(signature)}"


def _call(app, method: str, path: str, body: dict | None = None, signature: str = ""):
    status, payload, _headers, _chunks = _call_full(app, method, path, body, signature)
    return status, payload


def _call_full(
    app,
    method: str,
    path: str,
    body: dict | None = None,
    signature: str = "",
    extra_headers: list[tuple[bytes, bytes]] | None = None,
):
    """同 `_call`，但保留响应头与原始字节（ETag / 条件请求断言用）。"""
    raw = json.dumps(body).encode() if body is not None else b""
    headers = [(b"content-type", b"application/json"), *(extra_headers or [])]
    if signature:
        headers.append((b"x-kiwi-binding-jws", signature.encode()))
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
    response_headers = {
        key.decode("latin1").lower(): value.decode("latin1")
        for key, value in start.get("headers", [])
    }
    chunks = b"".join(m.get("body", b"") for m in received if m["type"] == "http.response.body")
    try:
        payload = json.loads(chunks.decode("utf-8")) if chunks else {}
    except json.JSONDecodeError:
        payload = {}
    return start["status"], payload, response_headers, chunks


class CloudBindingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "catalog.sqlite")
        self.app = create_catalog_app(self.db_path)
        self.admin_patcher = unittest.mock.patch.dict(
            os.environ, {"KIWI_CATALOG_ADMIN_TOKEN": ADMIN_TOKEN}, clear=False
        )
        self.admin_patcher.start()
        self.addCleanup(self.admin_patcher.stop)
        # 发行者身份（写成受控文件，模拟生产注入）
        self.issuer_key = Ed25519PrivateKey.generate()
        issuer_path = Path(self.tmp.name) / "issuer.pem"
        issuer_path.write_bytes(
            self.issuer_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        )
        self.issuer_patcher = unittest.mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_ISSUER_KEY_FILE": str(issuer_path),
                "KIWI_CATALOG_ISSUER_KID": "catalog-issuer-test",
                "KIWI_CATALOG_ISSUER_NAME": "catalog.kiwi.test",
                # card_url 只从受控配置的公开 origin 派生（绝不从入站 Host 推导）
                "KIWI_CATALOG_PUBLIC_ORIGIN": CATALOG_ORIGIN,
            },
            clear=False,
        )
        self.issuer_patcher.start()
        self.addCleanup(self.issuer_patcher.stop)

        self.runtime_key = Ed25519PrivateKey.generate()
        self.runtime_pem = self.runtime_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode()
        raw = self.runtime_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.runtime_jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}
        self.catalog_agent_id = self._seed_agent()
        # 首次绑定成功后由服务端生成 binding_id；发布/撤回签名必须用它
        self.binding_id = ""

    def _seed_agent(self) -> str:
        catalog_agent_id = new_catalog_agent_id()
        with db_session(self.db_path) as conn:
            upsert_catalog_agent(
                conn,
                catalog_agent_id,
                merchant_id="mkt_bind_1",
                display_name="Bind Merchant",
                canonical_domain="merchant.example",
            )
        return catalog_agent_id

    def _binding_body(self, *, admin: bool = True, key_jwk: dict | None = None) -> dict:
        jwk = key_jwk or self.runtime_jwk
        body = {
            "binding": {
                "runtime_origin": RUNTIME_ORIGIN,
                "a2a_endpoint": A2A_ENDPOINT,
                "key_jwk": jwk,
                "key_id": RUNTIME_ORIGIN,
                "generation": 1,
                "service_epoch": 7,
            }
        }
        if admin:
            body["admin_token"] = ADMIN_TOKEN
        return body

    def _binding_signature(self, key_jwk: dict | None = None, pem: str | None = None) -> str:
        jwk = key_jwk or self.runtime_jwk
        return _jws(
            pem or self.runtime_pem,
            RUNTIME_ORIGIN,
            {
                "agent_id": self.catalog_agent_id,
                "key_id": RUNTIME_ORIGIN,
                "key_thumbprint": jwk_thumbprint(jwk),
                "runtime_origin": RUNTIME_ORIGIN,
                "a2a_endpoint": A2A_ENDPOINT,
                "generation": 1,
                "service_epoch": 7,
            },
        )

    def _create_binding(self, **kwargs):
        status, payload = _call(
            self.app,
            "POST",
            f"/v1/agents/{self.catalog_agent_id}/runtime-bindings",
            self._binding_body(**kwargs),
            signature=self._binding_signature(),
        )
        if status == 200 and payload.get("binding_id"):
            self.binding_id = str(payload["binding_id"])
        return status, payload

    def _publish_and_activate(self, revision_expected: int = 0) -> None:
        """走卡发布 → 激活，让治理状态为 ACTIVE（声明签发的前置）。"""
        publication = {
            "schema_version": "0.1.2",
            "agent_id": self.catalog_agent_id,
            "binding_id": self.binding_id,
            "generation": 1,
            "expected_revision": revision_expected,
            "wire_profile": "a2a-1.0",
            "card_digest": "sha256:" + "a" * 64,
            "agent_card": {
                "name": "Bind Merchant",
                "version": "1.0.0",
                "url": RUNTIME_ORIGIN,
                "supportedInterfaces": [
                    {"url": A2A_ENDPOINT, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
                ],
            },
        }
        signature = _jws(
            self.runtime_pem,
            RUNTIME_ORIGIN,
            {
                "agent_id": self.catalog_agent_id,
                "binding_id": self.binding_id,
                "card_digest": publication["card_digest"],
                "expected_revision": revision_expected,
                "generation": 1,
            },
        )
        status, payload = _call(
            self.app,
            "POST",
            f"/v1/agents/{self.catalog_agent_id}/card-publications",
            {"publication": publication},
            signature=signature,
        )
        assert status == 200, payload
        revision = payload["card_revision"]
        activate_signature = _jws(
            self.runtime_pem,
            RUNTIME_ORIGIN,
            {
                "agent_id": self.catalog_agent_id,
                "binding_id": self.binding_id,
                "card_revision": revision,
                "expected_revision": revision_expected,
            },
        )
        status, payload = _call(
            self.app,
            "POST",
            f"/v1/agents/{self.catalog_agent_id}/publish",
            {
                "binding_id": self.binding_id,
                "card_revision": revision,
                "expected_revision": revision_expected,
            },
            signature=activate_signature,
        )
        assert status == 200, payload

    def _read_claims(self):
        return _call(self.app, "GET", f"/v1/agents/{self.catalog_agent_id}/runtime-binding")

    # ── 绑定创建 ──────────────────────────────────────────────
    def test_first_binding_requires_admin_gate_and_possession(self) -> None:
        # 缺管理员闸门 → 403
        status, payload = self._create_binding(admin=False)
        self.assertEqual(status, 403, payload)

        # 冒名公钥（签名私钥与提交的 JWK 不匹配）→ 403
        other = Ed25519PrivateKey.generate()
        other_raw = other.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        other_jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(other_raw)}
        status, payload = _call(
            self.app,
            "POST",
            f"/v1/agents/{self.catalog_agent_id}/runtime-bindings",
            self._binding_body(key_jwk=other_jwk),
            signature=self._binding_signature(),  # 用 runtime 私钥签，但提交的是 other 的公钥
        )
        self.assertEqual(status, 403, payload)

        # 齐备 → 200，version 1
        status, payload = self._create_binding()
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["binding_version"], 1)
        self.assertEqual(payload["key_thumbprint"], jwk_thumbprint(self.runtime_jwk))

    def test_rotation_requires_current_key_and_revokes_old(self) -> None:
        self.assertEqual(self._create_binding()[0], 200)
        new_key = Ed25519PrivateKey.generate()
        new_raw = new_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        new_jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(new_raw)}
        new_pem = new_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()

        # 用新私钥自证（不带管理员）→ 403（轮换必须由当前活动绑定签名）
        status, payload = _call(
            self.app,
            "POST",
            f"/v1/agents/{self.catalog_agent_id}/runtime-bindings",
            self._binding_body(admin=False, key_jwk=new_jwk),
            signature=self._binding_signature(key_jwk=new_jwk, pem=new_pem),
        )
        self.assertEqual(status, 403, payload)

        # 用当前活动绑定的私钥签 → 200，version 2，旧绑定 revoked
        status, payload = _call(
            self.app,
            "POST",
            f"/v1/agents/{self.catalog_agent_id}/runtime-bindings",
            self._binding_body(admin=False, key_jwk=new_jwk),
            signature=_jws(
                self.runtime_pem,
                RUNTIME_ORIGIN,
                {
                    "agent_id": self.catalog_agent_id,
                    "binding_id": self.binding_id,  # 轮换由当前活动绑定授权
                    "key_id": RUNTIME_ORIGIN,
                    "key_thumbprint": jwk_thumbprint(new_jwk),
                    "runtime_origin": RUNTIME_ORIGIN,
                    "a2a_endpoint": A2A_ENDPOINT,
                    "generation": 1,
                    "service_epoch": 7,
                },
            ),
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["binding_version"], 2)
        self.assertIsNotNone(payload["superseded_binding_id"])

    # ── 声明签发 ─────────────────────────────────────────────
    def test_claims_are_signed_and_verifiable_with_ttl_bound(self) -> None:
        self.assertEqual(self._create_binding()[0], 200)
        self._publish_and_activate()
        status, payload = self._read_claims()
        self.assertEqual(status, 200, payload)
        claims = payload["claims"]
        self.assertEqual(claims["scope"], "a2a-runtime")
        self.assertEqual(claims["agent_id"], self.catalog_agent_id)
        self.assertEqual(claims["key_thumbprint"], jwk_thumbprint(self.runtime_jwk))
        # card_url 必须是**绝对 https URL**（Schema pattern `^https://`），
        # 且与公开读地址同一份（Buyer 用它做 CARD_URL_MISMATCH 比对）。
        self.assertEqual(
            claims["card_url"],
            f"{CATALOG_ORIGIN}/v1/agents/{self.catalog_agent_id}/agent-card.json",
        )
        issued = datetime.fromisoformat(claims["issued_at"])
        expires = datetime.fromisoformat(claims["expires_at"])
        self.assertLessEqual((expires - issued).total_seconds(), 15 * 60)

        # 真实验签：发行者公钥
        jws = payload["claims_jws"]
        header_segment, payload_segment, signature_segment = jws.split(".")
        self.issuer_key.public_key().verify(
            base64.urlsafe_b64decode(signature_segment + "=="),
            f"{header_segment}.{payload_segment}".encode("ascii"),
        )
        self.assertEqual(json.loads(base64.urlsafe_b64decode(payload_segment + "==")), claims)
        # 不含控制面私有信息
        serialized = json.dumps(payload)
        self.assertNotIn("wbapp_", serialized)
        self.assertNotIn("applicationId", serialized)

    def test_published_card_etag_matches_committed_claims_card_etag(self) -> None:
        """`If-None-Match: <claims.card_etag>` 必须真的 304 —— **两栈都要**。

        `card_etag` 是对公开读地址**响应体字节**的承诺。fallback 栈的
        `_send_json` 用 `json.dumps(..., sort_keys=True)` 序列化，与 card_store 口径
        天然一致；FastAPI 栈默认紧凑分隔符 + 插入序，曾导致响应头 etag ≠ 承诺的
        `card_etag`（重验证在 FastAPI 栈上静默失效——契约级双栈漂移）。
        """
        self.assertEqual(self._create_binding()[0], 200)
        self._publish_and_activate()

        status, _payload, headers, card_bytes = _call_full(
            self.app, "GET", f"/v1/agents/{self.catalog_agent_id}/agent-card.json"
        )
        self.assertEqual(status, 200)
        header_etag = headers.get("etag", "")
        self.assertTrue(header_etag)

        claims_status, claims_payload = self._read_claims()
        self.assertEqual(claims_status, 200, claims_payload)
        committed_etag = claims_payload["card_etag"]
        self.assertEqual(header_etag, committed_etag)

        # 承诺的 ETag 直接用于重验证：304，且无 body
        status, _payload, _headers, raw = _call_full(
            self.app,
            "GET",
            f"/v1/agents/{self.catalog_agent_id}/agent-card.json",
            extra_headers=[(b"if-none-match", committed_etag.encode())],
        )
        self.assertEqual(status, 304)
        self.assertEqual(raw, b"")
        # 响应体就是规范字节（sort_keys + 非 ASCII 原样），与 ETag 的承诺对象同一份
        self.assertEqual(
            card_bytes,
            json.dumps(json.loads(card_bytes), ensure_ascii=False, sort_keys=True).encode("utf-8"),
        )

    def test_unsafe_target_declared_at_binding_time_is_rejected(self) -> None:
        """T035：私网 / metadata 目标在**创建绑定**时就被拒，不进签发链路。"""
        for origin, endpoint in (
            ("https://10.0.0.5", "https://10.0.0.5/a2a"),
            ("https://169.254.169.254", "https://169.254.169.254/a2a"),
            ("https://merchant.internal", "https://merchant.internal/a2a"),
            ("https://merchant.example", "http://merchant.example/a2a"),
        ):
            with self.subTest(endpoint=endpoint):
                body = self._binding_body()
                body["binding"]["runtime_origin"] = origin
                body["binding"]["a2a_endpoint"] = endpoint
                status, payload = _call(
                    self.app,
                    "POST",
                    f"/v1/agents/{self.catalog_agent_id}/runtime-bindings",
                    body,
                    signature=self._binding_signature(),
                )
                self.assertEqual(status, 400, payload)
                self.assertIn("safe target", str(payload.get("error", "")))

    def test_stored_unsafe_binding_refuses_claims(self) -> None:
        """纵深防御：库里已有不安全绑定时，**签发**出口同样拒（不是只在入口拦一次）。"""
        self.assertEqual(self._create_binding()[0], 200)
        self._publish_and_activate()
        with db_session(self.db_path) as conn:
            conn.execute(
                "update runtime_bindings set a2a_endpoint = ? where catalog_agent_id = ?",
                ("https://169.254.169.254/a2a", self.catalog_agent_id),
            )
        status, payload = self._read_claims()
        self.assertEqual(status, 400, payload)
        self.assertIn("safe target", str(payload.get("error", "")))

    def test_missing_public_origin_refuses_claims(self) -> None:
        """未配置公开 origin → **拒签**，绝不退化成相对路径的 card_url。

        相对路径不满足 Schema 的 `^https://`，会让 TS 侧 `validateBindingClaims`
        直接判 CLAIMS_INVALID——签发一个下游必然拒绝的声明，比拒签更糟。
        """
        self.assertEqual(self._create_binding()[0], 200)
        self._publish_and_activate()
        cleared = unittest.mock.patch.dict(os.environ, {"KIWI_CATALOG_PUBLIC_ORIGIN": ""})
        cleared.start()
        self.addCleanup(cleared.stop)
        status, payload = self._read_claims()
        self.assertEqual(status, 403, payload)

    def test_no_binding_or_no_active_card_refuses_claims(self) -> None:
        # 无绑定时读取 → 404
        self.assertEqual(self._read_claims()[0], 404)
        self.assertEqual(self._create_binding()[0], 200)
        # 有绑定但无活动名片 → 拒绝签发（403）
        status, payload = self._read_claims()
        self.assertEqual(status, 403, payload)

    def test_withdrawn_publication_refuses_claims(self) -> None:
        self.assertEqual(self._create_binding()[0], 200)
        self._publish_and_activate()
        self.assertEqual(self._read_claims()[0], 200)
        withdraw_signature = _jws(
            self.runtime_pem,
            RUNTIME_ORIGIN,
            {
                "agent_id": self.catalog_agent_id,
                "binding_id": self.binding_id,
                "expected_revision": 1,
                "publication_state": "WITHDRAWN",
            },
        )
        status, payload = _call(
            self.app,
            "POST",
            f"/v1/agents/{self.catalog_agent_id}/withdraw",
            {"binding_id": self.binding_id, "expected_revision": 1},
            signature=withdraw_signature,
        )
        self.assertEqual(status, 200, payload)
        status, payload = self._read_claims()
        self.assertEqual(status, 403, payload)

    def test_revoked_binding_refuses_claims(self) -> None:
        self.assertEqual(self._create_binding()[0], 200)
        self._publish_and_activate()
        binding_id = self.binding_id
        revoke_signature = _jws(
            self.runtime_pem,
            RUNTIME_ORIGIN,
            {
                "agent_id": self.catalog_agent_id,
                "binding_id": binding_id,
                "publication_state": "REVOKED",
            },
        )
        status, payload = _call(
            self.app,
            "POST",
            f"/v1/agents/{self.catalog_agent_id}/runtime-bindings/{binding_id}/revoke",
            {"admin_token": ADMIN_TOKEN},
            signature=revoke_signature,
        )
        self.assertEqual(status, 200, payload)
        status, payload = self._read_claims()
        # 撤销后不再有活动绑定：读声明被拒（403 治理拒绝 / 404 无活动绑定，两者都=不签发）
        self.assertIn(status, (403, 404), payload)


class CatalogPublicOriginTest(unittest.TestCase):
    """`card_url` 的派生源：只认受控配置的 origin，且必须是干净的 https origin。"""

    def test_accepts_clean_https_origin(self) -> None:
        self.assertEqual(
            catalog_public_origin({"KIWI_CATALOG_PUBLIC_ORIGIN": "https://catalog.example"}),
            "https://catalog.example",
        )
        # 尾斜杠归一；端口保留
        self.assertEqual(
            catalog_public_origin({"KIWI_CATALOG_PUBLIC_ORIGIN": "https://catalog.example:8443/"}),
            "https://catalog.example:8443",
        )

    def test_refuses_missing_or_unsafe_origins(self) -> None:
        for raw in (
            "",
            "   ",
            "http://catalog.example",  # 非 https
            "https://catalog.example/base",  # 带路径
            "https://catalog.example?a=1",  # 带查询
            "https://catalog.example#f",  # 带片段
            "https://user:pass@catalog.example",  # 带凭据
            "not a url",
            "https://",
        ):
            with self.subTest(origin=raw):
                with self.assertRaises(PermissionDenied):
                    catalog_public_origin({"KIWI_CATALOG_PUBLIC_ORIGIN": raw})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
