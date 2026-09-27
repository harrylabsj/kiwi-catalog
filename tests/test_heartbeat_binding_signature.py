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

"""D6 心跳鉴权测试：heartbeat 接受**活动绑定的私钥签名**（设计 §4.5/§7-D6/§8）。

覆盖（§8「心跳（D6）」条目）：
- 绑定签名心跳成功（真实 Ed25519 签名，与名片发布/绑定同一套
  verify_runtime_request，expected_fields 锁死 agent_id）；
- 无签名/错签名被拒（403，与既有失败同码同形）；nonce 重放拒；
- revoked / 过期绑定的签名被拒；
- 心跳后 freshness 按 TTL 复 fresh（stale → fresh）；
- owner token / admin 旧路径不变（既有 test_agent_freshness 守护，不重写）。
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

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from kiwi_catalog.a2a.binding_claims import jwk_thumbprint
from kiwi_catalog.agent_catalog.sqlite_repository import new_catalog_agent_id, upsert_catalog_agent
from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.db.session import db_session

ADMIN_TOKEN = "admin-token-m3"
RUNTIME_ORIGIN = "https://pilot.example.app.workbuddy.host"
A2A_ENDPOINT = f"{RUNTIME_ORIGIN}/a2a"


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


def _call(app, method: str, path: str, body: dict | None = None, signature: str = ""):
    raw = json.dumps(body).encode() if body is not None else b""
    headers = [(b"content-type", b"application/json")]
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
    chunks = b"".join(m.get("body", b"") for m in received if m["type"] == "http.response.body")
    try:
        payload = json.loads(chunks.decode("utf-8")) if chunks else {}
    except json.JSONDecodeError:
        payload = {}
    return start["status"], payload


class HeartbeatBindingSignatureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "catalog.sqlite")
        self.app = create_catalog_app(self.db_path)
        env_patch = unittest.mock.patch.dict(
            os.environ, {"KIWI_CATALOG_ADMIN_TOKEN": ADMIN_TOKEN}, clear=False
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        key = Ed25519PrivateKey.generate()
        self.runtime_pem = key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode()
        raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.runtime_jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}
        self.cagt = new_catalog_agent_id()
        with db_session(self.db_path) as conn:
            upsert_catalog_agent(
                conn, self.cagt, merchant_id="mkt_hb", display_name="HB Merchant"
            )
        # admin + 持钥证明直绑（运维兜底路径），拿到活动绑定
        body = {
            "binding": {
                "runtime_origin": RUNTIME_ORIGIN,
                "a2a_endpoint": A2A_ENDPOINT,
                "key_jwk": self.runtime_jwk,
                "key_id": RUNTIME_ORIGIN,
                "generation": 1,
                "service_epoch": 7,
            },
            "admin_token": ADMIN_TOKEN,
        }
        sig = _jws(
            self.runtime_pem,
            RUNTIME_ORIGIN,
            {
                "agent_id": self.cagt,
                "key_id": RUNTIME_ORIGIN,
                "key_thumbprint": jwk_thumbprint(self.runtime_jwk),
                "runtime_origin": RUNTIME_ORIGIN,
                "a2a_endpoint": A2A_ENDPOINT,
                "generation": 1,
                "service_epoch": 7,
            },
        )
        status, payload = _call(
            self.app, "POST", f"/v1/agents/{self.cagt}/runtime-bindings", body, signature=sig
        )
        self.assertEqual(status, 200, payload)
        self.binding_id = str(payload["binding_id"])

    def _heartbeat_sig(self, *, pem: str | None = None, kid: str = RUNTIME_ORIGIN,
                       agent_id: str | None = None, binding_id: str | None = None) -> str:
        return _jws(
            pem or self.runtime_pem,
            kid,
            {
                "agent_id": agent_id or self.cagt,
                "binding_id": binding_id or self.binding_id,
            },
        )

    def _heartbeat(self, signature: str = "", body: dict | None = None):
        return _call(
            self.app, "POST", f"/v1/agent-catalog/agents/{self.cagt}/heartbeat",
            body if body is not None else {}, signature=signature,
        )

    # ── 成功路径 ──────────────────────────────────────────────────────────

    def test_binding_signature_heartbeat_succeeds(self) -> None:
        # 先打回 stale（模拟 TTL 过期），签名心跳应复活 freshness
        with db_session(self.db_path) as conn:
            conn.execute(
                "update catalog_agents set freshness_state = 'stale', last_seen_at = ''"
                " where catalog_agent_id = ?",
                (self.cagt,),
            )
        status, payload = self._heartbeat(signature=self._heartbeat_sig())
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["actor"], f"runtime:{self.binding_id}")
        self.assertEqual(payload["freshness_state"], "fresh")  # 按 TTL 复 fresh
        self.assertTrue(payload["last_seen_at"])
        # 读侧读到的也是 fresh（effective_freshness_state 同源数据）
        conn = sqlite3.connect(self.db_path)
        try:
            row = conn.execute(
                "select freshness_state, last_seen_at from catalog_agents"
                " where catalog_agent_id = ?",
                (self.cagt,),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(row[0], "fresh")
        self.assertTrue(row[1])

    # ── 拒绝路径（与既有失败同码同形：403）────────────────────────────────

    def test_missing_or_bad_signature_rejected(self) -> None:
        # 无任何凭据 → 403（与既有 test_agent_freshness 一致）
        status, _ = self._heartbeat()
        self.assertEqual(status, 403)
        # 错签名：另一把私钥签、但 kid 指向绑定 key
        other = Ed25519PrivateKey.generate()
        other_pem = other.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
        status, payload = self._heartbeat(signature=self._heartbeat_sig(pem=other_pem))
        self.assertEqual(status, 403, payload)
        # 签名覆盖的 agent_id 与路径不一致 → 403（字段挪用）
        other_agent = new_catalog_agent_id()
        status, payload = self._heartbeat(signature=self._heartbeat_sig(agent_id=other_agent))
        self.assertEqual(status, 403, payload)

    def test_nonce_replay_rejected(self) -> None:
        sig = self._heartbeat_sig()
        status, payload = self._heartbeat(signature=sig)
        self.assertEqual(status, 200, payload)
        status, payload = self._heartbeat(signature=sig)
        self.assertEqual(status, 403, payload)  # nonce 已消费

    def test_revoked_binding_signature_rejected(self) -> None:
        status, payload = _call(
            self.app,
            "POST",
            f"/v1/agents/{self.cagt}/runtime-bindings/{self.binding_id}/revoke",
            {"admin_token": ADMIN_TOKEN},
        )
        self.assertEqual(status, 200, payload)
        status, payload = self._heartbeat(signature=self._heartbeat_sig())
        self.assertEqual(status, 403, payload)

    def test_expired_binding_signature_rejected(self) -> None:
        with db_session(self.db_path) as conn:
            conn.execute(
                "update runtime_bindings set expires_at = '2020-01-01T00:00:00+00:00'"
                " where binding_id = ?",
                (self.binding_id,),
            )
        status, payload = self._heartbeat(signature=self._heartbeat_sig())
        self.assertEqual(status, 403, payload)

    def test_signature_does_not_leak_into_other_write_endpoints(self) -> None:
        """签名分支只挂在 heartbeat：refresh 等其它写端点不接受绑定签名（不扩大授权面）。"""
        status, _ = _call(
            self.app, "POST", f"/v1/agent-catalog/agents/{self.cagt}/refresh",
            {"idempotency_key": "hb-scope-1"}, signature=self._heartbeat_sig(),
        )
        self.assertEqual(status, 403)


if __name__ == "__main__":
    unittest.main()
