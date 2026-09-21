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

"""SIG-04：控制面写请求的 **nonce 重放保护**。

边界要说清：
  - 消费发生在**全部校验之后**——无效签名不得"占掉"合法请求的 nonce（否则重放
    保护反而成了拒绝服务面）；
  - 判定用**主键冲突**（`(key_id, nonce)`），不是"先查后插"（并发下会双放行）；
  - 记录只在时钟偏移窗口内保留，过窗惰性清理；窗口外的请求本来就被时间窗拒绝。
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from kiwi_catalog.a2a.request_signature import (
    consume_request_nonce,
    sign_runtime_request,
    verify_runtime_request,
)
from kiwi_catalog.agent_catalog.sqlite_repository import (
    new_catalog_agent_id,
    upsert_catalog_agent,
)
from kiwi_catalog.core.errors import PermissionDenied, ValidationError
from kiwi_catalog.db.session import db_session

RUNTIME_ORIGIN = "https://pilot.example.app.workbuddy.host"
A2A_ENDPOINT = f"{RUNTIME_ORIGIN}/a2a"
BINDING_ID = "binding-replay-1"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class ControlPlaneNonceReplayTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "catalog.sqlite")
        self.private_key = Ed25519PrivateKey.generate()
        self.private_pem = self.private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode()
        raw = self.private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        with db_session(self.db_path) as conn:
            self.agent_id = new_catalog_agent_id()
            upsert_catalog_agent(
                conn,
                self.agent_id,
                merchant_id="mkt_replay_1",
                display_name="Replay Merchant",
                canonical_domain="merchant.example",
            )
            conn.execute(
                "insert into runtime_bindings (binding_id, catalog_agent_id, merchant_id,"
                " runtime_origin, a2a_endpoint, key_id, key_thumbprint, key_jwk_json,"
                " binding_version, service_epoch, status, expires_at, created_at, updated_at)"
                " values (?, ?, 'mkt_replay_1', ?, ?, ?, 'sha256:0', ?, 1, 1,"
                " 'active', '', '', '')",
                (
                    BINDING_ID,
                    self.agent_id,
                    RUNTIME_ORIGIN,
                    A2A_ENDPOINT,
                    RUNTIME_ORIGIN,
                    json.dumps({"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}),
                ),
            )

    def _sign(self, fields: dict, *, issued_at: str, nonce: str) -> str:
        return sign_runtime_request(
            kid=RUNTIME_ORIGIN,
            private_key_pem=self.private_pem,
            signed_fields=fields,
            issued_at=issued_at,
            nonce=nonce,
        )

    def _fields(self) -> dict:
        # binding_id 是验签的必含字段（把签名钉在具体绑定上）
        return {
            "binding_id": BINDING_ID,
            "agent_id": self.agent_id,
            "card_digest": "sha256:" + "a" * 64,
        }

    # ── 端到端：同一签名第二次即拒 ───────────────────────────────
    def test_replayed_request_is_refused_on_second_use(self) -> None:
        now = datetime.now(timezone.utc)
        issued = now.isoformat()
        jws = self._sign(self._fields(), issued_at=issued, nonce=f"nonce-{uuid.uuid4().hex}")
        with db_session(self.db_path) as conn:
            verify_runtime_request(
                conn,
                catalog_agent_id=self.agent_id,
                jws=jws,
                expected_fields=self._fields(),
                now=now,
            )
            # 同一 JWS 原样重放 → 403
            with self.assertRaises(PermissionDenied) as ctx:
                verify_runtime_request(
                    conn,
                    catalog_agent_id=self.agent_id,
                    jws=jws,
                    expected_fields=self._fields(),
                    now=now,
                )
            self.assertIn("replayed", str(ctx.exception))

    def test_fresh_nonce_is_accepted(self) -> None:
        now = datetime.now(timezone.utc)
        with db_session(self.db_path) as conn:
            for _ in range(3):
                verify_runtime_request(
                    conn,
                    catalog_agent_id=self.agent_id,
                    jws=self._sign(
                        self._fields(),
                        issued_at=now.isoformat(),
                        nonce=f"nonce-{uuid.uuid4().hex}",
                    ),
                    expected_fields=self._fields(),
                    now=now,
                )

    # ── DoS 面：无效签名不得占掉 nonce ───────────────────────────
    def test_failed_verification_does_not_burn_the_nonce(self) -> None:
        """伪造签名（nonce 为 N）不得让合法请求的 nonce=N 被提前占掉。"""
        now = datetime.now(timezone.utc)
        nonce = f"nonce-{uuid.uuid4().hex}"
        forged = self._sign(
            {"binding_id": BINDING_ID, "agent_id": self.agent_id, "card_digest": "sha256:" + "b" * 64},
            issued_at=now.isoformat(),
            nonce=nonce,
        )
        with db_session(self.db_path) as conn:
            # 伪造签名：字段与请求体不一致 → 403
            with self.assertRaises(PermissionDenied):
                verify_runtime_request(
                    conn,
                    catalog_agent_id=self.agent_id,
                    jws=forged,
                    expected_fields=self._fields(),
                    now=now,
                )
            rows = conn.execute("select count(*) from control_plane_nonces").fetchone()[0]
            self.assertEqual(rows, 0, "校验失败不该写入 nonce")
            # 合法请求用同一 nonce 仍然通过
            verify_runtime_request(
                conn,
                catalog_agent_id=self.agent_id,
                jws=self._sign(self._fields(), issued_at=now.isoformat(), nonce=nonce),
                expected_fields=self._fields(),
                now=now,
            )

    def test_clock_skew_rejection_does_not_burn_the_nonce(self) -> None:
        now = datetime.now(timezone.utc)
        nonce = f"nonce-{uuid.uuid4().hex}"
        stale = now - timedelta(seconds=1200)
        jws = self._sign(self._fields(), issued_at=stale.isoformat(), nonce=nonce)
        with db_session(self.db_path) as conn:
            with self.assertRaises(PermissionDenied):
                verify_runtime_request(
                    conn,
                    catalog_agent_id=self.agent_id,
                    jws=jws,
                    expected_fields=self._fields(),
                    now=now,
                )
            self.assertEqual(
                conn.execute("select count(*) from control_plane_nonces").fetchone()[0], 0
            )

    # ── 存储层语义 ───────────────────────────────────────────────
    def test_nonce_is_scoped_per_key(self) -> None:
        """同一 nonce 在不同 key 下互不影响（重放表按 (key_id, nonce) 索引）。"""
        now = datetime.now(timezone.utc)
        with db_session(self.db_path) as conn:
            consume_request_nonce(
                conn, key_id="key-a", nonce="nonce-aaaaaaaa", issued_at=now.isoformat(), now=now
            )
            consume_request_nonce(
                conn, key_id="key-b", nonce="nonce-aaaaaaaa", issued_at=now.isoformat(), now=now
            )
            with self.assertRaises(PermissionDenied):
                consume_request_nonce(
                    conn, key_id="key-a", nonce="nonce-aaaaaaaa", issued_at=now.isoformat(), now=now
                )

    def test_nonce_length_is_bounded(self) -> None:
        now = datetime.now(timezone.utc)
        with db_session(self.db_path) as conn:
            for bad in ("", "short", "x" * 129):
                with self.subTest(nonce=bad):
                    with self.assertRaises(ValidationError):
                        consume_request_nonce(
                            conn,
                            key_id="key-a",
                            nonce=bad,
                            issued_at=now.isoformat(),
                            now=now,
                        )

    def test_expired_rows_are_pruned(self) -> None:
        """过窗记录被清理：重放表不会只增不删。"""
        now = datetime.now(timezone.utc)
        long_ago = now - timedelta(days=30)
        with db_session(self.db_path) as conn:
            conn.execute(
                "insert into control_plane_nonces (key_id, nonce, issued_at, expires_at, created_at)"
                " values ('key-old', 'nonce-oldoldold', ?, ?, ?)",
                (long_ago.isoformat(), long_ago.isoformat(), long_ago.isoformat()),
            )
            # 触发惰性清理（计数器阈值）
            for index in range(70):
                consume_request_nonce(
                    conn,
                    key_id="key-a",
                    nonce=f"nonce-{index:08d}",
                    issued_at=now.isoformat(),
                    now=now,
                )
            remaining = conn.execute(
                "select count(*) from control_plane_nonces where key_id = 'key-old'"
            ).fetchone()[0]
            self.assertEqual(remaining, 0)

    def test_expiry_is_issued_at_plus_window(self) -> None:
        """记录只在时间窗内保留：窗口外的请求本来就被时间窗拒绝，不必留更久。"""
        now = datetime.now(timezone.utc)
        issued = now - timedelta(seconds=300)
        with db_session(self.db_path) as conn:
            consume_request_nonce(
                conn,
                key_id="key-a",
                nonce="nonce-cccccccc",
                issued_at=issued.isoformat(),
                now=now,
                window_seconds=300,
            )
            expires_at = conn.execute(
                "select expires_at from control_plane_nonces where key_id = 'key-a'"
            ).fetchone()[0]
        self.assertEqual(
            datetime.fromisoformat(expires_at), issued + timedelta(seconds=300)
        )

    def test_missing_nonce_is_rejected(self) -> None:
        """声明里没有 nonce 的签名一律拒绝（不能"没有 nonce 就跳过重放保护"）。"""
        now = datetime.now(timezone.utc)
        header = {"alg": "EdDSA", "kid": RUNTIME_ORIGIN}
        payload = {**self._fields(), "issued_at": now.isoformat()}
        header_segment = _b64url(json.dumps(header, separators=(",", ":")).encode())
        payload_segment = _b64url(json.dumps(payload, separators=(",", ":")).encode())
        signature = self.private_key.sign(f"{header_segment}.{payload_segment}".encode("ascii"))
        jws = f"{header_segment}.{payload_segment}.{_b64url(signature)}"
        with db_session(self.db_path) as conn:
            with self.assertRaises(ValidationError):
                verify_runtime_request(
                    conn,
                    catalog_agent_id=self.agent_id,
                    jws=jws,
                    expected_fields=self._fields(),
                    now=now,
                )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
