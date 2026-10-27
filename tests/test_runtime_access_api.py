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

"""WorkBuddy 访问配置 API 测试（G1 契约 §2.3/§2.4；C-02/C-03/C-05）。

覆盖：
- PUT runtime-access 更新：签名校验、CAS 版本、带码端点挑战、原子轮换、
  失败保留旧 active、撤销无网络挑战；
- 首绑附带 access_config：D1 暂存 → 确认激活 / 拒绝失效；
- Buyer 受控获取：会话 + 活跃关注、no-store、401/403/404 语义；
- 公开投影：active 才出现，无秘密字段。
全部离线：网络挑战以 monkeypatch ProfileFetcher.post_json 替身模拟。
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
import unittest.mock
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

from kiwi_catalog.a2a.binding_claims import jwk_thumbprint
from kiwi_catalog.a2a.enrollment_canonical import canonical_digest
from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.discovery.fetcher import FetchResult, ProfileFetcher

ADMIN_TOKEN = "admin-token-m3"
OWNER_SECRET = "test-owner-secret"
RUNTIME_ORIGIN = "https://pilot.example.app.workbuddy.host"
A2A_ENDPOINT = f"{RUNTIME_ORIGIN}/a2a"
CATALOG_ORIGIN = "https://catalog.example"
SHARE_SECRET_V1 = "sharecode-alpha-1"
SHARE_SECRET_V2 = "sharecode-beta-2"


def _access_config(secret: str, expected_version: int) -> dict:
    return {
        "provider": "workbuddy",
        "access_mode": "share_parameter",
        "parameter_name": "sharecode",
        "secret_value": secret,
        "adapter_version": "workbuddy-share-v1",
        "auth_mode": "signature",
        "expected_version": expected_version,
    }


def _revoke_config(expected_version: int) -> dict:
    return {"access_mode": "none", "expected_version": expected_version}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _runtime_key() -> tuple[str, dict]:
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return pem, {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}


def _jws(private_pem: str, kid: str, fields: dict, *, with_exp: bool = False) -> str:
    """与 Runtime 侧同形状的 compact JWS（EdDSA）——nonce 每次唯一。"""
    header = {"alg": "EdDSA", "kid": kid}
    payload = {
        **fields,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "nonce": f"nonce-{uuid.uuid4().hex}",
    }
    if with_exp:
        payload["exp"] = (datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat()
    header_segment = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_segment = _b64url(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode())
    key = load_pem_private_key(private_pem.encode(), password=None)
    signature = key.sign(f"{header_segment}.{payload_segment}".encode("ascii"))
    return f"{header_segment}.{payload_segment}.{_b64url(signature)}"


def _challenge_subject_bytes(challenge: dict) -> bytes:
    subject = {
        "agent_id": challenge["agent_id"],
        "challenge_id": challenge["challenge_id"],
        "expires_at": challenge["expires_at"],
        "generation": challenge["generation"],
        "issued_at": challenge["issued_at"],
        "key_thumbprint": challenge["key_thumbprint"],
        "merchant_id": challenge["merchant_id"],
        "nonce": challenge["nonce"],
        "origin": challenge["origin"],
        "path": challenge["path"],
        "purpose": challenge["purpose"],
    }
    return json.dumps(subject, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _endpoint_proof_response(pem: str, kid: str, jwk: dict, challenge: dict) -> dict:
    """模拟运行时 /control/challenge 的 200 响应（签名主体=挑战主体）。"""
    subject = _challenge_subject_bytes(challenge)
    header = {"alg": "EdDSA", "kid": kid, "typ": "kiwi-binding-proof"}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(subject)
    key = load_pem_private_key(pem.encode(), password=None)
    sig = key.sign(f"{h}.{p}".encode("ascii"))
    return {
        "proof_jws": f"{h}.{p}.{_b64url(sig)}",
        "key_id": kid,
        "key_thumbprint": jwk_thumbprint(jwk),
        "subject_digest": f"sha256:{hashlib.sha256(subject).hexdigest()}",
    }


def _call_full(app, method: str, path: str, body: dict | None = None,
               signature: str = "", cookie: str = "",
               extra_headers: list[tuple[bytes, bytes]] | None = None):
    raw = json.dumps(body).encode() if body is not None else b""
    headers = [(b"content-type", b"application/json")]
    if signature:
        headers.append((b"x-kiwi-binding-jws", signature.encode()))
    if cookie:
        headers.append((b"cookie", cookie.encode()))
    headers.extend(extra_headers or [])
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
        k.decode().lower(): v.decode() for k, v in start.get("headers", [])
    }
    chunks = b"".join(m.get("body", b"") for m in received if m["type"] == "http.response.body")
    try:
        payload = json.loads(chunks.decode("utf-8")) if chunks else {}
    except json.JSONDecodeError:
        payload = {}
    return start["status"], payload, response_headers


def _call(app, method: str, path: str, body: dict | None = None,
          signature: str = "", cookie: str = ""):
    status, payload, _headers = _call_full(app, method, path, body, signature, cookie)
    return status, payload


class RuntimeAccessApiTest(unittest.TestCase):
    """PUT runtime-access、首绑附带配置与 Buyer 受控获取。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "catalog.sqlite")
        fernet_key = base64.urlsafe_b64encode(os.urandom(32)).decode()
        self.app = create_catalog_app(self.db_path)
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
                "KIWI_CATALOG_PUBLIC_ORIGIN": CATALOG_ORIGIN,
                "KIWI_CATALOG_ISSUER_KEY_FILE": str(issuer_path),
                "KIWI_CATALOG_ISSUER_KID": "catalog-issuer-test",
                "KIWI_CATALOG_ISSUER_NAME": "catalog.kiwi.test",
                "KIWI_CATALOG_ACCESS_CONFIG_KEYS_JSON": json.dumps(
                    {"ka-test-v1": fernet_key}
                ),
                "KIWI_CATALOG_ACCESS_CONFIG_ACTIVE_KEY_ID": "ka-test-v1",
            },
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.runtime_pem, self.runtime_jwk = _runtime_key()
        self.owner_session = self._register("owner@acme.example")
        self.merchant_id = self._merchant_id()
        self.cagt = self._create_agent()
        self.binding_id = self._admin_bind_with_config(SHARE_SECRET_V1)

    # ── 夹具助手 ─────────────────────────────────────────────────────────

    def _register(self, email: str) -> str:
        password = "strong-pw-123"
        status, payload = _call(self.app, "POST", "/v1/accounts/register/code", {"email": email})
        self.assertEqual(status, 200, payload)
        status, payload = _call(
            self.app, "POST", "/v1/accounts/register/verify",
            {"email": email, "code": payload["verification_code"]},
        )
        self.assertEqual(status, 200, payload)
        status, payload = _call(
            self.app, "POST", "/v1/accounts/register",
            {
                "merchant_name": "Acme 商贸",
                "email": email,
                "password": password,
                "phone": "+86 138 0000 0000",
                "verification_ticket": payload["verification_ticket"],
            },
        )
        self.assertEqual(status, 200, payload)
        status, payload = _call(
            self.app, "POST", "/v1/accounts/login", {"email": email, "password": password}
        )
        self.assertEqual(status, 200, payload)
        return self._session_of_last_login(email, password)

    def _session_of_last_login(self, email: str, password: str) -> str:
        _status, _payload, headers = _call_full(
            self.app, "POST", "/v1/accounts/login", {"email": email, "password": password}
        )
        return headers["set-cookie"].split(";")[0].split("=", 1)[1]

    def _merchant_id(self) -> str:
        status, payload = _call(
            self.app, "GET", "/v1/accounts/me", cookie=f"kiwi_session={self.owner_session}"
        )
        self.assertEqual(status, 200, payload)
        return payload["merchant_id"]

    def _create_agent(self) -> str:
        status, payload = _call(
            self.app, "POST", "/v1/accounts/agents", {},
            cookie=f"kiwi_session={self.owner_session}",
        )
        self.assertEqual(status, 200, payload)
        return payload["catalog_agent_id"]

    def _admin_bind_with_config(self, secret: str) -> str:
        """admin + 持钥证明首绑并附带 access_config（无网络挑战路径）。"""
        body = {
            "admin_token": ADMIN_TOKEN,
            "binding": {
                "runtime_origin": RUNTIME_ORIGIN,
                "a2a_endpoint": A2A_ENDPOINT,
                "key_jwk": self.runtime_jwk,
                "key_id": RUNTIME_ORIGIN,
                "generation": 1,
                "service_epoch": 7,
            },
            "access_config": _access_config(secret, 0),
        }
        sig = _jws(self.runtime_pem, RUNTIME_ORIGIN, {
            "agent_id": self.cagt,
            "key_id": RUNTIME_ORIGIN,
            "key_thumbprint": jwk_thumbprint(self.runtime_jwk),
            "runtime_origin": RUNTIME_ORIGIN,
            "a2a_endpoint": A2A_ENDPOINT,
            "generation": 1,
            "service_epoch": 7,
        })
        status, payload = _call(
            self.app, "POST", f"/v1/agents/{self.cagt}/runtime-bindings", body, signature=sig
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["runtime_access"]["status"], "active", payload)
        self.assertNotIn("secret_value", json.dumps(payload))
        return payload["binding_id"]

    def _put_access(self, access_config: dict, *, pem: str | None = None,
                    signature: str | None = None, binding_id: str | None = None) -> tuple[int, dict]:
        pem = pem or self.runtime_pem
        binding_id = binding_id or self.binding_id
        body = {
            "binding": {"binding_id": binding_id},
            "access_config": access_config,
        }
        sig = signature if signature is not None else _jws(
            pem,
            RUNTIME_ORIGIN,
            {
                "method": "PUT",
                "path": f"/v1/agents/{self.cagt}/runtime-access",
                "audience": "kiwi-catalog",
                "body_digest": canonical_digest(body),
                "catalog_agent_id": self.cagt,
                "binding_id": binding_id,
                "key_id": RUNTIME_ORIGIN,
                "runtime_origin": RUNTIME_ORIGIN,
                "service_epoch": 7,
            },
            with_exp=True,
        )
        return _call(self.app, "PUT", f"/v1/agents/{self.cagt}/runtime-access", body, signature=sig)

    def _config_row(self, version: int, cagt: str | None = None) -> sqlite3.Row | None:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            return conn.execute(
                "select * from runtime_access_configs where catalog_agent_id = ?"
                " and config_version = ?",
                (cagt or self.cagt, version),
            ).fetchone()
        finally:
            conn.close()

    def _challenge_stub(self, *, pem: str | None = None, jwk: dict | None = None,
                        status: int = 200, seen_urls: list[str] | None = None,
                        body_override: dict | None = None):
        """ProfileFetcher.post_json 替身：校验挑战形状并返回签名证明。"""
        pem = pem or self.runtime_pem
        jwk = jwk or self.runtime_jwk

        def _respond(url, payload, *, timeout):
            if seen_urls is not None:
                seen_urls.append(url)
            if status != 200:
                return FetchResult(url=url, status_code=status, body="", fetched_at=0.0)
            challenge = (payload or {}).get("challenge")
            assert isinstance(challenge, dict), payload
            assert challenge["origin"] == RUNTIME_ORIGIN
            assert challenge["path"] == "/a2a"
            assert challenge["purpose"] == "endpoint"
            body = body_override if body_override is not None else _endpoint_proof_response(
                pem, RUNTIME_ORIGIN, jwk, challenge
            )
            return FetchResult(
                url=url, status_code=200,
                body=json.dumps(body).encode("utf-8"), fetched_at=0.0,
            )

        return _respond

    # ── PUT 更新：成功轮换 ────────────────────────────────────────────────

    def test_put_update_rotates_share_code_through_coded_challenge(self) -> None:
        seen_urls: list[str] = []
        with unittest.mock.patch.object(
            ProfileFetcher, "post_json", side_effect=self._challenge_stub(seen_urls=seen_urls)
        ):
            status, payload = self._put_access(_access_config(SHARE_SECRET_V2, 1))
        self.assertEqual(status, 200, payload)
        projection = payload["runtime_access"]
        self.assertEqual(projection["config_version"], 2)
        self.assertEqual(projection["status"], "active")
        self.assertNotIn("secret_value", json.dumps(payload))
        # 挑战 URL 携带新分享码；挑战体不含秘密。
        self.assertEqual(len(seen_urls), 1)
        self.assertTrue(seen_urls[0].startswith(f"{RUNTIME_ORIGIN}/control/challenge?"), seen_urls)
        self.assertIn(
            f"sharecode={SHARE_SECRET_V2}", seen_urls[0]
        )
        old_row = self._config_row(1)
        new_row = self._config_row(2)
        assert old_row is not None and new_row is not None
        self.assertEqual(old_row["status"], "revoked")
        self.assertEqual(new_row["status"], "active")
        self.assertNotEqual(new_row["secret_ciphertext"], SHARE_SECRET_V2)

    def test_active_config_enters_public_record_and_buyer_view(self) -> None:
        status, payload = _call(self.app, "GET", "/v1/agents")
        self.assertEqual(status, 200, payload)
        record = next(r for r in payload["results"] if r["catalog_agent_id"] == self.cagt)
        self.assertEqual(record["runtime_access"]["config_version"], 1)
        self.assertEqual(record["runtime_access"]["provider"], "workbuddy")
        self.assertNotIn("secret_value", json.dumps(record))

    # ── PUT 更新：失败语义 ────────────────────────────────────────────────

    def test_put_without_signature_is_rejected(self) -> None:
        status, payload = self._put_access(_access_config(SHARE_SECRET_V2, 1), signature="")
        self.assertEqual(status, 400, payload)

    def test_put_with_wrong_key_is_rejected_and_active_preserved(self) -> None:
        wrong_pem, _wrong_jwk = _runtime_key()
        status, payload = self._put_access(
            _access_config(SHARE_SECRET_V2, 1), pem=wrong_pem
        )
        self.assertEqual(status, 403, payload)
        self.assertEqual(self._config_row(1)["status"], "active")

    def test_put_with_stale_version_is_conflict(self) -> None:
        status, payload = self._put_access(_access_config(SHARE_SECRET_V2, 0))
        self.assertEqual(status, 409, payload)
        self.assertEqual(self._config_row(1)["status"], "active")

    def test_put_nonce_replay_is_rejected(self) -> None:
        body = {
            "binding": {"binding_id": self.binding_id},
            "access_config": _access_config(SHARE_SECRET_V2, 1),
        }
        sig = _jws(
            self.runtime_pem,
            RUNTIME_ORIGIN,
            {
                "method": "PUT",
                "path": f"/v1/agents/{self.cagt}/runtime-access",
                "audience": "kiwi-catalog",
                "body_digest": canonical_digest(body),
                "catalog_agent_id": self.cagt,
                "binding_id": self.binding_id,
                "key_id": RUNTIME_ORIGIN,
                "runtime_origin": RUNTIME_ORIGIN,
                "service_epoch": 7,
            },
            with_exp=True,
        )
        with unittest.mock.patch.object(
            ProfileFetcher, "post_json", side_effect=self._challenge_stub()
        ):
            first = self._put_access(_access_config(SHARE_SECRET_V2, 1), signature=sig)
        self.assertEqual(first[0], 200, first[1])
        with unittest.mock.patch.object(
            ProfileFetcher, "post_json", side_effect=self._challenge_stub()
        ):
            replay = self._put_access(_access_config(SHARE_SECRET_V2, 1), signature=sig)
        self.assertEqual(replay[0], 403, replay[1])

    def test_put_activation_conflict_marks_staged_version_invalid(self) -> None:
        """契约 §2.3.3：提交阶段失败同样把新版本标 invalid，不残留 pending。"""
        from kiwi_catalog.core.errors import ConflictError
        from kiwi_catalog.services import runtime_access as runtime_access_service

        with unittest.mock.patch.object(
            ProfileFetcher, "post_json", side_effect=self._challenge_stub()
        ), unittest.mock.patch.object(
            runtime_access_service,
            "activate_runtime_access",
            side_effect=ConflictError("runtime access version conflict"),
        ):
            status, payload = self._put_access(_access_config(SHARE_SECRET_V2, 1))
        self.assertEqual(status, 409, payload)
        self.assertEqual(self._config_row(1)["status"], "active")
        self.assertEqual(self._config_row(2)["status"], "invalid")

    def test_put_challenge_failure_preserves_active_and_invalidates_pending(self) -> None:
        with unittest.mock.patch.object(
            ProfileFetcher, "post_json",
            side_effect=self._challenge_stub(status=502),
        ):
            status, payload = self._put_access(_access_config(SHARE_SECRET_V2, 1))
        self.assertEqual(status, 403, payload)
        self.assertEqual(self._config_row(1)["status"], "active")
        self.assertEqual(self._config_row(2)["status"], "invalid")

    def test_put_rotation_via_binding_endpoint_is_rejected(self) -> None:
        body = {
            "binding": {
                "runtime_origin": RUNTIME_ORIGIN,
                "a2a_endpoint": A2A_ENDPOINT,
                "key_jwk": self.runtime_jwk,
                "key_id": RUNTIME_ORIGIN,
                "generation": 1,
                "service_epoch": 7,
            },
            "access_config": _access_config(SHARE_SECRET_V2, 1),
        }
        sig = _jws(self.runtime_pem, RUNTIME_ORIGIN, {
            "agent_id": self.cagt,
            "binding_id": self.binding_id,
            "key_id": RUNTIME_ORIGIN,
            "key_thumbprint": jwk_thumbprint(self.runtime_jwk),
            "runtime_origin": RUNTIME_ORIGIN,
            "a2a_endpoint": A2A_ENDPOINT,
            "generation": 1,
            "service_epoch": 7,
        })
        status, payload = _call(
            self.app, "POST", f"/v1/agents/{self.cagt}/runtime-bindings", body, signature=sig
        )
        self.assertEqual(status, 400, payload)

    # ── 撤销 ─────────────────────────────────────────────────────────────

    def test_put_revoke_skips_challenge_and_stops_distribution(self) -> None:
        seen_urls: list[str] = []
        with unittest.mock.patch.object(
            ProfileFetcher, "post_json", side_effect=self._challenge_stub(seen_urls=seen_urls)
        ):
            status, payload = self._put_access(_revoke_config(1))
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["runtime_access"]["status"], "revoked")
        self.assertEqual(seen_urls, [], "撤销不得发起网络挑战")
        self.assertEqual(self._config_row(1)["status"], "revoked")
        # 公开投影移除；Buyer 获取 404。
        status, payload = _call(self.app, "GET", "/v1/agents")
        record = next(r for r in payload["results"] if r["catalog_agent_id"] == self.cagt)
        self.assertNotIn("runtime_access", record)
        buyer_session = self._register_and_follow()
        status, payload = _call(
            self.app, "GET", f"/v1/me/merchant-access/{self.cagt}",
            cookie=f"kiwi_session={buyer_session}",
        )
        self.assertEqual(status, 404, payload)

    # ── 首绑附带配置（D1）────────────────────────────────────────────────

    def _d1_stage_with_config(self, email: str) -> tuple[str, str, str, str, str]:
        """独立商家 + 无绑定 agent + 带配置 D1 请求。

        返回 (merchant_session, cagt_b, request_id, pem_b, jwk_b)。
        """
        session_b = self._register(email)
        status, payload = _call(
            self.app, "POST", "/v1/accounts/agents", {},
            cookie=f"kiwi_session={session_b}",
        )
        self.assertEqual(status, 200, payload)
        cagt_b = payload["catalog_agent_id"]
        pem_b, jwk_b = _runtime_key()
        body = {
            "binding": {
                "runtime_origin": RUNTIME_ORIGIN,
                "a2a_endpoint": A2A_ENDPOINT,
                "key_jwk": jwk_b,
                "key_id": RUNTIME_ORIGIN,
                "generation": 1,
                "service_epoch": 7,
            },
            "access_config": _access_config(SHARE_SECRET_V2, 0),
        }
        sig = _jws(pem_b, RUNTIME_ORIGIN, {
            "agent_id": cagt_b,
            "key_id": RUNTIME_ORIGIN,
            "key_thumbprint": jwk_thumbprint(jwk_b),
            "runtime_origin": RUNTIME_ORIGIN,
            "a2a_endpoint": A2A_ENDPOINT,
            "generation": 1,
            "service_epoch": 7,
        })
        status, payload = _call(
            self.app, "POST", f"/v1/agents/{cagt_b}/runtime-bindings", body, signature=sig
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["runtime_access"]["status"], "pending", payload)
        return session_b, cagt_b, payload["binding_request_id"], pem_b, jwk_b

    def test_d1_first_bind_stages_config_and_confirm_activates(self) -> None:
        session_b, cagt_b, request_id, _pem_b, _jwk_b = self._d1_stage_with_config(
            "owner-b@acme.example"
        )
        row = self._config_row(1, cagt_b)
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "pending")
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            linked = conn.execute(
                "select access_config_version from runtime_binding_requests"
                " where binding_request_id = ?",
                (request_id,),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(int(linked["access_config_version"]), 1)
        # 确认 → 配置随绑定同事务激活。
        status, payload = _call(
            self.app,
            "POST",
            f"/v1/accounts/agents/{cagt_b}/bindings/{request_id}/confirm",
            {},
            cookie=f"kiwi_session={session_b}",
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(self._config_row(1, cagt_b)["status"], "active")

    def test_d1_reject_invalidates_staged_config(self) -> None:
        session_b, cagt_b, request_id, _pem_b, _jwk_b = self._d1_stage_with_config(
            "owner-c@acme.example"
        )
        status, payload = _call(
            self.app,
            "POST",
            f"/v1/accounts/agents/{cagt_b}/bindings/{request_id}/reject",
            {"note": "wrong runtime"},
            cookie=f"kiwi_session={session_b}",
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(self._config_row(1, cagt_b)["status"], "invalid")

    # ── Buyer 受控获取 ────────────────────────────────────────────────────

    def _register_and_follow(self) -> str:
        session = self._register("buyer@example.com")
        status, payload = _call(
            self.app, "PUT", f"/v1/me/follows/{self.merchant_id}", {},
            cookie=f"kiwi_session={session}",
        )
        self.assertEqual(status, 200, payload)
        return session

    def test_buyer_access_requires_session(self) -> None:
        # 平台全局把缺失会话（AuthError）映射为 403；G1 §2.4 的「401」待契约
        # 评审对齐——此处按现行两栈一致约定断言。
        status, payload = _call(self.app, "GET", f"/v1/me/merchant-access/{self.cagt}")
        self.assertEqual(status, 403, payload)

    def test_buyer_access_requires_active_follow(self) -> None:
        session = self._register("buyer-nofollow@example.com")
        status, payload = _call(
            self.app, "GET", f"/v1/me/merchant-access/{self.cagt}",
            cookie=f"kiwi_session={session}",
        )
        self.assertEqual(status, 403, payload)

    def test_buyer_access_returns_controlled_projection_with_no_store(self) -> None:
        session = self._register_and_follow()
        status, payload, headers = _call_full(
            self.app, "GET", f"/v1/me/merchant-access/{self.cagt}",
            cookie=f"kiwi_session={session}",
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(headers.get("cache-control"), "no-store")
        self.assertEqual(payload["secret_value"], SHARE_SECRET_V1)
        self.assertEqual(payload["runtime_origin"], RUNTIME_ORIGIN)
        self.assertEqual(payload["config_version"], 1)
        self.assertNotIn("__no_store__", json.dumps(payload))

    def test_buyer_access_is_audited_without_secret(self) -> None:
        session = self._register_and_follow()
        status, payload = _call(
            self.app, "GET", f"/v1/me/merchant-access/{self.cagt}",
            cookie=f"kiwi_session={session}",
        )
        self.assertEqual(status, 200, payload)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "select actor, event, details_json from audit_events"
                " where event = 'runtime_access_issued'"
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual(len(rows), 1)
        self.assertTrue(str(rows[0]["actor"]).startswith("account:"), rows[0]["actor"])
        details = json.loads(rows[0]["details_json"])
        self.assertEqual(details["merchant_id"], self.merchant_id)
        self.assertEqual(details["config_version"], 1)
        self.assertNotIn(SHARE_SECRET_V1, rows[0]["details_json"])

    def test_buyer_access_hides_administratively_suspended_agent(self) -> None:
        session = self._register_and_follow()
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "update catalog_agents set administrative_state = 'suspended'"
                " where catalog_agent_id = ?",
                (self.cagt,),
            )
            conn.commit()
        finally:
            conn.close()
        status, payload = _call(
            self.app, "GET", f"/v1/me/merchant-access/{self.cagt}",
            cookie=f"kiwi_session={session}",
        )
        self.assertEqual(status, 404, payload)

    def test_buyer_access_is_rate_limited(self) -> None:
        session = self._register_and_follow()
        path = f"/v1/me/merchant-access/{self.cagt}"
        with unittest.mock.patch.dict(
            os.environ, {"KIWI_CATALOG_MERCHANT_ACCESS_RATE_LIMIT_PER_15MIN": "1"}, clear=False
        ):
            first_status, _first = _call(
                self.app, "GET", path, cookie=f"kiwi_session={session}"
            )
            second_status, second = _call(
                self.app, "GET", path, cookie=f"kiwi_session={session}"
            )
        self.assertEqual(first_status, 200)
        self.assertEqual(second_status, 429, second)

    def test_rate_limit_consumes_rejected_probes(self) -> None:
        """被拒请求同样计入限流（计数在独立事务提交，不被 404 回滚）。"""
        session = self._register_and_follow()
        with unittest.mock.patch.dict(
            os.environ, {"KIWI_CATALOG_MERCHANT_ACCESS_RATE_LIMIT_PER_15MIN": "1"}, clear=False
        ):
            probe_status, _probe = _call(
                self.app, "GET", "/v1/me/merchant-access/cagt_does_not_exist",
                cookie=f"kiwi_session={session}",
            )
            real_status, real = _call(
                self.app, "GET", f"/v1/me/merchant-access/{self.cagt}",
                cookie=f"kiwi_session={session}",
            )
        self.assertEqual(probe_status, 404)
        self.assertEqual(real_status, 429, real)

    def _app_on_stack(self, stack: str):
        """同一库上按指定栈构建 app（fallback 通过临时置空 FastAPI 分支触发）。"""
        from kiwi_catalog.api import app as app_module

        if stack == "fastapi":
            return app_module.create_catalog_app(self.db_path)
        with unittest.mock.patch.object(app_module, "FastAPI", None):
            app = app_module.create_catalog_app(self.db_path)
        self.assertEqual(type(app).__name__, "MarketplaceASGIApp")
        return app

    def test_merchant_access_no_etag_and_never_304_on_both_stacks(self) -> None:
        """受控凭据响应双栈一致：无 ETag、条件请求不返回 304（C-05/C-07）。

        fallback 栈历史上无条件算 ETag 并按 ``If-None-Match`` 回 304——等于把
        秘密响应的稳定指纹和条件请求语义都暴露出去。两栈都必须只发 no-store 体。
        """
        session = self._register_and_follow()
        path = f"/v1/me/merchant-access/{self.cagt}"
        for stack in ("fastapi", "fallback"):
            with self.subTest(stack=stack):
                app = self._app_on_stack(stack)
                status, payload, headers = _call_full(
                    app, "GET", path, cookie=f"kiwi_session={session}"
                )
                self.assertEqual(status, 200, payload)
                self.assertEqual(payload["secret_value"], SHARE_SECRET_V1)
                self.assertEqual(headers.get("cache-control"), "no-store")
                self.assertNotIn("etag", headers)
                conditional_status, body, conditional_headers = _call_full(
                    app,
                    "GET",
                    path,
                    cookie=f"kiwi_session={session}",
                    extra_headers=[(b"if-none-match", b"*")],
                )
                self.assertEqual(conditional_status, 200)
                self.assertEqual(body["secret_value"], SHARE_SECRET_V1)
                self.assertNotIn("etag", conditional_headers)

    def test_buyer_access_unknown_agent_is_not_found(self) -> None:
        session = self._register_and_follow()
        status, payload = _call(
            self.app, "GET", "/v1/me/merchant-access/cagt_does_not_exist",
            cookie=f"kiwi_session={session}",
        )
        self.assertEqual(status, 404, payload)


if __name__ == "__main__":
    unittest.main()
