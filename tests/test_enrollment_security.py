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

"""Security regressions for device enrollment and runtime publication.

All requests use a temporary SQLite database and test-generated Ed25519 keys.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from fastapi.testclient import TestClient

from kiwi_catalog.a2a.binding_claims import jwk_thumbprint
from kiwi_catalog.a2a.enrollment_canonical import canonical_digest
from kiwi_catalog.agent_catalog.sqlite_repository import new_catalog_agent_id, upsert_catalog_agent
from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.db.session import db_session
from kiwi_catalog.services import enrollments as enrollment_service

from tests.test_cloud_binding import _b64url, _call, _jws


ADMIN_TOKEN = "enrollment-security-admin"
OWNER_SECRET = "enrollment-security-owner-secret"
RUNTIME_ORIGIN = "https://merchant.security.example"
A2A_ENDPOINT = RUNTIME_ORIGIN + "/a2a"


class EnrollmentFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db_path = os.path.join(self.temp.name, "catalog.sqlite")
        self.owner = "security-owner@example.test"
        self._env = mock.patch.dict(os.environ, {
            "KIWI_CATALOG_ADMIN_TOKEN": ADMIN_TOKEN,
            "KIWI_CATALOG_PUBLIC_BASE_URL": "https://localhost",
            "KIWI_CATALOG_PUBLIC_ORIGIN": "https://catalog.example",
            "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
            "KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET,
        }, clear=False)
        self._env.start()
        self.addCleanup(self._env.stop)
        key_path = Path(self.temp.name) / "issuer.pem"
        issuer = Ed25519PrivateKey.generate()
        key_path.write_bytes(issuer.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        os.chmod(key_path, 0o600)
        self._issuer_env = mock.patch.dict(os.environ, {
            "KIWI_CATALOG_ISSUER_KEY_FILE": str(key_path),
            "KIWI_CATALOG_ISSUER_KID": "enrollment-security-issuer",
            "KIWI_CATALOG_ISSUER_NAME": "catalog.security.test",
        }, clear=False)
        self._issuer_env.start()
        self.addCleanup(self._issuer_env.stop)

        self.app = create_catalog_app(self.db_path)
        self.client = TestClient(self.app, base_url="https://localhost")
        registered = self.client.post("/v1/accounts/register", json={
            "merchant_name": "Security Merchant A",
            "email": self.owner,
            "password": "strong-password-123",
            "phone": "+1 555 0200",
        })
        self.assertEqual(registered.status_code, 200, registered.text)
        verified = self.client.post("/v1/accounts/verify-email", json={
            "email": self.owner, "code": registered.json()["verification_code"],
        })
        self.assertEqual(verified.status_code, 200, verified.text)
        me = self.client.get("/v1/accounts/me")
        self.assertEqual(me.status_code, 200, me.text)
        self.merchant_id = me.json()["merchant_id"]

        self.agent_id = new_catalog_agent_id()
        with db_session(self.db_path) as conn:
            upsert_catalog_agent(
                conn, self.agent_id, merchant_id=self.merchant_id,
                display_name="Security Merchant A", canonical_domain="merchant.security.example",
            )
        self.private_key = Ed25519PrivateKey.generate()
        self.private_pem = self.private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption(),
        ).decode()
        raw_public = self.private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw_public)}
        self.thumbprint = jwk_thumbprint(self.jwk)
        self.binding_id = ""

    def _create_legacy_binding(self) -> None:
        body = {
            "admin_token": ADMIN_TOKEN,
            "binding": {
                "runtime_origin": RUNTIME_ORIGIN,
                "a2a_endpoint": A2A_ENDPOINT,
                "key_jwk": self.jwk,
                "key_id": RUNTIME_ORIGIN,
                "generation": 1,
                "service_epoch": 7,
            },
        }
        sig = _jws(self.private_pem, RUNTIME_ORIGIN, {
            "agent_id": self.agent_id,
            "key_id": RUNTIME_ORIGIN,
            "key_thumbprint": self.thumbprint,
            "runtime_origin": RUNTIME_ORIGIN,
            "a2a_endpoint": A2A_ENDPOINT,
            "generation": 1,
            "service_epoch": 7,
        })
        status, result = _call(
            self.app, "POST", f"/v1/agents/{self.agent_id}/runtime-bindings", body, signature=sig,
        )
        self.assertEqual(status, 200, result)
        self.binding_id = result["binding_id"]

    def _publish(self, digest: str = "sha256:" + "a" * 64) -> int:
        card = {
            "name": "Security Merchant A", "version": "1.0.0", "url": RUNTIME_ORIGIN,
            "supportedInterfaces": [{
                "url": A2A_ENDPOINT, "protocolBinding": "JSONRPC", "protocolVersion": "1.0",
            }],
        }
        publication = {
            "schema_version": "0.1.2", "agent_id": self.agent_id, "binding_id": self.binding_id,
            "generation": 1, "expected_revision": 0, "wire_profile": "a2a-1.0",
            "card_digest": digest, "agent_card": card,
        }
        signature = _jws(self.private_pem, RUNTIME_ORIGIN, {
            "agent_id": self.agent_id, "binding_id": self.binding_id, "card_digest": digest,
            "expected_revision": 0, "generation": 1,
        })
        status, result = _call(
            self.app, "POST", f"/v1/agents/{self.agent_id}/card-publications",
            {"publication": publication}, signature=signature,
        )
        self.assertEqual(status, 200, result)
        revision = int(result["card_revision"])
        activate_sig = _jws(self.private_pem, RUNTIME_ORIGIN, {
            "agent_id": self.agent_id, "binding_id": self.binding_id,
            "card_revision": revision, "expected_revision": 0,
        })
        status, result = _call(self.app, "POST", f"/v1/agents/{self.agent_id}/publish", {
            "binding_id": self.binding_id, "card_revision": revision, "expected_revision": 0,
        }, signature=activate_sig)
        self.assertEqual(status, 200, result)
        return revision

    def _insert_enrollment(
        self, *, status: str = "authorized", enrollment_id: str = "enr_test_security",
        merchant_id: str | None = None, catalog_agent_id: str | None = None,
        binding_id: str = "", scopes: list[str] | None = None,
        approved_digest: str = "sha256:" + "a" * 64,
        expires_at: str | None = None, grant_expires_at: str | None = None,
    ) -> tuple[str, str]:
        device_code = "device-code-" + enrollment_id + "-" + ("x" * 36)
        user_code = "SEC12345" if enrollment_id == "enr_private_owner" else (
            "S" + hashlib.sha256(enrollment_id.encode()).hexdigest()[:7].upper()
        )
        device_hash = hashlib.sha256(device_code.encode()).hexdigest()
        now = datetime.now(UTC).replace(microsecond=0)
        enrollment_expiry = expires_at or (now + timedelta(minutes=10)).isoformat()
        grant_expiry = grant_expires_at or (now + timedelta(minutes=10)).isoformat()
        grant = enrollment_service._stable_grant(enrollment_id, device_hash)
        with db_session(self.db_path) as conn:
            conn.execute(
                "insert into enrollments(enrollment_id,device_code_hash,user_code,status,key_id,key_thumbprint,"
                "key_jwk_json,runtime_origin,a2a_endpoint,generation,service_epoch,public_preview_json,"
                "public_profile_revision,approved_card_digest,merchant_id,catalog_agent_id,grant_hash,scopes_json,"
                "expected_binding_version,binding_id,created_at,expires_at,grant_expires_at) "
                "values(?,?,?,?,?,?,?,?,?,1,7,?,'profile-v1',?,?,?,?,?,1,?,?,?,?)",
                (enrollment_id, device_hash, user_code, status, RUNTIME_ORIGIN, self.thumbprint,
                 json.dumps(self.jwk, separators=(",", ":")), RUNTIME_ORIGIN, A2A_ENDPOINT,
                 json.dumps({"name": "Security Merchant A", "description": "public", "skills": []}),
                 approved_digest, merchant_id or self.merchant_id, catalog_agent_id or self.agent_id,
                 hashlib.sha256(grant.encode()).hexdigest(),
                 json.dumps(scopes if scopes is not None else ["runtime:bind", "card:publish", "heartbeat"]),
                 binding_id, now.isoformat(), enrollment_expiry, grant_expiry),
            )
        return device_code, device_hash

class EnrollmentSecurityTest(EnrollmentFixture):
    def test_merchant_pause_cancels_enrollment_and_runtime_cannot_reactivate(self) -> None:
        self._create_legacy_binding()
        revision = self._publish()
        with db_session(self.db_path) as conn:
            digest = conn.execute(
                "select digest from agent_card_versions where catalog_agent_id=? and card_revision=?",
                (self.agent_id, revision),
            ).fetchone()["digest"]
        enrollment_id = "enr_pause_security"
        self._insert_enrollment(
            status="published", enrollment_id=enrollment_id, binding_id=self.binding_id,
            approved_digest=digest,
        )
        paused = self.client.post(
            f"/v1/accounts/agents/{self.agent_id}/card/pause",
            json={"expected_revision": revision},
        )
        self.assertEqual(paused.status_code, 200, paused.text)
        with db_session(self.db_path) as conn:
            row = conn.execute("select status,authorization_epoch from enrollments where enrollment_id=?",
                               (enrollment_id,)).fetchone()
            self.assertEqual(row["status"], "canceled")
            self.assertGreater(int(row["authorization_epoch"]), 1)

        # This is a fresh, correctly signed Runtime activation request. The old
        # enrollment authorization must not override a merchant pause.
        signature = _jws(self.private_pem, RUNTIME_ORIGIN, {
            "agent_id": self.agent_id, "binding_id": self.binding_id,
            "card_revision": revision, "expected_revision": revision,
        })
        status, result = _call(self.app, "POST", f"/v1/agents/{self.agent_id}/publish", {
            "binding_id": self.binding_id, "card_revision": revision, "expected_revision": revision,
        }, signature=signature)
        self.assertEqual(status, 409, result)
        with db_session(self.db_path) as conn:
            state = conn.execute("select publication_state from card_publications where catalog_agent_id=?",
                                 (self.agent_id,)).fetchone()["publication_state"]
            self.assertEqual(state, "PAUSED")

    def test_cross_merchant_enrollment_detail_and_authorize_are_denied(self) -> None:
        enrollment_id = "enr_private_owner"
        self._insert_enrollment(
            status="ready_for_authorization", enrollment_id=enrollment_id,
            merchant_id=self.merchant_id,
        )
        # Create and login a second merchant account in the same isolated DB.
        email = "security-other@example.test"
        registered = self.client.post("/v1/accounts/register", json={
            "merchant_name": "Security Merchant B", "email": email,
            "password": "strong-password-456", "phone": "+1 555 0201",
        })
        self.assertEqual(registered.status_code, 200, registered.text)
        verified = self.client.post("/v1/accounts/verify-email", json={
            "email": email, "code": registered.json()["verification_code"],
        })
        self.assertEqual(verified.status_code, 200, verified.text)
        other_merchant_id = self.client.get("/v1/accounts/me").json()["merchant_id"]
        self.assertNotEqual(other_merchant_id, self.merchant_id)

        detail = self.client.get(f"/v1/accounts/enrollments/{enrollment_id}")
        self.assertEqual(detail.status_code, 404)
        decision = self.client.post(
            f"/v1/accounts/enrollments/{enrollment_id}/authorize",
            json={"user_code": "SEC12345"}, headers={"Origin": "https://localhost"},
        )
        self.assertEqual(decision.status_code, 409, decision.text)
        with db_session(self.db_path) as conn:
            row = conn.execute("select status,merchant_id from enrollments where enrollment_id=?",
                               (enrollment_id,)).fetchone()
            self.assertEqual(row["status"], "ready_for_authorization")
            self.assertEqual(row["merchant_id"], self.merchant_id)

    def test_bound_retry_rejects_bad_runtime_signature(self) -> None:
        self._create_legacy_binding()
        enrollment_id = "enr_bound_bad_sig"
        _, device_hash = self._insert_enrollment(
            status="bound", enrollment_id=enrollment_id, binding_id=self.binding_id,
        )
        grant = enrollment_service._stable_grant(enrollment_id, device_hash)
        body = {
            "enrollment_id": enrollment_id, "grant": grant,
            "binding": {
                "runtime_origin": RUNTIME_ORIGIN, "a2a_endpoint": A2A_ENDPOINT,
                "key_jwk": self.jwk, "key_id": RUNTIME_ORIGIN,
                "generation": 1, "service_epoch": 7,
            },
        }
        wrong_key = Ed25519PrivateKey.generate()
        wrong_pem = wrong_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
        grant_hash = hashlib.sha256(grant.encode()).hexdigest()
        signature = _jws(wrong_pem, RUNTIME_ORIGIN, {
            "method": "POST", "path": f"/v1/agents/{self.agent_id}/runtime-bindings",
            "audience": "kiwi-catalog", "body_digest": canonical_digest(body),
            "enrollment_id": enrollment_id, "grant_hash": grant_hash,
            "catalog_agent_id": self.agent_id, "key_id": RUNTIME_ORIGIN,
            "key_thumbprint": self.thumbprint, "runtime_origin": RUNTIME_ORIGIN,
            "a2a_endpoint": A2A_ENDPOINT, "generation": 1, "service_epoch": 7,
            "authorization_epoch": 1,
            "exp": (datetime.now(UTC) + timedelta(seconds=30)).isoformat(),
        })
        status, result = _call(self.app, "POST", f"/v1/agents/{self.agent_id}/runtime-bindings",
                               body, signature=signature)
        self.assertEqual(status, 403, result)

    def test_poll_replay_fails_and_new_signed_poll_returns_same_grant(self) -> None:
        enrollment_id = "enr_poll_replay"
        device_code, _ = self._insert_enrollment(status="authorized", enrollment_id=enrollment_id)
        fields = {
            "method": "POST", "path": "/v1/enrollments/device/token", "audience": "kiwi-catalog",
            "device_code_hash": hashlib.sha256(device_code.encode()).hexdigest(),
            "key_id": RUNTIME_ORIGIN, "key_thumbprint": self.thumbprint,
            "exp": (datetime.now(UTC) + timedelta(seconds=30)).isoformat(),
        }
        body = {"device_code": device_code}
        first_signature = _jws(self.private_pem, RUNTIME_ORIGIN, fields)
        status, first = _call(self.app, "POST", "/v1/enrollments/device/token", body,
                              signature=first_signature)
        self.assertEqual(status, 200, first)
        self.assertNotIn("error", first)

        replay_status, replay = _call(self.app, "POST", "/v1/enrollments/device/token", body,
                                      signature=first_signature)
        self.assertIn(replay_status, (400, 403, 409), replay)
        self.assertIn("replay", str(replay.get("error", "")).lower())

        retry_signature = _jws(self.private_pem, RUNTIME_ORIGIN, fields)
        retry_status, retry = _call(self.app, "POST", "/v1/enrollments/device/token", body,
                                    signature=retry_signature)
        self.assertEqual(retry_status, 200, retry)
        self.assertEqual(retry["grant"], first["grant"])

    def test_missing_runtime_bind_scope_and_public_card_tampering_are_rejected(self) -> None:
        enrollment_id = "enr_scope_tamper"
        _, device_hash = self._insert_enrollment(
            status="authorized", enrollment_id=enrollment_id, scopes=["card:publish", "heartbeat"],
        )
        grant = enrollment_service._stable_grant(enrollment_id, device_hash)
        body = {
            "enrollment_id": enrollment_id, "grant": grant,
            "binding": {
                "runtime_origin": RUNTIME_ORIGIN, "a2a_endpoint": A2A_ENDPOINT,
                "key_jwk": self.jwk, "key_id": RUNTIME_ORIGIN,
                "generation": 1, "service_epoch": 7,
            },
        }
        binding_sig = _jws(self.private_pem, RUNTIME_ORIGIN, {
            "method": "POST", "path": f"/v1/agents/{self.agent_id}/runtime-bindings",
            "audience": "kiwi-catalog", "body_digest": canonical_digest(body),
            "enrollment_id": enrollment_id, "grant_hash": hashlib.sha256(grant.encode()).hexdigest(),
            "catalog_agent_id": self.agent_id, "key_id": RUNTIME_ORIGIN,
            "key_thumbprint": self.thumbprint, "runtime_origin": RUNTIME_ORIGIN,
            "a2a_endpoint": A2A_ENDPOINT, "generation": 1, "service_epoch": 7,
            "authorization_epoch": 1,
            "exp": (datetime.now(UTC) + timedelta(seconds=30)).isoformat(),
        })
        scope_status, scope_result = _call(
            self.app, "POST", f"/v1/agents/{self.agent_id}/runtime-bindings", body,
            signature=binding_sig,
        )
        self.assertEqual(scope_status, 403, scope_result)

        self._create_legacy_binding()
        self._publish()
        with db_session(self.db_path) as conn:
            conn.execute(
                "update enrollments set status='bound',binding_id=?,approved_card_digest=?,scopes_json=? "
                "where enrollment_id=?",
                (self.binding_id, "sha256:" + "a" * 64, '["runtime:bind","card:publish"]', enrollment_id),
            )
        changed_digest = "sha256:" + "b" * 64
        card = {
            "name": "Changed Public Name", "version": "1.0.0", "url": RUNTIME_ORIGIN,
            "supportedInterfaces": [{
                "url": A2A_ENDPOINT, "protocolBinding": "JSONRPC", "protocolVersion": "1.0",
            }],
        }
        publication = {
            "schema_version": "0.1.2", "agent_id": self.agent_id, "binding_id": self.binding_id,
            "generation": 1, "expected_revision": 1, "wire_profile": "a2a-1.0",
            "card_digest": changed_digest, "agent_card": card,
        }
        signature = _jws(self.private_pem, RUNTIME_ORIGIN, {
            "agent_id": self.agent_id, "binding_id": self.binding_id,
            "card_digest": changed_digest, "expected_revision": 1, "generation": 1,
        })
        card_status, card_result = _call(
            self.app, "POST", f"/v1/agents/{self.agent_id}/card-publications",
            {"publication": publication}, signature=signature,
        )
        self.assertEqual(card_status, 409, card_result)


class EnrollmentAuthorizationApiTest(EnrollmentFixture):
    """商家侧预览 / 授权 API 的行为与安全断言（不含任何页面依赖）。

    这些断言原本在 ``tests/test_portal_enrollment_flow.py`` 里与商家门户页面测试
    混在一个文件；门户页面移入私有扩展后该文件整体删除，但
    ``/v1/accounts/enrollments/{id}`` 与 ``/authorize`` 仍留在本包，其安全语义
    （匿名拒绝、字段不泄漏、CSRF 源校验、失败不改状态、重复授权幂等）必须继续
    有覆盖，故迁到这里。
    """

    def _user_code(self, enrollment_id: str) -> str:
        return "S" + hashlib.sha256(enrollment_id.encode()).hexdigest()[:7].upper()

    def _login_owner(self) -> None:
        logged_in = self.client.post("/v1/accounts/login", json={
            "email": self.owner, "password": "strong-password-123",
        })
        self.assertEqual(logged_in.status_code, 200, logged_in.text)

    def test_preview_and_authorize_api_flow(self) -> None:
        enrollment_id = "enr_authorize_api_flow"
        self._insert_enrollment(status="ready_for_authorization", enrollment_id=enrollment_id)
        user_code = self._user_code(enrollment_id)
        detail_url = f"/v1/accounts/enrollments/{enrollment_id}"

        # 商家私密预览：匿名必须被拒。
        self.client.cookies.clear()
        anonymous = self.client.get(detail_url)
        self.assertEqual(anonymous.status_code, 403, anonymous.text)

        self._login_owner()
        preview = self.client.get(detail_url)
        self.assertEqual(preview.status_code, 200, preview.text)
        self.assertEqual(preview.json()["user_code"], user_code)
        self.assertEqual(preview.json()["public_preview"]["name"], "Security Merchant A")
        # 预览不得泄漏设备码 / 运行时公钥 / 授权码。
        self.assertNotIn("device_code", preview.text)
        self.assertNotIn("key_jwk", preview.text)
        self.assertNotIn("grant", preview.text)

        authorized = self.client.post(
            f"{detail_url}/authorize",
            json={"user_code": user_code}, headers={"Origin": "https://localhost"},
        )
        self.assertEqual(authorized.status_code, 200, authorized.text)
        self.assertEqual(authorized.json()["status"], "authorized")
        self.assertNotIn("grant", authorized.text)

        # 重复授权是幂等的，不应把已授权的登记打回。
        replay = self.client.post(
            f"{detail_url}/authorize",
            json={"user_code": user_code}, headers={"Origin": "https://localhost"},
        )
        self.assertEqual(replay.status_code, 200, replay.text)

        final = self.client.get(detail_url)
        self.assertEqual(final.status_code, 200, final.text)
        self.assertEqual(final.json()["status"], "authorized")

    def test_authorize_rejects_cross_origin_and_wrong_code(self) -> None:
        enrollment_id = "enr_authorize_api_guard"
        self._insert_enrollment(status="ready_for_authorization", enrollment_id=enrollment_id)
        detail_url = f"/v1/accounts/enrollments/{enrollment_id}"

        cross_origin = self.client.post(
            f"{detail_url}/authorize",
            json={"user_code": self._user_code(enrollment_id)},
            headers={"Origin": "https://evil.example"},
        )
        self.assertEqual(cross_origin.status_code, 403, cross_origin.text)

        wrong_code = self.client.post(
            f"{detail_url}/authorize",
            json={"user_code": "00000000"}, headers={"Origin": "https://localhost"},
        )
        self.assertIn(wrong_code.status_code, (400, 409), wrong_code.text)

        # 失败的授权不得改变登记状态。
        still_ready = self.client.get(detail_url)
        self.assertEqual(still_ready.status_code, 200, still_ready.text)
        self.assertEqual(still_ready.json()["status"], "ready_for_authorization")


if __name__ == "__main__":
    unittest.main()
