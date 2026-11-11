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

"""商家接入方式 → 买家路由公开投影（v53）。

覆盖：
- 旧客户端不带 include 时 record 形状完全不变；
- include=buyer_access 的 legacy / 显式 relay / direct / auto 投影；
- 撤销、轮换、过期 binding 后旧行不再被信任（unknown，fail-closed）；
- CAS 并发、未知字段、非法模式、未签名写入；
- 模式切换不触碰 runtime_access 密文/版本（保留已保存分享码）；
- 公开响应不含 secret/binding_id/密文。
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
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
    load_pem_private_key,
)

from kiwi_catalog.a2a.binding_claims import jwk_thumbprint
from kiwi_catalog.a2a.enrollment_canonical import canonical_digest
from kiwi_catalog.agent_catalog.sqlite_repository import new_catalog_agent_id, upsert_catalog_agent
from kiwi_catalog.api.app import handle_request
from kiwi_catalog.db.migrations import CURRENT_SCHEMA_VERSION, run_migrations
from kiwi_catalog.db.session import db_session

ADMIN_TOKEN = "admin-token-buyer-access"
RUNTIME_ORIGIN = "https://pilot.example.app.workbuddy.host"
A2A_ENDPOINT = f"{RUNTIME_ORIGIN}/a2a"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _jws(private_pem: str, kid: str, fields: dict, *, expires: bool = True) -> str:
    header = {"alg": "EdDSA", "kid": kid}
    now = datetime.now(timezone.utc)
    payload = {
        **fields,
        "issued_at": now.isoformat(),
        "nonce": f"nonce-{uuid.uuid4().hex}",
    }
    if expires:
        payload["exp"] = (now + timedelta(seconds=60)).isoformat()
    header_segment = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_segment = _b64url(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode())
    key = load_pem_private_key(private_pem.encode(), password=None)
    signature = key.sign(f"{header_segment}.{payload_segment}".encode("ascii"))
    return f"{header_segment}.{payload_segment}.{_b64url(signature)}"


class BuyerAccessRoutesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "catalog.sqlite")
        conn = sqlite3.connect(self.db_path)
        run_migrations(conn)
        conn.close()
        os.environ["KIWI_CATALOG_ADMIN_TOKEN"] = ADMIN_TOKEN
        self.addCleanup(os.environ.pop, "KIWI_CATALOG_ADMIN_TOKEN", None)

        self.runtime_key = Ed25519PrivateKey.generate()
        self.runtime_pem = self.runtime_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode()
        raw = self.runtime_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.runtime_jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}
        self.catalog_agent_id = new_catalog_agent_id()
        with db_session(self.db_path) as conn:
            upsert_catalog_agent(
                conn,
                self.catalog_agent_id,
                merchant_id="mkt_buyer_access_1",
                display_name="Buyer Access Merchant",
                canonical_domain="merchant.example",
            )
        self.binding_id = self._create_binding()

    def _binding_signature(self) -> str:
        return _jws(
            self.runtime_pem,
            self.catalog_agent_id,
            {
                "agent_id": self.catalog_agent_id,
                "key_id": self.catalog_agent_id,
                "key_thumbprint": jwk_thumbprint(self.runtime_jwk),
                "runtime_origin": RUNTIME_ORIGIN,
                "a2a_endpoint": A2A_ENDPOINT,
                "generation": 1,
                "service_epoch": 7,
            },
        )

    def _create_binding(self) -> str:
        body = {
            "binding": {
                "runtime_origin": RUNTIME_ORIGIN,
                "a2a_endpoint": A2A_ENDPOINT,
                "key_jwk": self.runtime_jwk,
                "key_id": self.catalog_agent_id,
                "generation": 1,
                "service_epoch": 7,
            },
            "admin_token": ADMIN_TOKEN,
            "_binding_jws": self._binding_signature(),
        }
        status, payload = handle_request(
            self.db_path,
            "POST",
            f"/v1/agents/{self.catalog_agent_id}/runtime-bindings",
            body,
        )
        self.assertEqual(status, 200, payload)
        return str(payload["binding_id"])

    def _signed_fields(self, method: str, path: str, body: dict) -> dict:
        return {
            "method": method,
            "path": path,
            "audience": "kiwi-catalog",
            "body_digest": canonical_digest(body),
            "catalog_agent_id": self.catalog_agent_id,
            "binding_id": self.binding_id,
            "key_id": self.catalog_agent_id,
            "runtime_origin": RUNTIME_ORIGIN,
            "service_epoch": 7,
        }

    def _put(self, mode: str, expected_revision: int, *, extra: dict | None = None, sign: bool = True):
        body = {
            "binding": {"binding_id": self.binding_id},
            "mode": mode,
            "expected_revision": expected_revision,
            **(extra or {}),
        }
        if sign:
            body["_binding_jws"] = _jws(
                self.runtime_pem,
                self.catalog_agent_id,
                self._signed_fields("PUT", f"/v1/agents/{self.catalog_agent_id}/buyer-access", body),
            )
        return handle_request(
            self.db_path, "PUT", f"/v1/agents/{self.catalog_agent_id}/buyer-access", body
        )

    def _read_owner(self):
        body = {
            "_binding_jws": _jws(
                self.runtime_pem,
                self.catalog_agent_id,
                self._signed_fields("GET", f"/v1/agents/{self.catalog_agent_id}/buyer-access", {}),
            )
        }
        return handle_request(
            self.db_path, "GET", f"/v1/agents/{self.catalog_agent_id}/buyer-access", body
        )

    def _public(self, *, include: bool = True):
        status, payload = handle_request(
            self.db_path,
            "GET",
            f"/v1/agents/{self.catalog_agent_id}",
            query={"include": "buyer_access"} if include else {},
        )
        self.assertEqual(status, 200, payload)
        return payload["agent"]

    def _seed_runtime_access(self, secret_ciphertext: str = "ciphertext-not-plaintext") -> None:
        with db_session(self.db_path) as conn:
            conn.execute(
                "insert into runtime_access_configs"
                " (catalog_agent_id, config_version, provider, access_mode, parameter_name,"
                "  secret_ciphertext, key_id, adapter_version, auth_mode, status,"
                "  validated_at, created_at, updated_at, revoked_reason)"
                " values (?, 1, 'workbuddy', 'share_parameter', 'sharecode', ?, ?,"
                "         'workbuddy-share-v1', 'signature', 'active', ?, ?, ?, '')",
                (
                    self.catalog_agent_id,
                    secret_ciphertext,
                    "vault-key",
                    "2026-11-11T00:00:00+00:00",
                    "2026-11-11T00:00:00+00:00",
                    "2026-11-11T00:00:00+00:00",
                ),
            )

    def test_additive_schema_does_not_bump_user_version_for_rollback(self) -> None:
        # 版本由迁移链决定；additive 新表本身不能再把版本推高。
        self._put("no_share_code", 0)
        with db_session(self.db_path) as conn:
            version = conn.execute("pragma user_version").fetchone()[0]
            table = conn.execute(
                "select 1 from sqlite_master where type = 'table' and name = 'buyer_access_routes'"
            ).fetchone()
        self.assertEqual(version, CURRENT_SCHEMA_VERSION)
        self.assertIsNotNone(table)

    def test_lazy_schema_recreates_missing_table_for_existing_database(self) -> None:
        # 模拟已经处于当前迁移版本、升级前没有该表的存量库：首次访问应幂等补建。
        with db_session(self.db_path) as conn:
            conn.execute("drop table if exists buyer_access_routes")
        status, payload = self._put("share_code", 0)
        self.assertEqual(status, 200, payload)
        self.assertEqual(self._public()["buyer_access"]["state"], "relay")

    def test_default_public_record_is_unchanged(self) -> None:
        record = self._public(include=False)
        self.assertNotIn("buyer_access", record)
        self.assertEqual(
            set(record),
            {
                "catalog_agent_id",
                "principal_type",
                "display_name",
                "canonical_domain",
                "hosting_mode",
                "verification_level",
                "freshness_state",
                "administrative_state",
                "created_at",
                "updated_at",
                "merchant_id",
                "protocols",
            },
        )

    def test_legacy_record_defaults_to_non_authoritative_route(self) -> None:
        record = self._public()
        access = record["buyer_access"]
        self.assertEqual(access["state"], "direct")
        self.assertEqual(access["source"], "legacy_no_share_code")
        self.assertEqual(access["revision"], 0)
        self.assertEqual(access["platform_verification"], "unverified")
        self.assertNotIn("mode", access)

    def test_explicit_modes_and_auto_fallback(self) -> None:
        status, payload = self._put("share_code", 0)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["revision"], 1)
        access = self._public()["buyer_access"]
        self.assertEqual((access["state"], access["source"], access["mode"]), ("relay", "merchant_setting", "share_code"))

        status, payload = self._put("no_share_code", 1)
        self.assertEqual(status, 200, payload)
        access = self._public()["buyer_access"]
        self.assertEqual((access["state"], access["source"], access["mode"]), ("direct", "merchant_setting", "no_share_code"))

        # auto 没有平台白名单 API：按目录既有事实回退，不声称已验证。
        status, payload = self._put("auto", 2)
        self.assertEqual(status, 200, payload)
        access = self._public()["buyer_access"]
        self.assertEqual((access["state"], access["source"]), ("direct", "legacy_no_share_code"))
        self.assertEqual(access["platform_verification"], "unverified")

    def test_owner_read_is_signed_and_non_secret(self) -> None:
        self._put("share_code", 0)
        status, payload = self._read_owner()
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["mode"], "share_code")
        self.assertEqual(payload["revision"], 1)
        self.assertEqual(payload["public_state"], "relay")
        self.assertNotIn("secret", json.dumps(payload).lower())
        self.assertNotIn("binding_id", payload)

    def test_cas_conflict_does_not_silently_overwrite(self) -> None:
        self.assertEqual(self._put("share_code", 0)[0], 200)
        status, payload = self._put("no_share_code", 0)
        self.assertEqual(status, 409, payload)
        self.assertEqual(self._public()["buyer_access"]["state"], "relay")

    def test_unknown_fields_and_invalid_modes_are_rejected(self) -> None:
        status, _ = self._put("share_code", 0, extra={"verified_by_platform": True})
        self.assertEqual(status, 400)
        status, _ = self._put("platform_verified", 0)
        self.assertEqual(status, 400)
        status, _ = self._put("share_code", -1)
        self.assertEqual(status, 400)

    def test_unsigned_write_is_rejected(self) -> None:
        status, _ = self._put("share_code", 0, sign=False)
        self.assertEqual(status, 400)

    def test_revoked_binding_invalidates_previous_route(self) -> None:
        self._put("no_share_code", 0)
        self.assertEqual(self._public()["buyer_access"]["state"], "direct")
        with db_session(self.db_path) as conn:
            conn.execute(
                "update runtime_bindings set status = 'revoked' where binding_id = ?",
                (self.binding_id,),
            )
        access = self._public()["buyer_access"]
        self.assertEqual(access["state"], "unknown")
        self.assertEqual(access["source"], "authorization_changed")

    def test_rotated_binding_invalidates_previous_route(self) -> None:
        self._put("no_share_code", 0)
        with db_session(self.db_path) as conn:
            conn.execute(
                "insert into runtime_bindings"
                " (binding_id, catalog_agent_id, merchant_id, runtime_origin, a2a_endpoint,"
                "  key_id, key_thumbprint, key_jwk_json, binding_version, service_epoch,"
                "  status, expires_at, created_at, updated_at, management_base_path,"
                "  management_api_major, mcp_path)"
                " values (?, ?, 'mkt_buyer_access_1', ?, ?, ?, ?, '{}', 2, 7, 'active', ?, ?, ?, '', 0, '')",
                (
                    "bind_rotated_2",
                    self.catalog_agent_id,
                    RUNTIME_ORIGIN,
                    A2A_ENDPOINT,
                    self.catalog_agent_id,
                    "thumb",
                    "",
                    "2026-11-11T00:00:00+00:00",
                    "2026-11-11T00:00:00+00:00",
                ),
            )
        access = self._public()["buyer_access"]
        self.assertEqual((access["state"], access["source"]), ("unknown", "authorization_changed"))

    def test_expired_binding_is_not_trusted(self) -> None:
        self._put("no_share_code", 0)
        with db_session(self.db_path) as conn:
            conn.execute(
                "update runtime_bindings set expires_at = ? where binding_id = ?",
                ("2020-01-01T00:00:00+00:00", self.binding_id),
            )
        access = self._public()["buyer_access"]
        self.assertEqual(access["state"], "unknown")

    def test_mode_switch_preserves_runtime_access_and_never_leaks_secret(self) -> None:
        self._seed_runtime_access("ciphertext-keep-me")
        self._put("no_share_code", 0)
        record = self._public()
        self.assertEqual(record["buyer_access"]["state"], "direct")
        # 已保存的分享码仍在目录：模式切换只写 buyer_access_routes。
        self.assertEqual(record["runtime_access"]["config_version"], 1)
        body = json.dumps(record)
        self.assertNotIn("ciphertext-keep-me", body)
        self.assertNotIn("vault-key", body)
        with db_session(self.db_path) as conn:
            row = conn.execute(
                "select secret_ciphertext, status from runtime_access_configs"
                " where catalog_agent_id = ?",
                (self.catalog_agent_id,),
            ).fetchone()
        self.assertEqual(row["secret_ciphertext"], "ciphertext-keep-me")
        self.assertEqual(row["status"], "active")

    def test_inactive_agent_returns_unknown(self) -> None:
        self._put("no_share_code", 0)
        with db_session(self.db_path) as conn:
            conn.execute(
                "update catalog_agents set administrative_state = 'suspended'"
                " where catalog_agent_id = ?",
                (self.catalog_agent_id,),
            )
        access = self._public()["buyer_access"]
        self.assertEqual((access["state"], access["source"]), ("unknown", "agent_inactive"))

    def test_unsupported_include_is_rejected(self) -> None:
        status, payload = handle_request(
            self.db_path,
            "GET",
            f"/v1/agents/{self.catalog_agent_id}",
            query={"include": "secret_stuff"},
        )
        self.assertEqual(status, 400, payload)


if __name__ == "__main__":
    unittest.main()
