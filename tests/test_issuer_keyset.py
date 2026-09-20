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

"""SIG-04（最小）：发行者密钥集合、状态机与轮换。

覆盖：
  - 单密钥 env 回退（视为 ACTIVE）与密钥集合文件两条加载路径；
  - **只有 ACTIVE 能签发**：无 ACTIVE / 多于一个 ACTIVE → 拒签；
  - **COMPROMISED 是终态**：任何"恢复"迁移被拒（泄漏密钥不得复活）；
  - `public_keys()` 只含公钥（分发形状，无任何私钥材料）；
  - 签发联动：密钥集合里 ACTIVE 轮换到 VERIFY_ONLY 后，`read_runtime_binding` 拒签。
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from kiwi_catalog.a2a.binding_claims import (
    ISSUER_KEYS_FILE_ENV,
    load_issuer_identity,
    load_issuer_key_set,
)
from kiwi_catalog.core.errors import NotFoundError, PermissionDenied, ValidationError


def _write_key(dir_path: Path, name: str) -> tuple[str, Path]:
    key = Ed25519PrivateKey.generate()
    path = dir_path / name
    path.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    return name, path


def _write_key_set(dir_path: Path, entries: list[dict]) -> Path:
    path = dir_path / "issuer-keys.json"
    path.write_text(json.dumps({"keys": entries}), encoding="utf-8")
    return path


class IssuerKeySetTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def _env_with_single(self) -> dict[str, str]:
        _, key_path = _write_key(self.dir, "single.pem")
        return {
            "KIWI_CATALOG_ISSUER_KEY_FILE": str(key_path),
            "KIWI_CATALOG_ISSUER_KID": "issuer-single",
        }

    def _env_with_set(self, states: list[str]) -> dict[str, str]:
        entries = []
        for index, state in enumerate(states):
            kid, key_path = _write_key(self.dir, f"issuer-{index}.pem")
            entries.append(
                {"kid": f"issuer-{index}", "state": state, "private_key_file": str(key_path)}
            )
        keys_path = _write_key_set(self.dir, entries)
        return {
            ISSUER_KEYS_FILE_ENV: str(keys_path),
            "KIWI_CATALOG_PUBLIC_ORIGIN": "https://catalog.example",
        }

    # ── 加载路径 ─────────────────────────────────────────────
    def test_single_key_env_falls_back_to_active(self) -> None:
        env = self._env_with_single()
        key_set = load_issuer_key_set(env)
        self.assertEqual(key_set.kids, ["issuer-single"])
        self.assertEqual(key_set.state_of("issuer-single"), "ACTIVE")
        self.assertEqual(key_set.signing_identity().kid, "issuer-single")
        # 与单密钥路径口径一致：同一把钥匙 → 同一 thumbprint
        self.assertEqual(
            key_set.signing_identity().thumbprint, load_issuer_identity(env).thumbprint
        )

    def test_missing_configuration_refuses_to_sign(self) -> None:
        with self.assertRaises(PermissionDenied):
            load_issuer_key_set({})
        with self.assertRaises(PermissionDenied):
            load_issuer_identity({})

    def test_key_set_file_entry_must_be_wellformed(self) -> None:
        _, key_path = _write_key(self.dir, "k.pem")
        bad_state = _write_key_set(
            self.dir, [{"kid": "k1", "state": "LIVE", "private_key_file": str(key_path)}]
        )
        with self.assertRaises(PermissionDenied):
            load_issuer_key_set({ISSUER_KEYS_FILE_ENV: str(bad_state)})

        missing_file = _write_key_set(
            self.dir, [{"kid": "k1", "state": "ACTIVE", "private_key_file": str(self.dir / "nope.pem")}]
        )
        with self.assertRaises(PermissionDenied):
            load_issuer_key_set({ISSUER_KEYS_FILE_ENV: str(missing_file)})

        empty = _write_key_set(self.dir, [])
        with self.assertRaises(PermissionDenied):
            load_issuer_key_set({ISSUER_KEYS_FILE_ENV: str(empty)})

    # ── 签发选择 ─────────────────────────────────────────────
    def test_exactly_one_active_required(self) -> None:
        no_active = load_issuer_key_set(self._env_with_set(["PREPARED", "VERIFY_ONLY"]))
        with self.assertRaises(PermissionDenied):
            no_active.signing_identity()

        two_active = load_issuer_key_set(self._env_with_set(["ACTIVE", "ACTIVE"]))
        with self.assertRaises(PermissionDenied):
            two_active.signing_identity()

        one_active = load_issuer_key_set(self._env_with_set(["VERIFY_ONLY", "ACTIVE", "PREPARED"]))
        self.assertEqual(one_active.signing_identity().kid, "issuer-1")

    def test_public_keys_distribution_shape_has_no_private_material(self) -> None:
        key_set = load_issuer_key_set(self._env_with_set(["ACTIVE", "RETIRED"]))
        distributed = key_set.public_keys()
        self.assertEqual(sorted(distributed), ["issuer-0", "issuer-1"])
        for kid, entry in distributed.items():
            self.assertIn(entry["state"], ("ACTIVE", "RETIRED"))
            self.assertEqual(entry["jwk"]["kty"], "OKP")
            self.assertEqual(entry["jwk"]["crv"], "Ed25519")
            self.assertNotIn("d", entry["jwk"])  # 绝无私钥参数
            self.assertEqual(sorted(entry["jwk"]), ["crv", "kty", "x"])
        serialized = json.dumps(distributed)
        self.assertNotIn("PRIVATE KEY", serialized)
        self.assertNotIn("private_key", serialized)

    # ── 状态机 ───────────────────────────────────────────────
    def test_rotation_lifecycle_and_compromised_is_terminal(self) -> None:
        key_set = load_issuer_key_set(self._env_with_set(["ACTIVE"]))
        self.assertEqual(key_set.signing_identity().kid, "issuer-0")

        # 轮换：新钥匙 PREPARED → ACTIVE，旧钥匙 ACTIVE → VERIFY_ONLY（验签期）
        self.assertEqual(key_set.transition("issuer-0", "VERIFY_ONLY"), "VERIFY_ONLY")
        with self.assertRaises(PermissionDenied):
            key_set.signing_identity()  # 无 ACTIVE 期间不签发
        # VERIFY_ONLY 仍用于验签（公钥可分发），随后可 RETIRED
        self.assertEqual(key_set.transition("issuer-0", "RETIRED"), "RETIRED")

        # 泄漏 → COMPROMISED 是终态
        self.assertEqual(key_set.transition("issuer-0", "COMPROMISED"), "COMPROMISED")
        for attempt in ("ACTIVE", "VERIFY_ONLY", "RETIRED", "PREPARED"):
            with self.assertRaises(PermissionDenied):
                key_set.transition("issuer-0", attempt)
        self.assertEqual(key_set.state_of("issuer-0"), "COMPROMISED")

    def test_transition_rejects_unknown_kid_and_state(self) -> None:
        key_set = load_issuer_key_set(self._env_with_set(["ACTIVE"]))
        with self.assertRaises(NotFoundError):
            key_set.transition("nope", "ACTIVE")
        with self.assertRaises(ValidationError):
            key_set.transition("issuer-0", "ACTIVEISH")

    # ── 与签发联动 ───────────────────────────────────────────
    def test_key_set_env_points_claims_issuance_at_active_key(self) -> None:
        """`read_runtime_binding` 使用密钥集合里的 ACTIVE kid 签发（不起用 RETIRED/COMPROMISED）。"""
        from datetime import datetime, timezone

        from kiwi_catalog.a2a.binding_claims import read_runtime_binding
        from kiwi_catalog.agent_catalog.sqlite_repository import (
            new_catalog_agent_id,
            upsert_catalog_agent,
        )
        from kiwi_catalog.db.session import db_session

        agent_id = new_catalog_agent_id()
        with db_session(self.dir / "catalog.sqlite") as conn:
            upsert_catalog_agent(
                conn,
                agent_id,
                merchant_id="mkt_keyset_1",
                display_name="KeySet Merchant",
                canonical_domain="keyset.example",
            )
            conn.execute(
                "insert into runtime_bindings (binding_id, catalog_agent_id, merchant_id,"
                " runtime_origin, a2a_endpoint, key_id, key_thumbprint, key_jwk_json,"
                " binding_version, service_epoch, status, expires_at, created_at, updated_at)"
                " values ('bind_keyset_1', ?, 'mkt_keyset_1', 'https://ks.example',"
                " 'https://ks.example/a2a', 'https://ks.example', 'sha256:abc', '{}', 1, 1,"
                " 'active', '', '', '')",
                (agent_id,),
            )
            conn.execute(
                "insert into agent_card_versions (catalog_agent_id, card_revision, wire_profile,"
                " canonical_bytes, digest, created_by, created_at)"
                " values (?, 1, 'a2a-1.0', '{}', 'sha256:x', 'test', '')",
                (agent_id,),
            )
            conn.execute(
                "insert into card_publications (catalog_agent_id, active_revision,"
                " publication_state, etag, updated_at) values (?, 1, 'ACTIVE', 'etag-1', '')",
                (agent_id,),
            )
            conn.commit()

            env = self._env_with_set(["VERIFY_ONLY", "ACTIVE"])
            document = read_runtime_binding(conn, agent_id, now=datetime.now(timezone.utc), env=env)
            self.assertEqual(document["issuer_kid"], "issuer-1")
            self.assertTrue(document["claims_jws"].startswith("eyJ"))

            # 把 ACTIVE 降为 VERIFY_ONLY（轮换窗口）→ 拒绝签发
            keys_path = Path(env[ISSUER_KEYS_FILE_ENV])
            payload = json.loads(keys_path.read_text(encoding="utf-8"))
            payload["keys"][1]["state"] = "VERIFY_ONLY"
            keys_path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(PermissionDenied):
                read_runtime_binding(conn, agent_id, now=datetime.now(timezone.utc), env=env)

    def test_issuer_keys_file_env_absent_from_os_environ_is_not_required(self) -> None:
        """未设置密钥集合 env 时，单密钥路径仍然工作（M3 现有部署形态不被打断）。"""
        self.assertNotIn(ISSUER_KEYS_FILE_ENV, os.environ)
        env = self._env_with_single()
        self.assertEqual(load_issuer_key_set(env).signing_identity().kid, "issuer-single")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
