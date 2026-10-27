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

from __future__ import annotations

import os
import sqlite3
import unittest
from unittest import mock

from cryptography.fernet import Fernet

from kiwi_catalog.core.errors import ConflictError, NotFoundError, ValidationError
from kiwi_catalog.db.migrations import (
    migration_043_runtime_access_configs,
    migration_044_runtime_access_consents,
    migration_045_runtime_access_revoked_reason,
)
from kiwi_catalog.services.runtime_access import (
    ACTIVE_KEY_ENV,
    KEYS_ENV,
    active_public_projections,
    active_runtime_access,
    activate_runtime_access,
    append_share_parameter,
    buyer_projection,
    invalidate_runtime_access,
    latest_runtime_access,
    merchant_projection,
    parse_access_config,
    public_projection,
    revoke_runtime_access,
    row_secret,
    stage_runtime_access,
)

_AGENT = "cagt_runtime_access"
_SECRET = "test-only-share-secret"


def _config(expected_version: int, *, secret: str = _SECRET) -> dict[str, object]:
    return {
        "provider": "workbuddy",
        "access_mode": "share_parameter",
        "parameter_name": "sharecode",
        "secret_value": secret,
        "adapter_version": "workbuddy-share-v1",
        "auth_mode": "signature",
        "expected_version": expected_version,
        "consent": {"terms_version": "workbuddy-share-v1-2026-10-27", "granted": True},
    }


class RuntimeAccessTest(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        migration_043_runtime_access_configs(self.conn)
        migration_044_runtime_access_consents(self.conn)
        migration_045_runtime_access_revoked_reason(self.conn)
        # 授权必须绑定真实商家：服务层会在激活时读 catalog_agents.merchant_id。
        self.conn.execute(
            "create table if not exists catalog_agents"
            " (catalog_agent_id text primary key, merchant_id text not null)"
        )
        self.conn.execute(
            "insert into catalog_agents (catalog_agent_id, merchant_id) values (?, 'mkt_test')",
            (_AGENT,),
        )
        self.keys = {"key-v1": Fernet.generate_key().decode("ascii")}
        self.env = mock.patch.dict(
            os.environ,
            {
                KEYS_ENV: __import__("json").dumps(self.keys),
                ACTIVE_KEY_ENV: "key-v1",
                "KIWI_CATALOG_ACCESS_CUSTODY_ENABLED": "1",
            },
            clear=False,
        )
        self.env.start()

    def tearDown(self) -> None:
        self.env.stop()
        self.conn.close()

    def test_strict_input_rejects_unknown_fields_and_unsupported_modes(self) -> None:
        invalid: list[object] = [
            None,
            [],
            {**_config(0), "unknown": True},
            {**_config(0), "provider": "other"},
            {**_config(0), "adapter_version": "other"},
            {**_config(0), "auth_mode": "bearer"},
            {**_config(0), "parameter_name": "code"},
            {**_config(0), "secret_value": ""},
            {**_config(0), "secret_value": "x" * 4097},
            {**_config(0), "expected_version": -1},
            {**_config(0), "expected_version": True},
            {**_config(0), "expected_version": "0"},
            {"access_mode": "none", "expected_version": 0, "secret_value": "forbidden"},
        ]
        for value in invalid:
            with self.subTest(value=value if not isinstance(value, dict) else sorted(value)):
                with self.assertRaises(ValidationError):
                    parse_access_config(value)

    def test_pending_is_private_and_database_contains_only_ciphertext(self) -> None:
        result = stage_runtime_access(
            self.conn, catalog_agent_id=_AGENT, access_config=_config(0)
        )
        self.assertEqual(result["status"], "pending")
        self.assertNotIn("secret_value", result)
        self.assertNotIn("secret_ciphertext", result)
        row = latest_runtime_access(self.conn, _AGENT)
        self.assertIsNotNone(row)
        assert row is not None
        self.assertIsNone(public_projection(row))
        self.assertNotIn(_SECRET, str(row["secret_ciphertext"]))
        self.assertEqual(row_secret(row), _SECRET)
        self.assertNotIn(_SECRET, repr(merchant_projection(row)))

    def test_activate_decrypts_for_buyer_without_exposing_storage_fields(self) -> None:
        stage_runtime_access(self.conn, catalog_agent_id=_AGENT, access_config=_config(0))
        activated = activate_runtime_access(
            self.conn, catalog_agent_id=_AGENT, config_version=1
        )
        self.assertEqual(activated["status"], "active")
        self.assertTrue(activated["validated_at"])
        row = active_runtime_access(self.conn, _AGENT)
        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(
            public_projection(row),
            {
                "provider": "workbuddy",
                "access_mode": "share_parameter",
                "parameter_name": "sharecode",
                "config_version": 1,
                "adapter_version": "workbuddy-share-v1",
                "auth_mode": "signature",
            },
        )
        buyer = buyer_projection(row, runtime_origin="https://merchant.example")
        self.assertEqual(buyer["secret_value"], _SECRET)
        self.assertEqual(buyer["catalog_agent_id"], _AGENT)
        self.assertNotIn("secret_ciphertext", buyer)
        self.assertNotIn("key_id", buyer)

    def test_failed_update_preserves_old_active_and_retry_uses_latest_head(self) -> None:
        stage_runtime_access(self.conn, catalog_agent_id=_AGENT, access_config=_config(0))
        activate_runtime_access(self.conn, catalog_agent_id=_AGENT, config_version=1)
        stage_runtime_access(
            self.conn, catalog_agent_id=_AGENT, access_config=_config(1, secret="replacement")
        )
        invalidate_runtime_access(self.conn, catalog_agent_id=_AGENT, config_version=2)
        old = active_runtime_access(self.conn, _AGENT)
        self.assertIsNotNone(old)
        assert old is not None
        self.assertEqual(int(old["config_version"]), 1)
        self.assertEqual(buyer_projection(old, runtime_origin="https://merchant.example")["secret_value"], _SECRET)
        with self.assertRaises(ConflictError):
            stage_runtime_access(self.conn, catalog_agent_id=_AGENT, access_config=_config(1))
        stage_runtime_access(
            self.conn, catalog_agent_id=_AGENT, access_config=_config(2, secret="replacement")
        )
        activate_runtime_access(self.conn, catalog_agent_id=_AGENT, config_version=3)
        current = active_runtime_access(self.conn, _AGENT)
        self.assertIsNotNone(current)
        assert current is not None
        self.assertEqual(int(current["config_version"]), 3)
        statuses = {
            int(row["config_version"]): str(row["status"])
            for row in self.conn.execute(
                "select config_version, status from runtime_access_configs where catalog_agent_id = ?",
                (_AGENT,),
            )
        }
        self.assertEqual(statuses, {1: "revoked", 2: "invalid", 3: "active"})

    def test_revocation_stops_distribution_and_blocks_pending_activation(self) -> None:
        stage_runtime_access(self.conn, catalog_agent_id=_AGENT, access_config=_config(0))
        activate_runtime_access(self.conn, catalog_agent_id=_AGENT, config_version=1)
        stage_runtime_access(self.conn, catalog_agent_id=_AGENT, access_config=_config(1))
        revoked = revoke_runtime_access(
            self.conn,
            catalog_agent_id=_AGENT,
            access_config={"access_mode": "none", "expected_version": 2},
        )
        self.assertEqual(revoked["status"], "revoked")
        self.assertIsNone(active_runtime_access(self.conn, _AGENT))
        pending = self.conn.execute(
            "select status from runtime_access_configs where catalog_agent_id = ? and config_version = 2",
            (_AGENT,),
        ).fetchone()
        self.assertEqual(pending["status"], "invalid")
        with self.assertRaises(ConflictError):
            activate_runtime_access(self.conn, catalog_agent_id=_AGENT, config_version=2)
        with self.assertRaises(NotFoundError):
            buyer_projection(
                self.conn.execute(
                    "select * from runtime_access_configs where catalog_agent_id = ? and config_version = 1",
                    (_AGENT,),
                ).fetchone(),
                runtime_origin="https://merchant.example",
            )

    def test_cas_allows_only_one_writer_at_the_same_head(self) -> None:
        stage_runtime_access(self.conn, catalog_agent_id=_AGENT, access_config=_config(0))
        with self.assertRaises(ConflictError):
            stage_runtime_access(self.conn, catalog_agent_id=_AGENT, access_config=_config(0))
        self.assertEqual(
            int(latest_runtime_access(self.conn, _AGENT)["config_version"]),
            1,
        )

    def test_historical_key_remains_decryptable_after_rotation(self) -> None:
        stage_runtime_access(self.conn, catalog_agent_id=_AGENT, access_config=_config(0))
        activate_runtime_access(self.conn, catalog_agent_id=_AGENT, config_version=1)
        self.keys["key-v2"] = Fernet.generate_key().decode("ascii")
        with mock.patch.dict(
            os.environ,
            {KEYS_ENV: __import__("json").dumps(self.keys), ACTIVE_KEY_ENV: "key-v2"},
            clear=False,
        ):
            row = active_runtime_access(self.conn, _AGENT)
            self.assertEqual(row_secret(row), _SECRET)
            stage_runtime_access(
                self.conn, catalog_agent_id=_AGENT, access_config=_config(1, secret="new-key-secret")
            )
            pending = latest_runtime_access(self.conn, _AGENT)
            self.assertEqual(pending["key_id"], "key-v2")
            self.assertEqual(row_secret(pending), "new-key-secret")

    def test_missing_or_unknown_encryption_key_fails_closed(self) -> None:
        with mock.patch.dict(os.environ, {KEYS_ENV: "", ACTIVE_KEY_ENV: ""}, clear=False):
            with self.assertRaisesRegex(RuntimeError, "not configured"):
                stage_runtime_access(self.conn, catalog_agent_id=_AGENT, access_config=_config(0))
        with mock.patch.dict(os.environ, {ACTIVE_KEY_ENV: "unknown"}, clear=False):
            with self.assertRaisesRegex(RuntimeError, "not configured"):
                stage_runtime_access(self.conn, catalog_agent_id=_AGENT, access_config=_config(0))

    def test_batch_projection_returns_only_active_rows(self) -> None:
        stage_runtime_access(self.conn, catalog_agent_id=_AGENT, access_config=_config(0))
        activate_runtime_access(self.conn, catalog_agent_id=_AGENT, config_version=1)
        stage_runtime_access(self.conn, catalog_agent_id="cagt_pending", access_config=_config(0))
        result = active_public_projections(self.conn, [_AGENT, "cagt_pending", "cagt_missing"])
        self.assertEqual(set(result), {_AGENT})
        self.assertNotIn("secret_ciphertext", repr(result))
        self.assertNotIn(_SECRET, repr(result))


class AppendShareParameterTest(unittest.TestCase):
    """发送地址构造（G1 §2.5 / §3 分享链接向量）：只追加，不改既有字节。"""

    def test_appends_parameter_to_bare_url(self) -> None:
        self.assertEqual(
            append_share_parameter("https://merchant.example/a2a", "code-1"),
            "https://merchant.example/a2a?sharecode=code-1",
        )

    def test_preserves_existing_query_bytes_and_order(self) -> None:
        # 既有业务参数必须按原样保留：签名覆盖的是去码地址，重编码会改变签名输入。
        for url, expected in (
            (
                "https://merchant.example/a2a?b=2&a=hello%20world",
                "https://merchant.example/a2a?b=2&a=hello%20world&sharecode=code-1",
            ),
            (
                "https://merchant.example/a2a?x=1&x=1&y=%2F",
                "https://merchant.example/a2a?x=1&x=1&y=%2F&sharecode=code-1",
            ),
            (
                # 尾部多余的 & 不产生空参数段。
                "https://merchant.example/a2a?a=1&",
                "https://merchant.example/a2a?a=1&sharecode=code-1",
            ),
            (
                "https://merchant.example/a2a?flag",
                "https://merchant.example/a2a?flag&sharecode=code-1",
            ),
        ):
            with self.subTest(url=url):
                self.assertEqual(append_share_parameter(url, "code-1"), expected)

    def test_encodes_secret_so_it_cannot_terminate_the_query(self) -> None:
        result = append_share_parameter("https://merchant.example/a2a", "a&b=c d/+%")
        self.assertTrue(result.endswith("?sharecode=a%26b%3Dc%20d%2F%2B%25"), result)

    def test_rejects_existing_parameter_including_encoded_name(self) -> None:
        for url in (
            "https://merchant.example/a2a?sharecode=old",
            "https://merchant.example/a2a?x=1&sharecode=",
            "https://merchant.example/a2a?%73harecode=old",
        ):
            with self.subTest(url=url):
                with self.assertRaises(ValidationError):
                    append_share_parameter(url, "new")

    def test_rejects_unsafe_target_shapes(self) -> None:
        for url in (
            "http://merchant.example/a2a",
            "https:///a2a",
            "https://merchant.example/a2a#frag",
            "https://user:pass@merchant.example/a2a",
            "https://merchant.example/a2a?sharecode=x#frag",
        ):
            with self.subTest(url=url):
                with self.assertRaises(ValidationError):
                    append_share_parameter(url, "code-1")


if __name__ == "__main__":
    unittest.main()
