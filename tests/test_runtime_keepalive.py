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

import json
import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from cryptography.fernet import Fernet

from kiwi_catalog.api import auth as api_auth
from kiwi_catalog.api.handlers import runtime_keepalive as keepalive_api
from kiwi_catalog.core.errors import AuthError, ValidationError
from kiwi_catalog.db.session import init_db
from kiwi_catalog.services import runtime_access, runtime_keepalive

_NOW = "2026-11-04T04:00:00+00:00"
_OLD = "2026-11-01T00:00:00+00:00"
_SECRET = "test-only-keepalive-secret"
_AGENT = "cagt_keepalive"
_MERCHANT = "mkt_keepalive"


class MockGateway:
    def __init__(self, *, status: str = "request_sent") -> None:
        self.status = status
        self.calls: list[tuple[str, str]] = []
        self.lock = threading.Lock()

    def wake(self, *, agent_id: str, runtime_origin: str, secret: str) -> str:
        with self.lock:
            self.calls.append((agent_id, secret))
        return self.status


class KeepaliveTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "catalog.sqlite")
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        init_db(self.conn)
        self.keys = {"key-v1": Fernet.generate_key().decode("ascii")}
        self.env = mock.patch.dict(
            os.environ,
            {
                runtime_access.KEYS_ENV: json.dumps(self.keys),
                runtime_access.ACTIVE_KEY_ENV: "key-v1",
                runtime_access.CUSTODY_ENV: "1",
                "KIWI_CATALOG_OWNER_TOKEN_SECRET": "test-owner-secret",
            },
            clear=False,
        )
        self.env.start()
        self._seed()

    def tearDown(self) -> None:
        self.env.stop()
        self.conn.close()
        self.tmp.cleanup()

    def _seed(self) -> None:
        cipher, key_id = runtime_access.encrypt_secret(_SECRET)
        self.conn.execute(
            "insert into catalog_agents"
            " (catalog_agent_id,merchant_id,display_name,source_type,lifecycle_status,"
            " verification_status,freshness_state,administrative_state,first_seen_at,"
            " last_seen_at,created_at,updated_at)"
            " values (?,?,?,?,?,?,?,?,?,?,?,?)",
            (_AGENT, _MERCHANT, "fixture", "hosted", "active", "commerce_verified",
             "fresh", "active", _OLD, _OLD, _OLD, _OLD),
        )
        self.conn.execute(
            "insert into runtime_bindings"
            " (binding_id,catalog_agent_id,merchant_id,runtime_origin,a2a_endpoint,key_id,"
            " key_thumbprint,key_jwk_json,binding_version,service_epoch,status,created_at,updated_at)"
            " values (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("binding-1", _AGENT, _MERCHANT, "https://fixture.app.workbuddy.host",
             "https://fixture.app.workbuddy.host/a2a", "key", "thumb", "{}", 1, 1,
             "active", _NOW, _NOW),
        )
        self.conn.execute(
            "insert into runtime_access_configs"
            " (catalog_agent_id,config_version,provider,access_mode,parameter_name,"
            " secret_ciphertext,key_id,adapter_version,auth_mode,status,validated_at,"
            " created_at,updated_at,revoked_reason)"
            " values (?,?,?,?,?,?,?,?,?,?,?,?,?,'')",
            (_AGENT, 1, "workbuddy", "share_parameter", "sharecode", cipher, key_id,
             "workbuddy-share-v1", "signature", "active", _NOW, _NOW, _NOW),
        )
        self.conn.execute(
            "insert into runtime_access_consents values (?,?,?,?,?,'')",
            (_AGENT, _MERCHANT, "directory_custody", runtime_access.CONSENT_TERMS_VERSION, _NOW),
        )
        self.conn.commit()

    def _grant(self) -> None:
        runtime_keepalive.grant(
            self.conn,
            catalog_agent_id=_AGENT,
            merchant_id=_MERCHANT,
            terms_version=runtime_keepalive.TERMS_VERSION,
        )
        self.conn.commit()

    def _scheduler(self, gateway: MockGateway, **kwargs):
        return runtime_keepalive.KeepaliveScheduler(
            db_path=self.db_path,
            gateway=gateway,
            enabled=True,
            clock=lambda: _NOW,
            **kwargs,
        )

    def _owner_payload(self, *, granted: bool, terms: str | None = None, merchant: str = _MERCHANT) -> dict:
        return {
            "owner_token": api_auth.owner_token(merchant),
            "consent": {
                "granted": granted,
                "terms_version": terms if terms is not None else runtime_keepalive.TERMS_VERSION,
            },
        }

    def test_owner_entry_requires_owner_token_and_explicit_consent(self) -> None:
        with self.assertRaises(AuthError):
            keepalive_api.update_consent(self.db_path, _AGENT, {"consent": {
                "granted": True, "terms_version": runtime_keepalive.TERMS_VERSION}})
        with self.assertRaises(AuthError):
            keepalive_api.update_consent(
                self.db_path, _AGENT, self._owner_payload(granted=True, merchant="mkt_other")
            )
        # Existing custody consent alone is not keepalive consent.
        view = keepalive_api.read_consent(self.db_path, _AGENT, {"owner_token": api_auth.owner_token(_MERCHANT)})
        self.assertFalse(view["granted"])
        self.assertFalse(view["default_enabled"])
        self.assertFalse(view["scheduler_enabled"])

    def test_owner_grant_and_revoke_are_visible_and_stop_scheduler(self) -> None:
        granted = keepalive_api.update_consent(self.db_path, _AGENT, self._owner_payload(granted=True))
        self.assertTrue(granted["granted"])
        read = keepalive_api.read_consent(self.db_path, _AGENT, {"owner_token": api_auth.owner_token(_MERCHANT)})
        self.assertTrue(read["granted"])
        self.assertEqual(read["scope"], runtime_keepalive.SCOPE)
        self.assertIn("签名心跳", read["terms_text"])

        gateway = MockGateway()
        self._scheduler(gateway).run_once(now=_NOW)
        self.assertEqual(len(gateway.calls), 1)

        revoked = keepalive_api.update_consent(
            self.db_path, _AGENT,
            self._owner_payload(granted=False, terms="obsolete-terms"),
        )
        self.assertFalse(revoked["granted"])
        read_after = keepalive_api.read_consent(self.db_path, _AGENT, {"owner_token": api_auth.owner_token(_MERCHANT)})
        self.assertFalse(read_after["granted"])
        self.assertFalse(runtime_keepalive.enabled(self.conn, _AGENT))
        self._scheduler(gateway).run_once(now="2026-11-04T04:20:00+00:00")
        self.assertEqual(len(gateway.calls), 1)

    def test_old_terms_are_rejected_for_grant_but_revoke_stays_available(self) -> None:
        with self.assertRaises(ValidationError):
            keepalive_api.update_consent(
                self.db_path, _AGENT,
                self._owner_payload(granted=True, terms="old-keepalive-terms"),
            )
        granted = keepalive_api.update_consent(self.db_path, _AGENT, self._owner_payload(granted=True))
        self.assertTrue(granted["granted"])
        revoked = keepalive_api.update_consent(
            self.db_path, _AGENT, self._owner_payload(granted=False, terms="old-keepalive-terms")
        )
        self.assertFalse(revoked["granted"])

    def test_default_is_off_and_consent_is_separate_and_revocable(self) -> None:
        gateway = MockGateway()
        disabled = runtime_keepalive.KeepaliveScheduler(db_path=self.db_path, gateway=gateway)
        self.assertFalse(disabled.run_once(now=_NOW).enabled)

        # Existing custody consent alone never authorizes keepalive.
        self.assertFalse(
            runtime_keepalive.KeepaliveScheduler(
                db_path=self.db_path, gateway=gateway, enabled=True, clock=lambda: _NOW
            ).run_once(now=_NOW).wake_requested
        )
        self._grant()
        self._scheduler(gateway).run_once(now=_NOW)
        self.assertEqual(len(gateway.calls), 1)

        runtime_keepalive.revoke(self.conn, catalog_agent_id=_AGENT, merchant_id=_MERCHANT)
        self.conn.commit()
        self.assertFalse(runtime_keepalive.enabled(self.conn, _AGENT))
        after = self._scheduler(gateway).run_once(now="2026-11-04T04:20:00+00:00")
        self.assertEqual(after.wake_requested, 0)
        self.assertEqual(len(gateway.calls), 1)

    def test_only_a_real_heartbeat_changes_freshness(self) -> None:
        self._grant()
        gateway = MockGateway()
        tick = self._scheduler(gateway).run_once(now=_NOW)
        self.assertEqual(tick.wake_requested, 1)
        row = self.conn.execute("select last_seen_at from catalog_agents").fetchone()
        self.assertEqual(row[0], _OLD)  # wake never updates catalog state
        # Simulate the merchant's own signed heartbeat, not the scheduler.
        self.conn.execute("update catalog_agents set last_seen_at=?", (_NOW,))
        self.conn.commit()
        second = self._scheduler(gateway).run_once(now="2026-11-04T04:10:00+00:00")
        self.assertEqual(second.wake_requested, 0)
        self.assertEqual(len(gateway.calls), 1)

    def test_per_agent_cooldown_prevents_repeated_requests(self) -> None:
        self._grant()
        gateway = MockGateway()
        scheduler = self._scheduler(gateway, interval_seconds=300)
        scheduler.run_once(now=_NOW)
        tick = scheduler.run_once(now="2026-11-04T04:05:01+00:00")
        self.assertEqual(tick.skipped, "cooldown")
        self.assertEqual(len(gateway.calls), 1)

    def test_unsafe_origin_is_never_sent(self) -> None:
        self._grant()
        self.conn.execute("update runtime_bindings set runtime_origin='https://127.0.0.1'")
        self.conn.commit()
        gateway = MockGateway()
        tick = self._scheduler(gateway).run_once(now=_NOW)
        self.assertEqual(tick.candidates, 0)
        self.assertEqual(gateway.calls, [])

    def test_unverified_gateway_never_sends_and_is_not_default(self) -> None:
        self._grant()
        gateway = runtime_keepalive.UnverifiedWorkBuddyGateway()
        tick = self._scheduler(gateway).run_once(now=_NOW)  # type: ignore[arg-type]
        self.assertEqual(tick.wake_requested, 0)
        self.assertEqual(tick.failed, 1)
        with self.assertRaises(runtime_keepalive.KeepaliveNotVerified):
            gateway.wake(agent_id=_AGENT, runtime_origin="https://fixture.app.workbuddy.host", secret=_SECRET)

    def test_concurrent_wake_limit_is_bounded(self) -> None:
        # Add a second independently opted-in agent.
        cipher, key_id = runtime_access.encrypt_secret("second-secret")
        second = "cagt_keepalive_2"
        self.conn.execute(
            "insert into catalog_agents"
            " (catalog_agent_id,merchant_id,display_name,source_type,lifecycle_status,"
            " verification_status,freshness_state,administrative_state,first_seen_at,"
            " last_seen_at,created_at,updated_at)"
            " values (?,?,?,?,?,?,?,?,?,?,?,?)",
            (second, "mkt_2", "second", "hosted", "active", "commerce_verified",
             "fresh", "active", _OLD, _OLD, _OLD, _OLD),
        )
        self.conn.execute(
            "insert into runtime_bindings"
            " (binding_id,catalog_agent_id,merchant_id,runtime_origin,a2a_endpoint,key_id,"
            " key_thumbprint,key_jwk_json,binding_version,service_epoch,status,created_at,updated_at)"
            " values (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("binding-2", second, "mkt_2", "https://second.app.workbuddy.host",
             "https://second.app.workbuddy.host/a2a", "key", "thumb", "{}", 1, 1,
             "active", _NOW, _NOW),
        )
        self.conn.execute(
            "insert into runtime_access_configs"
            " (catalog_agent_id,config_version,provider,access_mode,parameter_name,"
            " secret_ciphertext,key_id,adapter_version,auth_mode,status,validated_at,"
            " created_at,updated_at,revoked_reason)"
            " values (?,?,?,?,?,?,?,?,?,?,?,?,?,'')",
            (second, 1, "workbuddy", "share_parameter", "sharecode", cipher, key_id,
             "workbuddy-share-v1", "signature", "active", _NOW, _NOW, _NOW),
        )
        self.conn.execute(
            "insert into runtime_access_consents values (?,?,?,?,?,'')",
            (second, "mkt_2", "directory_custody", runtime_access.CONSENT_TERMS_VERSION, _NOW),
        )
        self.conn.execute(
            "insert into runtime_keepalive_consents values (?,?,?,?,?,'')",
            (second, "mkt_2", runtime_keepalive.SCOPE, runtime_keepalive.TERMS_VERSION, _NOW),
        )
        self._grant()
        self.conn.commit()
        gateway = MockGateway()
        tick = self._scheduler(gateway, max_concurrency=2).run_once(now=_NOW)
        self.assertEqual(tick.wake_requested, 2)
        self.assertEqual(len(gateway.calls), 2)

    def test_wrong_terms_are_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            runtime_keepalive.grant(
                self.conn,
                catalog_agent_id=_AGENT,
                merchant_id=_MERCHANT,
                terms_version="old-terms",
            )


if __name__ == "__main__":
    unittest.main()
