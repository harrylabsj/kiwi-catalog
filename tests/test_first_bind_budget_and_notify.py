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

"""审查 P1-13：首绑 per-IP/per-key 预算 + 通知异步去重。"""

from __future__ import annotations

import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from kiwi_catalog.core.errors import RateLimitError
from kiwi_catalog.db.session import open_connection
from kiwi_catalog.services import notification_outbox
from kiwi_catalog.services.binding_requests import (
    enforce_first_bind_budget,
    first_bind_ip_budget,
    first_bind_key_budget,
)

_IP_ENV = "KIWI_CATALOG_FIRST_BIND_IP_PER_HOUR"
_KEY_ENV = "KIWI_CATALOG_FIRST_BIND_KEY_PER_HOUR"


class FirstBindBudgetTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.conn = open_connection(Path(self.tmp.name) / "catalog.sqlite")
        self.addCleanup(self.conn.close)
        for env in (_IP_ENV, _KEY_ENV):
            os.environ.pop(env, None)

    def test_per_ip_budget_blocks_after_limit(self) -> None:
        limit = first_bind_ip_budget()
        for index in range(limit):
            enforce_first_bind_budget(
                self.conn, client_ip="203.0.113.7", key_thumbprint=f"key-{index}"
            )
        with self.assertRaises(RateLimitError):
            enforce_first_bind_budget(
                self.conn, client_ip="203.0.113.7", key_thumbprint="key-overflow"
            )
        # 其他 IP 不受影响。
        enforce_first_bind_budget(
            self.conn, client_ip="203.0.113.8", key_thumbprint="key-other"
        )

    def test_per_key_budget_blocks_after_limit(self) -> None:
        limit = first_bind_key_budget()
        for index in range(limit):
            enforce_first_bind_budget(
                self.conn, client_ip=f"198.51.100.{index}", key_thumbprint="shared-key"
            )
        with self.assertRaises(RateLimitError):
            enforce_first_bind_budget(
                self.conn, client_ip="198.51.100.99", key_thumbprint="shared-key"
            )

    def test_env_overrides_budget(self) -> None:
        os.environ[_IP_ENV] = "1"
        self.addCleanup(os.environ.pop, _IP_ENV, None)
        enforce_first_bind_budget(self.conn, client_ip="192.0.2.1", key_thumbprint="k1")
        with self.assertRaises(RateLimitError):
            enforce_first_bind_budget(self.conn, client_ip="192.0.2.1", key_thumbprint="k2")

    def test_missing_ip_falls_back_to_shared_bucket(self) -> None:
        """传输层没有对端时也不能绕过预算（与账号限流同口径）。"""
        os.environ[_IP_ENV] = "1"
        self.addCleanup(os.environ.pop, _IP_ENV, None)
        enforce_first_bind_budget(self.conn, client_ip="", key_thumbprint="k1")
        with self.assertRaises(RateLimitError):
            enforce_first_bind_budget(self.conn, client_ip="", key_thumbprint="k2")


class NotificationOutboxTest(unittest.TestCase):
    def setUp(self) -> None:
        notification_outbox.reset_for_tests()
        self.addCleanup(notification_outbox.reset_for_tests)

    def test_notification_is_delivered_off_thread_and_deduped(self) -> None:
        delivered = threading.Event()
        calls: list[dict[str, object]] = []

        def fake_notify(**kwargs: object) -> bool:
            calls.append(kwargs)
            delivered.set()
            return True

        with mock.patch(
            "kiwi_catalog.services.accounts.notify_admin_binding_request",
            side_effect=fake_notify,
        ):
            first = notification_outbox.enqueue_admin_binding_request(
                merchant_id="mrc-1",
                catalog_agent_id="cagt_1",
                binding_request_id="breq_1",
                runtime_origin="https://runtime.example",
                a2a_endpoint="https://runtime.example/a2a",
                key_thumbprint="thumb-1",
                expires_at="2026-11-13T00:00:00+00:00",
            )
            self.assertTrue(first)
            self.assertTrue(delivered.wait(2), "notification worker did not run")
            # 同 agent + 同密钥在去重窗口内不重复发送。
            second = notification_outbox.enqueue_admin_binding_request(
                merchant_id="mrc-1",
                catalog_agent_id="cagt_1",
                binding_request_id="breq_2",
                runtime_origin="https://runtime.example",
                a2a_endpoint="https://runtime.example/a2a",
                key_thumbprint="thumb-1",
                expires_at="2026-11-13T00:00:00+00:00",
            )
            self.assertFalse(second)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["binding_request_id"], "breq_1")


if __name__ == "__main__":
    unittest.main()
