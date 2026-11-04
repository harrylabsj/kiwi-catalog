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

import tempfile
import threading
import unittest
from pathlib import Path

from kiwi_catalog.services import runtime_keepalive_lifecycle as lifecycle


class FakeScheduler:
    def __init__(self) -> None:
        self.calls = 0
        self.event = threading.Event()

    def run_once(self) -> None:
        self.calls += 1
        self.event.set()


class LifecycleTest(unittest.TestCase):
    def test_disabled_has_no_thread(self) -> None:
        runner = lifecycle.KeepaliveLifecycle(None, poll_seconds=0.01)
        self.assertFalse(runner.enabled)
        runner.start()
        self.assertFalse(runner.thread_alive)
        runner.stop()

    def test_start_stop_joins_single_thread_and_can_restart(self) -> None:
        scheduler = FakeScheduler()
        runner = lifecycle.KeepaliveLifecycle(scheduler, poll_seconds=0.01)
        runner.start()
        self.assertTrue(scheduler.event.wait(1))
        self.assertTrue(runner.thread_alive)
        runner.stop()
        self.assertFalse(runner.thread_alive)
        scheduler.event.clear()
        runner.start()
        self.assertTrue(scheduler.event.wait(1))
        runner.stop()
        self.assertFalse(runner.thread_alive)
        self.assertLessEqual(scheduler.calls, 2)

    def test_app_lifecycle_is_disabled_by_default(self) -> None:
        from kiwi_catalog.api.app import FastAPI, create_catalog_app

        if FastAPI is None:
            self.skipTest("FastAPI is not installed in this environment")
        with tempfile.TemporaryDirectory() as tmp:
            app = create_catalog_app(str(Path(tmp) / "catalog.sqlite"))
            runner = getattr(app.state, "keepalive_lifecycle", None)
            self.assertIsNotNone(runner)
            self.assertFalse(runner.enabled)
            runner.start()
            self.assertFalse(runner.thread_alive)
            runner.stop()

    def test_explicit_config_requires_enabled_flag_and_host_allowlist(self) -> None:
        self.assertIsNone(
            lifecycle.configured_scheduler(":memory:", env={})
        )
        self.assertIsNone(
            lifecycle.configured_scheduler(
                ":memory:",
                env={"KIWI_CATALOG_KEEPALIVE_ENABLED": "1"},
            )
        )
        scheduler = lifecycle.configured_scheduler(
            ":memory:",
            env={
                "KIWI_CATALOG_KEEPALIVE_ENABLED": "1",
                "KIWI_CATALOG_KEEPALIVE_TRUSTED_HOSTS": "linkluck-reception.app.workbuddy.host",
            },
        )
        self.assertIsNotNone(scheduler)
        self.assertTrue(scheduler.enabled)
        self.assertEqual(
            scheduler.gateway.trusted_hosts,
            frozenset({"linkluck-reception.app.workbuddy.host"}),
        )


if __name__ == "__main__":
    unittest.main()
