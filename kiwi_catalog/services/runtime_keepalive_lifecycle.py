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

"""Optional lifecycle runner for the catalog keepalive scheduler.

Disabled by default. Even with ``KIWI_CATALOG_KEEPALIVE_ENABLED=1`` no
scheduler is created unless a trusted WorkBuddy host allowlist is configured.
The runner owns at most one daemon thread and joins it on shutdown.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Any

from kiwi_catalog.services.runtime_keepalive import (
    KeepaliveScheduler,
    WorkBuddyKeepaliveGateway,
    scheduler_from_env,
)

ENABLED_ENV = "KIWI_CATALOG_KEEPALIVE_ENABLED"
HOSTS_ENV = "KIWI_CATALOG_KEEPALIVE_TRUSTED_HOSTS"
POLL_ENV = "KIWI_CATALOG_KEEPALIVE_POLL_SECONDS"


def gateway_from_env(env: Any = None) -> WorkBuddyKeepaliveGateway | None:
    values = os.environ if env is None else env
    raw = str(values.get(HOSTS_ENV) or "").strip()
    hosts = [part.strip().lower() for part in raw.split(",") if part.strip()]
    if not hosts:
        return None
    return WorkBuddyKeepaliveGateway(trusted_hosts=hosts)


def configured_scheduler(db_path: str, env: Any = None) -> KeepaliveScheduler | None:
    values = os.environ if env is None else env
    gateway = gateway_from_env(values)
    if gateway is None:
        return None
    return scheduler_from_env(db_path=db_path, gateway=gateway, env=values)


class KeepaliveLifecycle:
    """Single-thread lifecycle wrapper; no thread exists until start()."""

    def __init__(
        self,
        scheduler: KeepaliveScheduler | None,
        *,
        poll_seconds: float | None = None,
        env: Any = None,
    ) -> None:
        self.scheduler = scheduler
        values = os.environ if env is None else env
        default_poll = (
            min(15.0, max(1.0, float(getattr(scheduler, "interval_seconds", 30)) / 2))
            if scheduler is not None
            else 30.0
        )
        try:
            raw = values.get(POLL_ENV)
            self.poll_seconds = max(
                1.0, float(raw) if raw not in (None, "") else (poll_seconds or default_poll)
            )
        except (TypeError, ValueError):
            self.poll_seconds = max(1.0, poll_seconds or default_poll)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._started = False

    @property
    def enabled(self) -> bool:
        return self.scheduler is not None

    def start(self) -> None:
        if self.scheduler is None or self._started:
            return
        self._stop.clear()
        self._started = True
        self._thread = threading.Thread(
            target=self._run,
            name="kiwi-catalog-keepalive",
            daemon=True,
        )
        self._thread.start()

    def _run(self) -> None:
        assert self.scheduler is not None
        while not self._stop.is_set():
            try:
                self.scheduler.run_once()
            except Exception:
                # Scheduler already fail-closes individual requests; never let
                # one unexpected exception kill the only runner thread.
                pass
            if self._stop.wait(self.poll_seconds):
                break

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            # Scheduler/gateway timeouts are bounded; don't hold process exit
            # indefinitely if a transport is slow.
            thread.join(timeout=5.0)
        self._thread = None
        self._started = False

    @property
    def thread_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
