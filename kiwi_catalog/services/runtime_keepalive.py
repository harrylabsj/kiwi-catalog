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

"""Catalog-side, default-off keepalive for explicitly opted-in WorkBuddy agents.

The existing ``directory_custody`` consent only authorizes Catalog to hold and
distribute the share parameter for buyer access; it does **not** authorize
periodic merchant wake requests. This module therefore has a separate,
merchant-selected ``directory_keepalive`` consent with its own terms version.

The scheduler is a controlled, caller-driven unit: there is no background
timer in this module and it is disabled unless a caller explicitly enables it.
It never updates ``catalog_agents`` freshness/last_seen_at. Only the merchant
runtime's signed heartbeat endpoint can make an agent fresh again.
"""
from __future__ import annotations

import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Collection, Protocol
from urllib.parse import urlsplit

from kiwi_catalog.a2a.endpoint_policy import assert_safe_binding_endpoint
from kiwi_catalog.agent_catalog.freshness import effective_freshness_state
from kiwi_catalog.core.errors import ValidationError
from kiwi_catalog.db.session import db_session, now_iso
from kiwi_catalog.services import runtime_access

SCOPE = "directory_keepalive"
TERMS_VERSION = "workbuddy-keepalive-v1-2026-11-04"
TERMS_TEXT = (
    "我授权 Kiwi Catalog 在我另行授予的 WorkBuddy 分享码代管配置有效期间，"
    "仅对我已绑定的商家运行时发起低频保活探测。保活探测不等于在线；在线只以"
    "我的运行时签名心跳为准。我可随时撤回本授权；撤回后立即停止后续探测。"
)
MIN_INTERVAL_SECONDS = 300
MIN_COOLDOWN_SECONDS = 900
MAX_CONCURRENCY = 4


class KeepaliveNotVerified(RuntimeError):
    """The WorkBuddy wake endpoint has not been empirically verified."""


class KeepaliveGateway(Protocol):
    def wake(self, *, agent_id: str, runtime_origin: str, secret: str) -> str:
        """Send one wake request; return a fixed status label, never the secret."""


class UnverifiedWorkBuddyGateway:
    """Placeholder for the real endpoint probe; intentionally unusable.

    A future verified adapter must use the existing SSRF-safe ProfileFetcher
    path and a fixed, reviewed endpoint. Until then this class only fails closed.
    """

    def wake(self, *, agent_id: str, runtime_origin: str, secret: str) -> str:
        raise KeepaliveNotVerified("WorkBuddy keepalive endpoint is not verified")


def _current_binding(conn: sqlite3.Connection, catalog_agent_id: str, merchant_id: str) -> bool:
    row = conn.execute(
        "select expires_at from runtime_bindings where catalog_agent_id=? and merchant_id=?"
        " and status='active'",
        (catalog_agent_id, merchant_id),
    ).fetchone()
    if row is None:
        return False
    expires = str(row[0] or "")
    if not expires:
        return True
    try:
        stamp = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        return stamp.tzinfo is not None and stamp > datetime.now(UTC)
    except ValueError:
        return False


def grant(
    conn: sqlite3.Connection,
    *,
    catalog_agent_id: str,
    merchant_id: str,
    terms_version: str,
) -> None:
    """Record explicit merchant consent; absent/old/revoked means no keepalive."""
    if terms_version != TERMS_VERSION:
        raise ValidationError("explicit current keepalive terms are required")
    if not runtime_access.custody_enabled():
        raise ValidationError("directory custody is disabled")
    agent = conn.execute(
        "select merchant_id from catalog_agents where catalog_agent_id=?",
        (catalog_agent_id,),
    ).fetchone()
    if agent is None or str(agent[0] or "") != merchant_id:
        raise ValidationError("merchant identity does not match catalog agent")
    if runtime_access.active_consent(conn, catalog_agent_id) is None:
        raise ValidationError("active directory-custody consent is required")
    if runtime_access.active_runtime_access(conn, catalog_agent_id) is None:
        raise ValidationError("active runtime access configuration is required")
    if not _current_binding(conn, catalog_agent_id, merchant_id):
        raise ValidationError("active runtime binding is required")
    stamp = now_iso()
    conn.execute(
        "insert into runtime_keepalive_consents"
        " (catalog_agent_id,merchant_id,scope,terms_version,granted_at,revoked_at)"
        " values (?,?,?,?,?,'')"
        " on conflict(catalog_agent_id) do update set"
        " merchant_id=excluded.merchant_id,scope=excluded.scope,"
        " terms_version=excluded.terms_version,granted_at=excluded.granted_at,revoked_at='',"
        " last_attempt_at=''",
        (catalog_agent_id, merchant_id, SCOPE, TERMS_VERSION, stamp),
    )


def revoke(conn: sqlite3.Connection, *, catalog_agent_id: str, merchant_id: str) -> None:
    """Idempotently revoke; subsequent scheduler ticks must stop immediately."""
    conn.execute(
        "update runtime_keepalive_consents set revoked_at=?"
        " where catalog_agent_id=? and merchant_id=? and revoked_at=''",
        (now_iso(), catalog_agent_id, merchant_id),
    )


def enabled(conn: sqlite3.Connection, catalog_agent_id: str) -> bool:
    """Fail closed on missing/old/revoked consent, custody/config/binding changes."""
    row = conn.execute(
        "select merchant_id,terms_version,revoked_at from runtime_keepalive_consents"
        " where catalog_agent_id=?",
        (catalog_agent_id,),
    ).fetchone()
    if row is None or row[1] != TERMS_VERSION or row[2]:
        return False
    merchant_id = str(row[0] or "")
    if not runtime_access.custody_enabled():
        return False
    if runtime_access.active_consent(conn, catalog_agent_id) is None:
        return False
    if runtime_access.active_runtime_access(conn, catalog_agent_id) is None:
        return False
    agent = conn.execute(
        "select merchant_id, administrative_state, lifecycle_status"
        " from catalog_agents where catalog_agent_id=?",
        (catalog_agent_id,),
    ).fetchone()
    if agent is None or str(agent[0] or "") != merchant_id:
        return False
    if str(agent[1] or "") != "active" or str(agent[2] or "active") != "active":
        return False
    return _current_binding(conn, catalog_agent_id, merchant_id)


class KeepaliveDeliveryError(RuntimeError):
    """Fixed, redacted failure from a keepalive transport."""


class NoRedirectFetcher(Protocol):
    def fetch_no_redirect(self, url: str, *, timeout: float = 5.0) -> Any: ...


class WorkBuddyKeepaliveGateway:
    """Verified-path adapter for the evidence-backed ``GET /merchant/`` probe.

    The target host must be explicitly allowlisted by the caller. The URL is
    fixed to ``/merchant/``; no user path, query, redirect, cookie or header is
    accepted. DNS pinning, private-range rejection and response bounds are
    delegated to ProfileFetcher.fetch_no_redirect.
    """

    def __init__(
        self,
        *,
        trusted_hosts: Collection[str],
        fetcher: NoRedirectFetcher | None = None,
        timeout: float = 5.0,
    ) -> None:
        hosts = frozenset(str(host).strip().lower() for host in trusted_hosts)
        if not hosts or any(not host or "*" in host or "/" in host for host in hosts):
            raise ValidationError("keepalive trusted_hosts must be explicit hostnames")
        self.trusted_hosts = hosts
        self.timeout = timeout
        self._fetcher = fetcher

    def wake(self, *, agent_id: str, runtime_origin: str, secret: str) -> str:
        try:
            parsed = urlsplit(runtime_origin)
            if (
                parsed.scheme != "https"
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query != ""
                or parsed.fragment != ""
                or parsed.path not in ("", "/")
                or parsed.hostname is None
                or parsed.hostname.lower() not in self.trusted_hosts
            ):
                raise KeepaliveDeliveryError("origin_not_trusted")
            target = runtime_access.append_share_parameter(
                runtime_origin.rstrip("/") + "/merchant/", secret
            )
            fetcher = self._fetcher
            if fetcher is None:
                from kiwi_catalog.discovery.fetcher import ProfileFetcher
                from kiwi_catalog.discovery.trust import TrustPolicy

                fetcher = ProfileFetcher(TrustPolicy.defaults(), timeout=self.timeout)
            result = fetcher.fetch_no_redirect(target, timeout=self.timeout)
            if int(getattr(result, "status_code", 0)) != 200:
                raise KeepaliveDeliveryError("delivery_failed")
            return "request_sent"
        except KeepaliveDeliveryError:
            raise
        except Exception:
            # Never include URL, sharecode or upstream text.
            raise KeepaliveDeliveryError("delivery_failed") from None


@dataclass(frozen=True)
class Candidate:
    agent_id: str
    merchant_id: str
    runtime_origin: str
    secret: str = field(repr=False)
    last_seen_at: str
    freshness_state: str


@dataclass(frozen=True)
class KeepaliveTick:
    enabled: bool
    ran: bool
    candidates: int
    wake_requested: int
    failed: int
    skipped: str = ""


class KeepaliveScheduler:
    """Caller-driven scheduler; no thread/timer is created by this class.

    ``enabled`` defaults to False. A production caller must explicitly enable
    it only after the WorkBuddy endpoint has been verified. Each tick re-reads
    consent, config and binding, and never touches freshness.
    """

    def __init__(
        self,
        *,
        db_path: str | Path,
        gateway: KeepaliveGateway | None = None,
        enabled: bool = False,
        interval_seconds: int = 900,
        per_agent_cooldown_seconds: int = 900,
        max_concurrency: int = 1,
        max_agents: int = 10,
        clock=now_iso,
    ) -> None:
        if interval_seconds < MIN_INTERVAL_SECONDS:
            raise ValidationError("keepalive interval is below the safe minimum")
        if per_agent_cooldown_seconds < MIN_COOLDOWN_SECONDS:
            raise ValidationError("keepalive per-agent cooldown is below the safe minimum")
        if not 1 <= max_concurrency <= MAX_CONCURRENCY:
            raise ValidationError("keepalive concurrency is out of range")
        if not 1 <= max_agents <= 100:
            raise ValidationError("keepalive agent batch is out of range")
        self.db_path = db_path
        self.gateway = gateway
        self.enabled = enabled is True
        self.interval_seconds = interval_seconds
        self.per_agent_cooldown_seconds = per_agent_cooldown_seconds
        self.max_concurrency = max_concurrency
        self.max_agents = max_agents
        self.clock = clock
        self._lock = threading.Lock()

    def run_once(self, *, now: str | None = None) -> KeepaliveTick:
        if not self.enabled:
            return KeepaliveTick(False, False, 0, 0, 0, "disabled")
        if self.gateway is None:
            return KeepaliveTick(True, False, 0, 0, 0, "gateway_unconfigured")
        if not self._lock.acquire(blocking=False):
            return KeepaliveTick(True, False, 0, 0, 0, "already_running")
        try:
            stamp = now or self.clock()
            current = _parse(stamp)
            if not self._claim_tick(stamp, current):
                return KeepaliveTick(True, False, 0, 0, 0, "interval")
            candidates = self._candidates(stamp, current)
            if not candidates:
                return KeepaliveTick(True, True, 0, 0, 0, "cooldown")
            executor = ThreadPoolExecutor(max_workers=self.max_concurrency)
            try:
                futures = [executor.submit(self._wake, candidate) for candidate in candidates]
                results: list[bool] = []
                for future in futures:
                    try:
                        results.append(future.result(timeout=5))
                    except (FutureTimeout, Exception):
                        results.append(False)
            finally:
                # A timed-out worker is bounded by its own gateway timeout; do
                # not make a new tick wait for it and accumulate scheduling work.
                executor.shutdown(wait=False, cancel_futures=True)
            return KeepaliveTick(
                True,
                True,
                len(candidates),
                sum(1 for result in results if result),
                sum(1 for result in results if not result),
            )
        finally:
            self._lock.release()

    def _claim_tick(self, stamp: str, current: datetime) -> bool:
        cutoff = (current - timedelta(seconds=self.interval_seconds)).replace(microsecond=0).isoformat()
        with db_session(self.db_path) as conn:
            result = conn.execute(
                "update runtime_keepalive_state set last_tick_at=?"
                " where singleton=1 and (last_tick_at='' or last_tick_at<=?)",
                (stamp, cutoff),
            )
            return result.rowcount == 1

    def _wake(self, candidate: Candidate) -> bool:
        if self.gateway is None:
            return False
        # Narrow the revoke race: consent/binding may have changed after claim.
        try:
            with db_session(self.db_path) as conn:
                if not enabled(conn, candidate.agent_id):
                    return False
        except Exception:
            return False
        try:
            result = self.gateway.wake(
                agent_id=candidate.agent_id,
                runtime_origin=candidate.runtime_origin,
                secret=candidate.secret,
            )
            return result == "request_sent"
        except Exception:
            return False

    def _candidates(self, now: str, current: datetime) -> list[Candidate]:
        cutoff = (current - timedelta(seconds=self.per_agent_cooldown_seconds)).replace(microsecond=0).isoformat()
        with db_session(self.db_path) as conn:
            rows = conn.execute(
                "select k.catalog_agent_id,k.merchant_id,b.runtime_origin,"
                " a.last_seen_at,a.freshness_state"
                " from runtime_keepalive_consents k"
                " join runtime_access_consents c on c.catalog_agent_id=k.catalog_agent_id"
                " join runtime_access_configs cfg on cfg.catalog_agent_id=k.catalog_agent_id"
                " join runtime_bindings b on b.catalog_agent_id=k.catalog_agent_id"
                " join catalog_agents a on a.catalog_agent_id=k.catalog_agent_id"
                " where k.revoked_at='' and k.terms_version=?"
                " and c.revoked_at='' and c.terms_version=?"
                " and cfg.status='active' and cfg.secret_ciphertext!=''"
                " and b.status='active' and b.merchant_id=k.merchant_id"
                " and a.merchant_id=k.merchant_id and a.administrative_state='active'"
                " and a.lifecycle_status='active'"
                " order by a.last_seen_at asc limit ?",
                (TERMS_VERSION, runtime_access.CONSENT_TERMS_VERSION, self.max_agents),
            ).fetchall()
            candidates: list[Candidate] = []
            for row in rows:
                agent_id = str(row["catalog_agent_id"])
                try:
                    assert_safe_binding_endpoint(str(row["runtime_origin"]), field="runtime_origin")
                except Exception:
                    continue
                claim = conn.execute(
                    "update runtime_keepalive_consents set last_attempt_at=?"
                    " where catalog_agent_id=? and revoked_at='' and terms_version=?"
                    " and (last_attempt_at='' or last_attempt_at<=?)",
                    (now, agent_id, TERMS_VERSION, cutoff),
                )
                if claim.rowcount != 1:
                    continue
                if not enabled(conn, agent_id):
                    continue
                record = {"freshness_state": row["freshness_state"], "last_seen_at": row["last_seen_at"]}
                if effective_freshness_state(record, now=now) == "fresh":
                    continue
                config = runtime_access.active_runtime_access(conn, agent_id)
                if config is None:
                    continue
                try:
                    secret = runtime_access.row_secret(config, statuses=frozenset({"active"}))
                except Exception:
                    continue
                candidates.append(
                    Candidate(
                        agent_id=agent_id,
                        merchant_id=str(row["merchant_id"]),
                        runtime_origin=str(row["runtime_origin"]),
                        secret=secret,
                        last_seen_at=str(row["last_seen_at"] or ""),
                        freshness_state=str(row["freshness_state"] or ""),
                    )
                )
        return candidates


def scheduler_from_env(
    *,
    db_path: str | Path,
    gateway: KeepaliveGateway | None,
    env: Any = None,
) -> KeepaliveScheduler | None:
    """Explicit production opt-in; returns None unless the flag is exactly on.

    No timer is started here. An operator/caller must invoke ``run_once`` so
    deployment and restart policy remain explicit.
    """
    values = os.environ if env is None else env
    enabled = str(values.get("KIWI_CATALOG_KEEPALIVE_ENABLED") or "").strip().lower()
    if enabled not in {"1", "true", "yes", "on"}:
        return None
    return KeepaliveScheduler(
        db_path=db_path,
        gateway=gateway,
        enabled=True,
        interval_seconds=int(values.get("KIWI_CATALOG_KEEPALIVE_INTERVAL_SECONDS") or 900),
        per_agent_cooldown_seconds=int(
            values.get("KIWI_CATALOG_KEEPALIVE_COOLDOWN_SECONDS") or 900
        ),
        max_concurrency=int(values.get("KIWI_CATALOG_KEEPALIVE_CONCURRENCY") or 1),
        max_agents=int(values.get("KIWI_CATALOG_KEEPALIVE_MAX_AGENTS") or 10),
    )


def _parse(value: str) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValidationError("keepalive clock must be timezone-aware")
    return parsed.astimezone(UTC)
