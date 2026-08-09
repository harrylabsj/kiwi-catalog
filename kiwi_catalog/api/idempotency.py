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

"""Buyer bootstrap and Agent Catalog write idempotency and rate-limit helpers."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any

from kiwi_catalog.api.auth import payload_token
from kiwi_catalog.core.errors import IdempotencyConflict, ValidationError
from kiwi_catalog.core.tokens import token_digest
from kiwi_catalog.db.session import decode_json, encode_json, now_iso

DEFAULT_BUYER_BOOTSTRAP_RATE_LIMIT_PER_MINUTE = 60
BUYER_BOOTSTRAP_RATE_LIMIT_WINDOW_SECONDS = 60
MAX_IDEMPOTENCY_KEY_LENGTH = 160
MAX_SQLITE_INTEGER = 2**63 - 1

# Agent Catalog write endpoints (§10.4) — a bounded per-actor budget and a
# rolling idempotency claim.  These live in dedicated tables so catalog writes
# never share (or pollute) the buyer bootstrap idempotency ledger.
CATALOG_WRITE_RATE_LIMIT_WINDOW_SECONDS = 60
CATALOG_WRITE_ENDPOINTS = frozenset({
    "/v1/agent-catalog/agents/register",
    "/v1/agent-catalog/agents/{id}/refresh",
    "/v1/agent-catalog/agents/{id}/verify",
    "/v1/agent-catalog/agents/{id}/claim",
})



def idempotency_key_from_payload(payload: dict[str, Any]) -> str:
    key = str(payload.get("idempotency_key") or payload.get("_idempotency_key") or "").strip()
    if len(key) > MAX_IDEMPOTENCY_KEY_LENGTH:
        raise ValidationError(f"idempotency_key must be <= {MAX_IDEMPOTENCY_KEY_LENGTH} characters")
    return key


def request_hash(values: dict[str, Any]) -> str:
    canonical = json.dumps(values, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return token_digest(canonical)


def catalog_write_window_start(current: datetime, window_seconds: int = CATALOG_WRITE_RATE_LIMIT_WINDOW_SECONDS) -> str:
    epoch_seconds = int(current.timestamp())
    window_epoch = epoch_seconds - (epoch_seconds % window_seconds)
    return datetime.fromtimestamp(window_epoch, tz=UTC).replace(microsecond=0).isoformat()


def catalog_write_actor_key(payload: dict[str, Any], canonical_domain: str = "") -> str:
    """Derive the idempotency/rate-limit actor from a request payload.

    The presented API token (admin / merchant / verification worker) is the
    actor when present.  The public register route may be unauthenticated; its
    actor is a *constant* anonymous bucket so that (a) reusing an idempotency
    key with a different request is detected even when the canonical domain
    differs (the request_hash mismatch is what raises IdempotencyConflict),
    and (b) all unauthenticated catalog writes share one bounded per-minute
    budget.  The §17.4 per-domain registration limit independently caps each
    domain, so the constant bucket adds a global bound without becoming an
    SSRF amplification vector.
    """
    token = (
        payload_token(payload)
        or str(payload.get("owner_token") or "")
        or str(payload.get("_auth_token") or "")
    )
    if token:
        return token_digest(str(token))
    return "anon:" + token_digest("catalog-write")


def catalog_register_request_hash(payload: dict[str, Any]) -> str:
    return request_hash(
        {
            "domain": str(payload.get("domain") or "").strip(),
            "agent_card_url": str(payload.get("agent_card_url") or "").strip(),
            "ucp_profile_url": str(payload.get("ucp_profile_url") or "").strip(),
            "merchant_id": str(payload.get("merchant_id") or "").strip(),
            # 审查 P2：其余 public 白名单字段纳入 hash——同 key 改 display_name/
            # hosting_mode/handoff/capabilities/skills 此前 hash 相同被静默重放，
            # 调用方以为新字段已生效。
            "display_name": str(payload.get("display_name") or "").strip(),
            "hosting_mode": str(payload.get("hosting_mode") or "").strip(),
            "handoff_destination_types": payload.get("handoff_destination_types") or [],
            "capabilities": payload.get("capabilities") or [],
            "skills": payload.get("skills") or [],
        }
    )


def catalog_agent_action_request_hash(payload: dict[str, Any], catalog_agent_id: str) -> str:
    return request_hash(
        {
            "catalog_agent_id": str(catalog_agent_id or "").strip(),
            "merchant_id": str(payload.get("merchant_id") or "").strip(),
            "action": str(payload.get("action") or "").strip(),
        }
    )


def enforce_agent_catalog_rate_limit(
    conn: Any,
    actor_key: str,
    limit: int,
    current: datetime | None = None,
) -> None:
    """Raise RateLimitError when *actor_key* exceeds its per-minute write budget.

    Delegates to the shared fixed-window core (v3.0-P5) — see
    ``shopping_cli.services.rate_limit`` for the backend abstraction.
    """
    from kiwi_catalog.services.rate_limit import (
        SQLiteRateLimitBackend,
        enforce_rate_limit,
    )

    backend = SQLiteRateLimitBackend(
        conn, table="agent_catalog_write_rate_limits", key_column="actor_key"
    )
    enforce_rate_limit(
        backend,
        key=actor_key,
        limit=limit,
        window_seconds=CATALOG_WRITE_RATE_LIMIT_WINDOW_SECONDS,
        description="agent catalog write",
        current=current,
    )


def catalog_write_idempotency_row(
    conn: Any,
    endpoint: str,
    actor_key: str,
    idempotency_key: str,
) -> Any:
    return conn.execute(
        """
        select endpoint, actor_key, idempotency_key, request_hash, status, response_json
        from agent_catalog_write_idempotency
        where endpoint = ? and actor_key = ? and idempotency_key = ?
        """,
        (endpoint, actor_key, idempotency_key),
    ).fetchone()


def replay_catalog_write_idempotency(
    conn: Any,
    endpoint: str,
    actor_key: str,
    idempotency_key: str,
    request_hash_value: str,
) -> dict[str, Any] | None:
    if not idempotency_key:
        return None
    row = catalog_write_idempotency_row(conn, endpoint, actor_key, idempotency_key)
    if row is None:
        return None
    if str(row["request_hash"]) != request_hash_value:
        raise IdempotencyConflict("idempotency key was reused with a different request")
    if row["status"] != "completed":
        raise IdempotencyConflict("idempotent request is still processing")
    response = decode_json(row["response_json"], {})
    if not isinstance(response, dict):
        response = {"ok": True}
    result = dict(response)
    result["idempotent"] = True
    return result


def claim_catalog_write_idempotency(
    conn: Any,
    endpoint: str,
    actor_key: str,
    idempotency_key: str,
    request_hash_value: str,
) -> dict[str, Any] | None:
    if not idempotency_key:
        return None
    current = now_iso()
    try:
        conn.execute(
            """
            insert into agent_catalog_write_idempotency(
                endpoint, actor_key, idempotency_key, request_hash, status,
                response_json, created_at, updated_at
            )
            values (?, ?, ?, ?, 'processing', '{}', ?, ?)
            """,
            (endpoint, actor_key, idempotency_key, request_hash_value, current, current),
        )
    except sqlite3.IntegrityError:
        return replay_catalog_write_idempotency(
            conn, endpoint, actor_key, idempotency_key, request_hash_value
        )
    return None


_IDEMPOTENCY_RETENTION_DAYS = 7
_IDEMPOTENCY_PRUNE_EVERY = 128


def complete_catalog_write_idempotency(
    conn: Any,
    endpoint: str,
    actor_key: str,
    idempotency_key: str,
    request_hash_value: str,
    response: dict[str, Any],
) -> None:
    if not idempotency_key:
        return
    stored = dict(response)
    # 审查 P3：惰性清理已完成行（键空间此前只增不删——60/min/actor 上限下
    # 每日约 8.6 万行）。updated_at 是 ISO 文本，字符串比较即时间序。
    complete_catalog_write_idempotency._prune_count = getattr(
        complete_catalog_write_idempotency, "_prune_count", 0
    ) + 1
    if complete_catalog_write_idempotency._prune_count % _IDEMPOTENCY_PRUNE_EVERY == 0:
        try:
            cutoff = (datetime.now(UTC) - timedelta(days=_IDEMPOTENCY_RETENTION_DAYS)).isoformat()
            conn.execute(
                "delete from agent_catalog_write_idempotency"
                " where status = 'completed' and updated_at < ?",
                (cutoff,),
            )
        except sqlite3.Error:
            pass  # 清理失败不影响主路径
    conn.execute(
        """
        update agent_catalog_write_idempotency
        set status = 'completed', response_json = ?, updated_at = ?
        where endpoint = ? and actor_key = ? and idempotency_key = ? and request_hash = ?
        """,
        (
            encode_json(stored),
            now_iso(),
            endpoint,
            actor_key,
            idempotency_key,
            request_hash_value,
        ),
    )


def clear_catalog_write_idempotency_claim(
    conn: Any,
    endpoint: str,
    actor_key: str,
    idempotency_key: str,
    request_hash_value: str,
) -> None:
    if not idempotency_key:
        return
    conn.execute(
        """
        delete from agent_catalog_write_idempotency
        where endpoint = ? and actor_key = ? and idempotency_key = ? and request_hash = ?
          and status = 'processing'
        """,
        (endpoint, actor_key, idempotency_key, request_hash_value),
    )
