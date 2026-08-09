"""Pure keyset-pagination helpers for the catalog repository."""

from __future__ import annotations

import base64
import json
from typing import Any


AGENT_STATUS_RANK = {
    "commerce_verified": 0,
    "agent_verified": 1,
    "domain_verified": 2,
    "profile_valid": 3,
    "discovered": 4,
    "stale": 5,
    "unreachable": 6,
    "suspended": 7,
    "rejected": 8,
}

AGENT_STATUS_RANK_CASE = """
    case ca.verification_status
        when 'commerce_verified' then 0
        when 'agent_verified' then 1
        when 'domain_verified' then 2
        when 'profile_valid' then 3
        when 'discovered' then 4
        when 'stale' then 5
        when 'unreachable' then 6
        when 'suspended' then 7
        when 'rejected' then 8
        else 9
    end
"""

AGENT_SORT_NAME = "coalesce(ca.display_name, '')"


def agent_status_rank(status: str) -> int:
    return AGENT_STATUS_RANK.get(str(status or ""), 9)


def encode_agent_cursor(
    rank: int, last_verified_at: str | None, display_name: str, catalog_agent_id: str
) -> str:
    payload = json.dumps([rank, last_verified_at, display_name, catalog_agent_id])
    return "v2:" + base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii")


def decode_agent_cursor(cursor: str) -> tuple[list[Any], bool]:
    if cursor.startswith("v2:"):
        try:
            keys = json.loads(base64.urlsafe_b64decode(cursor[3:].encode("ascii")).decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            keys = None
        if isinstance(keys, list) and len(keys) == 4:
            return keys, True
    return [cursor], False


def agent_cursor_predicate(cursor: str) -> tuple[str, list[Any]]:
    keys, is_v2 = decode_agent_cursor(cursor)
    if not is_v2:
        return "ca.catalog_agent_id > ?", [keys[0]]
    rank, last_verified_at, name, catalog_agent_id = keys
    clauses = [
        f"{AGENT_STATUS_RANK_CASE} > ?",
        f"{AGENT_STATUS_RANK_CASE} = ? and "
        f"(ca.last_verified_at < ? or ca.last_verified_at is null)",
        f"{AGENT_STATUS_RANK_CASE} = ? and ca.last_verified_at is ? "
        f"and {AGENT_SORT_NAME} > ?",
        f"{AGENT_STATUS_RANK_CASE} = ? and ca.last_verified_at is ? "
        f"and {AGENT_SORT_NAME} = ? and ca.catalog_agent_id > ?",
    ]
    params: list[Any] = [
        rank,
        rank, last_verified_at,
        rank, last_verified_at, name,
        rank, last_verified_at, name, catalog_agent_id,
    ]
    return "(" + " or ".join(clauses) + ")", params
