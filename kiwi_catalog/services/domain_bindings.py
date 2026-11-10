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

"""domain-control 一次性挑战绑定（审查 P1-12）。

旧 domain-control 只证明「域名在 well-known 路径返回 200」，不证明该
``catalog_agents`` 行属于域名控制者。因为产品规则允许「一个域名注册多个
商家」，攻击者可以注册第二个商家、把 ``agent_card``/``ucp_profile`` 指向
受害者真实地址，验证管线抓取受害者 profile 后整体通过——信任徽章被克隆。

本模块把「谁能代表该域名下的这一行」落成可核验的一次性 challenge：

- 每个非 hosted agent 一行 ``catalog_domain_bindings``；
- ``challenge_pending``：已签发 token，等待域名发布
  ``https://{domain}/.well-known/kiwi-catalog-agent.json``；
- ``verified``：域名的 well-known 文件回指了本行的 ``catalog_agent_id`` 与
  token，且每次验证都会重新读取比对（文件撤掉即降级）；
- ``legacy``：升级前已通过 domain 阶段的存量行，保留旧语义，不再影响新行。

token 只发给已认证的商家/管理员（HTTP）或本地 CLI，不进入公开 DTO。
"""

from __future__ import annotations

import hmac
import secrets
import sqlite3
from typing import Any

from kiwi_catalog.discovery.verifier import (
    CHALLENGE_WELL_KNOWN_PATH,
    CHALLENGE_DOCUMENT_KEYS,
)

STATE_PENDING = "challenge_pending"
STATE_VERIFIED = "verified"
STATE_LEGACY = "legacy"

# 需要 challenge 绑定的 source_type。hosted 走绑定身份（不走本阶梯）；
# imported/admin_curated 是运营方写入的可信来源，保留旧语义。
CHALLENGE_REQUIRED_SOURCE_TYPES: frozenset[str] = frozenset({"self_registered", "discovered"})


def challenge_url(canonical_domain: str) -> str:
    return f"https://{canonical_domain}/{CHALLENGE_WELL_KNOWN_PATH}"


def new_challenge() -> str:
    return f"kc1_{secrets.token_urlsafe(32)}"


def challenge_document(
    catalog_agent_id: str, canonical_domain: str, challenge: str
) -> dict[str, str]:
    """The exact JSON the domain owner must publish (all required keys)."""
    return {
        "catalog_agent_id": catalog_agent_id,
        "canonical_domain": canonical_domain,
        "challenge": challenge,
        "schema_version": "1",
    }


def get_domain_binding(conn: sqlite3.Connection, catalog_agent_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "select * from catalog_domain_bindings where catalog_agent_id = ?",
        (catalog_agent_id,),
    ).fetchone()
    return dict(row) if row is not None else None


def ensure_domain_binding(
    conn: sqlite3.Connection,
    catalog_agent_id: str,
    canonical_domain: str,
    *,
    now: str,
) -> dict[str, Any]:
    """Return this agent's binding, issuing a challenge when missing/domain-changed.

    A binding left over from a different canonical domain is rotated: its old
    challenge must never authorize a new domain.  This write is intentionally
    cheap so callers can commit immediately before any network I/O.
    """
    existing = get_domain_binding(conn, catalog_agent_id)
    if existing is not None and str(existing.get("canonical_domain")) == canonical_domain:
        return existing
    if existing is not None:
        conn.execute(
            "delete from catalog_domain_bindings where catalog_agent_id = ?",
            (catalog_agent_id,),
        )
    challenge = new_challenge()
    conn.execute(
        "insert into catalog_domain_bindings"
        " (catalog_agent_id, canonical_domain, state, challenge,"
        "  challenge_issued_at, bound_at, updated_at)"
        " values (?, ?, ?, ?, ?, '', ?)",
        (catalog_agent_id, canonical_domain, STATE_PENDING, challenge, now, now),
    )
    return get_domain_binding(conn, catalog_agent_id) or {}


def rotate_domain_binding(
    conn: sqlite3.Connection,
    catalog_agent_id: str,
    canonical_domain: str,
    *,
    now: str,
) -> dict[str, Any]:
    """Explicitly issue a fresh challenge (operator recovery from a leaked token)."""
    conn.execute(
        "delete from catalog_domain_bindings where catalog_agent_id = ?",
        (catalog_agent_id,),
    )
    return ensure_domain_binding(conn, catalog_agent_id, canonical_domain, now=now)


def mark_domain_bound(
    conn: sqlite3.Connection,
    catalog_agent_id: str,
    canonical_domain: str,
    *,
    now: str,
) -> None:
    conn.execute(
        "update catalog_domain_bindings"
        " set state = ?, bound_at = ?, updated_at = ?"
        " where catalog_agent_id = ? and canonical_domain = ?",
        (STATE_VERIFIED, now, now, catalog_agent_id, canonical_domain),
    )


def drop_domain_binding(conn: sqlite3.Connection, catalog_agent_id: str) -> None:
    conn.execute(
        "delete from catalog_domain_bindings where catalog_agent_id = ?",
        (catalog_agent_id,),
    )


def binding_legacy_allowed(binding: dict[str, Any] | None, canonical_domain: str) -> bool:
    """True when this agent keeps pre-migration domain-control semantics."""
    return (
        binding is not None
        and str(binding.get("state")) == STATE_LEGACY
        and str(binding.get("canonical_domain")) == canonical_domain
    )


def shared_domain_peer_count(
    conn: sqlite3.Connection, catalog_agent_id: str, canonical_domain: str
) -> int:
    """Active catalog agents on the same domain, excluding this row.

    Reported in verification evidence so operators can see the "one domain,
    multiple merchants" fact without changing the public wire contract.
    """
    row = conn.execute(
        "select count(*) from catalog_agents"
        " where canonical_domain = ? and catalog_agent_id != ?"
        " and administrative_state = 'active'",
        (canonical_domain, catalog_agent_id),
    ).fetchone()
    return int(row[0]) if row is not None else 0


def challenge_matches(expected: str, actual: str) -> bool:
    # compare_digest(str, str) 对非 ASCII 抛 TypeError；统一按 UTF-8 字节比较。
    return bool(expected) and hmac.compare_digest(
        str(expected).encode("utf-8"), str(actual).encode("utf-8")
    )


def is_challenge_document(parsed: Any) -> bool:
    return isinstance(parsed, dict) and set(CHALLENGE_DOCUMENT_KEYS) <= set(parsed)
