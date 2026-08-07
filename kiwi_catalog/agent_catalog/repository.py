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

"""Persistence-abstraction boundary (§19.2) — Catalog / Conversation / Audit.

设计文档 `docs/shopping-cli-a2a-upgrade-design-v1.2.1.md` §19.2 要求：当
Agent Catalog 成为公网多实例服务时，SQLite 不应作为唯一生产数据库，先建
Repository abstraction，未来增加 Postgres adapter。 本模块定义三个
Protocol（契约）；SQLite 现状实现与接缝点清单见
`docs/shopping-cli-a2a-postgres-adapter-seam-v1.0.md`。

盘点结论（2026-08-06，P3）：
- catalog 域（agents / capabilities / endpoints / skills / snapshots /
  verifications / trust observations / register-domain rate limit）全部有
  SQLite 函数实现（`agent_catalog/sqlite_repository.py`），本模块补齐
  Protocol 覆盖（含此前遗漏的 trust observations）。
- API 基础设施（write idempotency / write rate limits，表
  agent_catalog_write_idempotency / agent_catalog_write_rate_limits）直连
  SQLite（`api/idempotency.py`）——属于传输层，不并入 CatalogRepository，
  PG 适配时作为独立接缝处理（文档 §接缝点清单）。
- hosted gateway 的 a2a 入站幂等 ledger（表 a2a_inbound_idempotency）由
  `a2a/hosted_server.py` 直接 SQL——属于 hosted 域接缝点，同理独立。
- Marketplace 会话域（conversations / messages）与 audit_events 由
  core 层直接 SQL；本模块定义 ConversationRepository / AuditRepository
  契约以封闭第二、三层边界。

契约方法名与 SQLite 实现函数的对应关系固化在
`tests/test_repository_abstraction.py` 的映射表（防接口漂移）。
"""

from __future__ import annotations

from typing import Any, Protocol


class CatalogRepository(Protocol):
    """Persistence contract for the Commerce Agent Catalog (catalog 域).

    SQLite is the MVP implementation (`agent_catalog/sqlite_repository.py`);
    a Postgres adapter may be added when the catalog becomes a public
    multi-instance service.  All methods are aggregate-boundary shaped:
    they take values (never a connection) and return plain dicts / lists.
    """

    # ── Catalog agent lifecycle ───────────────────────────────────────────

    def upsert_catalog_agent(
        self,
        catalog_agent_id: str,
        merchant_id: str,
        hosted_runtime_agent_id: str,
        display_name: str,
        provider_name: str,
        canonical_domain: str,
        agent_type: str,
        source_type: str,
        lifecycle_status: str,
        verification_status: str,
        hosting_mode: str,
    ) -> dict[str, Any]:
        """Insert or update a catalog_agents row.  Returns the row as a dict."""
        ...

    def require_catalog_agent(self, catalog_agent_id: str) -> dict[str, Any]:
        """Return the catalog_agents row or raise NotFoundError."""
        ...

    def get_catalog_agent(self, catalog_agent_id: str) -> dict[str, Any] | None:
        """Return the catalog_agents row joined with merchant name, or None."""
        ...

    def get_catalog_agent_by_domain(self, canonical_domain: str) -> dict[str, Any] | None:
        """Return the catalog_agents row for a canonical domain, or None."""
        ...

    def list_catalog_agents(self) -> list[dict[str, Any]]:
        """Return all catalog_agents rows."""
        ...

    def list_catalog_agents_by_merchant(self, merchant_id: str) -> list[dict[str, Any]]:
        """Return all catalog_agents rows bound to a merchant."""
        ...

    def set_verification_status(
        self,
        catalog_agent_id: str,
        verification_status: str,
        *,
        last_verified_at: str | None = None,
    ) -> None:
        """Update verification_status (and optionally last_verified_at)."""
        ...

    def set_catalog_agent_merchant(self, catalog_agent_id: str, merchant_id: str) -> None:
        """Bind a catalog agent to a merchant (claim/ownership change §6.2)."""
        ...

    # ── Capabilities / endpoints / skills ────────────────────────────────

    def list_capabilities(self, catalog_agent_id: str) -> list[dict[str, Any]]:
        """Return all agent_capabilities rows for a catalog agent."""
        ...

    def upsert_capabilities(
        self,
        catalog_agent_id: str,
        capabilities: list[dict[str, Any]],
    ) -> None:
        """Replace all capabilities for a catalog agent atomically."""
        ...

    def list_endpoints(self, catalog_agent_id: str) -> list[dict[str, Any]]:
        """Return all agent_endpoints rows for a catalog agent."""
        ...

    def upsert_profile_endpoints(
        self,
        catalog_agent_id: str,
        endpoints: list[dict[str, Any]],
    ) -> None:
        """Insert or update profile endpoints (agent_card / ucp_profile)."""
        ...

    def replace_skills(
        self,
        catalog_agent_id: str,
        skills: list[dict[str, Any]],
    ) -> None:
        """Replace all skills for a catalog agent atomically."""
        ...

    def list_skills(self, catalog_agent_id: str) -> list[dict[str, Any]]:
        """Return all agent_skills rows for a catalog agent."""
        ...

    # ── Profile snapshots (§5.5, §18) ─────────────────────────────────────

    def insert_profile_snapshot(
        self,
        catalog_agent_id: str,
        profile_type: str,
        snapshot: dict[str, Any],
    ) -> int:
        """Insert one agent_profile_snapshots row (append-only).  Returns id."""
        ...

    def latest_profile_snapshot(
        self, catalog_agent_id: str, profile_type: str
    ) -> dict[str, Any] | None:
        """Return the most recent snapshot row of a profile type, or None."""
        ...

    def list_profile_snapshots(self, catalog_agent_id: str) -> list[dict[str, Any]]:
        """Return all profile snapshot rows for a catalog agent."""
        ...

    # ── Verification runs (§6, §23) ───────────────────────────────────────

    def insert_verification(self, catalog_agent_id: str, verification: dict[str, Any]) -> int:
        """Insert one agent_verifications row.  Returns the verification id."""
        ...

    def list_verifications(self, catalog_agent_id: str) -> list[dict[str, Any]]:
        """Return all verification rows for a catalog agent."""
        ...

    def latest_verification(
        self,
        catalog_agent_id: str,
        verification_type: str,
    ) -> dict[str, Any] | None:
        """Return the newest verification row of a type (v0.3 §7.1 级别重算依据)."""
        ...

    # ── Trust observations (§5.7) ─────────────────────────────────────────

    def insert_trust_observation(
        self,
        catalog_agent_id: str,
        observation: dict[str, Any],
    ) -> int:
        """Append one private trust observation.  Returns the observation id.

        ``observation`` carries kind / value / source / evidence_ref /
        observed_at / expires_at.  The caller validates kind/value (see
        ``services/agent_trust_observations``); values are never aggregated
        into a reputation score.
        """
        ...

    def list_trust_observations(self, catalog_agent_id: str) -> list[dict[str, Any]]:
        """Return all trust observations for a catalog agent (private)."""
        ...

    def count_trust_observations(self, catalog_agent_id: str) -> int:
        """Return the number of trust observations for a catalog agent."""
        ...

    def trust_observation_counts_by_kind(self, catalog_agent_id: str) -> dict[str, int]:
        """Return trust observation counts grouped by kind."""
        ...

    def set_state_domains(
        self,
        catalog_agent_id: str,
        *,
        verification_level: str | None,
        freshness_state: str | None,
        administrative_state: str | None,
        handoff_destination_types: list[str] | None,
        last_verified_at: str | None,
    ) -> dict[str, Any]:
        """三正交状态域 + 折叠投影同步写入（v0.3 §7）。

        任一无参 domain 保持现状；枚举成员校验 fail-closed；迁移合法性由
        服务层状态机约束。返回更新后的 catalog_agents 行。
        """
        ...

    # ── Discovery / search / governance ───────────────────────────────────

    def search(
        self,
        q: str,
        category: str,
        skill: str,
        capability: str,
        protocol: str,
        hosting_mode: str,
        verification_status: str,
        verified_after: str,
        verification_level: str,
        freshness_state: str,
        administrative_state: str,
        handoff_destination_types: str,
        limit: int,
        cursor: str,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Search catalog agents with hard filters and deterministic ordering.

        三正交状态域过滤（verification_level / freshness_state /
        administrative_state）+ handoff_destination_types（KTH 词表，
        逗号分隔）在 v0.3 加入；legacy 单状态过滤保留。

        Returns (results, next_cursor).  next_cursor is None when there are
        no more pages.
        """
        ...

    def append_audit(
        self,
        catalog_agent_id: str,
        actor: str,
        event: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Write an audit event scoped to a catalog agent (§23)."""
        ...

    def enforce_catalog_register_domain_limit(self, canonical_domain: str, limit_per_hour: int) -> None:
        """Enforce the §17.4 per-domain registration budget (raises on breach)."""
        ...


class ConversationRepository(Protocol):
    """§19.2 Conversation persistence boundary (conversations / messages).

    SQLite 现状实现：`core/conversations.py`（直连 SQL）。 PG 适配接缝见
    `docs/shopping-cli-a2a-postgres-adapter-seam-v1.0.md`。
    """

    def ensure_conversation(
        self,
        *,
        buyer_id: str,
        merchant_id: str,
        sku: str,
        reuse_open: bool,
    ) -> dict[str, Any]:
        """Return an open conversation for (buyer, merchant, sku), creating it."""
        ...

    def require_conversation(self, conversation_id: str) -> dict[str, Any]:
        """Return the conversation row or raise NotFoundError."""
        ...

    def append_message(
        self,
        conversation_id: str,
        sender: str,
        intent: str,
        text: str,
        *,
        structured_payload: dict[str, Any],
    ) -> int:
        """Append one message to a conversation.  Returns the message id."""
        ...

    def conversation_messages(self, conversation_id: str) -> list[dict[str, Any]]:
        """Return all messages in a conversation (chronological)."""
        ...

    def close_conversation(
        self,
        conversation_id: str,
        *,
        closed_by: str,
        reason: str,
        status: str,
    ) -> dict[str, Any]:
        """Close a conversation; returns the updated conversation row."""
        ...


class AuditRepository(Protocol):
    """§19.2 Audit persistence boundary (audit_events).

    SQLite 现状实现：`core/harness.py` 的 ``append_audit_event`` 与
    ``conversation_audit_events``（直连 SQL）。  PG 适配接缝见
    `docs/shopping-cli-a2a-postgres-adapter-seam-v1.0.md`。
    """

    def append_event(
        self,
        *,
        conversation_id: str,
        actor: str,
        event: str,
        details: dict[str, Any] | None = None,
    ) -> int:
        """Write one audit_events row.  Returns the event id (§23)."""
        ...

    def conversation_audit_events(self, conversation_id: str) -> list[dict[str, Any]]:
        """Return all audit events for a conversation (chronological)."""
        ...
