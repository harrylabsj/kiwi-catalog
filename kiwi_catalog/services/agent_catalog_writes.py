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

"""Agent Catalog write service — registration and claim (§10.2, §10.4, §6.2).

This module holds the *shared* write use-cases used by both the API handlers
(``shopping_cli/api/handlers/agent_catalog.py``) and the CLI
(``shopping_cli/cli_agent_catalog_commands.py``).  It performs persistence and
writes §23 audit events; it does NOT enforce transport-level idempotency,
rate limiting, or auth — those live in the API layer.

The register/claim proof rules come from design §6.2:

    hosted          → existing merchant/admin identity is proof
    self_registered → HTTPS domain-control challenge
    discovered      → UNCLAIMED → claim → same HTTPS domain-control challenge

"Knowing the Agent Card URL" is never proof of ownership — the domain must
actually serve the standard well-known locations over HTTPS.
"""

from __future__ import annotations

import re
from typing import Any

from kiwi_catalog.agent_catalog.sqlite_repository import (
    list_catalog_agents_by_merchant,
    append_catalog_audit,
    get_catalog_agent_by_domain,
    list_endpoints,
    new_catalog_agent_id,
    replace_capabilities,
    replace_skills,
    require_catalog_agent,
    set_catalog_agent_merchant,
    set_state_domains,
    upsert_catalog_agent,
    upsert_profile_endpoints,
)
from kiwi_catalog.agent_catalog.state_domains import HANDOFF_DESTINATION_TYPES
from kiwi_catalog.core.errors import ConflictError, PermissionDenied, ValidationError
from kiwi_catalog.services.agent_catalog import get_catalog_agent_write_detail
from kiwi_catalog.services.catalog_runtime_metrics import record_funnel

# 行政处置终态：可被重新注册恢复（v0.3 §7.3——REJECTED / SUSPENDED 属
# administrative_state；legacy 折叠值同义）。
_RE_REGISTERABLE_ADMIN = frozenset({"rejected", "suspended"})

# hosting_mode canonical（v0.3）→ legacy 存储值（catalog_agents CHECK 只收
# legacy 4 值；wire schema 两种都收，存储归一化后消费方不受影响）。
_CANONICAL_HOSTING_MODE: dict[str, str] = {
    "direct_only": "direct",
    "hosted_only": "hosted",
}


def normalize_hosting_mode(mode: str) -> str:
    """把 canonical hosting_mode 归一化为 legacy 存储值（非法值原样返回，
    由 DB CHECK / schema 兜底拒绝）。"""
    return _CANONICAL_HOSTING_MODE.get(mode, mode)

# Bare-hostname shape: letters/digits/hyphen/dot, at least one dot.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\.?$")


def normalize_canonical_domain(domain: Any) -> str:
    """Validate and normalize a bare canonical domain.

    Rejects scheme/path/port forms — a canonical domain is a bare hostname
    (``merchant.example``), never a URL.
    """
    text = str(domain or "").strip().lower().rstrip(".")
    if not text:
        raise ValidationError("domain is required")
    if "/" in text or ":" in text or " " in text:
        raise ValidationError(f"invalid canonical domain: {domain!r}")
    if not _HOSTNAME_RE.match(text):
        raise ValidationError(f"invalid canonical domain: {domain!r}")
    return text


def _default_identity_verifier() -> Any:
    from kiwi_catalog.discovery.fetcher import ProfileFetcher
    from kiwi_catalog.discovery.trust import TrustPolicy
    from kiwi_catalog.discovery.verifier import IdentityVerifier

    policy = TrustPolicy.defaults()
    return IdentityVerifier(ProfileFetcher(policy), policy)


def _declared_profile_urls(conn: Any, catalog_agent_id: str) -> dict[str, str]:
    declared: dict[str, str] = {}
    for ep in list_endpoints(conn, catalog_agent_id):
        kind = str(ep.get("kind", ""))
        url = str(ep.get("url", "")).strip()
        if kind in ("agent_card", "ucp_profile") and url:
            declared[kind] = url
    return declared


def register_catalog_agent(
    conn: Any,
    *,
    domain: str,
    agent_card_url: str = "",
    ucp_profile_url: str = "",
    merchant_id: str = "",
    actor: str = "cli",
    display_name: str = "",
    hosting_mode: str = "",
    handoff_destination_types: list[str] | None = None,
    capabilities: list[str] | None = None,
    skills: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Create (or re-open) a DISCOVERED self_registered catalog agent (§10.2).

    v0.3 扩展字段：display_name / hosting_mode / handoff_destination_types
    （KTH destination_type 词表）/ capabilities（全限定 fqid）/ skills 均
    public-only（完成定义 #8）。

    Returns the public detail (§8.2 contract).  Verification is deliberately
    NOT run here — the API layer enqueues it into the bounded verification
    queue (§25 Phase 2) and the CLI lets the caller run ``agent catalog verify``
    explicitly.
    """
    canonical = normalize_canonical_domain(domain)
    merchant_id = str(merchant_id or "").strip()

    # 一商家一 agent（弱引用 schema 的业务约束）：merchant 已有一个 catalog
    # agent 时拒绝新注册（数据层有部分唯一索引兜底，此处给明确错误）。
    if merchant_id:
        owned, _ = list_catalog_agents_by_merchant(conn, merchant_id)
        if owned:
            raise ConflictError(
                f"merchant {merchant_id} already has a catalog agent "
                f"({owned[0]['catalog_agent_id']})"
            )

    # §17.4 cooldown: the same domain may only be registered once while the
    # record is live.  行政终态（rejected / suspended）可重新注册（v0.3 §7.3）。
    existing = get_catalog_agent_by_domain(conn, canonical)
    if existing is not None and existing["administrative_state"] not in _RE_REGISTERABLE_ADMIN:
        raise ConflictError(f"domain {canonical} is already registered")

    catalog_agent_id = str(existing["catalog_agent_id"]) if existing else new_catalog_agent_id()
    upsert_catalog_agent(
        conn,
        catalog_agent_id=catalog_agent_id,
        merchant_id=merchant_id,
        hosted_runtime_agent_id="",
        display_name=display_name or canonical,
        provider_name="",
        canonical_domain=canonical,
        agent_type="commerce",
        source_type="self_registered",
        lifecycle_status="active",
        verification_status="discovered",
        hosting_mode=normalize_hosting_mode(hosting_mode) or "direct",
    )
    # v0.3 public 扩展字段（全部 public-only，完成定义 #8）：
    # handoff_destination_types 必须是 KTH destination_type 词表成员
    # （单一来源，禁止 supports_* 平行词表）。
    if handoff_destination_types:
        invalid = [d for d in handoff_destination_types if d not in HANDOFF_DESTINATION_TYPES]
        if invalid:
            raise ValidationError(
                f"invalid handoff_destination_types (must be KTH destination_type "
                f"values): {invalid}"
            )
        set_state_domains(conn, catalog_agent_id, handoff_destination_types=list(handoff_destination_types))
    if capabilities:
        replace_capabilities(
            conn,
            catalog_agent_id,
            [
                {"namespace": (c.split(":", 1)[0] if ":" in c else ""), "capability_id": (c.split(":", 1)[1] if ":" in c else c)}
                for c in capabilities
            ],
        )
    if skills:
        replace_skills(
            conn,
            catalog_agent_id,
            [
                {
                    "skill_id": str(s.get("skill_id") or ""),
                    "name": str(s.get("name") or ""),
                    "description": str(s.get("description") or ""),
                    "tags_json": s.get("tags_json", "[]"),
                }
                for s in skills
            ],
        )

    endpoints: list[dict[str, Any]] = []
    if str(agent_card_url or "").strip():
        endpoints.append({
            "kind": "agent_card",
            "url": str(agent_card_url).strip(),
            "protocol": "a2a",
            "protocol_version": "",
            "preference": 1,
        })
    if str(ucp_profile_url or "").strip():
        endpoints.append({
            "kind": "ucp_profile",
            "url": str(ucp_profile_url).strip(),
            "protocol": "ucp",
            "protocol_version": "",
            "preference": 1,
        })
    if endpoints:
        upsert_profile_endpoints(conn, catalog_agent_id, endpoints)

    append_catalog_audit(
        conn,
        catalog_agent_id,
        actor,
        "catalog_agent_registered",
        {
            "canonical_domain": canonical,
            "source_type": "self_registered",
            "merchant_id": merchant_id or None,
            "agent_card_url_present": bool(endpoints and any(e["kind"] == "agent_card" for e in endpoints)),
            "ucp_profile_url_present": bool(endpoints and any(e["kind"] == "ucp_profile" for e in endpoints)),
        },
    )
    # §24 funnel: a successful registration is the discovery event.
    record_funnel("discovery")
    return get_catalog_agent_write_detail(conn, catalog_agent_id)


def claim_catalog_agent(
    conn: Any,
    *,
    catalog_agent_id: str,
    merchant_id: str,
    actor: str,
    identity_verifier: Any | None = None,
) -> dict[str, Any]:
    """Claim ownership of a catalog agent (§10.4, §6.2).

    *hosted* agents are proven by the caller's merchant/admin identity (already
    enforced by the API auth layer).  *self_registered* / *discovered* agents
    require an HTTPS domain-control challenge against the canonical domain —
    merely knowing the Agent Card URL is never sufficient proof.

    On success the agent is bound to *merchant_id* and a ``catalog_agent_claimed``
    audit event is written.  Returns the public detail.
    """
    catalog_agent_id = str(catalog_agent_id or "").strip()
    merchant_id = str(merchant_id or "").strip()
    if not merchant_id:
        raise ValidationError("merchant_id is required to claim a catalog agent")

    # 一商家一 agent：目标 merchant 已认领其他 agent 时拒绝（当前 agent
    # 已在 claim 流程中，不受影响）。
    owned, _ = list_catalog_agents_by_merchant(conn, merchant_id)
    owned = [a for a in owned if a["catalog_agent_id"] != catalog_agent_id]
    if owned:
        raise ConflictError(
            f"merchant {merchant_id} already has a catalog agent "
            f"({owned[0]['catalog_agent_id']})"
        )

    agent = require_catalog_agent(conn, catalog_agent_id)
    canonical = str(agent.get("canonical_domain") or "").strip()
    if not canonical:
        raise ValidationError(f"catalog agent {catalog_agent_id} has no canonical_domain to claim")

    source_type = str(agent.get("source_type") or "")
    claim_method = "hosted_identity"
    if source_type != "hosted":
        # §6.2: HTTPS domain-control challenge — proof of domain control, not
        # knowledge of the Agent Card URL.
        verifier = identity_verifier or _default_identity_verifier()
        evidence = verifier.verify_domain_control(canonical, declared=_declared_profile_urls(conn, catalog_agent_id))
        if not evidence.passed:
            raise PermissionDenied(f"claim denied: {evidence.reason}")
        claim_method = "https_domain_control"

    current_merchant = str(agent.get("merchant_id") or "").strip()
    if current_merchant and current_merchant != merchant_id:
        raise ConflictError(f"catalog agent {catalog_agent_id} is already claimed by merchant {current_merchant}")

    set_catalog_agent_merchant(conn, catalog_agent_id, merchant_id)
    append_catalog_audit(
        conn,
        catalog_agent_id,
        actor,
        "catalog_agent_claimed",
        {
            "merchant_id": merchant_id,
            "claim_method": claim_method,
            "canonical_domain": canonical,
        },
    )
    return get_catalog_agent_write_detail(conn, catalog_agent_id)
