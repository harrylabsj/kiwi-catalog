"""Public serializers for the Commerce Agent Catalog.

These serializers enforce §3.4: they ONLY expose fields from the "MAY
expose" list and MUST NOT leak automation_boundaries, floor price, cost,
private discount policy, agent/merchant tokens, private contact, LLM
prompts, internal strategy, or private reputation evidence.

Every public response MUST go through these functions — never return raw
DB rows to callers.
"""

from __future__ import annotations

from typing import Any

from kiwi_catalog.agent_catalog.candidate_dto import (
    CANDIDATE_CONTRACT_NAME,
    CANDIDATE_DTO_VERSION,
)
from kiwi_catalog.db.session import decode_json

# ── Fields that MUST NOT appear in any public response (§3.4) ───────────────
_PRIVATE_MERCHANT_FIELDS = frozenset({
    "automation_boundaries",
    "contact",
    "hours",
    "delivery_fee",
    "delivery_currency",
    "delivery_eta_minutes",
    "delivery_radius_km",
    "delivery_notes",
    "floor_price",
    "cost",
    "discount_policy",
    "agent_token",
    "merchant_token",
    "private_contact",
    "llm_prompt",
    "internal_strategy",
    "private_reputation_evidence",
})

_PRIVATE_CATALOG_FIELDS = frozenset({
    "first_seen_at",
    "last_seen_at",
    "created_at",
    "updated_at",
    "provider_name",
})


def _strip_private(obj: dict[str, Any], private_fields: frozenset[str]) -> dict[str, Any]:
    """Return a shallow copy of *obj* with private fields removed."""
    return {k: v for k, v in obj.items() if k not in private_fields}


def public_merchant_ref(merchant: dict[str, Any] | None) -> dict[str, Any] | None:
    """Project a merchant dict down to public-safe fields (§3.4)."""
    if merchant is None:
        return None
    safe = _strip_private(merchant, _PRIVATE_MERCHANT_FIELDS)
    # Always include id, name; tags as list
    # 弱引用语义（独立 schema）：影子 merchants 表无对应行时 join 字段为
    # None——public ref 输出空串而非 null（与 shopping-cli 的分叉点）。
    result: dict[str, Any] = {
        "id": safe.get("id", "") or "",
        "name": safe.get("name", "") or "",
    }
    if safe.get("city"):
        result["city"] = safe["city"]
    if safe.get("service_area"):
        result["service_area"] = safe["service_area"]
    # domain: prefer canonical_domain, fall back to merchant domain-like fields
    domain = safe.get("canonical_domain") or safe.get("domain") or ""
    if domain:
        result["domain"] = domain
    tags = safe.get("tags")
    if isinstance(tags, list):
        result["tags"] = tags
    elif isinstance(safe.get("tags_json"), str):
        result["tags"] = decode_json(safe["tags_json"], [])
    return result


def public_capability_summary(cap: dict[str, Any]) -> dict[str, Any]:
    """Public view of one agent_capability row — fully-qualified id (§8.2)."""
    ns = str(cap.get("namespace", ""))
    cid = str(cap.get("capability_id", ""))
    fqid = f"{ns}:{cid}" if ns else cid
    result: dict[str, Any] = {
        "capability_id": fqid,
    }
    if cap.get("version"):
        result["version"] = cap["version"]
    return result


def public_skill_summary(skill: dict[str, Any]) -> dict[str, Any]:
    """Public view of one agent_skill row."""
    result: dict[str, Any] = {
        "skill_id": skill.get("skill_id", ""),
        "name": skill.get("name", ""),
    }
    if skill.get("description"):
        result["description"] = skill["description"]
    tags = decode_json(skill.get("tags_json", ""), [])
    if tags:
        result["tags"] = tags
    return result


def public_endpoint_summary(ep: dict[str, Any]) -> dict[str, Any] | None:
    """Public view of one agent_endpoint row, or None if the endpoint is not
    public-facing (e.g. internal hosted_gateway endpoints without a URL)."""
    kind = str(ep.get("kind", ""))
    url = str(ep.get("url", ""))
    if not url and kind not in ("agent_card", "ucp_profile"):
        return None
    result: dict[str, Any] = {"kind": kind}
    if url:
        result["url"] = url
    if ep.get("protocol"):
        result["protocol"] = ep["protocol"]
    if ep.get("protocol_version"):
        result["protocol_version"] = ep["protocol_version"]
    return result


def catalog_search_result(
    catalog_agent: dict[str, Any],
    merchant: dict[str, Any] | None = None,
    capabilities: list[dict[str, Any]] | None = None,
    endpoints: list[dict[str, Any]] | None = None,
    skills: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a §8.2 Search Result Contract response.

    Returns a Candidate dict, NOT a verified live identity.
    """
    safe_catalog = _strip_private(catalog_agent, _PRIVATE_CATALOG_FIELDS)

    result: dict[str, Any] = {
        "catalog_agent_id": safe_catalog.get("catalog_agent_id", ""),
    }

    # ── merchant block ──────────────────────────────────────────────────
    merchant_block: dict[str, Any] | None = None
    if merchant:
        public_m = public_merchant_ref(merchant)
        if public_m:
            merchant_block = public_m
    # If catalog row carries merchant_name from a join, use it as fallback
    if not merchant_block:
        mname = safe_catalog.get("merchant_name") or safe_catalog.get("display_name") or ""
        if mname:
            merchant_block = {"name": mname}
    if merchant_block:
        result["merchant"] = merchant_block

    # ── discovery block ─────────────────────────────────────────────────
    discovery: dict[str, Any] = {}
    if endpoints:
        for ep in endpoints:
            pub = public_endpoint_summary(ep)
            if pub is None:
                continue
            kind = pub["kind"]
            if kind == "agent_card" and pub.get("url"):
                discovery["agent_card_url"] = pub["url"]
            elif kind == "ucp_profile" and pub.get("url"):
                discovery["ucp_profile_url"] = pub["url"]
            elif kind == "a2a" and pub.get("url"):
                discovery.setdefault("a2a_urls", []).append(pub["url"])
    if discovery:
        result["discovery"] = discovery

    # ── protocols block ─────────────────────────────────────────────────
    protocols: dict[str, list[str]] = {}
    if endpoints:
        for ep in endpoints:
            pub = public_endpoint_summary(ep)
            if pub is None:
                continue
            proto = pub.get("protocol", "")
            ver = pub.get("protocol_version", "")
            if proto:
                versions = protocols.setdefault(proto, [])
                if ver and ver not in versions:
                    versions.append(ver)
    if protocols:
        result["protocols"] = protocols

    # ── capabilities block ──────────────────────────────────────────────
    if capabilities:
        result["capabilities"] = [
            public_capability_summary(c)["capability_id"] for c in capabilities
        ]

    # ── skills block ────────────────────────────────────────────────────
    if skills:
        result["skills"] = [public_skill_summary(s) for s in skills]

    # ── verification block ──────────────────────────────────────────────
    result["verification"] = {
        "status": safe_catalog.get("verification_status", "discovered"),
    }
    last_verified = safe_catalog.get("last_verified_at", "")
    if last_verified:
        result["verification"]["last_verified_at"] = last_verified

    # ── hosting block ───────────────────────────────────────────────────
    result["hosting"] = {
        "mode": safe_catalog.get("hosting_mode", "unknown"),
    }

    # ── contract annotation (v2.3-T1) ───────────────────────────────────
    # Every Candidate carries the DTO name + version so consumers can gate on
    # the contract without guessing.  Injected once at the serializer layer so
    # all four read routes stay consistent (additive; see candidate_dto.py).
    result["contract"] = {
        "name": CANDIDATE_CONTRACT_NAME,
        "version": CANDIDATE_DTO_VERSION,
    }

    return result


def catalog_agent_detail(
    catalog_agent: dict[str, Any],
    merchant: dict[str, Any] | None = None,
    capabilities: list[dict[str, Any]] | None = None,
    endpoints: list[dict[str, Any]] | None = None,
    skills: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Full public detail for get_catalog_agent, based on the §8.2 contract."""
    return catalog_search_result(
        catalog_agent=catalog_agent,
        merchant=merchant,
        capabilities=capabilities,
        endpoints=endpoints,
        skills=skills,
    )


def catalog_agent_write_result(
    catalog_agent: dict[str, Any],
    merchant: dict[str, Any] | None = None,
    capabilities: list[dict[str, Any]] | None = None,
    endpoints: list[dict[str, Any]] | None = None,
    skills: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Public detail for write responses (register §10.2 / claim §10.4).

    Extends the §8.2 search-result contract with the canonical identity the
    caller just acted on (``canonical_domain`` and ``source_type``) so a
    register/claim response is self-describing.  These are both §3.4
    MAY-expose fields; nothing private leaks through.
    """
    result = catalog_agent_detail(
        catalog_agent=catalog_agent,
        merchant=merchant,
        capabilities=capabilities,
        endpoints=endpoints,
        skills=skills,
    )
    result["canonical_domain"] = str(catalog_agent.get("canonical_domain") or "")
    result["source_type"] = str(catalog_agent.get("source_type") or "")
    return result


def catalog_agent_record(
    catalog_agent: dict[str, Any],
    merchant: dict[str, Any] | None = None,
    capabilities: list[dict[str, Any]] | None = None,
    endpoints: list[dict[str, Any]] | None = None,
    skills: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """CatalogAgentRecord —— /v1/agents wire 形状（v0.3 §6/§7）。

    契约：contracts/kiwi-catalog/1.0/agent-record.schema.json
    （additionalProperties: false —— 未知/私有字段进不来，完成定义 #8）。
    三正交状态域原样输出（不折叠）；handoff_destination_types 为精确
    KTH destination_type 词表（单一来源，禁止 supports_* 平行词表）。
    """
    safe = _strip_private(catalog_agent, _PRIVATE_CATALOG_FIELDS)
    record: dict[str, Any] = {
        "catalog_agent_id": safe.get("catalog_agent_id", ""),
        "principal_type": "merchant",
        "display_name": safe.get("display_name") or "",
        "canonical_domain": safe.get("canonical_domain") or "",
        "hosting_mode": safe.get("hosting_mode", "unknown"),
        "verification_level": safe.get("verification_level", "discovered"),
        "freshness_state": safe.get("freshness_state", "fresh"),
        "administrative_state": safe.get("administrative_state", "active"),
        "created_at": safe.get("created_at", ""),
        "updated_at": safe.get("updated_at", ""),
    }
    merchant_id = safe.get("merchant_id") or ""
    if merchant_id:
        record["merchant_id"] = merchant_id

    protocols: dict[str, list[str]] = {}
    if endpoints:
        for ep in endpoints:
            pub = public_endpoint_summary(ep)
            if pub is None:
                continue
            kind = pub["kind"]
            if kind == "agent_card" and pub.get("url"):
                record["agent_card_url"] = pub["url"]
            elif kind == "ucp_profile" and pub.get("url"):
                record["ucp_profile_url"] = pub["url"]
            proto = pub.get("protocol", "")
            ver = pub.get("protocol_version", "")
            if proto:
                versions = protocols.setdefault(proto, [])
                if ver and ver not in versions:
                    versions.append(ver)
    if protocols:
        record["protocols"] = protocols

    if capabilities:
        record["capabilities"] = [
            public_capability_summary(c)["capability_id"] for c in capabilities
        ]
    if skills:
        record["skills"] = [public_skill_summary(s) for s in skills]

    handoff = decode_json(safe.get("handoff_destination_types", "[]"), [])
    if handoff:
        record["handoff_destination_types"] = handoff
    if safe.get("last_verified_at"):
        record["last_verified_at"] = safe["last_verified_at"]
    return record
