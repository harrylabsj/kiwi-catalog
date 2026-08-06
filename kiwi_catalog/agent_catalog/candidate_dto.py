"""CandidateAgent DTO contract (v1.0) — the public wire shape for catalog reads.

Formalises §8.2 of docs/shopping-cli-a2a-upgrade-design-v1.2.1.md into an
explicit, versioned, testable contract.  This repo owns the DTO (§21): Kiwi's
``ShoppingCliCatalogSource`` consumes it as-is and MUST NOT redefine the shape.

A Candidate is a discoverable commerce agent — NOT a verified live identity.
§8.2: the catalog returns candidates; converting a candidate into a usable
``CounterpartyProfile`` is Kiwi's responsibility.

§3.4 boundary: only the MAY-expose field list may appear.  Private merchant
state (floor_price, agent_token, automation_boundaries, …) is stripped by the
serializers and MUST never appear in a validated Candidate.
"""

from __future__ import annotations

from typing import Any

# ── Contract identity ────────────────────────────────────────────────────────
# Versioning policy (see docs/a2a/candidate-agent-dto-1.0.md):
#   * within 1.x — additive-only; existing fields keep type/semantics
#   * a breaking change bumps the major (e.g. 2.0) and ships a new $id

CANDIDATE_DTO_VERSION = "1.0"
CANDIDATE_CONTRACT_NAME = "candidate-agent"

# §22 canonical hosting modes.
CONTRACT_HOSTING_MODES: frozenset[str] = frozenset({
    "direct_only",
    "hosted_only",
    "hybrid",
    "unknown",
})

# Legacy DB storage values (see the hosting_mode check constraint in
# db/models.py / db/migrations.py) and their §22 canonical forms.  The DB keeps
# storing the legacy values in v1.x — no migration — so the contract normalises
# through :func:`to_contract_hosting_mode`.
_LEGACY_HOSTING_MODE_MAP: dict[str, str] = {
    "direct": "direct_only",
    "hosted": "hosted_only",
    "hybrid": "hybrid",
    "unknown": "unknown",
}


def to_contract_hosting_mode(stored_mode: str) -> str:
    """Map a stored ``hosting_mode`` value to the §22 canonical enum.

    Legacy DB values (``direct``/``hosted``) map to their §22 counterparts
    (``direct_only``/``hosted_only``).  ``hybrid``/``unknown`` pass through.
    Unrecognised or empty values fail closed to ``unknown`` — a candidate
    never fabricates a hosting mode it does not actually store.

    This is the explicit mapping required by v2.3-T1: the contract enum is
    §22-aligned while the DB continues to store the legacy set, so consumers
    that require canonical values normalise via this function.
    """
    key = str(stored_mode or "").strip().lower()
    return _LEGACY_HOSTING_MODE_MAP.get(key, "unknown")


# ── CandidateAgent JSON Schema (draft-07 subset) ─────────────────────────────
# Required/additionalProperties are tightened to what the public serializers
# actually emit (shopping_cli/agent_catalog/serializers.py).  Every field is a
# §3.4 MAY-expose field.
#
# Note on hosting.mode: the enum accepts BOTH the §22 canonical values and the
# legacy stored values (``direct``/``hosted``) so the schema validates today's
# real serializer output unchanged.  New producers SHOULD emit the canonical
# form (see :func:`to_contract_hosting_mode`); a future 2.0 contract may drop
# the legacy aliases.

CANDIDATE_AGENT_SCHEMA: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": "urn:shopping-cli:candidate-agent:1.0",
    "title": "CandidateAgent",
    "description": (
        "Public CandidateAgent DTO (§8.2, §21). A Candidate is a discoverable "
        "commerce agent, NOT a verified live identity. Only §3.4 MAY-expose "
        "fields may appear; private merchant state is never part of this DTO."
    ),
    "type": "object",
    "properties": {
        "catalog_agent_id": {
            "type": "string",
            "minLength": 1,
            "description": "Stable catalog identifier for the candidate.",
        },
        "merchant": {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "name": {"type": "string"},
                "city": {"type": "string"},
                "service_area": {"type": "string"},
                "domain": {"type": "string"},
                "tags": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["id", "name"],
            "additionalProperties": False,
        },
        "discovery": {
            "type": "object",
            "properties": {
                "agent_card_url": {"type": "string"},
                "ucp_profile_url": {"type": "string"},
                "a2a_urls": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "additionalProperties": False,
        },
        "protocols": {
            "type": "object",
            "description": "Map of protocol name → advertised protocol versions.",
            "additionalProperties": {
                "type": "array",
                "items": {"type": "string"},
            },
        },
        "capabilities": {
            "type": "array",
            "items": {"type": "string", "minLength": 1},
            "description": (
                "Fully-qualified capability identifiers (§8.2). When a "
                "namespace is present it is joined with ':' before the "
                "capability id, e.g. 'com.harrylabsj.shopping.capability:catalog'."
            ),
        },
        "skills": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "skill_id": {"type": "string"},
                    "name": {"type": "string"},
                    "description": {"type": "string"},
                    "tags": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["skill_id", "name"],
                "additionalProperties": False,
            },
        },
        "verification": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "description": (
                        "Verification status. Known values: discovered, "
                        "profile_valid, domain_verified, agent_verified, "
                        "commerce_verified, stale, unreachable, suspended, "
                        "rejected (§6 state machine)."
                    ),
                },
                "last_verified_at": {
                    "type": "string",
                    "description": "ISO-8601 timestamp of the last verification.",
                },
            },
            "required": ["status"],
            "additionalProperties": False,
        },
        "hosting": {
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": [
                        "direct",
                        "hosted",
                        "hybrid",
                        "unknown",
                        "direct_only",
                        "hosted_only",
                    ],
                    "description": (
                        "Hosting mode (§22). Canonical values are "
                        "direct_only / hosted_only / hybrid / unknown; "
                        "'direct' and 'hosted' are the legacy DB storage "
                        "values retained for backward compatibility. See "
                        "to_contract_hosting_mode for the normalization."
                    ),
                },
            },
            "required": ["mode"],
            "additionalProperties": False,
        },
        "contract": {
            "type": "object",
            "properties": {
                "name": {
                    "const": CANDIDATE_CONTRACT_NAME,
                    "description": "The DTO name, always 'candidate-agent'.",
                },
                "version": {
                    "const": CANDIDATE_DTO_VERSION,
                    "description": "The additive-only contract version in use.",
                },
            },
            "required": ["name", "version"],
            "additionalProperties": False,
        },
    },
    "required": ["catalog_agent_id", "verification", "hosting", "contract"],
    "additionalProperties": False,
}
