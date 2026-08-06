"""Structured capability/skill extraction from validated discovery profiles.

Design: docs/shopping-cli-a2a-upgrade-design-v1.2.1.md §5.3–5.5, §8.2

These helpers run AFTER a profile has passed the full §17.2 validation
pipeline.  They turn the public projection into rows shaped like the
``agent_capabilities`` and ``agent_skills`` tables so the catalog layer (W3)
can persist them without re-interpreting the raw profile.

Public capability identifiers MUST be fully qualified (namespace +
capability_id, rendered ``namespace:capability_id``).  Short names are only
an internal alias and never appear in a public contract (§8.2).
"""

from __future__ import annotations

import json
from typing import Any

# ── Row-shaped capability dict ─────────────────────────────────────────────

# Column names match shopping_cli/db/migrations.py agent_capabilities.
_CAPABILITY_ROW_KEYS = ("namespace", "capability_id", "version", "required", "source", "schema_url", "spec_url")

# Column names match shopping_cli/db/migrations.py agent_skills.
_SKILL_ROW_KEYS = ("skill_id", "name", "description", "tags_json", "input_modes_json", "output_modes_json")


def _capability_row(
    namespace: str,
    capability_id: str,
    *,
    version: str = "",
    source: str = "",
) -> dict[str, Any]:
    """Build a row-shaped agent_capabilities dict (all keys present)."""
    return {
        "namespace": namespace,
        "capability_id": capability_id,
        "version": version,
        "required": 0,
        "source": source,
        "schema_url": "",
        "spec_url": "",
    }


def _json_dumps(value: Any) -> str:
    """Compact JSON encoding of a list column, defaulting to ``[]``."""
    if value is None:
        return "[]"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


# ── Fully-qualified capability identifiers (§8.2) ──────────────────────────


def split_capability_id(value: str, *, default_namespace: str = "") -> tuple[str, str]:
    """Split a capability identifier into ``(namespace, capability_id)``.

    Rule (deterministic, round-trips ``namespace:capability_id``):

    * contains ``:``       → split on the LAST ``:`` (preserves URNs and
      colon-delimited ids: ``urn:x:cap:shopping`` stays whole).
    * dotted reverse-domain → the part before the LAST ``.`` is itself dotted
      (``com.example.shopping`` → namespace ``com.example``, capability_id
      ``shopping``); the namespace is a real namespacing prefix.
    * compound name        → a single dotted name such as
      ``shopping.negotiation`` is NOT self-namespacing; the whole value is
      attributed to *default_namespace* (the agent's canonical domain, which
      is the authority for a self-declared capability, §3.1).
    * otherwise            → a bare id is attributed to *default_namespace*.
    """
    value = value.strip()
    if not value:
        return (default_namespace, "")
    if ":" in value:
        namespace, _, capability_id = value.rpartition(":")
        return (namespace, capability_id)
    if "." in value:
        namespace, _, capability_id = value.rpartition(".")
        if "." in namespace:
            return (namespace, capability_id)
        return (default_namespace, value)
    return (default_namespace, value)


# ── A2A Agent Card extraction ──────────────────────────────────────────────


def extract_agent_card_capabilities(public: dict[str, Any], *, version: str = "") -> list[dict[str, Any]]:
    """Extract agent_capabilities rows from a validated Agent Card projection.

    Emits a protocol marker (``a2a:agent_card`` at the card's version) plus
    one row per advertised A2A interface capability flag that is true.
    """
    rows: list[dict[str, Any]] = [
        _capability_row("a2a", "agent_card", version=version, source="agent_card"),
    ]
    caps = public.get("capabilities")
    if isinstance(caps, dict):
        # A2A AgentCard capability flags → snake_case capability ids.
        flag_map = (
            ("streaming", "streaming"),
            ("pushNotifications", "push_notifications"),
            ("stateTransitionHistory", "state_transition_history"),
        )
        for flag, capability_id in flag_map:
            if caps.get(flag) is True:
                rows.append(
                    _capability_row("a2a", capability_id, version=version, source="agent_card")
                )
    return rows


def extract_agent_card_skills(public: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract agent_skills rows from a validated Agent Card projection.

    Only public skill fields are carried (§5.4 "只存公开 skill"); list columns
    are JSON-encoded strings matching the table's ``*_json`` columns.
    """
    rows: list[dict[str, Any]] = []
    for skill in public.get("skills", []):
        if not isinstance(skill, dict):
            continue
        rows.append(
            {
                "skill_id": str(skill.get("id", "")),
                "name": str(skill.get("name", "")),
                "description": str(skill.get("description", "")),
                "tags_json": _json_dumps(skill.get("tags")),
                "input_modes_json": _json_dumps(skill.get("inputModes")),
                "output_modes_json": _json_dumps(skill.get("outputModes")),
            }
        )
    return rows


# ── UCP Profile extraction ─────────────────────────────────────────────────


def extract_ucp_capabilities(
    public: dict[str, Any],
    *,
    default_namespace: str = "",
    specification_version: str = "",
) -> list[dict[str, Any]]:
    """Extract agent_capabilities rows from a validated UCP projection.

    Emits a protocol marker (``ucp:profile`` at the specification version)
    plus one row per capability declared across all services.  Capability ids
    are made fully qualified via :func:`split_capability_id`, defaulting to
    the agent's canonical domain for unqualified identifiers.
    """
    rows: list[dict[str, Any]] = [
        _capability_row("ucp", "profile", version=specification_version, source="ucp_profile"),
    ]
    for service in public.get("services", []):
        if not isinstance(service, dict):
            continue
        for capability in service.get("capabilities", []):
            if not isinstance(capability, str):
                continue
            namespace, capability_id = split_capability_id(
                capability, default_namespace=default_namespace
            )
            rows.append(
                _capability_row(namespace, capability_id, version="", source="ucp_profile")
            )
    return rows


def extract_ucp_skills(public: dict[str, Any]) -> list[dict[str, Any]]:
    """UCP carries commerce capabilities, not agent skills — always empty."""
    return []
