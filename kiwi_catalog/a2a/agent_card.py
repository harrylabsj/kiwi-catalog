"""Hosted A2A Agent Card v1.0.0 builder (v2.4-W1).

A read-only projection: the card is derived entirely from existing catalog /
merchant / skill state and never writes to the database.

The generated document MUST be accepted by the §17.2 Agent Card parser
(``kiwi_catalog.discovery.agent_card``) — that round-trip is the structural
self-check and fails closed if it ever breaks.

Binding: docs/a2a/shopping-cli-a2a-binding-1.0-rc1.md §5 (capability
advertisement), §6 (security invariants)
"""

from __future__ import annotations

from typing import Any

from kiwi_catalog.a2a._common import (
    agent_card_url,
    display_name,
    load_hosted_agent,
    merchant_public_ref,
    publication_description,
)
from kiwi_catalog.agent_catalog.sqlite_repository import list_skills
from kiwi_catalog.db.session import decode_json
from kiwi_catalog.discovery._validation import ProfileValidationError
from kiwi_catalog.discovery.agent_card import parse_agent_card

# Pinned A2A protocol version this card conforms to (§0.3).  The Agent Card
# parser validates ``card.version`` against the TrustPolicy A2A version
# allowlist, so this MUST stay on the pinned value.
CARD_VERSION = "1.0.0"

# JSON-RPC is the only A2A transport interface the hosted endpoint declares.
# The server itself ships in a later work item (v2.4-W3); the card may already
# advertise the future endpoint URL (§14.1).
SUPPORTED_INTERFACES = [{"name": "jsonrpc", "version": "1.0"}]


def _project_skills(skill_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Project agent_skills rows into A2A skill objects (§5.4 public only)."""
    projected: list[dict[str, Any]] = []
    for skill in skill_rows:
        item: dict[str, Any] = {
            "id": str(skill.get("skill_id", "")),
            "name": str(skill.get("name", "")),
        }
        if skill.get("description"):
            item["description"] = str(skill["description"])
        tags = decode_json(skill.get("tags_json", ""), [])
        if tags:
            item["tags"] = tags
        input_modes = decode_json(skill.get("input_modes_json", ""), [])
        if input_modes:
            item["inputModes"] = input_modes
        output_modes = decode_json(skill.get("output_modes_json", ""), [])
        if output_modes:
            item["outputModes"] = output_modes
        projected.append(item)
    return projected


def build_hosted_agent_card(
    conn: Any,
    catalog_agent_id: str,
    *,
    base_url: str,
) -> dict[str, Any]:
    """Build the A2A v1.0.0 Agent Card for a hosted catalog agent.

    Only ``source_type=hosted`` + ``lifecycle_status=active`` agents are
    publishable; anything else raises NotFoundError.

    The card carries public metadata only (§3.4): identity, the §14.1
    shared-host agent URL, the JSON-RPC interface declaration, public skills,
    and the merchant's public organization name.  No secret-boundary field
    (tokens, floor_price, automation boundaries, ...) is ever read.

    The result is round-tripped through ``parse_agent_card`` as a structural
    self-check; a failure raises an internal error (fail-closed).
    """
    cagt_id = str(catalog_agent_id or "").strip()
    card_url = agent_card_url(base_url, cagt_id)  # validates base_url
    row = load_hosted_agent(conn, cagt_id)
    merchant_ref = merchant_public_ref(row)
    name = display_name(row, merchant_ref, cagt_id)

    card: dict[str, Any] = {
        "name": name,
        "version": CARD_VERSION,
        "url": card_url,
        "description": publication_description(row, merchant_ref),
        "provider": {"organization": str(merchant_ref.get("name") or name)},
        "supportedInterfaces": [dict(i) for i in SUPPORTED_INTERFACES],
    }

    skill_rows = list_skills(conn, cagt_id)
    projected_skills = _project_skills(skill_rows)
    if projected_skills:
        card["skills"] = projected_skills

    # NOTE: no ``capabilities.extensions`` entry is emitted for the Kiwi
    # negotiation extension — the production namespace is not frozen
    # (binding rc1 §5) and the design forbids inventing a URI.
    # The A2A capability flags (streaming / pushNotifications /
    # stateTransitionHistory) are all unsupported by the hosted server, so the
    # ``capabilities`` block is omitted entirely.

    try:
        parse_agent_card(card, source_url=card_url)
    except ProfileValidationError as exc:
        raise RuntimeError(
            f"internal error: generated Agent Card failed structural validation: {exc}"
        ) from exc

    return card
