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

"""Hosted UCP Profile 2026-04-08 builder (v2.4-W1).

A read-only projection of existing catalog state into the UCP commerce
discovery document.  The generated profile MUST be accepted by the §17.2 UCP
parser (``kiwi_catalog.discovery.ucp``) — the round-trip is the structural
self-check and fails closed if it ever breaks.

Binding: docs/a2a/shopping-cli-a2a-binding-1.0-rc1.md §5 (a2a service shape:
``transport = a2a`` + ``endpoint = Agent Card URL``)
"""

from __future__ import annotations

from typing import Any

from kiwi_catalog import VERSION
from kiwi_catalog.a2a._common import (
    agent_card_url,
    display_name,
    load_hosted_agent,
    merchant_public_ref,
    publication_description,
    validate_base_url,
)
from kiwi_catalog.agent_catalog.sqlite_repository import list_capabilities
from kiwi_catalog.discovery._validation import ProfileValidationError
from kiwi_catalog.discovery.ucp import parse_ucp_profile

# Pinned UCP specification family (§0.3).  The UCP parser validates
# ``specificationVersion`` against the TrustPolicy UCP version allowlist.
UCP_SPEC_VERSION = "2026-04-08"


def _fq_capability_ids(cap_rows: list[dict[str, Any]]) -> list[str]:
    """Render agent_capabilities rows as fully-qualified ids (§8.2)."""
    fq: list[str] = []
    seen: set[str] = set()
    for cap in cap_rows:
        namespace = str(cap.get("namespace") or "").strip()
        capability_id = str(cap.get("capability_id") or "").strip()
        if not namespace or not capability_id:
            continue
        fqid = f"{namespace}:{capability_id}"
        if fqid in seen:
            continue
        seen.add(fqid)
        fq.append(fqid)
    return fq


def build_hosted_ucp_profile(
    conn: Any,
    catalog_agent_id: str,
    *,
    base_url: str,
) -> dict[str, Any]:
    """Build the UCP 2026-04-08 profile for a hosted catalog agent.

    Only ``source_type=hosted`` + ``lifecycle_status=active`` agents are
    publishable; anything else raises NotFoundError.

    The profile carries one ``a2a`` commerce service whose endpoint is the
    agent's Agent Card URL (binding rc1 §5).  Commerce capabilities are
    projected from ``agent_capabilities`` as fully-qualified ids; no secret
    boundary field is ever read.

    The result is round-tripped through ``parse_ucp_profile`` as a structural
    self-check; a failure raises an internal error (fail-closed).
    """
    cagt_id = str(catalog_agent_id or "").strip()
    base = validate_base_url(base_url)
    card_url = agent_card_url(base, cagt_id)
    row = load_hosted_agent(conn, cagt_id)
    merchant_ref = merchant_public_ref(row)
    name = display_name(row, merchant_ref, cagt_id)
    description = publication_description(row, merchant_ref)

    cap_rows = list_capabilities(conn, cagt_id)
    capabilities = _fq_capability_ids(cap_rows)

    profile: dict[str, Any] = {
        "specificationVersion": UCP_SPEC_VERSION,
        "implementationVersion": f"shopping-cli/{VERSION}",
        "serviceIdentity": {
            "id": card_url,
            "name": name,
            "description": description,
        },
        "services": [
            {
                "id": f"a2a:{cagt_id}",
                "type": "commerce",
                "name": name,
                "description": description,
                "capabilities": capabilities,
                "endpoints": [
                    {"uri": card_url, "protocol": "a2a"},
                ],
                "documentationUri": (
                    f"{base}/v1/hosted/agents/{cagt_id}/agent-card.json"
                ),
            }
        ],
    }

    source_url = f"{base}/v1/hosted/agents/{cagt_id}/ucp"
    try:
        parse_ucp_profile(profile, source_url=source_url)
    except ProfileValidationError as exc:
        raise RuntimeError(
            f"internal error: generated UCP Profile failed structural validation: {exc}"
        ) from exc

    return profile
