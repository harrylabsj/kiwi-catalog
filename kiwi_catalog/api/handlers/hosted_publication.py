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

"""Hosted A2A publication API handlers (v2.4-W1) — read-only.

Serves the generated Agent Card / UCP Profile documents for hosted catalog
agents.  The documents are pure projections of existing catalog state (see
``kiwi_catalog.a2a``); these handlers only resolve the shared-host base URL
and open a read-only database session.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from kiwi_catalog.a2a.agent_card import build_hosted_agent_card
from kiwi_catalog.a2a.ucp_profile import build_hosted_ucp_profile
from kiwi_catalog.db.session import db_session


def hosted_base_url() -> str:
    """Resolve the shared-host base URL for hosted A2A publication.

    Precedence: ``KIWI_CATALOG_HOSTED_A2A_BASE_URL`` →
    ``KIWI_CATALOG_PUBLIC_BASE_URL`` → ``http://localhost`` (local dev default).
    Legacy ``SHOPPING_*`` names still honored for extracted deployments.
    The builders validate the resolved value (http/https, no userinfo).
    """
    raw = (
        os.environ.get("KIWI_CATALOG_HOSTED_A2A_BASE_URL")
        or os.environ.get("KIWI_CATALOG_PUBLIC_BASE_URL")
        or os.environ.get("SHOPPING_HOSTED_A2A_BASE_URL")
        or os.environ.get("SHOPPING_PUBLIC_BASE_URL")
        or ""
    )
    return str(raw).strip() or "http://localhost"


def hosted_agent_card(db_path: str | Path, catalog_agent_id: str) -> dict[str, Any]:
    """GET /v1/hosted/agents/{catalog_agent_id}/agent-card.json.

    Returns the raw A2A Agent Card document (not an ``ok`` envelope).
    Non-hosted / non-active / unknown agents raise NotFoundError → 404.
    """
    with db_session(db_path) as conn:
        return build_hosted_agent_card(
            conn,
            catalog_agent_id=str(catalog_agent_id or "").strip(),
            base_url=hosted_base_url(),
        )


def hosted_ucp_profile(db_path: str | Path, catalog_agent_id: str) -> dict[str, Any]:
    """GET /v1/hosted/agents/{catalog_agent_id}/ucp.

    Returns the raw UCP 2026-04-08 profile document (not an ``ok`` envelope).
    Non-hosted / non-active / unknown agents raise NotFoundError → 404.
    """
    with db_session(db_path) as conn:
        return build_hosted_ucp_profile(
            conn,
            catalog_agent_id=str(catalog_agent_id or "").strip(),
            base_url=hosted_base_url(),
        )
