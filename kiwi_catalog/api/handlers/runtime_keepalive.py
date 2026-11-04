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

"""Owner-authenticated merchant consent for catalog-side keepalive.

This is a Workbench entry: the owner token (or the existing account session
bridge) identifies the merchant. The runtime-access binding signature is not
used here because this is a merchant opt-in, not a runtime control operation.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from kiwi_catalog.agent_catalog.catalog_audit import append_catalog_audit
from kiwi_catalog.api import auth as api_auth
from kiwi_catalog.core.errors import NotFoundError, ValidationError
from kiwi_catalog.db.session import db_session
from kiwi_catalog.services import runtime_keepalive

_PATH = "/v1/agents/{catalog_agent_id}/runtime-keepalive-consent"


def _agent_merchant(conn: Any, agent_id: str) -> str:
    row = conn.execute(
        "select merchant_id, administrative_state from catalog_agents where catalog_agent_id=?",
        (agent_id,),
    ).fetchone()
    if row is None:
        raise NotFoundError("catalog agent not found")
    if str(row["administrative_state"] or "") != "active":
        raise NotFoundError("catalog agent not found")
    merchant_id = str(row["merchant_id"] or "").strip()
    if merchant_id == "":
        raise NotFoundError("catalog agent has no owner")
    return merchant_id


def _body(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        str(key): value
        for key, value in payload.items()
        if not str(key).startswith("_") and key != "owner_token"
    }


def read_consent(db_path: str | Path, catalog_agent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """GET owner view; no secret or probe material is returned."""
    agent_id = str(catalog_agent_id or "").strip()
    with db_session(db_path) as conn:
        merchant_id = _agent_merchant(conn, agent_id)
        api_auth.require_merchant_token(payload, merchant_id, conn)
        row = conn.execute(
            "select merchant_id,terms_version,granted_at,revoked_at"
            " from runtime_keepalive_consents where catalog_agent_id=?",
            (agent_id,),
        ).fetchone()
        granted = bool(
            row is not None
            and str(row["merchant_id"]) == merchant_id
            and str(row["terms_version"]) == runtime_keepalive.TERMS_VERSION
            and not str(row["revoked_at"] or "")
        )
        return {
            "granted": granted,
            "scope": runtime_keepalive.SCOPE,
            "terms_version": runtime_keepalive.TERMS_VERSION,
            "terms_text": runtime_keepalive.TERMS_TEXT,
            "default_enabled": False,
            "probe_verified": False,
            "scheduler_enabled": False,
            "__no_store__": True,
        }


def update_consent(db_path: str | Path, catalog_agent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """PUT owner consent; grant is explicit, revoke is always available."""
    agent_id = str(catalog_agent_id or "").strip()
    body = _body(payload)
    if set(body) != {"consent"} or not isinstance(body.get("consent"), dict):
        raise ValidationError("consent is required")
    consent = body["consent"]
    if set(consent) != {"granted", "terms_version"} or type(consent.get("granted")) is not bool:
        raise ValidationError("consent.granted and consent.terms_version are required")
    terms_version = consent.get("terms_version")
    if not isinstance(terms_version, str) or terms_version == "":
        raise ValidationError("consent.terms_version is required")
    with db_session(db_path) as conn:
        merchant_id = _agent_merchant(conn, agent_id)
        api_auth.require_merchant_token(payload, merchant_id, conn)
        if consent["granted"]:
            runtime_keepalive.grant(
                conn,
                catalog_agent_id=agent_id,
                merchant_id=merchant_id,
                terms_version=terms_version,
            )
        else:
            # Revocation must remain possible even if terms or custody changed.
            runtime_keepalive.revoke(
                conn,
                catalog_agent_id=agent_id,
                merchant_id=merchant_id,
            )
        append_catalog_audit(
            conn,
            catalog_agent_id=agent_id,
            actor=f"owner:{merchant_id}",
            event="runtime_keepalive_consent_changed",
            details={
                "granted": consent["granted"],
                "terms_version": terms_version,
            },
        )
        return {
            "granted": bool(consent["granted"]),
            "scope": runtime_keepalive.SCOPE,
            "terms_version": runtime_keepalive.TERMS_VERSION,
            "default_enabled": False,
            "probe_verified": False,
            "scheduler_enabled": False,
            "__no_store__": True,
        }
