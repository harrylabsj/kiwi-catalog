# Copyright 2026 harrylabsj
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""当前商家服务状态的连接器只读投影。"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from kiwi_catalog.agent_catalog.freshness import effective_freshness_state
from kiwi_catalog.core.errors import AuthError, NotFoundError, PermissionDenied
from kiwi_catalog.db.session import db_session, now_iso
from kiwi_catalog.services import connector_identity as identity_service
from kiwi_catalog.services.listing_entitlements import capacity


def _merchant_identity(conn: Any, payload: dict[str, Any]) -> dict[str, Any]:
    token = str(payload.get("_auth_token") or "")
    identity = identity_service.verify_merchant_token(conn, token)
    if identity is None:
        raise AuthError("invalid or expired connector merchant token")
    if "catalog:read" not in str(identity.get("scope") or "").split():
        raise AuthError("connector merchant token lacks catalog:read scope")
    return identity


def _origin(value: str) -> str:
    parsed = urlsplit(str(value or ""))
    if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.username or parsed.password:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def _service_url(enrollment_id: str) -> str:
    base = str(os.environ.get("KIWI_CATALOG_PUBLIC_BASE_URL") or "http://localhost").rstrip("/")
    return f"{base}/portal/connect/{enrollment_id}"


def _onboarding_status(enrollment: Any, publication: Any) -> str:
    if enrollment is None:
        return "not_started"
    state = str(enrollment["status"] or "")
    card_state = str(publication["publication_state"] or "") if publication is not None else ""
    if card_state == "PAUSED":
        return "paused"
    if state == "published" and card_state == "ACTIVE":
        return "published"
    if state == "published":
        return "failed"
    if state == "ready_for_authorization":
        expires_at = str(enrollment["expires_at"] or "")
        return "awaiting_merchant_confirmation" if expires_at and expires_at > now_iso() else "failed"
    if state in ("authorized", "verifying", "bound", "published"):
        return "binding"
    if state in ("expired", "canceled"):
        return "failed"
    return "failed"


def service_status(db_path: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    """只按有效连接器凭据中的商家身份读取服务状态，不接收商家 ID 参数。"""
    with db_session(db_path) as conn:
        identity = _merchant_identity(conn, payload)
        merchant_id = str(identity["merchant_id"])
        account = conn.execute(
            "select merchant_id,email_verified,status from merchant_accounts where account_id=? and merchant_id=?",
            (int(identity["account_id"]), merchant_id),
        ).fetchone()
        if account is None:
            raise NotFoundError("merchant account not found")

        binding = conn.execute(
            "select catalog_agent_id,runtime_origin,status from runtime_bindings "
            "where merchant_id=? and status<>'revoked' order by binding_version desc limit 1",
            (merchant_id,),
        ).fetchone()
        agent = None
        publication = None
        if binding is not None:
            agent = conn.execute(
                "select catalog_agent_id,freshness_state,last_seen_at,verification_level "
                "from catalog_agents where catalog_agent_id=? and merchant_id=?",
                (str(binding["catalog_agent_id"]), merchant_id),
            ).fetchone()
            publication = conn.execute(
                "select active_revision,publication_state from card_publications where catalog_agent_id=?",
                (str(binding["catalog_agent_id"]),),
            ).fetchone()
        enrollment = conn.execute(
            "select enrollment_id,status,expires_at,catalog_agent_id from enrollments "
            "where merchant_id=? order by created_at desc,enrollment_id desc limit 1",
            (merchant_id,),
        ).fetchone()

        if agent is None:
            presence = "unknown"
            last_seen_at = ""
            verification_level = "unknown"
        else:
            fresh = effective_freshness_state(dict(agent), now=now_iso())
            presence = "fresh" if fresh == "fresh" else "stale"
            last_seen_at = str(agent["last_seen_at"] or "")
            verification_level = str(agent["verification_level"] or "unknown")

        try:
            quota = capacity(conn, merchant_id)
            listings = {
                "used": quota["active_used"],
                "total": quota["active_limit"],
                "plan": quota["plan_code"],
            }
        except PermissionDenied:
            # No entitlement means no grant; still expose already-active usage
            # while returning a zero total rather than implying publishing access.
            used = conn.execute(
                "select count(*) from commerce_listings where merchant_id=? and publication_state='ACTIVE'",
                (merchant_id,),
            ).fetchone()[0]
            listings = {"used": int(used), "total": 0, "plan": None}

        enrollment_status = _onboarding_status(enrollment, publication)
        awaiting = enrollment is not None and enrollment_status == "awaiting_merchant_confirmation"
        published = publication is not None and str(publication["publication_state"]) == "ACTIVE"
        return {
            "ok": True,
            "account": {
                "merchant_id": merchant_id,
                "email_verified": bool(account["email_verified"]),
            },
            "onboarding": {
                "status": enrollment_status,
                "authorization_url": _service_url(str(enrollment["enrollment_id"])) if awaiting else "",
                "expires_at": str(enrollment["expires_at"] or "") if awaiting else "",
            },
            "card": {
                "published": published,
                "origin": _origin(str(binding["runtime_origin"] or "")) if binding is not None and published else "",
                "verification_level": verification_level,
            },
            "presence": {"state": presence, "last_seen_at": last_seen_at},
            "listings": listings,
        }
