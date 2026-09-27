# Copyright 2026 harrylabsj
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0

"""Merchant listing capacity, independent of credentials and enrollment grants."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from kiwi_catalog.core.errors import NotFoundError, PermissionDenied, ValidationError
from kiwi_catalog.db.session import now_iso


def ensure_free_entitlement(conn: sqlite3.Connection, merchant_id: str) -> None:
    now = now_iso()
    conn.execute("insert or ignore into listing_plans values ('free', 20, ?)", (now,))
    conn.execute("""insert or ignore into merchant_listing_entitlements
        (merchant_id,plan_code,status,limit_override,updated_at)
        values (?,'free','active',null,?)""", (merchant_id, now))


def capacity(conn: sqlite3.Connection, merchant_id: str) -> dict[str, Any]:
    row = conn.execute("""select e.plan_code,e.status,e.limit_override,p.active_limit
        from merchant_listing_entitlements e join listing_plans p
        on p.plan_code=e.plan_code where e.merchant_id=?""", (merchant_id,)).fetchone()
    if row is None:
        raise PermissionDenied("LISTINGS_ENTITLEMENT_REQUIRED: merchant has no listing plan")
    used = conn.execute("""select count(*) from commerce_listings
        where merchant_id=? and publication_state='ACTIVE'""", (merchant_id,)).fetchone()[0]
    limit = row["limit_override"] if row["limit_override"] is not None else row["active_limit"]
    return {"plan_code": row["plan_code"], "status": row["status"],
            "active_limit": int(limit), "active_used": int(used),
            "active_remaining": max(0, int(limit) - int(used))}


def require_publication_capacity(
    conn: sqlite3.Connection, merchant_id: str, *, existing_state: str | None
) -> None:
    """Call inside the same write transaction as the upsert.

    Updates to an already ACTIVE row do not consume another slot. A stale row
    still occupies its slot because refreshing it can make it discoverable.
    """
    account = conn.execute("""select status,email_verified from merchant_accounts
        where merchant_id=? order by account_id limit 1""", (merchant_id,)).fetchone()
    if account is None or account["status"] != "active" or account["email_verified"] != 1:
        raise PermissionDenied("LISTINGS_ACCOUNT_NOT_READY: verify an active merchant account")
    current = capacity(conn, merchant_id)
    if current["status"] != "active":
        raise PermissionDenied("LISTINGS_ENTITLEMENT_SUSPENDED")
    if existing_state != "ACTIVE" and current["active_used"] >= current["active_limit"]:
        raise PermissionDenied("LISTINGS_CAPACITY_EXCEEDED: no active listing slots remain")


def set_plan_limit(conn: sqlite3.Connection, plan_code: str, active_limit: int, *, actor: str) -> None:
    if not plan_code or active_limit < 0:
        raise ValidationError("plan code and nonnegative active limit are required")
    if conn.execute("select 1 from listing_plans where plan_code=?", (plan_code,)).fetchone() is None:
        raise NotFoundError("unknown listing plan")
    now = now_iso()
    conn.execute("update listing_plans set active_limit=?,updated_at=? where plan_code=?",
                 (active_limit, now, plan_code))
    _audit(conn, "", actor, "plan_limit_changed", {"plan_code": plan_code, "active_limit": active_limit})


def set_merchant_entitlement(
    conn: sqlite3.Connection, merchant_id: str, *, actor: str,
    plan_code: str | None = None, limit_override: int | None = None,
    status: str | None = None, clear_override: bool = False,
) -> dict[str, Any]:
    if status is not None and status not in ("active", "suspended"):
        raise ValidationError("listing entitlement status must be active or suspended")
    if limit_override is not None and limit_override < 0:
        raise ValidationError("listing limit override must be nonnegative")
    if conn.execute("select 1 from merchants where id=?", (merchant_id,)).fetchone() is None:
        raise NotFoundError("unknown merchant")
    ensure_free_entitlement(conn, merchant_id)
    if plan_code is not None:
        if conn.execute("select 1 from listing_plans where plan_code=?", (plan_code,)).fetchone() is None:
            raise NotFoundError("unknown listing plan")
        conn.execute("update merchant_listing_entitlements set plan_code=? where merchant_id=?",
                     (plan_code, merchant_id))
    if clear_override:
        conn.execute("update merchant_listing_entitlements set limit_override=null where merchant_id=?", (merchant_id,))
    elif limit_override is not None:
        conn.execute("update merchant_listing_entitlements set limit_override=? where merchant_id=?",
                     (limit_override, merchant_id))
    if status is not None:
        conn.execute("update merchant_listing_entitlements set status=? where merchant_id=?", (status, merchant_id))
    conn.execute("update merchant_listing_entitlements set updated_at=? where merchant_id=?",
                 (now_iso(), merchant_id))
    result = capacity(conn, merchant_id)
    _audit(conn, merchant_id, actor, "merchant_entitlement_changed", result)
    return result


def _audit(conn: sqlite3.Connection, merchant_id: str, actor: str, action: str, detail: dict[str, Any]) -> None:
    conn.execute("""insert into listing_entitlement_audit
        (merchant_id,actor,action,detail_json,created_at) values (?,?,?,?,?)""",
        (merchant_id, actor, action, json.dumps(detail, sort_keys=True), now_iso()))
