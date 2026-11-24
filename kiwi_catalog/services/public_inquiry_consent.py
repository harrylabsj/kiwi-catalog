"""Binding-scoped policy and routing for open inquiries.

These helpers do not authenticate callers and are not registered as routes.
Only an owner-authenticated, binding-signed handler may call grant/revoke.
Existing directory-custody consent does not grant public-inquiry consent.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from urllib.parse import urlsplit

from kiwi_catalog.core.errors import NotFoundError, ValidationError
from kiwi_catalog.db.session import now_iso
from kiwi_catalog.services import buyer_access, runtime_access

TERMS_VERSION = "open-inquiry-v1"


def _current_binding(conn: sqlite3.Connection, agent_id: str, merchant_id: str, binding_id: str) -> sqlite3.Row | None:
    row = conn.execute(
        "select b.expires_at,b.runtime_origin,b.a2a_endpoint from runtime_bindings b "
        "join catalog_agents a on a.catalog_agent_id=b.catalog_agent_id "
        "where b.catalog_agent_id=? and b.merchant_id=? and b.binding_id=? "
        "and b.status='active' and a.merchant_id=? and a.administrative_state='active' "
        "and a.lifecycle_status='active' and a.freshness_state!='unreachable'",
        (agent_id, merchant_id, binding_id, merchant_id),
    ).fetchone()
    if row is None:
        return None
    expires = str(row[0] or "")
    if not expires:
        return row
    try:
        when = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        return row if when.tzinfo is not None and when > datetime.now(timezone.utc) else None
    except ValueError:
        return None


def _is_workbuddy(binding: sqlite3.Row) -> bool:
    try:
        origin = urlsplit(str(binding["runtime_origin"]))
    except ValueError:
        return False
    return (
        origin.scheme == "https"
        and origin.username is None
        and (origin.hostname or "").endswith(".app.workbuddy.host")
    )


def grant(conn: sqlite3.Connection, *, agent_id: str, merchant_id: str,
          binding_id: str, terms_version: str) -> None:
    """Grant only after the handler verifies the current owner and binding signature."""
    if terms_version != TERMS_VERSION:
        raise ValidationError("explicit current public-inquiry terms are required")
    binding = _current_binding(conn, agent_id, merchant_id, binding_id)
    if binding is None:
        raise NotFoundError("active merchant binding not found")
    if not _is_workbuddy(binding) and _active_custody(conn, agent_id) is None:
        raise ValidationError("active WorkBuddy custody consent and access are required")
    conn.execute(
        "insert into public_inquiry_consents "
        "(catalog_agent_id,merchant_id,binding_id,terms_version,granted_at,revoked_at) "
        "values (?,?,?,?,?,'') on conflict(catalog_agent_id) do update set "
        "merchant_id=excluded.merchant_id,binding_id=excluded.binding_id,"
        "terms_version=excluded.terms_version,granted_at=excluded.granted_at,revoked_at=''",
        (agent_id, merchant_id, binding_id, TERMS_VERSION, now_iso()),
    )


def revoke(conn: sqlite3.Connection, *, agent_id: str, merchant_id: str, binding_id: str) -> None:
    """Revoke after owner authentication, including after binding expiration.

    No row for this binding means the target state (not granted) already holds:
    keep revoke idempotent so the console's "open status, then close" flow does
    not fail with 404.  Enforcement still re-checks binding/custody/publication
    in :func:`enabled` and stays fail-closed.
    """
    row = conn.execute("select 1 from public_inquiry_consents where catalog_agent_id=? "
                       "and merchant_id=? and binding_id=?", (agent_id, merchant_id, binding_id)).fetchone()
    if row is None:
        return
    conn.execute("update public_inquiry_consents set revoked_at=? "
                 "where catalog_agent_id=? and merchant_id=? and binding_id=? and revoked_at=''",
                 (now_iso(), agent_id, merchant_id, binding_id))


def _active_custody(conn: sqlite3.Connection, agent_id: str) -> sqlite3.Row | None:
    if not runtime_access.custody_enabled() or runtime_access.active_consent(conn, agent_id) is None:
        return None
    return runtime_access.active_runtime_access(conn, agent_id)


def relay_route(conn: sqlite3.Connection, agent_id: str) -> tuple[str, sqlite3.Row | None] | None:
    """Resolve the current published binding and optional gateway configuration."""
    row = conn.execute(
        "select merchant_id,binding_id,terms_version,revoked_at from public_inquiry_consents "
        "where catalog_agent_id=?", (agent_id,),
    ).fetchone()
    if row is None or row[2] != TERMS_VERSION or row[3]:
        return None
    binding = _current_binding(conn, agent_id, str(row[0]), str(row[1]))
    if binding is None:
        return None
    publication = conn.execute(
        "select publication_state from card_publications where catalog_agent_id=?", (agent_id,),
    ).fetchone()
    endpoint = str(binding["a2a_endpoint"])
    if publication is None or publication[0] != "ACTIVE" or endpoint != str(binding["runtime_origin"]).rstrip("/") + "/a2a":
        return None

    if _is_workbuddy(binding):
        route = buyer_access.route_row(conn, agent_id)
        if route is not None and (route["binding_id"] != row[1] or route["merchant_id"] != row[0]):
            return None
        mode = str(route["mode"]) if route is not None else "auto"
        if mode == "no_share_code":
            return endpoint, None
        # Auto mode respects previous share-code use, including revocation or expiry.
        if mode == "auto" and runtime_access.latest_runtime_access(conn, agent_id) is None:
            return endpoint, None

    config = _active_custody(conn, agent_id)
    return (endpoint, config) if config is not None else None


def enabled(conn: sqlite3.Connection, agent_id: str) -> bool:
    return relay_route(conn, agent_id) is not None


def code_free_inquiry_bindings(
    conn: sqlite3.Connection, bindings: dict[str, sqlite3.Row],
) -> set[str]:
    """Batch the directory's auto-route projection for WorkBuddy without a gate credential."""
    candidates = {agent_id: binding for agent_id, binding in bindings.items() if _is_workbuddy(binding)}
    if not candidates:
        return set()
    placeholders = ",".join("?" for _ in candidates)
    rows = conn.execute(
        "select c.catalog_agent_id,c.binding_id,c.merchant_id from public_inquiry_consents c"
        " join card_publications p on p.catalog_agent_id=c.catalog_agent_id"
        " join catalog_agents a on a.catalog_agent_id=c.catalog_agent_id and a.merchant_id=c.merchant_id"
        " where c.terms_version=? and c.revoked_at='' and p.publication_state='ACTIVE'"
        " and a.administrative_state='active' and a.lifecycle_status='active' and a.freshness_state!='unreachable'"
        " and not exists (select 1 from runtime_access_configs r where r.catalog_agent_id=c.catalog_agent_id)"
        f" and c.catalog_agent_id in ({placeholders})",
        (TERMS_VERSION, *candidates),
    )
    return {
        str(row["catalog_agent_id"]) for row in rows
        if row["binding_id"] == candidates[row["catalog_agent_id"]]["binding_id"]
        and row["merchant_id"] == candidates[row["catalog_agent_id"]]["merchant_id"]
    }
