"""Separate, binding-scoped consent for open inquiries.

These helpers do not authenticate callers and are not registered as routes.
Only an owner-authenticated, binding-signed handler may call grant/revoke.
Existing directory-custody consent does not grant public-inquiry consent.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from kiwi_catalog.core.errors import NotFoundError, ValidationError
from kiwi_catalog.db.session import now_iso

TERMS_VERSION = "open-inquiry-v1"


def _current_binding(conn: sqlite3.Connection, agent_id: str, merchant_id: str, binding_id: str) -> bool:
    row = conn.execute(
        "select b.expires_at from runtime_bindings b "
        "join catalog_agents a on a.catalog_agent_id=b.catalog_agent_id "
        "where b.catalog_agent_id=? and b.merchant_id=? and b.binding_id=? "
        "and b.status='active' and a.merchant_id=? and a.administrative_state='active' "
        "and a.lifecycle_status='active' and a.freshness_state!='unreachable'",
        (agent_id, merchant_id, binding_id, merchant_id),
    ).fetchone()
    if row is None:
        return False
    expires = str(row[0] or "")
    if not expires:
        return True
    try:
        when = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        return when.tzinfo is not None and when > datetime.now(timezone.utc)
    except ValueError:
        return False


def grant(conn: sqlite3.Connection, *, agent_id: str, merchant_id: str,
          binding_id: str, terms_version: str) -> None:
    """Grant only after the handler verifies the current owner and binding signature."""
    if terms_version != TERMS_VERSION:
        raise ValidationError("explicit current public-inquiry terms are required")
    if not _current_binding(conn, agent_id, merchant_id, binding_id):
        raise NotFoundError("active merchant binding not found")
    from kiwi_catalog.services.runtime_access import active_consent, active_runtime_access, custody_enabled
    if not custody_enabled() or active_consent(conn, agent_id) is None or active_runtime_access(conn, agent_id) is None:
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


def enabled(conn: sqlite3.Connection, agent_id: str) -> bool:
    """Fail closed on revocation, rebinding, expiration, custody or publication changes."""
    row = conn.execute(
        "select merchant_id,binding_id,terms_version,revoked_at from public_inquiry_consents "
        "where catalog_agent_id=?", (agent_id,),
    ).fetchone()
    if row is None or row[2] != TERMS_VERSION or row[3]:
        return False
    if not _current_binding(conn, agent_id, str(row[0]), str(row[1])):
        return False
    from kiwi_catalog.services.runtime_access import active_consent, active_runtime_access, custody_enabled
    if not custody_enabled() or active_consent(conn, agent_id) is None or active_runtime_access(conn, agent_id) is None:
        return False
    publication = conn.execute(
        "select publication_state from card_publications where catalog_agent_id=?", (agent_id,),
    ).fetchone()
    return publication is not None and publication[0] == "ACTIVE"
