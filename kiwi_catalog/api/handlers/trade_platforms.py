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

"""交易平台规则：公开读取 + 运营（admin token）写入。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kiwi_catalog.api import auth as api_auth
from kiwi_catalog.db.session import db_session
from kiwi_catalog.services import trade_platforms


def list_marketplace_platforms(
    db_path: str | Path, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/marketplace-platforms — enabled rules for merchant import."""
    del query
    with db_session(db_path) as conn:
        from kiwi_catalog.a2a.public_read_limit import enforce_public_read_limit

        enforce_public_read_limit(conn, payload, surface="marketplace platforms")
        rows = trade_platforms.list_platforms(conn, enabled_only=True)
    return {
        "ok": True,
        "platforms": [
            {
                "id": row["id"],
                "label": row["label"],
                "domain": row["domain"],
                "url_template": row["url_template"],
                "sort_order": row["sort_order"],
            }
            for row in rows
        ],
    }


def list_marketplace_platforms_for_admin(
    db_path: str | Path, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/marketplace-platforms/admin — 运营视图（含 disabled 与审计字段）。"""
    del query
    with db_session(db_path) as conn:
        api_auth.require_admin_token(payload, conn)
        rows = trade_platforms.list_platforms(conn)
    return {"ok": True, "platforms": rows}


def create_marketplace_platform(
    db_path: str | Path, payload: dict[str, Any]
) -> dict[str, Any]:
    """POST /v1/marketplace-platforms — 新增平台规则（admin only）。"""
    with db_session(db_path) as conn:
        api_auth.require_admin_token(payload, conn)
        created = trade_platforms.create_platform(conn, payload)
    return {"ok": True, "platform": created}


def update_marketplace_platform(
    db_path: str | Path, platform_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """PUT /v1/marketplace-platforms/{platform_id} — 更新平台规则（admin only）。"""
    with db_session(db_path) as conn:
        api_auth.require_admin_token(payload, conn)
        updated = trade_platforms.update_platform(conn, str(platform_id), payload)
    return {"ok": True, "platform": updated}


def delete_marketplace_platform(
    db_path: str | Path, platform_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """DELETE /v1/marketplace-platforms/{platform_id} — 删除平台规则（admin only）。"""
    with db_session(db_path) as conn:
        api_auth.require_admin_token(payload, conn)
        trade_platforms.delete_platform(conn, str(platform_id))
    return {"ok": True, "deleted": str(platform_id)}
