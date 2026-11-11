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

"""公开的交易平台规则（商家导入/链接生成读取，不暴露运营字段）。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kiwi_catalog.db.session import db_session
from kiwi_catalog.services import trade_platforms


def list_marketplace_platforms(
    db_path: str | Path, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/marketplace-platforms — enabled rules for merchant import."""
    del payload, query
    with db_session(db_path) as conn:
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
