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

"""Merchant token 自查 API（docs/kiwi-catalog-token-portal-design-v0.1 §4）。

/v1/merchants/self 自查（token 即身份）。申请提交
（POST /v1/merchants/applications）2026-08-12 起为会话鉴权——匿名公开通道
被滥用（假邮箱直接提交工单）关闭，路由指向 accounts handlers 的
token_request（与 /v1/accounts/token-request 同一处理函数），本模块不承载
提交逻辑。

admin 审核/签发端点（applications 列表、approve/reject、token rotate/
revoke）已移至私有扩展 kiwi-catalog-admin（docs/extensions.md）；本地运营
走 CLI（与 services/merchant_tokens.py 直连，见 cli_merchant_commands.py）。

薄封装：admin 校验（fail-closed，无默认 token 未配置即拒绝）+ 响应组织；
核心数据操作在 services/merchant_tokens.py。
明文 token 永不落库、不进审计（审计只记 merchant_id + token_prefix 指纹）。
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from kiwi_catalog.api import auth as api_auth
from kiwi_catalog.core.errors import AuthError
from kiwi_catalog.db.session import db_session
from kiwi_catalog.services import merchant_tokens as tokens_service
from kiwi_catalog.services import usage_metrics


def self_status(
    db_path: str | Path, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/merchants/self?owner_token=…（token 即身份，商家自查）。

    返回 merchant_id、token 状态与名下 agent / listing 计数。owner token
    经 query string（token 即身份的既有语义，CLAUDE.md 记录）；admin 查询
    任意商家时 admin token 只经 Authorization header（KC-SEC-02）。
    """
    merchant_id = str(query.get("merchant_id") or "").strip()
    presented = str(query.get("owner_token") or payload.get("owner_token") or "").strip()
    with db_session(db_path) as conn:
        if merchant_id:
            api_auth.require_admin_token(payload, db_path)
            token_row: sqlite3.Row | None = tokens_service.require_token_row(conn, merchant_id)
        else:
            if not presented:
                raise AuthError("invalid owner token")
            token_row = tokens_service.resolve_merchant_by_token(conn, presented)
            if token_row is None:
                raise AuthError("invalid owner token")
            merchant_id = str(token_row["merchant_id"])
            # 埋点只记商家自查动作（token 即身份的路径），admin 查询不计
            usage_metrics.record_usage(conn, usage_metrics.METRIC_MERCHANT_SELF_CHECK)
        assert token_row is not None  # 两条分支都保证非空（fail-closed）
        status = tokens_service.merchant_status(conn, token_row)
        return {"ok": True, **status}
