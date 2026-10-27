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

"""买家关注 API handlers（M4 拉取式订阅，docs/accounts.md §follows）。

4 条路由：follow（PUT，显式关注，幂等）/ unfollow（DELETE，取消）/
list（GET 我的关注）/ updates（GET 主动拉取增量更新）。全部**会话认证**
（cookie kiwi_session 或 kiwi_session 字段，与 merchant_publications 同一
机制）：buyer_subject 一律取自服务端会话（``account:{account_id}`` 不透明
字符串），不信客户端传值。关注/取消按买家限流；操作本身落 audit_events
（系统审计可见，商家侧只有匿名汇总数字，永远拿不到买家身份）。
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from kiwi_catalog.agent_catalog.sqlite_repository import append_catalog_audit
from kiwi_catalog.core.errors import (
    AuthError,
    NotFoundError,
    PermissionDenied,
    ValidationError,
)
from kiwi_catalog.db.session import db_session
from kiwi_catalog.services import accounts as accounts_service
from kiwi_catalog.services import buyer_follows as follows_service
from kiwi_catalog.services import runtime_access as runtime_access_service
from kiwi_catalog.services.rate_limit import SQLiteRateLimitBackend, enforce_rate_limit

_FOLLOW_RATE_LIMIT_PER_15MIN_ENV = "KIWI_CATALOG_FOLLOW_RATE_LIMIT_PER_15MIN"


def _follow_rate_limit_per_15min() -> int:
    raw = os.environ.get(_FOLLOW_RATE_LIMIT_PER_15MIN_ENV) or ""
    try:
        return max(0, int(raw))
    except ValueError:
        return 60


def _session_token(payload: dict[str, Any]) -> str:
    """从请求取会话 token：cookie 优先（页面），kiwi_session 字段备选。"""
    cookie = accounts_service.session_token_from_cookie(str(payload.get("_cookie") or ""))
    return cookie or str(payload.get("kiwi_session") or "")


def _require_buyer(conn: Any, payload: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """会话 → (账号, buyer_subject)；无效/过期抛 AuthError。

    任何已登录账号都可以作为买家关注商家；buyer_subject 取账号稳定标识
    （不透明字符串，未来可换 WorkBuddy open_id）。
    """
    session_token = _session_token(payload)
    if not session_token:
        raise AuthError("login required")
    account = accounts_service.resolve_session(conn, session_token)
    if account is None:
        raise AuthError("session expired or invalid")
    return account, follows_service.buyer_subject_for_account(account)


def _enforce_follow_rate_limit(conn: Any, buyer_subject: str) -> None:
    """关注/取消按买家限流（复用 merchant_application_limits 表，15min 窗口）。"""
    limit = _follow_rate_limit_per_15min()
    if limit <= 0:
        return
    backend = SQLiteRateLimitBackend(
        conn, table="merchant_application_limits", key_column="actor_key"
    )
    enforce_rate_limit(
        backend,
        key=f"follow:{buyer_subject}",
        limit=limit,
        window_seconds=900,
        description=f"buyer follow write ({limit}/15min per buyer)",
    )


def _validated_merchant_id(raw: Any) -> str:
    merchant_id = str(raw or "").strip()
    if not merchant_id:
        raise ValidationError("merchant_id is required")
    return merchant_id


def follow_merchant(
    db_path: str | Path, merchant_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """PUT /v1/me/follows/{merchant_id}（会话）——显式关注（幂等）。

    重复关注不产生重复记录（可更新 category/consent_version）；首次关注水位
    从关注时刻起（不补历史），取消后重新关注水位重置。仅显式调用本端点
    构成订阅——搜索/浏览/询价不产生关注行。
    """
    merchant_id = _validated_merchant_id(merchant_id)
    with db_session(db_path) as conn:
        account, buyer_subject = _require_buyer(conn, payload)
        if not follows_service.merchant_exists(conn, merchant_id):
            raise NotFoundError(f"Unknown merchant: {merchant_id}")
        category, consent_version = follows_service.validate_follow_fields(payload)
        _enforce_follow_rate_limit(conn, buyer_subject)
        row, created, reactivated = follows_service.follow_merchant(
            conn,
            buyer_subject=buyer_subject,
            merchant_id=merchant_id,
            category=category,
            consent_version=consent_version,
        )
        append_catalog_audit(
            conn,
            "",
            f"account:{account.get('account_id')}",
            "buyer_followed",
            {
                "merchant_id": merchant_id,
                "category": category,
                "created": created,
                "reactivated": reactivated,
            },
        )
        return {
            "ok": True,
            "follow": follows_service.follow_view(conn, row),
            "created": created,
        }


def unfollow_merchant(
    db_path: str | Path, merchant_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """DELETE /v1/me/follows/{merchant_id}（会话）——取消关注（幂等）。

    状态置 cancelled：取消后不再出现在 updates 与关注列表里；商家匿名汇总
    数字随之减一。无活跃关注时同样返回 ok（幂等删除语义）。
    """
    merchant_id = _validated_merchant_id(merchant_id)
    with db_session(db_path) as conn:
        account, buyer_subject = _require_buyer(conn, payload)
        _enforce_follow_rate_limit(conn, buyer_subject)
        cancelled = follows_service.unfollow_merchant(
            conn, buyer_subject=buyer_subject, merchant_id=merchant_id
        )
        if cancelled:
            append_catalog_audit(
                conn,
                "",
                f"account:{account.get('account_id')}",
                "buyer_unfollowed",
                {"merchant_id": merchant_id},
            )
        return {"ok": True, "merchant_id": merchant_id, "following": False}


def list_my_follows(db_path: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    """GET /v1/me/follows（会话）——我的活跃关注列表（买家管理面）。"""
    with db_session(db_path) as conn:
        _, buyer_subject = _require_buyer(conn, payload)
        return {
            "ok": True,
            "follows": follows_service.list_follows(conn, buyer_subject=buyer_subject),
        }


def follow_updates(db_path: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    """GET /v1/me/follows/updates（会话）——仅响应买家主动查询的增量拉取。

    按各活跃关注的 last_seen_at 返回商家已批准公开的事件（拉取式订阅，无
    推送通道）；返回后推进水位（返回什么再推进，不丢不重）。不含商家内部
    信息——事件 payload 即 M0 公开投影。
    """
    with db_session(db_path) as conn:
        _, buyer_subject = _require_buyer(conn, payload)
        return {
            "ok": True,
            "updates": follows_service.fetch_updates(conn, buyer_subject=buyer_subject),
        }


_MERCHANT_ACCESS_RATE_LIMIT_ENV = "KIWI_CATALOG_MERCHANT_ACCESS_RATE_LIMIT_PER_15MIN"


def _merchant_access_rate_limit_per_15min() -> int:
    raw = os.environ.get(_MERCHANT_ACCESS_RATE_LIMIT_ENV) or ""
    try:
        return max(0, int(raw))
    except ValueError:
        return 60


def _enforce_merchant_access_rate_limit(conn: Any, buyer_subject: str) -> None:
    """受控凭据分发按买家限流（复用 merchant_application_limits 表）。

    每次发放都做一次解密，且是可以在外部分发的凭据——限流既防刷也限住
    审计与解密的放大面。``0`` 表示关闭（沿用既有数值约定）。
    """
    limit = _merchant_access_rate_limit_per_15min()
    if limit <= 0:
        return
    backend = SQLiteRateLimitBackend(
        conn, table="merchant_application_limits", key_column="actor_key"
    )
    enforce_rate_limit(
        backend,
        key=f"merchant-access:{buyer_subject}",
        limit=limit,
        window_seconds=900,
        description=f"merchant access distribution ({limit}/15min per buyer)",
    )


def get_merchant_access(
    db_path: str | Path, catalog_agent_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/me/merchant-access/{catalog_agent_id}（会话 + 活跃关注；C-05）。

    受控分享配置分发：仅已登录且**活跃关注**目标商家的 Buyer 可获取当前
    active 版本（含 secret_value）；无会话/未关注 403（平台全局映射，见
    G1 §2.4 偏差）、商家不存在或未 active、绑定/配置缺失统一 404（防枚举）。
    响应标记 no-store——配置交付后即可被持有或再传播，不提供业务权限隔离
    （G1 契约 §1.2/§2.4）。成功发放留审计（商家、配置版本、脱敏主体），
    日志、审计与响应元数据均不含秘密。
    """
    agent_id = str(catalog_agent_id or "").strip()
    # tx1：认证 + 限流计数**独立提交**。``db_session`` 只在成功时提交，若把计数
    # 放进后续查找的同一事务，403/404 拒绝会把它回滚——探测型滥用反而完全不受限。
    with db_session(db_path) as conn:
        account, buyer_subject = _require_buyer(conn, payload)
        _enforce_merchant_access_rate_limit(conn, buyer_subject)
    with db_session(db_path) as conn:
        agent = conn.execute(
            "select catalog_agent_id, merchant_id, administrative_state"
            " from catalog_agents where catalog_agent_id = ?",
            (agent_id,),
        ).fetchone()
        # 行政处置（suspended/rejected）与不存在同口径 404：被处置的商家不得
        # 继续向 Buyer 发放平台门禁凭据。
        if (
            agent is None
            or not str(agent["merchant_id"] or "").strip()
            or str(agent["administrative_state"] or "") != "active"
        ):
            raise NotFoundError("catalog agent not found")
        merchant_id = str(agent["merchant_id"])
        follow = follows_service.get_follow(
            conn, buyer_subject=buyer_subject, merchant_id=merchant_id
        )
        if follow is None or str(follow.get("status")) != "active":
            raise PermissionDenied("an active follow of this merchant is required")
        binding = conn.execute(
            "select runtime_origin from runtime_bindings"
            " where catalog_agent_id = ? and status = 'active'"
            " order by binding_version desc limit 1",
            (agent_id,),
        ).fetchone()
        config = runtime_access_service.active_runtime_access(conn, agent_id)
        if binding is None or config is None:
            raise NotFoundError("active runtime access configuration not found")
        result = runtime_access_service.buyer_projection(
            config, runtime_origin=str(binding["runtime_origin"])
        )
        # 发放审计：主体用账户不透明 id（与 buyer_followed 同一约定），不记秘密。
        append_catalog_audit(
            conn,
            catalog_agent_id=agent_id,
            actor=f"account:{account.get('account_id')}",
            event="runtime_access_issued",
            details={
                "merchant_id": merchant_id,
                "config_version": int(result["config_version"]),
                "access_mode": str(result["access_mode"]),
                "adapter_version": str(result["adapter_version"]),
            },
        )
        result["__no_store__"] = True
        return result
