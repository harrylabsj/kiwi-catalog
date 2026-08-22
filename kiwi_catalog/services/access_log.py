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

"""个体访问日志（运营质量 + 安全审计数据源，v28）。

运营原则修订（2026-08-22）：从「只记次数不记个体日志」改为「记录个体访问
日志用于运营质量与安全审计」。最小必要仍适用：

- **绝不记录凭据本体**：actor_key = SHA-256(身份原文) 截断 12 hex；
  query_summary 剔除 owner_token/token/key/password/code 等凭据参数；
- **身份一律派生**：按端点面派生 buyer/merchant/admin，全无身份 → anonymous；
- **IP 只存截断前缀**：IPv4 /24（最后一段置 0），IPv6 截前 4 段，不存完整 IP；
- **日志有保留期**：env ``KIWI_CATALOG_ACCESS_LOG_RETENTION_DAYS`` 默认
  90 天，写路径每 ``_PRUNE_EVERY_N`` 条概率触发清理（参照 buyer_search_events
  的有界保留风格）。

与 usage_metrics（只记次数）互补：access_log 是原始请求级记录，供运营回溯
单个请求（谁/何时/哪个端点/结果如何）与安全审计。记录失败绝不抛错——访问
日志是旁路，不得影响请求本身。
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from kiwi_catalog.db.session import db_session, now_iso

# ── surface 词表（五分类；运营端以此为单一来源）──────────────────────────────
SURFACE_BUYER_SEARCH = "buyer_search"
SURFACE_BUYER_DETAIL = "buyer_detail"
SURFACE_MERCHANT_WRITE = "merchant_write"
SURFACE_ACCOUNT_PORTAL = "account_portal"
SURFACE_ADMIN = "admin"

ALL_SURFACES = (
    SURFACE_BUYER_SEARCH,
    SURFACE_BUYER_DETAIL,
    SURFACE_MERCHANT_WRITE,
    SURFACE_ACCOUNT_PORTAL,
    SURFACE_ADMIN,
)

# ── actor_kind 词表 ─────────────────────────────────────────────────────────
ACTOR_ANONYMOUS = "anonymous"
ACTOR_BUYER = "buyer"
ACTOR_MERCHANT = "merchant"
ACTOR_ADMIN = "admin"

ALL_ACTOR_KINDS = (
    ACTOR_ANONYMOUS,
    ACTOR_BUYER,
    ACTOR_MERCHANT,
    ACTOR_ADMIN,
)

# 搜索面路径集合（买家搜索三类：新 /v1 + legacy /v1/agent-catalog）
_SEARCH_PATHS = frozenset(
    {
        "/v1/agents/search",
        "/v1/listings/search",
        "/v1/agent-catalog/agents/search",
    }
)

# 详情面路径：买家读详情（/v1/agents/{id}、/v1/listings/{id}、hosted card/ucp、
# legacy agent detail）。静态动作段（search/register/publish…）由
# _STATIC_SEGMENTS 排除，避免 /v1/agents/search 被当作 {id}。
_DETAIL_RE = re.compile(
    r"^/v1/agents/([^/]+)$"
    r"|^/v1/listings/([^/]+)$"
    r"|^/v1/agent-catalog/agents/([^/]+)$"
    r"|^/v1/hosted/agents/[^/]+/(?:agent-card\.json|ucp)$"
)

# 路径中的静态动作段——不算 target_id / 详情资源 id
_STATIC_SEGMENTS = frozenset(
    {
        "search",
        "register",
        "refresh",
        "verify",
        "claim",
        "suspend",
        "reinstate",
        "publish",
        "withdraw",
        "self",
        "applications",
        "approve",
        "reject",
    }
)

# target_id 提取：路径里的 {listing_id}/{catalog_agent_id}/{merchant_id}
_TARGET_ID_RE = re.compile(
    r"^/(?:"
    r"v1/agents|v1/agent-catalog/agents|v1/hosted/agents"
    r"|v1/listings|v1/merchants|v1/admin/merchants"
    r")/([^/]+)"
)

_QUERY_SUMMARY_CAP = 500
_USER_AGENT_CAP = 256
_ACTOR_KEY_HEX_LEN = 12
_PATH_CAP = 512
_METHOD_CAP = 16

_RETENTION_DAYS_ENV = "KIWI_CATALOG_ACCESS_LOG_RETENTION_DAYS"
_DEFAULT_RETENTION_DAYS = 90
_MAX_RETENTION_DAYS = 3650
# 写路径概率清理：每 _PRUNE_EVERY_N 条访问日志触发一次 prune（lastrowid 模，
# 无状态、确定；参照 buyer_search_events 的有界保留风格）。
_PRUNE_EVERY_N = 50

# 凭据类 query 参数名子串（大小写不敏感）——query_summary 一律剔除
_CREDENTIAL_PARAM_SUBSTRINGS = (
    "token",
    "password",
    "passwd",
    "secret",
    "key",
    "code",
    "auth",
)


def classify_surface(method: str, path: str) -> str | None:
    """surface 五分类；``/health`` 不记录返回 None。

    - ``buyer_search``：三个搜索端点（/v1/agents/search、/v1/listings/search、
      legacy /v1/agent-catalog/agents/search）；
    - ``buyer_detail``：买家读详情（/v1/agents/{id}、/v1/listings/{id}、
      /v1/hosted/agents/{id}/agent-card.json、/v1/hosted/agents/{id}/ucp 等）；
    - ``merchant_write``：其余商家写操作 POST /v1/*（含商家读端点自查——
      /v1/merchants/self 等归入商家面）；
    - ``account_portal``：账号体系 /v1/accounts/* 与门户 HTML 页 /portal/*；
    - ``admin``：运营后台 /v1/admin/*、/portal/admin*、/portal/dashboard。
    """
    path = str(path or "").split("?", 1)[0]
    if path == "/health":
        return None
    if (
        path.startswith("/v1/admin/")
        or path.startswith("/portal/admin")
        or path.startswith("/portal/dashboard")
    ):
        return SURFACE_ADMIN
    if path.startswith("/v1/accounts/") or path == "/portal" or path.startswith("/portal/"):
        return SURFACE_ACCOUNT_PORTAL
    if path in _SEARCH_PATHS:
        return SURFACE_BUYER_SEARCH
    if _is_buyer_detail_path(path):
        return SURFACE_BUYER_DETAIL
    if method in ("POST", "PUT", "PATCH", "DELETE") and path.startswith("/v1/"):
        return SURFACE_MERCHANT_WRITE
    if path.startswith("/v1/"):
        # 其余 /v1/* 读端点：agent/listing/hosted 目录读归 buyer_detail，
        # 商家面读端点（/v1/merchants/*）归 merchant_write。
        if path.startswith(("/v1/agents", "/v1/listings", "/v1/hosted", "/v1/agent-catalog")):
            return SURFACE_BUYER_DETAIL
        return SURFACE_MERCHANT_WRITE
    return None


def _is_buyer_detail_path(path: str) -> bool:
    match = _DETAIL_RE.match(path)
    if not match:
        return False
    groups = [group for group in match.groups() if group]
    return not any(group in _STATIC_SEGMENTS for group in groups)


def derive_actor(surface: str, has_identity: bool) -> str:
    """按端点面派生 actor_kind；全无身份 → anonymous。

    带身份时：管理员端点 → admin；商家写端点 / 账号门户面 → merchant；
    搜索 / 详情面 → buyer。
    """
    if not has_identity:
        return ACTOR_ANONYMOUS
    if surface == SURFACE_ADMIN:
        return ACTOR_ADMIN
    if surface in (SURFACE_MERCHANT_WRITE, SURFACE_ACCOUNT_PORTAL):
        return ACTOR_MERCHANT
    return ACTOR_BUYER  # buyer_search / buyer_detail


def _has_identity(headers: dict[str, str]) -> bool:
    """请求是否带身份（Authorization Bearer 或 X-Buyer-Id）。"""
    authorization = str(headers.get("authorization") or "")
    if authorization.lower().startswith("bearer "):
        return True
    return bool(str(headers.get("x-buyer-id") or "").strip())


def _identity_value(headers: dict[str, str]) -> str:
    """身份原文（Bearer token 或 X-Buyer-Id）；只用于派生 hash，绝不落库。"""
    authorization = str(headers.get("authorization") or "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return str(headers.get("x-buyer-id") or "").strip()


def _actor_key(headers: dict[str, str]) -> str:
    """actor_key = SHA-256(身份原文) 前 12 位 hex；无身份 → 空串。"""
    identity = _identity_value(headers)
    if not identity:
        return ""
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:_ACTOR_KEY_HEX_LEN]


def _ip_prefix(ip: str) -> str:
    """IP 截断前缀：IPv4 /24（最后一段置 0），IPv6 截前 4 段；不存完整 IP。

    非 IP（域名 / 坏值）→ 空串——前缀必须是可信的截断结果。IPv4-mapped
    IPv6（::ffff:a.b.c.d）先转回 IPv4 再截断。
    """
    ip = (ip or "").strip()
    if not ip:
        return ""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    if isinstance(addr, ipaddress.IPv6Address):
        mapped = addr.ipv4_mapped
        if mapped is not None:
            addr = mapped
        else:
            return ":".join(addr.exploded.split(":")[:4])
    return ".".join(str(addr).split(".")[:3] + ["0"])


def _is_credential_param(name: str) -> bool:
    lowered = name.lower()
    return any(token in lowered for token in _CREDENTIAL_PARAM_SUBSTRINGS)


def build_query_summary(surface: str, query: dict[str, Any] | None) -> str:
    """搜索面的 q + 筛选键值（JSON，截断 500 字符）；其他面为空串。

    凭据参数（owner_token/token/key/password/code 等）一律剔除——绝不把
    凭据写进访问日志。产物保证是合法 JSON（P2-06 教训：不在字符串/结构
    中间切断）。
    """
    if surface != SURFACE_BUYER_SEARCH:
        return ""
    query = query or {}
    q = str(query.get("q") or "")
    filters = {
        str(key): str(value)
        for key, value in query.items()
        if key != "q" and not _is_credential_param(str(key))
    }
    summary: dict[str, Any] = {"q": q}
    if filters:
        summary["filters"] = filters
    return _bounded_query_summary(summary)


def _bounded_query_summary(summary: dict[str, Any]) -> str:
    """序列化并截断到 ≤500 字符，保证产物是合法 JSON。"""
    encoded = json.dumps(summary, ensure_ascii=False)
    if len(encoded) <= _QUERY_SUMMARY_CAP:
        return encoded
    budget = _QUERY_SUMMARY_CAP
    while budget > 32:
        shrunken = _shrink_query_summary(summary, budget)
        encoded = json.dumps(shrunken, ensure_ascii=False)
        if len(encoded) <= _QUERY_SUMMARY_CAP:
            return encoded
        budget //= 2
    # 病理输入兜底：极端长仍放不下 → 空对象（合法 JSON）。
    return "{}"


def _shrink_query_summary(summary: dict[str, Any], budget: int) -> dict[str, Any]:
    """按 *budget* 收缩 query 摘要（只缩短字符串 / 截断容器宽度，保持合法 JSON）。"""
    out: dict[str, Any] = {"q": str(summary.get("q") or "")[: max(0, budget - 8)]}
    filters = summary.get("filters")
    if isinstance(filters, dict):
        kept: dict[str, Any] = {}
        for i, (key, value) in enumerate(filters.items()):
            if i >= max(1, budget // 16):
                break
            kept[str(key)[: max(0, budget // 4)]] = str(value)[: max(0, budget // 4)]
        if kept:
            out["filters"] = kept
    return out


def extract_target_id(path: str) -> str:
    """路径里的 {listing_id}/{catalog_agent_id}/{merchant_id}（首个资源 id 段）。"""
    path = str(path or "").split("?", 1)[0]
    match = _TARGET_ID_RE.match(path)
    if not match:
        return ""
    candidate = match.group(1)
    if candidate in _STATIC_SEGMENTS:
        return ""
    return candidate


def result_count_from_body(body: bytes) -> int | None:
    """从响应 JSON 提取 result_count（len(results)）；非 JSON / 无 results → None。"""
    if not body:
        return None
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if isinstance(data, dict):
        results = data.get("results")
        if isinstance(results, list):
            return len(results)
    return None


def retention_days() -> int:
    """保留期：env ``KIWI_CATALOG_ACCESS_LOG_RETENTION_DAYS`` 默认 90。"""
    raw = str(os.environ.get(_RETENTION_DAYS_ENV) or "").strip()
    if not raw:
        return _DEFAULT_RETENTION_DAYS
    try:
        days = int(raw)
    except (TypeError, ValueError):
        return _DEFAULT_RETENTION_DAYS
    if days <= 0:
        return _DEFAULT_RETENTION_DAYS
    return days


def prune_access_log(
    conn: sqlite3.Connection, retention: int | None = None
) -> None:
    """删除超期行（*retention* 缺省取 env，默认 90 天）。失败绝不抛错。"""
    try:
        days = retention if retention is not None else retention_days()
        days = max(1, min(int(days), _MAX_RETENTION_DAYS))
        cutoff = (datetime.now(UTC) - timedelta(days=days)).replace(microsecond=0).isoformat()
        conn.execute("delete from access_log where occurred_at < ?", (cutoff,))
    except Exception:
        return


def record_access(
    conn: sqlite3.Connection,
    *,
    method: str,
    path: str,
    surface: str,
    actor_kind: str,
    actor_key: str = "",
    ip_prefix: str = "",
    user_agent: str = "",
    query_summary: str = "",
    target_id: str = "",
    status: int | None = None,
    result_count: int | None = None,
    latency_ms: int | None = None,
    occurred_at: str | None = None,
) -> None:
    """写一条访问日志（单行）。失败绝不抛错——访问日志是旁路，不影响请求。

    插入后按 lastrowid 模 ``_PRUNE_EVERY_N`` 概率触发有界清理（写路径
    触发，参照 buyer_search_events 的有界保留风格）。
    """
    try:
        rowid = conn.execute(
            "insert into access_log"
            " (occurred_at, method, path, surface, actor_kind, actor_key, ip_prefix,"
            "  user_agent, query_summary, target_id, status, result_count, latency_ms)"
            " values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                occurred_at or now_iso(),
                str(method or "")[:_METHOD_CAP],
                str(path or "")[:_PATH_CAP],
                str(surface or ""),
                str(actor_kind or ""),
                str(actor_key or ""),
                str(ip_prefix or ""),
                str(user_agent or "")[:_USER_AGENT_CAP],
                str(query_summary or ""),
                str(target_id or ""),
                int(status) if status is not None else None,
                int(result_count) if result_count is not None else None,
                int(latency_ms) if latency_ms is not None else None,
            ),
        ).lastrowid
        if rowid and rowid % _PRUNE_EVERY_N == 0:
            prune_access_log(conn)
    except Exception:
        return


def record_http_access(
    db_path: str | Path,
    *,
    method: str,
    path: str,
    query: dict[str, Any] | None,
    headers: dict[str, str],
    client_ip: str | None,
    status: int | None,
    latency_ms: int | None,
    result_count: int | None = None,
) -> None:
    """ASGI 中间件入口：字段提取 + 落库。失败绝不抛错，不影响请求。

    *headers* 为小写键 dict（fallback / FastAPI 双栈各自构造）；字段提取
    （surface/actor/IP 前缀/query 摘要/target_id）全部在本服务内完成。
    *path* 允许带 query string——落库前剥离（防凭据随路径泄漏，查询参数
    只进 query_summary 且已脱敏）。
    """
    try:
        path = str(path or "").split("?", 1)[0]
        surface = classify_surface(method, path)
        if surface is None:
            return  # /health 等不记录
        has_identity = _has_identity(headers)
        actor_kind = derive_actor(surface, has_identity)
        actor_key = _actor_key(headers)
        ip_prefix = _ip_prefix(client_ip or "")
        user_agent = str(headers.get("user-agent") or "")
        query_summary = build_query_summary(surface, query)
        target_id = extract_target_id(path)
        with db_session(db_path) as conn:
            record_access(
                conn,
                method=method,
                path=path,
                surface=surface,
                actor_kind=actor_kind,
                actor_key=actor_key,
                ip_prefix=ip_prefix,
                user_agent=user_agent,
                query_summary=query_summary,
                target_id=target_id,
                status=status,
                result_count=result_count,
                latency_ms=latency_ms,
            )
    except Exception:
        return  # 防御性：访问日志失败不得影响请求


def list_access_log(
    conn: sqlite3.Connection,
    *,
    surface: str = "",
    days: int = 7,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """最近 *days* 天访问日志（时间倒序），按 surface 可选过滤；limit 上限 500。

    days 上限 90、limit 上限 500（admin 端点参数钳制在 handler 侧再做一次，
    这里钳制是服务层兜底）。返回行不含任何凭据（库里本就不存凭据）。
    """
    days = max(1, min(int(days or 7), 90))
    limit = max(1, min(int(limit or 100), 500))
    cutoff = (datetime.now(UTC) - timedelta(days=days)).replace(microsecond=0).isoformat()
    sql = (
        "select id, occurred_at, method, path, surface, actor_kind, actor_key,"
        " ip_prefix, user_agent, query_summary, target_id, status, result_count,"
        " latency_ms from access_log where occurred_at >= ?"
    )
    params: list[Any] = [cutoff]
    surface = str(surface or "").strip()
    if surface:
        sql += " and surface = ?"
        params.append(surface)
    sql += " order by occurred_at desc, id desc limit ?"
    params.append(limit)
    rows = conn.execute(sql, params).fetchall()
    return [dict(row) for row in rows]
