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

"""商家公开资料（M0 工作包 A，kiwi 仓 merchant-buddy 第 0 版设计 §4）。

已验证商家账号**会话**（非 owner token）发布的 public-only 声明快照：

- 状态域：draft（私有草稿）→ published（公开可搜）→ withdrawn（撤回，终态）；
- ``source_kind`` 恒为 ``merchant_declared``——商家声明内容，不是 Kiwi 背书；
- public-only 白名单：注册账户的电话/邮箱/凭据绝不进入公开投影；写入侧对
  公开字段做私密字段扫描（明显的邮箱/手机号模式直接拒绝 + 审计）；
- 幂等：同一商家同名商品（merchant_id + lower(title)，非撤回行）重复发布
  是**更新既有行**（版本递增），不产生重复主体；部分唯一索引数据层兜底；
- 不产生虚假能力：无 Agent Card、无 A2A 端点、无实时报价——搜索/详情投影
  恒带 ``inquiry_available=false``（第 1 版商家走既有 Agent/Listing 链路）。
"""

from __future__ import annotations

import ipaddress
import re
import secrets
import sqlite3
import urllib.parse
from datetime import UTC, datetime
from typing import Any

from kiwi_catalog.core.errors import NotFoundError, ValidationError
from kiwi_catalog.db.session import decode_json, encode_json, now_iso
from kiwi_catalog.services import merchant_public_events as events_service

SOURCE_KIND = "merchant_declared"
STATUSES = ("draft", "published", "withdrawn")

# ── 内容长度上限（公开资料是声明快照，不是全文商品库）────────────────────
_MAX_DISPLAY_NAME = 200
_MAX_TITLE = 200
_MAX_CATEGORY = 100
_MAX_PLATFORM = 100
_MAX_SHOP_URL = 500
_MAX_SUMMARY = 2000
_MAX_FAQ_ITEMS = 20
_MAX_FAQ_QUESTION = 300
_MAX_FAQ_ANSWER = 1000

# ── 私密字段扫描（写入侧 fail-closed）────────────────────────────────────
# 至少拒绝明显的邮箱/手机号模式进入公开字段（注册账户的联系方式不得经商家
# 误填进入公开投影）。扫描对象：display_name/title/category/summary/faq。
_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
_CN_MOBILE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
_INTL_PHONE_RE = re.compile(r"\+\d[\d\s\-()]{7,}\d")

_PUBLIC_TEXT_FIELDS = ("merchant_display_name", "title", "category", "summary")


def new_publication_id() -> str:
    return "mpub_" + secrets.token_urlsafe(12)


def scan_private_fields(canonical: dict[str, Any]) -> list[str]:
    """返回命中私密模式的字段名列表（空 = 通过）。"""
    hits: list[str] = []
    texts: list[tuple[str, str]] = [
        (field, str(canonical.get(field) or "")) for field in _PUBLIC_TEXT_FIELDS
    ]
    for i, item in enumerate(canonical.get("faq") or []):
        texts.append((f"faq[{i}].question", str(item.get("question") or "")))
        texts.append((f"faq[{i}].answer", str(item.get("answer") or "")))
    for label, text in texts:
        if _EMAIL_RE.search(text) or _CN_MOBILE_RE.search(text) or _INTL_PHONE_RE.search(text):
            hits.append(label)
    return hits


def validate_shop_url(raw: str) -> str:
    """公开店铺链接安全校验：仅 http/https；拒绝内网/环回/保留地址字面量。

    空串合法（选填）。host 为 IP 字面量时必须全局可路由；域名不解析
    （写路径不做网络 IO）——长度与 scheme/字符集约束兜底。
    """
    url = str(raw or "").strip()
    if not url:
        return ""
    if len(url) > _MAX_SHOP_URL:
        raise ValidationError("shop_url too long")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValidationError("shop_url must be an http or https URL")
    host = parsed.hostname or ""
    if not host:
        raise ValidationError("shop_url must include a host")
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        ip = None
    if ip is not None and not ip.is_global:
        raise ValidationError("shop_url must not point to a private or internal address")
    return url


def _normalize_faq(raw: Any) -> list[dict[str, str]]:
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        raise ValidationError("faq must be a list of {question, answer} items")
    if len(raw) > _MAX_FAQ_ITEMS:
        raise ValidationError(f"faq must have at most {_MAX_FAQ_ITEMS} items")
    items: list[dict[str, str]] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValidationError(f"faq[{i}] must be an object")
        question = str(entry.get("question") or "").strip()
        answer = str(entry.get("answer") or "").strip()
        if not question or not answer:
            raise ValidationError(f"faq[{i}] requires non-empty question and answer")
        if len(question) > _MAX_FAQ_QUESTION:
            raise ValidationError(f"faq[{i}].question too long")
        if len(answer) > _MAX_FAQ_ANSWER:
            raise ValidationError(f"faq[{i}].answer too long")
        items.append({"question": question, "answer": answer})
    return items


def _normalize_expires_at(raw: Any) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValidationError("expires_at must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValidationError("expires_at must include a timezone offset")
    # 统一 UTC 秒级文本（与 now_iso 同格式，字符串比较即时间序）
    return parsed.astimezone(UTC).replace(microsecond=0).isoformat()


def validate_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """校验并归一化发布请求 → (canonical, action)。

    action：``draft``（保存草稿，缺省）/ ``publish``（确认发布）。必填：
    merchant_display_name、title（商品名）；其余选填。
    """
    action = str((payload or {}).get("action") or "draft").strip().lower()
    if action not in ("draft", "publish"):
        raise ValidationError("action must be one of ('draft', 'publish')")

    canonical: dict[str, Any] = {}
    for field, limit in (
        ("merchant_display_name", _MAX_DISPLAY_NAME),
        ("title", _MAX_TITLE),
        ("category", _MAX_CATEGORY),
        ("shop_platform", _MAX_PLATFORM),
        ("summary", _MAX_SUMMARY),
    ):
        value = str((payload or {}).get(field) or "").strip()
        if len(value) > limit:
            raise ValidationError(f"{field} too long (max {limit})")
        canonical[field] = value
    for required in ("merchant_display_name", "title"):
        if not canonical[required]:
            raise ValidationError(f"missing required field: {required}")
    canonical["shop_url"] = validate_shop_url(str((payload or {}).get("shop_url") or ""))
    canonical["faq"] = _normalize_faq((payload or {}).get("faq"))
    canonical["expires_at"] = _normalize_expires_at((payload or {}).get("expires_at"))
    return canonical, action


# ── 行读写 ────────────────────────────────────────────────────────────────


def _row_to_publication(row: sqlite3.Row) -> dict[str, Any]:
    publication = dict(row)
    publication["faq"] = decode_json(publication.pop("faq_json", ""), [])
    return publication


def get_publication(conn: sqlite3.Connection, publication_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "select * from merchant_publications where publication_id = ?",
        (str(publication_id or "").strip(),),
    ).fetchone()
    return _row_to_publication(row) if row is not None else None


def is_publicly_visible(publication: dict[str, Any], now: str) -> bool:
    """公开可见性：published 且未过期（expires_at 为空或在未来）。"""
    if str(publication.get("status") or "") != "published":
        return False
    expires_at = str(publication.get("expires_at") or "")
    return not expires_at or expires_at > now


def _find_by_merchant_title(
    conn: sqlite3.Connection, merchant_id: str, title: str
) -> dict[str, Any] | None:
    """幂等查找：同一商家的同名商品（非撤回行，大小写不敏感）。"""
    row = conn.execute(
        "select * from merchant_publications"
        " where merchant_id = ? and lower(title) = lower(?) and status != 'withdrawn'",
        (merchant_id, title),
    ).fetchone()
    return _row_to_publication(row) if row is not None else None


def _publish_event_type(
    existing: dict[str, Any] | None, canonical: dict[str, Any]
) -> str:
    """发布动作 → 事件类型：新增 product_added；仅 FAQ 变化 faq_updated；其余
    字段变化（含无任何变化的重复发布）product_updated。"""
    if existing is None:
        return "product_added"
    faq_changed = (existing.get("faq") or []) != (canonical.get("faq") or [])
    others_changed = any(
        str(existing.get(field) or "") != str(canonical.get(field) or "")
        for field in (
            "merchant_display_name",
            "shop_platform",
            "shop_url",
            "title",
            "category",
            "summary",
            "expires_at",
        )
    )
    if faq_changed and not others_changed:
        return "faq_updated"
    return "product_updated"


def upsert_publication(
    conn: sqlite3.Connection,
    *,
    merchant_id: str,
    canonical: dict[str, Any],
    action: str,
) -> tuple[dict[str, Any], bool, bool]:
    """写入公开资料 → (row, created, idempotent_replay)。

    同一商家同名商品的重复提交更新既有行（不产生重复主体——部分唯一索引
    数据层兜底）；``publish`` 动作置 published + published_at 并递增版本。
    """
    now = now_iso()
    existing = _find_by_merchant_title(conn, merchant_id, str(canonical["title"]))
    faq_json = encode_json(canonical["faq"])
    if existing is None:
        publication_id = new_publication_id()
        status = "published" if action == "publish" else "draft"
        published_at = now if action == "publish" else ""
        conn.execute(
            "insert into merchant_publications("
            " publication_id, merchant_id, status, source_kind,"
            " merchant_display_name, shop_platform, shop_url, title, category,"
            " summary, faq_json, published_at, expires_at, version, created_at, updated_at)"
            " values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
            (
                publication_id,
                merchant_id,
                status,
                SOURCE_KIND,
                canonical["merchant_display_name"],
                canonical["shop_platform"],
                canonical["shop_url"],
                canonical["title"],
                canonical["category"],
                canonical["summary"],
                faq_json,
                published_at,
                canonical["expires_at"],
                now,
                now,
            ),
        )
        row = get_publication(conn, publication_id)
        assert row is not None
        if action == "publish":
            # M4 公开事件：发布动态（草稿保存不产生事件）。
            events_service.emit_public_event(
                conn,
                merchant_id=merchant_id,
                publication_id=str(row["publication_id"]),
                event_type="product_added",
                payload=public_projection(row),
            )
        return row, True, False
    # 幂等更新路径：版本仅在（重新）发布时递增——草稿保存不消耗版本号。
    version = int(existing["version"] or 1)
    status = str(existing["status"])
    published_at = str(existing["published_at"] or "")
    if action == "publish":
        version += 1
        status = "published"
        published_at = now
    conn.execute(
        "update merchant_publications set"
        " merchant_display_name = ?, shop_platform = ?, shop_url = ?,"
        " category = ?, summary = ?, faq_json = ?, status = ?,"
        " published_at = ?, expires_at = ?, version = ?, updated_at = ?"
        " where publication_id = ?",
        (
            canonical["merchant_display_name"],
            canonical["shop_platform"],
            canonical["shop_url"],
            canonical["category"],
            canonical["summary"],
            faq_json,
            status,
            published_at,
            canonical["expires_at"],
            version,
            now,
            existing["publication_id"],
        ),
    )
    row = get_publication(conn, str(existing["publication_id"]))
    assert row is not None
    if action == "publish":
        events_service.emit_public_event(
            conn,
            merchant_id=merchant_id,
            publication_id=str(row["publication_id"]),
            event_type=_publish_event_type(existing, canonical),
            payload=public_projection(row),
        )
    return row, False, True


def withdraw_publication(
    conn: sqlite3.Connection, *, publication_id: str, merchant_id: str
) -> dict[str, Any]:
    """撤回公开资料（终态）：行必须存在且归属当前商家。"""
    row = get_publication(conn, publication_id)
    if row is None:
        raise NotFoundError(f"Unknown publication: {publication_id}")
    if str(row["merchant_id"]) != merchant_id:
        from kiwi_catalog.core.errors import PermissionDenied

        raise PermissionDenied("publication belongs to another merchant")
    now = now_iso()
    conn.execute(
        "update merchant_publications set status = 'withdrawn', updated_at = ?"
        " where publication_id = ?",
        (now, row["publication_id"]),
    )
    updated = get_publication(conn, publication_id)
    assert updated is not None
    events_service.emit_public_event(
        conn,
        merchant_id=merchant_id,
        publication_id=str(updated["publication_id"]),
        event_type="publication_withdrawn",
        payload=public_projection(updated),
    )
    return updated


def record_public_view(conn: sqlite3.Connection, publication_id: str) -> None:
    """公开详情浏览计数（非商家本人视角；商家匿名汇总数据源）。"""
    conn.execute(
        "update merchant_publications set view_count = view_count + 1"
        " where publication_id = ?",
        (str(publication_id or "").strip(),),
    )


# ── 公开投影（public-only 白名单）────────────────────────────────────────


def public_projection(publication: dict[str, Any]) -> dict[str, Any]:
    """公开搜索/详情投影：仅公开字段；恒带 inquiry_available=false。

    绝不包含注册账户的电话/邮箱（本表本就不存）；不生成 Agent Card / A2A
    端点 / 实时报价标记。
    """
    return {
        "publication_id": publication["publication_id"],
        "merchant_id": publication["merchant_id"],
        "merchant_display_name": publication["merchant_display_name"],
        "title": publication["title"],
        "category": publication["category"],
        "summary": publication["summary"],
        "shop_platform": publication["shop_platform"],
        "shop_url": publication["shop_url"],
        "faq": publication.get("faq") or [],
        "source_kind": publication["source_kind"],
        "status": publication["status"],
        "version": publication["version"],
        "published_at": publication["published_at"],
        "expires_at": publication["expires_at"],
        "updated_at": publication["updated_at"],
        "inquiry_available": False,
    }


# ── 公开搜索（沿用 listings 搜索约定：LIKE 转义 + 确定性排序 + cursor）─────

_SEARCH_QUERY_KEYS = frozenset({"q", "category", "merchant_id", "limit", "cursor"})


class SearchQueryError(ValueError):
    """搜索 query 非法（fail-closed：未知键拒绝，不静默忽略）。"""


def _like_escaped(term: str) -> str:
    escaped = str(term).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _encode_cursor(updated_at: str, publication_id: str) -> str:
    return urllib.parse.quote(f"{updated_at}|{publication_id}", safe="")


def _decode_cursor(cursor: str) -> tuple[str, str]:
    parts = urllib.parse.unquote(str(cursor)).split("|")
    if len(parts) != 2:
        raise ValueError("malformed cursor")
    return parts[0], parts[1]


def search_publications(
    conn: sqlite3.Connection, query: dict[str, Any]
) -> tuple[list[dict[str, Any]], str]:
    """公开搜索：仅 published 且未过期；排序 (updated_at desc, publication_id desc)。

    Returns (rows, next_cursor)——rows 为 public_projection 形状。
    """
    unknown = set(query or {}) - _SEARCH_QUERY_KEYS
    if unknown:
        raise SearchQueryError(f"unknown publication search query keys: {sorted(unknown)}")
    limit = 20
    raw_limit = (query or {}).get("limit")
    if raw_limit not in (None, ""):
        try:
            limit = int(raw_limit)
        except (TypeError, ValueError) as exc:
            raise SearchQueryError("limit must be an integer") from exc
        if not 1 <= limit <= 100:
            raise SearchQueryError("limit must be between 1 and 100")

    where: list[str] = ["status = 'published'"]
    values: list[Any] = []
    now = now_iso()
    # 未过期：expires_at 为空或在未来
    where.append("(expires_at = '' or expires_at > ?)")
    values.append(now)

    q = str((query or {}).get("q") or "").strip()
    if q:
        where.append(
            "(title like ? escape '\\' or category like ? escape '\\'"
            " or summary like ? escape '\\' or merchant_display_name like ? escape '\\')"
        )
        pattern = _like_escaped(q)
        values.extend([pattern, pattern, pattern, pattern])

    category = str((query or {}).get("category") or "").strip()
    if category:
        where.append("category = ?")
        values.append(category)

    merchant_id = str((query or {}).get("merchant_id") or "").strip()
    if merchant_id:
        where.append("merchant_id = ?")
        values.append(merchant_id)

    cursor = str((query or {}).get("cursor") or "").strip()
    if cursor:
        try:
            c_updated_at, c_publication_id = _decode_cursor(cursor)
        except ValueError as exc:
            raise SearchQueryError(f"malformed cursor: {exc}") from exc
        where.append(
            "(updated_at < ? or (updated_at = ? and publication_id < ?))"
        )
        values.extend([c_updated_at, c_updated_at, c_publication_id])

    rows = conn.execute(
        f"""
        select * from merchant_publications
        where {' and '.join(where)}
        order by updated_at desc, publication_id desc
        limit ?
        """,
        (*values, limit + 1),
    ).fetchall()

    results = [_row_to_publication(row) for row in rows[:limit]]
    next_cursor = ""
    if len(rows) > limit and results:
        last = results[-1]
        next_cursor = _encode_cursor(str(last["updated_at"]), str(last["publication_id"]))
    return results, next_cursor
