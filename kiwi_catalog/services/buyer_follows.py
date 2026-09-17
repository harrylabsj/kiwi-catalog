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

"""买家关注（M4 拉取式订阅，kiwi 仓 merchant-buddy 第 0 版设计 §4/§2 买家路径 3-5）。

- 关注是买家**显式操作**：搜索、浏览、调用专家或发询价都不产生订阅行；
- ``buyer_subject`` 是不透明字符串：当前取 Kiwi 自有账号的稳定标识
  ``account:{account_id}``（不用邮箱等可变/私密字段），未来切换 WorkBuddy
  open_id 时只需换 ``buyer_subject_for_account`` 的取值；
- 拉取语义：``GET /v1/me/follows/updates`` 仅响应买家主动查询——按各关注
  的 ``last_seen_at`` 增量返回商家已批准公开的事件，**返回什么再推进水位**
  （推进到本次实际取到的最后一条事件的 created_at，截断/类目过滤均不丢
  不重）；无任何向关注者写消息或推送的通道；
- 商家侧只有匿名汇总（关注者总数），永远拿不到 buyer_subject / 关注列表。
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from typing import Any

from kiwi_catalog.core.errors import ValidationError
from kiwi_catalog.db.session import now_iso
from kiwi_catalog.services import merchant_public_events as events_service

FOLLOW_STATUSES = ("active", "cancelled")

_MAX_CATEGORY = 100
_MAX_CONSENT_VERSION = 100
# 单次拉取每个关注至多返回的事件数——截断处推进水位不丢（余量下次拉取）。
UPDATES_PER_FOLLOW_CAP = 100


def buyer_subject_for_account(account: dict[str, Any]) -> str:
    """账号 → 买家主体标识（稳定、不透明；未来可换 WorkBuddy open_id）。"""
    return f"account:{int(account['account_id'])}"


def merchant_exists(conn: sqlite3.Connection, merchant_id: str) -> bool:
    """关注目标必须是已注册商家（merchants 影子表，注册即建行）。"""
    row = conn.execute(
        "select id from merchants where id = ?", (str(merchant_id or "").strip(),)
    ).fetchone()
    return row is not None


def _merchant_name(conn: sqlite3.Connection, merchant_id: str) -> str:
    row = conn.execute(
        "select name from merchants where id = ?", (merchant_id,)
    ).fetchone()
    return str(row["name"]) if row is not None else ""


def validate_follow_fields(payload: dict[str, Any]) -> tuple[str, str]:
    """校验关注请求的可选字段 → (category, consent_version)。"""
    category = str((payload or {}).get("category") or "").strip()
    if len(category) > _MAX_CATEGORY:
        raise ValidationError(f"category too long (max {_MAX_CATEGORY})")
    consent_version = str((payload or {}).get("consent_version") or "").strip()
    if len(consent_version) > _MAX_CONSENT_VERSION:
        raise ValidationError(f"consent_version too long (max {_MAX_CONSENT_VERSION})")
    return category, consent_version


def _watermark_now() -> str:
    """关注水位基准：µs 精度（与事件 created_at 同域——秒级基准会让同一秒内
    先于关注发生的事件越过水位被误投）。"""
    return datetime.now(UTC).isoformat(timespec="microseconds")


def _row_to_follow(row: sqlite3.Row) -> dict[str, Any]:
    return dict(row)


def get_follow(
    conn: sqlite3.Connection, *, buyer_subject: str, merchant_id: str
) -> dict[str, Any] | None:
    row = conn.execute(
        "select * from buyer_follows where buyer_subject = ? and merchant_id = ?",
        (buyer_subject, merchant_id),
    ).fetchone()
    return _row_to_follow(row) if row is not None else None


def follow_merchant(
    conn: sqlite3.Connection,
    *,
    buyer_subject: str,
    merchant_id: str,
    category: str,
    consent_version: str,
) -> tuple[dict[str, Any], bool, bool]:
    """显式关注（幂等）→ (row, created, reactivated)。

    首次关注水位从关注时刻起（不补历史）；活跃重复关注只更新
    category/consent_version、**保留 last_seen_at**（不丢未读）；取消后重新
    关注水位重置到重新关注时刻。
    """
    now = now_iso()
    existing = get_follow(conn, buyer_subject=buyer_subject, merchant_id=merchant_id)
    if existing is None:
        watermark = _watermark_now()
        conn.execute(
            "insert into buyer_follows("
            " buyer_subject, merchant_id, category, status, consent_version,"
            " last_seen_at, created_at, updated_at)"
            " values (?, ?, ?, 'active', ?, ?, ?, ?)",
            (buyer_subject, merchant_id, category, consent_version, watermark, now, now),
        )
        row = get_follow(conn, buyer_subject=buyer_subject, merchant_id=merchant_id)
        assert row is not None
        return row, True, False
    reactivated = str(existing["status"]) != "active"
    last_seen_at = _watermark_now() if reactivated else str(existing["last_seen_at"])
    conn.execute(
        "update buyer_follows set category = ?, consent_version = ?, status = 'active',"
        " last_seen_at = ?, updated_at = ?"
        " where buyer_subject = ? and merchant_id = ?",
        (category, consent_version, last_seen_at, now, buyer_subject, merchant_id),
    )
    row = get_follow(conn, buyer_subject=buyer_subject, merchant_id=merchant_id)
    assert row is not None
    return row, False, reactivated


def unfollow_merchant(
    conn: sqlite3.Connection, *, buyer_subject: str, merchant_id: str
) -> bool:
    """取消关注（状态置 cancelled，保留行供审计）→ 是否有活跃关注被取消。"""
    existing = get_follow(conn, buyer_subject=buyer_subject, merchant_id=merchant_id)
    if existing is None or str(existing["status"]) != "active":
        return False
    conn.execute(
        "update buyer_follows set status = 'cancelled', updated_at = ?"
        " where buyer_subject = ? and merchant_id = ?",
        (now_iso(), buyer_subject, merchant_id),
    )
    return True


def follow_view(conn: sqlite3.Connection, follow: dict[str, Any]) -> dict[str, Any]:
    """买家视角的关注视图（不含 buyer_subject——响应即买家本人）。"""
    return {
        "merchant_id": follow["merchant_id"],
        "merchant_name": _merchant_name(conn, str(follow["merchant_id"])),
        "category": follow["category"],
        "status": follow["status"],
        "consent_version": follow["consent_version"],
        "created_at": follow["created_at"],
        "last_seen_at": follow["last_seen_at"],
    }


def list_follows(conn: sqlite3.Connection, *, buyer_subject: str) -> list[dict[str, Any]]:
    """我的活跃关注列表（cancelled 不展示——取消即退出管理面）。"""
    rows = conn.execute(
        "select * from buyer_follows where buyer_subject = ? and status = 'active'"
        " order by created_at asc, merchant_id asc",
        (buyer_subject,),
    ).fetchall()
    return [follow_view(conn, _row_to_follow(row)) for row in rows]


def fetch_updates(conn: sqlite3.Connection, *, buyer_subject: str) -> list[dict[str, Any]]:
    """主动拉取更新：按各活跃关注的 last_seen_at 增量返回公开事件并推进水位。

    水位推进到本次**实际取到**的最后一条事件的 created_at（created_at 按商家
    严格递增）：条数截断时余量下次拉取不丢；类目过滤跳过的事件随水位越过、
    不再重复扫描。只返回有新事件的商家。
    """
    rows = conn.execute(
        "select * from buyer_follows where buyer_subject = ? and status = 'active'"
        " order by created_at asc, merchant_id asc",
        (buyer_subject,),
    ).fetchall()
    updates: list[dict[str, Any]] = []
    for raw in rows:
        follow = _row_to_follow(raw)
        merchant_id = str(follow["merchant_id"])
        events = events_service.list_events_after(
            conn,
            merchant_id=merchant_id,
            last_seen_at=str(follow["last_seen_at"]),
            limit=UPDATES_PER_FOLLOW_CAP,
        )
        if not events:
            continue
        new_seen_at = str(events[-1]["created_at"])
        conn.execute(
            "update buyer_follows set last_seen_at = ?, updated_at = ?"
            " where buyer_subject = ? and merchant_id = ?",
            (new_seen_at, now_iso(), buyer_subject, merchant_id),
        )
        category = str(follow["category"])
        matching = [
            event
            for event in events
            if not category or str((event["payload"] or {}).get("category") or "") == category
        ]
        if matching:
            updates.append(
                {
                    "merchant_id": merchant_id,
                    "merchant_name": _merchant_name(conn, merchant_id),
                    "events": matching,
                    "last_seen_at": new_seen_at,
                }
            )
    return updates


def follower_count(conn: sqlite3.Connection, merchant_id: str) -> int:
    """商家匿名汇总：活跃关注者总数（只有数字，没有买家身份）。"""
    row = conn.execute(
        "select count(*) as n from buyer_follows where merchant_id = ? and status = 'active'",
        (merchant_id,),
    ).fetchone()
    return int(row["n"] or 0)
