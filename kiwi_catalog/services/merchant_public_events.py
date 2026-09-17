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

"""商家公开事件流（M4 拉取式订阅，kiwi 仓 merchant-buddy 第 0 版设计 §4）。

发布/更新/撤回公开资料时由服务端生成的 public-only **发布动态**：

- 只代表商家发布动态——RFQ、内部任务状态、价格底线、未发布草稿一律不
  进入本流；payload 由调用方以 M0 公开投影（public-only 白名单）构建；
- ``version`` 按 merchant_id 单调递增（``(merchant_id, version)`` 唯一
  索引数据层兜底）；
- ``created_at`` 按 merchant_id **严格递增**（µs 精度，同刻冲突自增 1µs）
  ——买家 ``last_seen_at`` 水位（``created_at > last_seen_at``）不丢不重
  的前提；秒级精度下同秒事件会被水位跳过；
- ``publication_id`` 可空：``service_notice`` 类动态可不绑定单个资料
  （词表保留；当前生成点为发布/更新/撤回，均绑定资料）。
"""

from __future__ import annotations

import secrets
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any

from kiwi_catalog.db.session import decode_json, encode_json

EVENT_TYPES = (
    "product_added",
    "product_updated",
    "faq_updated",
    "service_notice",
    "publication_withdrawn",
)


def new_event_id() -> str:
    return "mev_" + secrets.token_urlsafe(12)


def _row_to_event(row: sqlite3.Row) -> dict[str, Any]:
    event = dict(row)
    event["payload"] = decode_json(event.pop("payload_json", ""), {})
    return event


def _next_version_and_timestamp(conn: sqlite3.Connection, merchant_id: str) -> tuple[int, str]:
    """下一版本号 + 严格递增时间戳（同刻冲突在前值上 +1µs）。"""
    row = conn.execute(
        "select max(version) as v, max(created_at) as c from merchant_public_events"
        " where merchant_id = ?",
        (merchant_id,),
    ).fetchone()
    version = int(row["v"] or 0) + 1
    now = datetime.now(UTC).isoformat(timespec="microseconds")
    previous = str(row["c"] or "")
    if previous and now <= previous:
        now = (datetime.fromisoformat(previous) + timedelta(microseconds=1)).isoformat(
            timespec="microseconds"
        )
    return version, now


def emit_public_event(
    conn: sqlite3.Connection,
    *,
    merchant_id: str,
    publication_id: str,
    event_type: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """写入一条公开事件（同库事务内随资料写一起提交/回滚）。"""
    if event_type not in EVENT_TYPES:
        raise ValueError(f"unknown event_type: {event_type}")
    version, created_at = _next_version_and_timestamp(conn, merchant_id)
    event_id = new_event_id()
    conn.execute(
        "insert into merchant_public_events("
        " event_id, merchant_id, publication_id, event_type, version, payload_json,"
        " created_at) values (?, ?, ?, ?, ?, ?, ?)",
        (
            event_id,
            merchant_id,
            str(publication_id or ""),
            event_type,
            version,
            encode_json(payload),
            created_at,
        ),
    )
    return {
        "event_id": event_id,
        "merchant_id": merchant_id,
        "publication_id": str(publication_id or ""),
        "event_type": event_type,
        "version": version,
        "payload": payload,
        "created_at": created_at,
    }


def list_events_after(
    conn: sqlite3.Connection,
    *,
    merchant_id: str,
    last_seen_at: str,
    limit: int,
) -> list[dict[str, Any]]:
    """按水位增量取事件：``created_at > last_seen_at``，按时间升序，至多 limit 条。

    created_at 按商家严格递增，截断在 limit 处推进水位不丢事件（余量下次拉取）。
    """
    rows = conn.execute(
        "select * from merchant_public_events where merchant_id = ? and created_at > ?"
        " order by created_at asc, version asc limit ?",
        (merchant_id, str(last_seen_at or ""), int(limit)),
    ).fetchall()
    return [_row_to_event(row) for row in rows]
