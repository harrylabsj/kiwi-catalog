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

"""运营埋点（dashboard 数据源）。

usage_metrics 表：metric × UTC 日期（YYYY-MM-DD）每日计数，原子
INSERT ON CONFLICT +1。埋点只记「发生了多少次」——个体访问日志由
access_log 承担（v28，2026-08-22 原则修订：记录个体访问日志用于运营质量
与安全审计；最小必要仍适用——绝不记录凭据本体、身份一律派生、日志有保留期）。
历史说明：2026-08-22 之前按「不记调用方身份（隐私最小化：catalog 不存
buyer/merchant 的个体访问日志）」运行。

指标词表（dashboard 消费方以此为单一来源）：
- ``buyer_agent_search``    /v1/agents/search（含 legacy 搜索）
- ``buyer_listing_search``  /v1/listings/search
- ``merchant_self_check``   /v1/merchants/self（商家自查）
- ``listing_publish``       /v1/listings/publish（商家上传商品）
"""

from __future__ import annotations

import sqlite3
from typing import Any

from kiwi_catalog.db.session import now_iso

METRIC_BUYER_AGENT_SEARCH = "buyer_agent_search"
METRIC_BUYER_LISTING_SEARCH = "buyer_listing_search"
METRIC_MERCHANT_SELF_CHECK = "merchant_self_check"
METRIC_LISTING_PUBLISH = "listing_publish"

ALL_METRICS = (
    METRIC_BUYER_AGENT_SEARCH,
    METRIC_BUYER_LISTING_SEARCH,
    METRIC_MERCHANT_SELF_CHECK,
    METRIC_LISTING_PUBLISH,
)

# 时区：UTC 日期（与全库 now_iso UTC 一致；跨时区运营看的是 UTC 日）
_DAY_PREFIX_LEN = 10


def record_usage(conn: sqlite3.Connection, metric: str) -> None:
    """原子 +1（今日窗口）。未知 metric 静默跳过（防脏数据，不抛错）。"""
    if metric not in ALL_METRICS:
        return
    day = now_iso()[:_DAY_PREFIX_LEN]
    conn.execute(
        "insert into usage_metrics(metric, day, count, updated_at) values (?, ?, 1, ?)"
        " on conflict(metric, day) do update set"
        " count = usage_metrics.count + 1, updated_at = excluded.updated_at",
        (metric, day, now_iso()),
    )


def usage_series(
    conn: sqlite3.Connection, days: int = 14
) -> list[dict[str, Any]]:
    """最近 *days* 天各指标日计数（含 0 的日期补齐——dashboard 画连续趋势）。"""
    import datetime as _dt

    today = _dt.datetime.now(_dt.UTC).date()
    start = today - _dt.timedelta(days=days - 1)
    rows = conn.execute(
        "select metric, day, count from usage_metrics where day >= ? order by day",
        (start.isoformat(),),
    ).fetchall()
    by_day: dict[str, dict[str, int]] = {}
    for row in rows:
        bucket = by_day.setdefault(str(row["day"]), {})
        bucket[str(row["metric"])] = int(row["count"])
    series = []
    for offset in range(days):
        day = (start + _dt.timedelta(days=offset)).isoformat()
        series.append(
            {
                "day": day,
                "counts": {metric: by_day.get(day, {}).get(metric, 0) for metric in ALL_METRICS},
                "total": sum(by_day.get(day, {}).values()),
            }
        )
    return series
