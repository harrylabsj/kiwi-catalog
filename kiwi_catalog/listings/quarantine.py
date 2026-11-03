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

"""Listing 分享码污染的**纯读**隔离。

Listing 的 ``listing_digest`` 是发布方对原始内容的摘要；公开读侧如果为了
隐藏分享码而原地改写 title/summary/attributes，再返回原 digest，就等于伪造
摘要。正确做法：

- 正常记录原样输出（内容与 digest 保持既有契约）；
- 检测到分享码链接的历史/手工写入行 → **只在本次响应中隐藏**，不修改
  publication_state、governance_hold、updated_at 或内容；商家可在自查面看到
  ``quarantined`` / ``republish_required`` 提示；
- 商家用同 key 重新发布时，``publish_listing`` 重新计算 digest；历史上已经
  被旧版本写回 ``governance_hold=2`` 的行仍按旧隔离标记隐藏，发布成功后清除。

GET 搜索/详情/主页是只读路径：它们绝不把行持久改成 SUSPENDED 或治理 hold。
"""

from __future__ import annotations

from typing import Any

from kiwi_catalog.services.merchant_publications import contains_share_code_payload

#: 旧版本写回的内容隔离标记。仅用于兼容存量行；新的公开读不再写入它。
#: 0 = 无处置；1 = 管理员治理暂停（只能管理员解除）；2 = 旧的分享码内容隔离。
QUARANTINE_HOLD = 2

_LISTING_CONTENT_FIELDS = (
    "title",
    "category",
    "summary",
    "brand",
    "source_product_ref",
    "source_revision",
    "attributes_json",
    "regions_json",
    "tags_json",
    "commercial_hints_json",
    "handoff_destination_ref",
)


def listing_has_share_code(row: dict[str, Any]) -> bool:
    """行内容（含 JSON 列）里是否出现分享码 URL。纯读，不做任何写入。"""
    return any(
        contains_share_code_payload(row.get(field)) for field in _LISTING_CONTENT_FIELDS
    )


def is_quarantined(row: dict[str, Any]) -> bool:
    """是否为旧版本持久化的内容隔离行（兼容存量数据）。"""
    return int(row.get("governance_hold") or 0) == QUARANTINE_HOLD


def is_hidden_from_public(row: dict[str, Any]) -> bool:
    """公开搜索/详情/主页是否应隐藏该行（纯读判定）。"""
    return is_quarantined(row) or listing_has_share_code(row)


def public_visible_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """过滤掉不应公开的行；不写库、不改变输入行。"""
    return [row for row in rows if not is_hidden_from_public(row)]
