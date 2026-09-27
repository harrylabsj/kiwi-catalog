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

"""云端端点行同步（§4.5：可发现性的落点）。

缺口背景：`discovery.agent_card_url` / `a2a_urls` 来自 ``agent_endpoints``
表，此前唯一写入者是注册路径的 ``upsert_profile_endpoints``——名片发布
成功买家也找不到云端商家。本模块按**当前库状态**推导云端点行的目标形态
并幂等落地，触发点（绑定确认 / 名片激活 / 轮换 / 撤销 / 撤回 / 注册）全部
**同一事务**调用：

- ``a2a`` 行：有活动绑定且名片未撤回 → upsert 其 ``a2a_endpoint``；无绑定或
  已撤回 → 删除。**另写**——不碰 ``upsert_profile_endpoints``「只管
  agent_card/ucp_profile」的不变量；
- ``agent_card`` 行：有活动绑定 **且** 有非 WITHDRAWN 的卡片发布 → 写稳定读
  地址（经 ``upsert_profile_endpoints``）；否则只删**本模块管理的那一行**
  （url = 稳定读地址）——direct 商家自己域名的 agent_card 行不受影响。

触发点对照：绑定确认（此时通常无卡 → 只写 a2a）；名片激活（两行都写）；
轮换（a2a 地址更新）；撤销（无其他活动绑定时两行皆删）；暂停（PAUSED ≠
WITHDRAWN → 两行保留，这是 PAUSED「公开信息保留」的语义）；撤回（两行皆删，
与稳定地址 410 同口径——撤回 = 不再可被发现）。
"""

from __future__ import annotations

import sqlite3

from kiwi_catalog.agent_catalog.sqlite_repository import upsert_profile_endpoints


def cloud_card_url(catalog_agent_id: str) -> str:
    """云名片稳定读地址（本机 hosted base 下的规范形态）。"""
    from kiwi_catalog.api.handlers.hosted_publication import hosted_base_url

    return f"{hosted_base_url().rstrip('/')}/v1/agents/{catalog_agent_id}/agent-card.json"


def _active_binding(conn: sqlite3.Connection, catalog_agent_id: str) -> sqlite3.Row | None:
    return conn.execute(
        "select * from runtime_bindings where catalog_agent_id = ? and status = 'active'"
        " order by binding_version desc limit 1",
        (catalog_agent_id,),
    ).fetchone()


def _upsert_a2a_endpoint(
    conn: sqlite3.Connection, catalog_agent_id: str, url: str, now: str
) -> None:
    """upsert `a2a` 行（另写：形状与 upsert_profile_endpoints 一致，但不走它）。"""
    row = conn.execute(
        "select endpoint_id from agent_endpoints where catalog_agent_id = ? and kind = 'a2a'",
        (catalog_agent_id,),
    ).fetchone()
    if row is None:
        conn.execute(
            "insert into agent_endpoints("
            " catalog_agent_id, kind, url, protocol, protocol_version,"
            " preference, auth_summary_json, status, last_checked_at)"
            " values (?, 'a2a', ?, 'a2a', '', 1, '{}', 'active', ?)",
            (catalog_agent_id, url, now),
        )
    else:
        conn.execute(
            "update agent_endpoints set url = ?, last_checked_at = ? where endpoint_id = ?",
            (url, now, int(row["endpoint_id"])),
        )


def sync_cloud_endpoints(conn: sqlite3.Connection, catalog_agent_id: str, now: str) -> None:
    """按当前库状态同步云端点行（幂等；调用方负责把它放进自己的事务）。"""
    agent_id = str(catalog_agent_id)
    publication = conn.execute(
        "select publication_state from card_publications where catalog_agent_id = ?",
        (agent_id,),
    ).fetchone()
    withdrawn = publication is not None and str(publication["publication_state"]) == "WITHDRAWN"
    binding = _active_binding(conn, agent_id)
    # a2a 行：活动绑定且名片未撤回 → upsert；其余（无绑定 / 已撤回）→ 删除。
    # 撤回 = 不再可被发现（与稳定地址 410 同口径），即使绑定仍在。
    if binding is not None and not withdrawn:
        _upsert_a2a_endpoint(conn, agent_id, str(binding["a2a_endpoint"]), now)
    else:
        conn.execute(
            "delete from agent_endpoints where catalog_agent_id = ? and kind = 'a2a'",
            (agent_id,),
        )
    has_card = publication is not None and not withdrawn
    card_url = cloud_card_url(agent_id)
    if binding is not None and has_card:
        upsert_profile_endpoints(
            conn,
            agent_id,
            [
                {
                    "kind": "agent_card",
                    "url": card_url,
                    "protocol": "a2a",
                    "protocol_version": "",
                    "preference": 1,
                }
            ],
        )
    else:
        conn.execute(
            "delete from agent_endpoints"
            " where catalog_agent_id = ? and kind = 'agent_card' and url = ?",
            (agent_id, card_url),
        )
