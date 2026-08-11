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

"""发现条目（discovery entry）服务：catalog 本地的轻量商品名称目录。

架构转向（2026-08）：catalog 与 shopping-cli 零运行时依赖——不再代理
商品 CRUD。商家在门户上传商品名称（仅名称）进本表；买家 agent 经
/v1/discovery/search 匿名检索，按结果中的 agent 引用跳转商家 agent。

创建门槛（fail-closed，中文引导文案）：
- 商家必须持有 ACTIVE owner token（未签发 → 引导申请令牌）；
- 商家必须已有 ≥1 个注册 agent（catalog_agents 有 merchant_id 行——
  没有 agent 的条目是死发现链接，阻塞并引导完成注册）；
- 名称 trim 后非空、≤200 字符；同商家名称不区分大小写去重。无配额。
"""

from __future__ import annotations

import secrets
import sqlite3
from typing import Any

from kiwi_catalog.core.errors import NotFoundError, ValidationError
from kiwi_catalog.db.session import now_iso

_ENTRY_ID_PREFIX = "dsc_"
MAX_NAME_LENGTH = 200


def new_entry_id() -> str:
    """生成 entry_id（dsc_ + 20 hex，参照 new_listing_id 先例）。"""
    return f"{_ENTRY_ID_PREFIX}{secrets.token_hex(10)}"


def entry_record(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    """行 → 条目视图（own-list / 搜索结果共用的 entry 投影）。"""
    return {
        "entry_id": str(row["entry_id"]),
        "merchant_id": str(row["merchant_id"]),
        "name": str(row["name"]),
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }


def _require_active_token(
    conn: sqlite3.Connection, merchant_id: str, *, action: str = "上传商品名称"
) -> None:
    row = conn.execute(
        "select status from merchant_tokens where merchant_id = ?", (merchant_id,)
    ).fetchone()
    if row is None or str(row["status"]) != "active":
        raise ValidationError(
            f"{action}需要有效商家令牌——令牌未签发或已吊销，"
            "请先在「我的账户」的令牌信息页申请令牌"
        )


def _require_registered_agent(conn: sqlite3.Connection, merchant_id: str) -> None:
    row = conn.execute(
        "select count(*) as n from catalog_agents where merchant_id = ?",
        (merchant_id,),
    ).fetchone()
    if row is None or int(row["n"]) < 1:
        raise ValidationError(
            "你还没有注册 Agent——商品名称需要挂在已注册的 Agent 下才会被买家发现，"
            "请先完成 Agent 注册再上传"
        )


def create_entry(conn: sqlite3.Connection, merchant_id: str, name: str) -> dict[str, Any]:
    """创建发现条目（门槛见模块 docstring）。"""
    merchant_id = str(merchant_id or "").strip()
    name = str(name or "").strip()
    if not name:
        raise ValidationError("商品名称不能为空")
    if len(name) > MAX_NAME_LENGTH:
        raise ValidationError(f"商品名称过长（最多 {MAX_NAME_LENGTH} 字符）")
    _require_active_token(conn, merchant_id)
    _require_registered_agent(conn, merchant_id)
    duplicate = conn.execute(
        "select 1 from discovery_entries where merchant_id = ? and lower(name) = lower(?)",
        (merchant_id, name),
    ).fetchone()
    if duplicate is not None:
        raise ValidationError("该商品名称已存在（同商家下名称不能重复）")
    now = now_iso()
    entry_id = new_entry_id()
    conn.execute(
        "insert into discovery_entries(entry_id, merchant_id, name, created_at, updated_at)"
        " values (?, ?, ?, ?, ?)",
        (entry_id, merchant_id, name, now, now),
    )
    row = conn.execute(
        "select * from discovery_entries where entry_id = ?", (entry_id,)
    ).fetchone()
    return entry_record(row)


def list_entries(conn: sqlite3.Connection, merchant_id: str) -> list[dict[str, Any]]:
    """列商家自己的发现条目（按名称排序，确定性）。

    取舍（审查 P3-04）：只读自身数据，不做 active token 检查——令牌吊销后
    商家在会话有效期内仍可查看自己的条目（无写面副作用，数据本就属于
    该商家）；写路径（create/delete）强制 active token。
    """
    rows = conn.execute(
        "select * from discovery_entries where merchant_id = ?"
        " order by lower(name), entry_id",
        (str(merchant_id or "").strip(),),
    ).fetchall()
    return [entry_record(row) for row in rows]


def delete_entry(conn: sqlite3.Connection, merchant_id: str, entry_id: str) -> None:
    """删除商家自己的条目（越权/不存在 → 404，不泄露归属）。

    审查 P3-04：与 create 同款 active token 检查——令牌吊销后，7 天会话
    cookie 不得再改动发现目录写面。
    """
    entry_id = str(entry_id or "").strip()
    if not entry_id:
        raise ValidationError("entry_id is required")
    merchant_id = str(merchant_id or "").strip()
    # 先归属/存在性（404 不泄露归属），再令牌门槛——无令牌商家删他人条目
    # 仍是 404，只有删自己的条目才暴露「令牌已吊销」。
    owned = conn.execute(
        "select 1 from discovery_entries where entry_id = ? and merchant_id = ?",
        (entry_id, merchant_id),
    ).fetchone()
    if owned is None:
        raise NotFoundError(f"Unknown discovery entry: {entry_id}")
    _require_active_token(conn, merchant_id, action="删除商品名称")
    conn.execute(
        "delete from discovery_entries where entry_id = ? and merchant_id = ?",
        (entry_id, merchant_id),
    )


def search_entries(
    conn: sqlite3.Connection, q: str, *, limit: int
) -> list[dict[str, Any]]:
    """公开检索（买家 agent）：名称子串匹配（大小写不敏感）。

    每行 join 商家的注册 agent（一商家一 agent 唯一索引兜底，不会扇出）与
    merchants 影子表；agent/merchant 投影由调用方按既有公开投影构造。
    """
    needle = str(q or "").strip().lower()
    sql = (
        "select e.*, a.catalog_agent_id as agent_catalog_agent_id,"
        " a.canonical_domain as agent_canonical_domain,"
        " a.verification_level as agent_verification_level,"
        " a.freshness_state as agent_freshness_state,"
        " a.administrative_state as agent_administrative_state,"
        " m.id as merchant_shadow_id, m.name as merchant_shadow_name"
        " from discovery_entries e"
        " left join catalog_agents a on a.merchant_id = e.merchant_id"
        " left join merchants m on m.id = e.merchant_id"
    )
    params: list[Any] = []
    if needle:
        # instr 子串匹配——避开 LIKE 通配符注入（q 原样入参）
        sql += " where instr(lower(e.name), ?) > 0"
        params.append(needle)
    sql += " order by lower(e.name), e.entry_id limit ?"
    params.append(limit)
    return [dict(row) for row in conn.execute(sql, params).fetchall()]
