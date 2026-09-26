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

"""运营 admin token 轮换（2026-09-26；迁移 v37）。

背景：admin token 此前只有"服务器 env 里的一个静态值"——轮换要登录服务器改
配置并重启，且旧值一旦泄露无法快速作废。门户的「记住」只解决"本浏览器不用
重输"，不能解决"换一个值"（生产反馈的误解即由此而来）。

三条设计取舍：

1. **只存摘要**：表里是 SHA-256 摘要，与商家令牌同一模型（`core.tokens`）；
   明文只在轮换响应里返回一次。摘要不加固盐——token 是 256 位随机串，不是
   低熵口令，字典攻击不适用（与商家令牌同理）。
2. **有行 = 已轮换**：一旦存在行，env 里的 `KIWI_CATALOG_ADMIN_TOKEN` **不再被
   接受**（它退回"首次引导"角色）。否则轮换对已拿到旧值的人毫无作用。
3. **恢复路径是显式的**：`clear()` 删行 → 控制权交回服务器配置。生产上这一步
   需要改库（sqlite3）+ 重启服务，属于运维动作，不做成 HTTP 接口。

本模块只碰数据库；env 的读取留在 `api.auth`（服务层不依赖 api 层）。
"""

from __future__ import annotations

import secrets
import sqlite3
from typing import Any

from kiwi_catalog.core.errors import ValidationError
from kiwi_catalog.core.tokens import token_digest

#: 单例行主键（表上有 check(credential_id = 1) 兜底）。
CREDENTIAL_ID = 1

#: 新 token 的最小长度。与商家令牌（32 随机字节）同量级；短于此的一律拒绝，
#: 避免把全权凭据换成可猜的口令。
ADMIN_TOKEN_MIN_LENGTH = 24


def generate_admin_token() -> str:
    """生成新 admin token：32 随机字节 urlsafe（≈43 字符）。

    不加前缀：它要能直接替进服务器配置里的既有值，形态越普通越好。
    """
    return secrets.token_urlsafe(32)


def validate_new_token(value: str) -> str:
    """校验调用方自选的 token；返回原值（不做 trim——空白一律视为非法输入）。"""
    token = str(value or "")
    if token != token.strip():
        raise ValidationError("new_token must not contain leading/trailing whitespace")
    if any(char.isspace() for char in token):
        raise ValidationError("new_token must not contain whitespace")
    if len(token) < ADMIN_TOKEN_MIN_LENGTH:
        raise ValidationError(f"new_token must be at least {ADMIN_TOKEN_MIN_LENGTH} characters")
    return token


def load(conn: sqlite3.Connection) -> dict[str, Any] | None:
    """当前轮换行（无则 None = 仍由 env 引导）。"""
    row = conn.execute(
        "select * from admin_credentials where credential_id = ?", (CREDENTIAL_ID,)
    ).fetchone()
    return dict(row) if row is not None else None


def current_digest(conn: sqlite3.Connection) -> str:
    """当前生效的 admin token 摘要；未轮换时返回 ''（由调用方回退到 env）。"""
    row = load(conn)
    return str(row["token_digest"]) if row is not None else ""


def rotate(
    conn: sqlite3.Connection, *, new_token: str, actor: str, now: str
) -> dict[str, Any]:
    """写入/覆盖轮换行。返回 {rotated_at, rotation_count}（**不含**摘要与明文）。"""
    token = validate_new_token(new_token)
    existing = load(conn)
    count = int(existing["rotation_count"]) + 1 if existing is not None else 1
    conn.execute(
        "insert into admin_credentials (credential_id, token_digest, rotated_at, rotated_by, rotation_count)"
        " values (?, ?, ?, ?, ?)"
        " on conflict(credential_id) do update set"
        " token_digest = excluded.token_digest, rotated_at = excluded.rotated_at,"
        " rotated_by = excluded.rotated_by, rotation_count = excluded.rotation_count",
        (CREDENTIAL_ID, token_digest(token), now, str(actor or ""), count),
    )
    return {"rotated_at": now, "rotation_count": count}


def clear(conn: sqlite3.Connection) -> None:
    """删除轮换行：控制权交回服务器配置里的 env 值（恢复路径，运维动作）。"""
    conn.execute("delete from admin_credentials where credential_id = ?", (CREDENTIAL_ID,))
