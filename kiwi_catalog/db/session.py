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

"""SQLite connection and serialization helpers."""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from kiwi_catalog.db.migrations import (
    CURRENT_SCHEMA_VERSION,
    run_migrations,
)
from kiwi_catalog.db.models import INDEXES, SCHEMA

VERSION = "0.2.1"  # kiwi-catalog standalone

SQLITE_BUSY_TIMEOUT_MS = 5000


def now_iso() -> str:
    # 统一 UTC（fresh_until 等跨模块时间戳逐字符比较的前提；历史教训：
    # 本地 naive 与 UTC-aware 混用会让 freshness TTL 偏移服务器时区差）。
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def encode_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def decode_json(value: str | None, default: Any) -> Any:
    if value in (None, ""):
        return default
    try:
        decoded = json.loads(value)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return default
    if isinstance(default, list):
        if not isinstance(decoded, list):
            return default
        normalized: list[str] = []
        for item in decoded:
            if item is None or isinstance(item, (dict, list)):
                continue
            text = str(item).strip()
            if text:
                normalized.append(text)
        return normalized
    if isinstance(default, dict) and not isinstance(decoded, dict):
        return default
    return decoded


def open_connection(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path).expanduser()
    # 审查 P2：数据目录/文件 0700/0600（CLAUDE.md 约定落地）——SQLite 库含
    # owner token digest / 审计事件 / 影子表，共享机器上不得被其他本地用户读取。
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    conn = sqlite3.connect(path, timeout=SQLITE_BUSY_TIMEOUT_MS / 1000)
    try:
        os.chmod(path, 0o600)
    except OSError:
        # 只读文件系统/不可写场景：权限收紧失败不阻塞连接（fail-open 于可用性，
        # 目录 0700 已挡住大部分暴露面）
        pass
    try:
        conn.row_factory = sqlite3.Row
        conn.execute(f"pragma busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
        conn.execute("pragma journal_mode = wal")
        conn.execute("pragma foreign_keys = on")
        version_row = conn.execute("pragma user_version").fetchone()
        current_version = int(version_row[0] or 0) if version_row is not None else 0
        if current_version < CURRENT_SCHEMA_VERSION:
            init_db(conn)
        elif current_version > CURRENT_SCHEMA_VERSION:
            raise RuntimeError(
                f"database schema version {current_version} is newer than the supported version "
                f"{CURRENT_SCHEMA_VERSION}; upgrade kiwi-catalog instead of opening this database "
                "with an older release"
            )
        return conn
    except Exception:
        conn.close()
        raise


def init_db(conn: sqlite3.Connection) -> None:
    for statement in SCHEMA:
        conn.execute(statement)
    run_migrations(conn)
    for statement in INDEXES:
        conn.execute(statement)
    conn.execute(
        "insert or replace into meta(key, value) values('schema_version', ?)",
        (str(CURRENT_SCHEMA_VERSION),),
    )
    conn.execute(
        "insert or replace into meta(key, value) values('package_version', ?)",
        (VERSION,),
    )
    conn.commit()


@contextmanager
def db_session(db_path: str | Path) -> Iterator[sqlite3.Connection]:
    conn = open_connection(db_path)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return dict(row)
