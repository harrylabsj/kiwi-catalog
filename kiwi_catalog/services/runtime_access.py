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

"""WorkBuddy 运行时访问配置：严格校验、独立加密与版本状态机。

分享码不是 Catalog 凭据或业务签名密钥。库中只保存由独立环境密钥加密的
Fernet 密文；公开投影只包含 active 元数据，明文只在带码验证和受控 Buyer
分发时解密。所有函数只管理自己的 SQL 状态，事务边界由调用方持有。
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from typing import Any

from kiwi_catalog.core.errors import ConflictError, NotFoundError, ValidationError
from kiwi_catalog.db.session import now_iso

PROVIDER = "workbuddy"
ACCESS_MODE = "share_parameter"
PARAMETER_NAME = "sharecode"
ADAPTER_VERSION = "workbuddy-share-v1"
AUTH_MODE = "signature"
SECRET_MAX_LENGTH = 4096
KEYS_ENV = "KIWI_CATALOG_ACCESS_CONFIG_KEYS_JSON"
ACTIVE_KEY_ENV = "KIWI_CATALOG_ACCESS_CONFIG_ACTIVE_KEY_ID"

_SHARE_FIELDS = {
    "provider",
    "access_mode",
    "parameter_name",
    "secret_value",
    "adapter_version",
    "auth_mode",
    "expected_version",
}
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def append_share_parameter(url: str, secret: str) -> str:
    """把分享参数追加到目标 URL 查询串末尾；已有同名参数或非法形状时拒绝。

    追加发生在发送前，不参与任何签名覆盖；同名参数已存在时 fail-closed——
    不覆盖、不猜测（契约 §2.5.3）。

    **原查询串按字节保留**（不重新编码、不重排）：签名覆盖的是去码地址，
    任何对既有业务参数的归一化（``%20``→``+``、重复参数合并）都会改变
    签名输入。解析只用于识别同名参数，结果不参与拼接。
    """
    from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

    parts = urlsplit(str(url))
    if parts.scheme != "https" or not parts.netloc:
        raise ValidationError("share parameter target must be an HTTPS URL")
    if parts.fragment:
        raise ValidationError("share parameter target must not carry a fragment")
    if parts.username or parts.password:
        raise ValidationError("share parameter target must not carry userinfo")
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if any(name == PARAMETER_NAME for name, _ in pairs):
        raise ValidationError("share parameter target already carries the parameter")
    parameter = f"{PARAMETER_NAME}={quote(str(secret), safe='')}"
    existing = parts.query.rstrip("&")
    query = f"{existing}&{parameter}" if existing else parameter
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def parse_access_config(value: Any) -> dict[str, Any]:
    """Validate the merchant-only write shape without echoing secret material."""
    if not isinstance(value, dict):
        raise ValidationError("access_config must be an object")
    expected = value.get("expected_version")
    if isinstance(expected, bool) or not isinstance(expected, int) or expected < 0:
        raise ValidationError("access_config.expected_version must be a non-negative integer")
    if value.get("access_mode") == "none":
        if set(value) != {"access_mode", "expected_version"}:
            raise ValidationError("runtime access revocation has an invalid shape")
        return {"access_mode": "none", "expected_version": expected}
    if set(value) != _SHARE_FIELDS:
        raise ValidationError("access_config has missing or unknown fields")
    constants = {
        "provider": PROVIDER,
        "access_mode": ACCESS_MODE,
        "parameter_name": PARAMETER_NAME,
        "adapter_version": ADAPTER_VERSION,
        "auth_mode": AUTH_MODE,
    }
    for field, expected_value in constants.items():
        if value.get(field) != expected_value:
            raise ValidationError(f"access_config.{field} is not supported")
    secret = value.get("secret_value")
    if not isinstance(secret, str) or not secret or len(secret) > SECRET_MAX_LENGTH:
        raise ValidationError("access_config.secret_value is invalid")
    return {field: value[field] for field in _SHARE_FIELDS}


def _encryption_keys() -> tuple[dict[str, Any], str]:
    """Load independent versioned Fernet keys; configuration errors fail closed."""
    raw = os.environ.get(KEYS_ENV) or ""
    active_key_id = str(os.environ.get(ACTIVE_KEY_ENV) or "").strip()
    try:
        encoded = json.loads(raw)
        if not isinstance(encoded, dict) or not encoded:
            raise ValueError("empty key set")
        if not _KEY_ID_RE.fullmatch(active_key_id) or active_key_id not in encoded:
            raise ValueError("unknown active key")
        from cryptography.fernet import Fernet

        keys: dict[str, Any] = {}
        for key_id, key in encoded.items():
            if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
                raise ValueError("invalid key id")
            if not isinstance(key, str):
                raise ValueError("invalid key")
            keys[key_id] = Fernet(key.encode("ascii"))
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError):
        raise RuntimeError("runtime access encryption is not configured correctly") from None
    return keys, active_key_id


def encrypt_secret(secret: str) -> tuple[str, str]:
    keys, active_key_id = _encryption_keys()
    ciphertext = keys[active_key_id].encrypt(secret.encode("utf-8")).decode("ascii")
    return ciphertext, active_key_id


def decrypt_secret(ciphertext: str, key_id: str) -> str:
    keys, _ = _encryption_keys()
    if key_id not in keys:
        raise RuntimeError("runtime access secret cannot be decrypted")
    from cryptography.fernet import InvalidToken

    try:
        return keys[key_id].decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError, UnicodeError):
        raise RuntimeError("runtime access secret cannot be decrypted") from None


def _head_version(conn: sqlite3.Connection, catalog_agent_id: str) -> int:
    row = conn.execute(
        "select max(config_version) as version from runtime_access_configs where catalog_agent_id = ?",
        (catalog_agent_id,),
    ).fetchone()
    return int(row["version"] or 0)


def _config_row(
    conn: sqlite3.Connection, catalog_agent_id: str, config_version: int
) -> sqlite3.Row:
    row = conn.execute(
        "select * from runtime_access_configs where catalog_agent_id = ? and config_version = ?",
        (catalog_agent_id, config_version),
    ).fetchone()
    if row is None:
        raise NotFoundError("runtime access configuration not found")
    return row


def active_runtime_access(
    conn: sqlite3.Connection, catalog_agent_id: str
) -> sqlite3.Row | None:
    return conn.execute(
        "select * from runtime_access_configs where catalog_agent_id = ? and status = 'active'",
        (catalog_agent_id,),
    ).fetchone()


def latest_runtime_access(
    conn: sqlite3.Connection, catalog_agent_id: str
) -> sqlite3.Row | None:
    return conn.execute(
        "select * from runtime_access_configs where catalog_agent_id = ?"
        " order by config_version desc limit 1",
        (catalog_agent_id,),
    ).fetchone()


def public_projection(row: sqlite3.Row | None) -> dict[str, Any] | None:
    """Public Agent Record projection: active metadata only, never ciphertext."""
    if row is None or str(row["status"]) != "active":
        return None
    return {
        "provider": str(row["provider"]),
        "access_mode": str(row["access_mode"]),
        "parameter_name": str(row["parameter_name"]),
        "config_version": int(row["config_version"]),
        "adapter_version": str(row["adapter_version"]),
        "auth_mode": str(row["auth_mode"]),
    }


def merchant_projection(row: sqlite3.Row) -> dict[str, Any]:
    """Merchant status projection: includes state but never secret or ciphertext."""
    result = public_projection(row)
    if result is None:
        result = {
            "provider": str(row["provider"]),
            "access_mode": str(row["access_mode"]),
            "parameter_name": str(row["parameter_name"]),
            "config_version": int(row["config_version"]),
            "adapter_version": str(row["adapter_version"]),
            "auth_mode": str(row["auth_mode"]),
        }
    return {
        **result,
        "status": str(row["status"]),
        "validated_at": str(row["validated_at"]),
        "updated_at": str(row["updated_at"]),
    }


def buyer_projection(row: sqlite3.Row, *, runtime_origin: str) -> dict[str, Any]:
    """Controlled Buyer projection; callers must authorize session and follow first."""
    if str(row["status"]) != "active":
        raise NotFoundError("active runtime access configuration not found")
    return {
        "catalog_agent_id": str(row["catalog_agent_id"]),
        "runtime_origin": runtime_origin,
        "provider": str(row["provider"]),
        "access_mode": str(row["access_mode"]),
        "parameter_name": str(row["parameter_name"]),
        "secret_value": decrypt_secret(str(row["secret_ciphertext"]), str(row["key_id"])),
        "config_version": int(row["config_version"]),
        "adapter_version": str(row["adapter_version"]),
        "auth_mode": str(row["auth_mode"]),
        "validated_at": str(row["validated_at"]),
        "updated_at": str(row["updated_at"]),
    }


def row_secret(row: sqlite3.Row, *, statuses: frozenset[str] = frozenset({"pending", "active"})) -> str:
    """Decrypt for an internal challenge; rejected states are never used."""
    if str(row["status"]) not in statuses:
        raise ConflictError("runtime access configuration is not usable")
    return decrypt_secret(str(row["secret_ciphertext"]), str(row["key_id"]))


def stage_runtime_access(
    conn: sqlite3.Connection, *, catalog_agent_id: str, access_config: Any
) -> dict[str, Any]:
    """Insert a new pending version using the latest version as the CAS head."""
    config = parse_access_config(access_config)
    if config["access_mode"] == "none":
        raise ValidationError("use revoke_runtime_access for access_mode none")
    head = _head_version(conn, catalog_agent_id)
    if config["expected_version"] != head:
        raise ConflictError("runtime access version conflict")
    version = head + 1
    ciphertext, key_id = encrypt_secret(config["secret_value"])
    now = now_iso()
    conn.execute(
        "update runtime_access_configs set status = 'invalid', updated_at = ?"
        " where catalog_agent_id = ? and status = 'pending'",
        (now, catalog_agent_id),
    )
    conn.execute(
        "insert into runtime_access_configs (catalog_agent_id, config_version, provider,"
        " access_mode, parameter_name, secret_ciphertext, key_id, adapter_version, auth_mode,"
        " status, validated_at, created_at, updated_at)"
        " values (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', '', ?, ?)",
        (
            catalog_agent_id,
            version,
            config["provider"],
            config["access_mode"],
            config["parameter_name"],
            ciphertext,
            key_id,
            config["adapter_version"],
            config["auth_mode"],
            now,
            now,
        ),
    )
    return merchant_projection(_config_row(conn, catalog_agent_id, version))


def activate_runtime_access(
    conn: sqlite3.Connection, *, catalog_agent_id: str, config_version: int
) -> dict[str, Any]:
    """Atomically activate only the latest still-pending version after validation."""
    row = _config_row(conn, catalog_agent_id, config_version)
    if str(row["status"]) != "pending":
        raise ConflictError("runtime access configuration is not pending")
    if _head_version(conn, catalog_agent_id) != config_version:
        raise ConflictError("runtime access version conflict")
    now = now_iso()
    conn.execute(
        "update runtime_access_configs set status = 'revoked', updated_at = ?"
        " where catalog_agent_id = ? and status = 'active'",
        (now, catalog_agent_id),
    )
    changed = conn.execute(
        "update runtime_access_configs set status = 'active', validated_at = ?, updated_at = ?"
        " where catalog_agent_id = ? and config_version = ? and status = 'pending'",
        (now, now, catalog_agent_id, config_version),
    )
    if changed.rowcount != 1:
        raise ConflictError("runtime access configuration activation conflict")
    return merchant_projection(_config_row(conn, catalog_agent_id, config_version))


def invalidate_runtime_access(
    conn: sqlite3.Connection, *, catalog_agent_id: str, config_version: int
) -> dict[str, Any]:
    """Mark a failed pending version invalid without touching the old active row."""
    row = _config_row(conn, catalog_agent_id, config_version)
    if str(row["status"]) == "invalid":
        return merchant_projection(row)
    if str(row["status"]) != "pending":
        raise ConflictError("only a pending runtime access configuration can be invalidated")
    now = now_iso()
    conn.execute(
        "update runtime_access_configs set status = 'invalid', updated_at = ?"
        " where catalog_agent_id = ? and config_version = ? and status = 'pending'",
        (now, catalog_agent_id, config_version),
    )
    return merchant_projection(_config_row(conn, catalog_agent_id, config_version))


def revoke_runtime_access(
    conn: sqlite3.Connection, *, catalog_agent_id: str, access_config: Any
) -> dict[str, Any]:
    """Revoke the active configuration and make every outstanding pending row unusable."""
    config = parse_access_config(access_config)
    if config["access_mode"] != "none":
        raise ValidationError("access_mode none is required for revocation")
    if config["expected_version"] != _head_version(conn, catalog_agent_id):
        raise ConflictError("runtime access version conflict")
    active = active_runtime_access(conn, catalog_agent_id)
    if active is None:
        raise NotFoundError("active runtime access configuration not found")
    now = now_iso()
    conn.execute(
        "update runtime_access_configs set status = 'invalid', updated_at = ?"
        " where catalog_agent_id = ? and status = 'pending'",
        (now, catalog_agent_id),
    )
    conn.execute(
        "update runtime_access_configs set status = 'revoked', updated_at = ?"
        " where catalog_agent_id = ? and status = 'active'",
        (now, catalog_agent_id),
    )
    return merchant_projection(_config_row(conn, catalog_agent_id, int(active["config_version"])))


def active_public_projections(
    conn: sqlite3.Connection, catalog_agent_ids: list[str]
) -> dict[str, dict[str, Any]]:
    """Batch public lookup used by list serializers to avoid per-record queries."""
    ids = list(dict.fromkeys(str(value) for value in catalog_agent_ids if value))
    if not ids:
        return {}
    placeholders = ",".join("?" for _ in ids)
    rows = conn.execute(
        f"select * from runtime_access_configs where status = 'active'"
        f" and catalog_agent_id in ({placeholders})",
        ids,
    ).fetchall()
    return {
        str(row["catalog_agent_id"]): projection
        for row in rows
        if (projection := public_projection(row)) is not None
    }
