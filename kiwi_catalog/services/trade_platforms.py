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

"""交易平台规则（运营后台可配置）。

商家导入商品时只提供「交易平台 + 平台商品 ID」，商品链接由服务端按这里
维护的模板生成；平台允许范围不再硬编码为京东/淘宝/天猫。每条规则包含：

- ``id``：稳定标识（小写 slug，商家导入与链接生成使用）
- ``label``：展示名（如 京东）
- ``domain``：可信域名（校验模板 host；如 jd.com）
- ``url_template``：https 链接模板，必须包含且只包含 ``{id}`` 占位符
- ``enabled`` / ``sort_order``：运营开关与排序

商家上传完整链接的路径已关闭；这里生成的链接是唯一入口。
"""

from __future__ import annotations

import re
import sqlite3
from typing import Any
from urllib.parse import urlsplit

from kiwi_catalog.core.errors import ConflictError, NotFoundError, ValidationError
from kiwi_catalog.db.session import now_iso

_ID_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_DOMAIN_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_PLACEHOLDER_RE = re.compile(r"\{[^}]*\}")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_PRODUCT_ID_RE = re.compile(r"^[1-9][0-9]*$")
_MAX_TEMPLATE = 512
_MAX_LABEL = 64

_COLUMNS = (
    "id",
    "label",
    "domain",
    "url_template",
    "enabled",
    "sort_order",
    "created_at",
    "updated_at",
)


def _project(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    data = {key: row[key] for key in _COLUMNS}
    data["enabled"] = bool(data["enabled"])
    return data


def list_platforms(
    conn: sqlite3.Connection, *, enabled_only: bool = False
) -> list[dict[str, Any]]:
    query = (
        "select id, label, domain, url_template, enabled, sort_order, created_at, updated_at"
        " from trade_platform_rules"
    )
    if enabled_only:
        query += " where enabled = 1"
    query += " order by sort_order, id"
    return [_project(row) for row in conn.execute(query).fetchall()]


def get_platform(conn: sqlite3.Connection, platform_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "select id, label, domain, url_template, enabled, sort_order, created_at, updated_at"
        " from trade_platform_rules where id = ?",
        (platform_id,),
    ).fetchone()
    return None if row is None else _project(row)


def _clean_label(value: Any) -> str:
    text = str(value or "").strip()
    if text == "":
        raise ValidationError("平台名称不能为空")
    if len(text) > _MAX_LABEL:
        raise ValidationError(f"平台名称最多 {_MAX_LABEL} 个字符")
    if _CONTROL_RE.search(text):
        raise ValidationError("平台名称不能包含控制字符")
    return text


def _clean_domain(value: Any) -> str:
    text = str(value or "").strip().lower().rstrip(".")
    if "://" in text or "/" in text or ":" in text:
        raise ValidationError("域名只填主机名，例如 jd.com（不要带协议、路径或端口）")
    if not _DOMAIN_RE.fullmatch(text):
        raise ValidationError("域名格式不合法，例如 jd.com")
    return text


def _clean_template(value: Any, domain: str) -> str:
    text = str(value or "").strip()
    if text == "":
        raise ValidationError("链接模板不能为空")
    if len(text) > _MAX_TEMPLATE:
        raise ValidationError(f"链接模板最多 {_MAX_TEMPLATE} 个字符")
    if _CONTROL_RE.search(text):
        raise ValidationError("链接模板不能包含控制字符")
    placeholders = set(_PLACEHOLDER_RE.findall(text))
    if placeholders != {"{id}"}:
        raise ValidationError(
            "链接模板必须包含且只包含 {id} 占位符（例：https://item.jd.com/{id}.html）"
        )
    parts = urlsplit(text)
    if parts.scheme != "https":
        raise ValidationError("链接模板必须以 https:// 开头")
    if parts.username or parts.password:
        raise ValidationError("链接模板不能包含用户名或密码")
    host = (parts.hostname or "").lower()
    if host != domain and not host.endswith("." + domain):
        raise ValidationError(f"链接模板的域名必须匹配所配置的域名（{domain}）")
    return text


def _clean_enabled(value: Any, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if value in (0, 1):
        return bool(value)
    raise ValidationError("enabled 必须是布尔值")


def _clean_sort_order(value: Any, default: int = 0) -> int:
    if value is None:
        return default
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError("sort_order 必须是整数") from exc
    if number < 0 or number > 1_000_000:
        raise ValidationError("sort_order 必须在 0..1000000 之间")
    return number


def _clean_platform_id(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not _ID_RE.fullmatch(text):
        raise ValidationError("平台 ID 必须是以小写字母开头的 1-32 位 slug（a-z0-9_-）")
    return text


def _fields(
    payload: dict[str, Any],
    *,
    existing: dict[str, Any] | None = None,
) -> dict[str, Any]:
    def pick(key: str, fallback: Any) -> Any:
        return payload[key] if key in payload else fallback

    label = _clean_label(pick("label", existing["label"] if existing else None))
    domain = _clean_domain(pick("domain", existing["domain"] if existing else None))
    template = _clean_template(
        pick("url_template", existing["url_template"] if existing else None), domain
    )
    return {
        "label": label,
        "domain": domain,
        "url_template": template,
        "enabled": _clean_enabled(
            pick("enabled", existing["enabled"] if existing else True)
        ),
        "sort_order": _clean_sort_order(
            pick("sort_order", existing["sort_order"] if existing else 0)
        ),
    }


def create_platform(conn: sqlite3.Connection, payload: dict[str, Any]) -> dict[str, Any]:
    platform_id = _clean_platform_id(payload.get("id"))
    fields = _fields(payload)
    now = now_iso()
    try:
        conn.execute(
            "insert into trade_platform_rules"
            " (id, label, domain, url_template, enabled, sort_order, created_at, updated_at)"
            " values (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                platform_id,
                fields["label"],
                fields["domain"],
                fields["url_template"],
                int(fields["enabled"]),
                fields["sort_order"],
                now,
                now,
            ),
        )
    except sqlite3.IntegrityError as exc:
        raise ConflictError(f"交易平台 {platform_id} 已存在") from exc
    conn.commit()
    created = get_platform(conn, platform_id)
    assert created is not None
    return created


def update_platform(
    conn: sqlite3.Connection, platform_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    existing = get_platform(conn, platform_id)
    if existing is None:
        raise NotFoundError(f"交易平台 {platform_id} 不存在")
    fields = _fields(payload, existing=existing)
    conn.execute(
        "update trade_platform_rules"
        " set label = ?, domain = ?, url_template = ?, enabled = ?, sort_order = ?,"
        " updated_at = ? where id = ?",
        (
            fields["label"],
            fields["domain"],
            fields["url_template"],
            int(fields["enabled"]),
            fields["sort_order"],
            now_iso(),
            platform_id,
        ),
    )
    conn.commit()
    updated = get_platform(conn, platform_id)
    assert updated is not None
    return updated


def delete_platform(conn: sqlite3.Connection, platform_id: str) -> None:
    if get_platform(conn, platform_id) is None:
        raise NotFoundError(f"交易平台 {platform_id} 不存在")
    conn.execute("delete from trade_platform_rules where id = ?", (platform_id,))
    conn.commit()


def build_product_url(platform_id: str, product_id: str, template: str, domain: str) -> str:
    """把平台商品 ID 代入运营配置的模板，并再次校验生成结果的域名。"""
    if not _PRODUCT_ID_RE.fullmatch(str(product_id)):
        raise ValidationError("平台商品ID必须为ASCII正整数字符串")
    url = template.replace("{id}", str(product_id))
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or (host != domain and not host.endswith("." + domain)):
        raise ValidationError("生成的商品链接不在该平台的可信域名内")
    return url
