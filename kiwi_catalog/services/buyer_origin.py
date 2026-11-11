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

"""买家来源（渠道）派生：运营侧回答「买家从哪里来」。

最小必要原则：只落一个**渠道标签**（如 ``workbuddy`` / ``web`` /
``openclaw``），不落完整 Referer、不落原始买家身份、不做地理定位。

来源判定优先级：
1. 显式 ``X-Buyer-Source`` 头（Host/连接器自报，最可靠）；
2. ``X-Buyer-Id`` 的渠道前缀（``workbuddy:<uuid>`` → ``workbuddy``）；
3. ``Origin`` / ``Referer`` 的 host（官网搜索 → ``web``）；
4. ``User-Agent`` 里的已知产品名；
5. ``unknown``。

所有输入都做归一化（小写、只留 ``[a-z0-9._-]``、截断 64 字符），因此
任意客户端都不能把敏感原文带进库。

注意：渠道标签是**客户端自报/启发式派生**的运营归因，不是身份或权限依据；
不能据此做鉴权、限流或商家可见性判断。
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

BUYER_SOURCE_UNKNOWN = "unknown"
_BUYER_SOURCE_CAP = 64
_SOURCE_RE = re.compile(r"[^a-z0-9._-]+")

#: 明确视为「官网/网页」的 host。
_WEB_HOSTS = frozenset(
    {
        "kiwi.harrylabsj.com",
        "www.kiwi.harrylabsj.com",
        "catalog.kiwi.harrylabsj.com",
        "localhost",
        "127.0.0.1",
    }
)

#: User-Agent 里可识别的产品名（小写子串 → 渠道标签）。
_UA_HINTS = (
    ("workbuddy", "workbuddy"),
    ("openclaw", "openclaw"),
    ("hermes", "hermes"),
    ("kiwi", "kiwi"),
    ("shopping-cli", "shopping-cli"),
    ("node", "node"),
)

#: ``X-Buyer-Id`` 里过于通用、不足以单独标识渠道的前缀；遇到时继续看
#: Referer/UA，避免所有默认客户端都被记成 ``buyer-agent``。
_GENERIC_ID_PREFIXES = frozenset({"buyer", "buyer-agent", "kiwi-mcp", "anonymous"})


def normalize_buyer_source(value: Any) -> str:
    """渠道标签归一化：小写、非法字符折成 ``-``、去首尾 ``-``、截断 64。"""
    text = str(value or "").strip().lower()
    if not text:
        return ""
    # 去掉常见的版本/参数后缀（如 ``OpenClaw/1.2``、``workbuddy;5.9``）：
    # 渠道标签只保留产品名，避免同一渠道因版本不同被拆成多行。
    text = text.split(";", 1)[0].split("/", 1)[0].strip()
    if not text:
        return ""
    text = _SOURCE_RE.sub("-", text).strip("-")
    return text[:_BUYER_SOURCE_CAP]


def _host_from_url(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        parts = urlsplit(raw if "://" in raw else f"//{raw}", scheme="https")
        host = (parts.hostname or "").strip().lower()
    except ValueError:
        return ""
    return host


def derive_buyer_source(headers: dict[str, str] | None) -> str:
    """从一个 HTTP 头 dict（小写键）派生渠道标签。绝不抛错。"""
    headers = headers or {}
    explicit = normalize_buyer_source(headers.get("x-buyer-source"))
    if explicit:
        return explicit

    buyer_id = str(headers.get("x-buyer-id") or "").strip()
    if ":" in buyer_id:
        prefix, suffix = buyer_id.split(":", 1)
        normalized_prefix = normalize_buyer_source(prefix)
        if normalized_prefix and normalized_prefix not in _GENERIC_ID_PREFIXES:
            return normalized_prefix
        # 过渡期：``buyer-agent:workbuddy`` 这类通用前缀 + 渠道名。
        lowered_suffix = suffix.lower()
        for needle, label in _UA_HINTS:
            if needle in lowered_suffix:
                return label

    for header_name in ("origin", "referer"):
        host = _host_from_url(str(headers.get(header_name) or ""))
        if not host:
            continue
        if host in _WEB_HOSTS:
            return "web"
        normalized = normalize_buyer_source(host)
        if normalized:
            return normalized

    user_agent = str(headers.get("user-agent") or "").lower()
    for needle, label in _UA_HINTS:
        if needle in user_agent:
            return label
    return BUYER_SOURCE_UNKNOWN


def buyer_source_from_payload(payload: dict[str, Any] | None) -> str:
    """从 transport 合并后的 payload 读取/派生渠道标签。

    双栈都会把 ``_buyer_source`` 注入 payload；缺失时回落到
    ``_buyer_id`` 的渠道前缀，再回落到 ``unknown``。
    """
    payload = payload or {}
    explicit = normalize_buyer_source(payload.get("_buyer_source"))
    if explicit:
        return explicit
    buyer_id = str(payload.get("_buyer_id") or "").strip()
    if ":" in buyer_id:
        prefix, suffix = buyer_id.split(":", 1)
        normalized_prefix = normalize_buyer_source(prefix)
        if normalized_prefix and normalized_prefix not in _GENERIC_ID_PREFIXES:
            return normalized_prefix
        lowered_suffix = suffix.lower()
        for needle, label in _UA_HINTS:
            if needle in lowered_suffix:
                return label
    return BUYER_SOURCE_UNKNOWN


__all__ = [
    "BUYER_SOURCE_UNKNOWN",
    "buyer_source_from_payload",
    "derive_buyer_source",
    "normalize_buyer_source",
]
