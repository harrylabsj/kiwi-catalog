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

"""绑定声明的端点安全策略（M3 / T035「跨域 SSRF」的 Catalog 侧）。

Runtime 在**创建绑定时**声明 `runtime_origin` / `a2a_endpoint`，Catalog 在**签发
声明时**把它们交给 Buyer。这两处都必须拒绝危险目标——否则 Catalog 会成为
"把 Buyer 指向内网/metadata 端点"的替罪羊。

判定分两层，本模块只做**第一层（确定性、无网络 I/O）**：

1. **字面判定**（本模块）：scheme、userinfo、IP 字面量落在保留网段
   （loopback/私网/link-local/cloud metadata/IPv4-mapped/NAT64 内嵌……复用
   `discovery.fetcher._is_blocked_ip` 的完整黑名单）、保留主机名。
2. **解析判定**（连接时，不在本模块）：公共主机名解析到内网地址的情况只能靠
   DNS 复查发现——Catalog 的出站抓取走 `discovery.fetcher`（先解析再按 IP 校验，
   且禁跳转），Buyer 侧走 `assertResolvableTargetUrl`。**本模块不假装覆盖它**。

因此绑定校验是"必要不充分"：通过本模块只说明"字面上不是危险目标"。
"""

from __future__ import annotations

import ipaddress
import urllib.parse
from typing import Any

from kiwi_catalog.core.errors import ValidationError

#: 保留主机名（大小写不敏感；按后缀匹配）。这些名字在云环境里恒等于控制面。
_RESERVED_HOSTNAMES = (
    "localhost",
    "metadata.google.internal",
    "metadata.goog",
)
_RESERVED_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".home.arpa",
)


def _hostname_reason(hostname: str) -> str | None:
    host = hostname.strip().lower().rstrip(".")
    if host == "":
        return "empty hostname"
    for name in _RESERVED_HOSTNAMES:
        if host == name:
            return f"reserved hostname {name}"
    for suffix in _RESERVED_SUFFIXES:
        if host.endswith(suffix):
            return f"reserved hostname suffix {suffix}"
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return None  # 普通主机名：交由连接时的 DNS 复查
    from kiwi_catalog.discovery.fetcher import _is_blocked_ip

    return _is_blocked_ip(ip)


def unsafe_endpoint_reason(value: str) -> str | None:
    """返回拒绝原因；None 表示"字面上安全"。**不做网络 I/O**。"""
    raw = str(value or "").strip()
    if raw == "":
        return "empty URL"
    try:
        parsed = urllib.parse.urlsplit(raw)
    except ValueError as exc:
        return f"unparsable URL ({exc})"
    if parsed.scheme != "https":
        return f"scheme must be https (got {parsed.scheme or 'none'!r})"
    if parsed.username or parsed.password:
        return "must not embed credentials (userinfo)"
    if not parsed.hostname:
        return "missing hostname"
    if parsed.port is not None and not (1 <= parsed.port <= 65535):
        return f"invalid port {parsed.port}"
    return _hostname_reason(parsed.hostname)


def assert_safe_binding_endpoint(value: str, *, field: str) -> str:
    """校验绑定声明里的 URL 字段；不安全即 ValidationError（fail-closed）。"""
    reason = unsafe_endpoint_reason(value)
    if reason is not None:
        raise ValidationError(f"binding.{field} is not a safe target: {reason}")
    return str(value).strip()


def assert_safe_binding_targets(binding: dict[str, Any]) -> None:
    """一次性校验 `runtime_origin` / `a2a_endpoint`（绑定创建与签发共用）。"""
    assert_safe_binding_endpoint(str(binding.get("runtime_origin") or ""), field="runtime_origin")
    assert_safe_binding_endpoint(str(binding.get("a2a_endpoint") or ""), field="a2a_endpoint")
