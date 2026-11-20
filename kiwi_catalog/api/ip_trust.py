"""客户端 IP 解析（审查 C-M2）。

``X-Forwarded-For`` 首跳此前被直接采信——直连部署下客户端自设 XFF 即可轮换
IP 绕过 per-IP 限流分桶（fallback ASGI 与 FastAPI 双栈同款）。仅在直连对端
属于已知可信代理（默认回环——catalog 通常位于本地反代之后）时才采信 XFF；
否则一律用直连对端，忽略客户端可控的 XFF。
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

_DEFAULT_TRUSTED_PROXIES = frozenset({"127.0.0.1", "::1"})


def resolve_asgi_client_ip(scope: Mapping[str, Any]) -> str:
    """Resolve the peer from the ordered forwarding chain in ASGI headers."""
    xff = ",".join(
        value.decode("latin1")
        for name, value in scope.get("headers", ())
        if name.lower() == b"x-forwarded-for"
    )
    client = scope.get("client")
    return resolve_client_ip(xff, str(client[0] or "") if client else None)


def resolve_client_ip(xff: str, direct_peer: str | None) -> str:
    """解析客户端 IP（限流分桶键）。

    - 直连对端是可信代理（回环及 ``KIWI_CATALOG_TRUSTED_PROXIES`` 附加地址）→
      从右向左取 XFF 中第一个非可信代理地址；
    - 否则忽略 XFF，用直连对端——直连客户端无法伪造 XFF 轮换 IP。
    """
    raw = os.environ.get("KIWI_CATALOG_TRUSTED_PROXIES", "")
    trusted = _DEFAULT_TRUSTED_PROXIES | {p.strip().lower() for p in raw.split(",") if p.strip()}
    peer = (direct_peer or "").strip()
    if peer and peer.lower() in trusted and xff.strip():
        # 审查 P2：取**最右**的非可信代理地址——代理把真实对端追加在右侧，
        # 左侧条目客户端可伪造/轮换。从右往左跳过已知可信代理。
        hops = [item.strip() for item in xff.split(",") if item.strip()]
        for candidate in reversed(hops):
            if candidate.lower() not in trusted:
                return candidate
    return peer
