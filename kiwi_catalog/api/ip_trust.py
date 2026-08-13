"""客户端 IP 解析（审查 C-M2）。

``X-Forwarded-For`` 首跳此前被直接采信——直连部署下客户端自设 XFF 即可轮换
IP 绕过 per-IP 限流分桶（fallback ASGI 与 FastAPI 双栈同款）。仅在直连对端
属于已知可信代理（默认回环——catalog 通常位于本地反代之后）时才采信 XFF；
否则一律用直连对端，忽略客户端可控的 XFF。
"""

from __future__ import annotations

import os

_DEFAULT_TRUSTED_PROXIES = frozenset({"127.0.0.1", "::1"})


def resolve_client_ip(xff: str, direct_peer: str | None) -> str:
    """解析客户端 IP（限流分桶键）。

    - 直连对端是可信代理（``KIWI_CATALOG_TRUSTED_PROXIES``，缺省回环）→ 采信
      XFF 首跳（代理链记录的客户端 IP）；
    - 否则忽略 XFF，用直连对端——直连客户端无法伪造 XFF 轮换 IP。
    """
    raw = os.environ.get("KIWI_CATALOG_TRUSTED_PROXIES", "")
    trusted = (
        frozenset(p.strip().lower() for p in raw.split(",") if p.strip())
        if raw.strip()
        else _DEFAULT_TRUSTED_PROXIES
    )
    peer = (direct_peer or "").strip()
    if peer and peer.lower() in trusted and xff.strip():
        first = xff.split(",")[0].strip()
        if first:
            return first
    return peer
