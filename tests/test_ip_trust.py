"""客户端 IP 解析（审查 C-M2）：XFF 首跳仅在可信代理时采信。

- 直连对端非可信代理 → 忽略客户端可控 XFF，用直连对端（防伪造 XFF 轮换 IP
  绕过 per-IP 限流分桶）；
- 直连对端可信（缺省回环）→ 采信 XFF 首跳（代理链记录的客户端 IP）；
- ``KIWI_CATALOG_TRUSTED_PROXIES`` env 可扩展可信代理。
"""

import os
import unittest
from unittest.mock import patch

from kiwi_catalog.api.ip_trust import resolve_client_ip


class ResolveClientIpTest(unittest.TestCase):
    def test_direct_peer_not_trusted_ignores_spoofed_xff(self) -> None:
        # 直连对端非可信代理：客户端自设 XFF 轮换 IP 被忽略。
        self.assertEqual(resolve_client_ip("1.2.3.4", "192.0.2.1"), "192.0.2.1")
        self.assertEqual(resolve_client_ip("9.9.9.9", "198.51.100.7"), "198.51.100.7")

    def test_trusted_loopback_peer_reads_xff_first_hop(self) -> None:
        # 直连对端是回环（可信代理缺省）→ 采信 XFF 首跳（代理记录的客户端）。
        self.assertEqual(resolve_client_ip("203.0.113.9, 127.0.0.1", "127.0.0.1"), "203.0.113.9")

    def test_trusted_proxies_env_extends_allowlist(self) -> None:
        with patch.dict(os.environ, {"KIWI_CATALOG_TRUSTED_PROXIES": "10.0.0.5"}):
            self.assertEqual(resolve_client_ip("203.0.113.9", "10.0.0.5"), "203.0.113.9")
            self.assertEqual(resolve_client_ip("203.0.113.9", "192.0.2.1"), "192.0.2.1")

    def test_no_direct_peer_returns_empty(self) -> None:
        self.assertEqual(resolve_client_ip("1.2.3.4", None), "")


if __name__ == "__main__":
    unittest.main()
