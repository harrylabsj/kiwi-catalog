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

"""T035「跨域 SSRF」的 Catalog 侧：绑定声明的端点安全策略。

两层判定的边界要在测试里说清楚：
  - 本模块覆盖**字面判定**（scheme / userinfo / IP 字面保留网段 / 保留主机名）；
  - **解析判定**（公共主机名解析到内网）不在本模块覆盖范围内，由连接时的
    DNS 复查兜底——所以这里**不**断言"example.com 一定安全"之外的任何事。
"""

from __future__ import annotations

import unittest

from kiwi_catalog.a2a.endpoint_policy import (
    assert_safe_binding_endpoint,
    assert_safe_binding_targets,
    unsafe_endpoint_reason,
)
from kiwi_catalog.core.errors import ValidationError


class EndpointPolicyTest(unittest.TestCase):
    def test_accepts_normal_public_https_targets(self) -> None:
        for url in (
            "https://pilot.example.app.workbuddy.host",
            "https://pilot.example.app.workbuddy.host/a2a",
            "https://merchant.example:8443/a2a",
            # 字面公网 IP：本层放行（是否真的可达/是否解析到内网由连接时复查）
            "https://8.8.8.8/a2a",
        ):
            with self.subTest(url=url):
                self.assertIsNone(unsafe_endpoint_reason(url))

    def test_rejects_reserved_ip_literals_with_stable_reasons(self) -> None:
        """只为措辞稳定的两条断言具体原因（其余按"被拒"断言，措辞随 Python 版本变）。"""
        for url, reason_part in (
            ("https://127.0.0.1/a2a", "loopback"),
            ("https://127.1.2.3/a2a", "loopback"),
            ("https://[::1]/a2a", "loopback"),
            ("https://169.254.169.254/latest/meta-data", "metadata"),
        ):
            with self.subTest(url=url):
                reason = unsafe_endpoint_reason(url)
                self.assertIsNotNone(reason, url)
                assert reason is not None
                self.assertIn(reason_part, reason)

    def test_rejects_every_other_reserved_literal(self) -> None:
        for url in (
            "https://10.0.0.5/a2a",
            "https://192.168.1.10/a2a",
            "https://172.16.9.9/a2a",
            "https://[fe80::1]/a2a",
            "https://[::ffff:10.0.0.5]/a2a",
            "https://[64:ff9b::10.0.0.5]/a2a",
        ):
            with self.subTest(url=url):
                self.assertIsNotNone(unsafe_endpoint_reason(url), url)

    def test_rejects_reserved_hostnames(self) -> None:
        for url in (
            "https://localhost/a2a",
            "https://LOCALHOST/a2a",
            "https://metadata.google.internal/computeMetadata/v1",
            "https://merchant.internal/a2a",
            "https://merchant.local/a2a",
            "https://api.localhost/a2a",
        ):
            with self.subTest(url=url):
                reason = unsafe_endpoint_reason(url)
                self.assertIsNotNone(reason, url)
                assert reason is not None
                self.assertIn("reserved hostname", reason)

    def test_trailing_dot_and_case_do_not_bypass(self) -> None:
        for url in ("https://localhost./a2a", "https://LocalHost/a2a", "https://10.0.0.5./a2a"):
            with self.subTest(url=url):
                self.assertIsNotNone(unsafe_endpoint_reason(url))

    def test_rejects_scheme_userinfo_and_malformed(self) -> None:
        self.assertIn("https", unsafe_endpoint_reason("http://merchant.example/a2a") or "")
        self.assertIn(
            "credentials", unsafe_endpoint_reason("https://user:pass@merchant.example/a2a") or ""
        )
        self.assertIsNotNone(unsafe_endpoint_reason(""))
        self.assertIsNotNone(unsafe_endpoint_reason("not a url"))
        self.assertIn("https", unsafe_endpoint_reason("ftp://merchant.example/a2a") or "")

    def test_assert_raises_validation_error_with_field_name(self) -> None:
        with self.assertRaises(ValidationError) as ctx:
            assert_safe_binding_endpoint("https://10.0.0.5/a2a", field="a2a_endpoint")
        self.assertIn("a2a_endpoint", str(ctx.exception))

    def test_assert_targets_checks_both_fields(self) -> None:
        safe = "https://pilot.example.app.workbuddy.host"
        assert_safe_binding_targets({"runtime_origin": safe, "a2a_endpoint": f"{safe}/a2a"})
        with self.assertRaises(ValidationError) as ctx:
            assert_safe_binding_targets(
                {"runtime_origin": "https://192.168.0.1", "a2a_endpoint": f"{safe}/a2a"}
            )
        self.assertIn("runtime_origin", str(ctx.exception))
        with self.assertRaises(ValidationError) as ctx2:
            assert_safe_binding_targets(
                {"runtime_origin": safe, "a2a_endpoint": "https://169.254.169.254/a2a"}
            )
        self.assertIn("a2a_endpoint", str(ctx2.exception))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
