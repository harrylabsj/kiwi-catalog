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

"""Unified device pairing and single business confirmation portal."""

from __future__ import annotations

import unittest

from kiwi_catalog.api.handlers import portal


class PortalConnectConfirmationTest(unittest.TestCase):
    def test_connect_page_loads_frozen_preview_and_requires_explicit_action(self) -> None:
        html = portal.portal_enrollment_connect("enroll-123")["__html__"]
        self.assertIn("连接此服务并发布", html)
        self.assertIn("enroll-123", html)
        self.assertIn("/v1/accounts/enrollments/", html)
        self.assertIn("public_preview", html)
        self.assertIn("user_code", html)
        self.assertIn("将此配对码与刚才运行 Runtime 的终端显示内容核对", html)
        self.assertIn("JSON.stringify({user_code: code})", html)
        self.assertIn("connect_authorize", html)
        self.assertIn("credentials: 'same-origin'", html)
        self.assertIn("Content-Security-Policy", html)

    def test_connect_page_does_not_auto_approve_or_expose_credentials(self) -> None:
        html = portal.portal_enrollment_connect("enroll-safe")["__html__"]
        self.assertIn("'/authorize'", html)
        self.assertNotIn("device_code", html)
        self.assertNotIn("grant", html.lower())
        self.assertNotIn("private_key", html.lower())
        self.assertIn("connect_authorize').disabled = !d.user_code", html)
        self.assertIn("addEventListener('click'", html)

    def test_connect_page_html_escapes_enrollment_id_attribute(self) -> None:
        html = portal.portal_enrollment_connect(
            'bad" autofocus="true"><script>alert(1)</script>'
        )["__html__"]
        self.assertIn(
            'data-enrollment-id="bad&quot; autofocus=&quot;true&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"',
            html,
        )
        self.assertIn(
            "const enrollmentId = document.getElementById('connect_state').dataset.enrollmentId;",
            html,
        )
        self.assertNotIn('<script>alert(1)</script>', html)

    def test_connect_page_has_https_recovery_guidance(self) -> None:
        html = portal.portal_enrollment_connect("enroll-safe")["__html__"]
        self.assertIn("可从互联网访问的 HTTPS 地址", html)
        self.assertIn("重新检查", html)
        self.assertIn("稍后继续", html)
        self.assertIn("配置公网 HTTPS 入口", html)


if __name__ == "__main__":
    unittest.main()
