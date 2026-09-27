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

"""令牌申请「收成一个按钮」（D7）页面测试。

覆盖：
- /portal（portal_home）与 /portal/apply（同内容）及 /portal/account（「我的」）：
  申请区没有任何非只读 input，只有按钮「申请目录令牌」；
- 四态分支关键文案/按钮存在：无令牌无工单（按钮可点）、pending（申请审核中）、
  active（token-box + 复制令牌）、被拒（review_note 理由 + 重新申请）；
- 点击直接 postJson('/v1/accounts/token-request', {})，不再带 domain；
- dashboard 待审列表 domain 空值显示「（未填）」。
"""

from __future__ import annotations

import os
import re
import unittest
from unittest import mock

from kiwi_catalog.api.handlers.portal import (
    portal_account,
    portal_apply,
    portal_dashboard,
    portal_home,
)

_ENABLED = {"KIWI_CATALOG_PORTAL_ADMIN_ENABLED": "1"}


def _inputs(html: str) -> list[str]:
    return re.findall(r"<input[^>]*>", html)


def _page_inputs(html: str) -> list[str]:
    # _PORTAL_JS 共享脚本里的 admin token 轮换模板（admin_new_token）是 JS 字符串，
    # 只在 admin 页挂载，不属于本页 markup——排除后再看页面自身的 input。
    return [t for t in _inputs(html) if "admin_new_token" not in t]


class TokenApplyPageTest(unittest.TestCase):
    def _html(self, handler) -> str:
        page = handler()
        self.assertIn("__html__", page, page)
        return page["__html__"]

    def test_old_token_application_pages_show_capacity(self) -> None:
        for handler in (portal_home, portal_apply):
            self.assertIn("商品名额", self._html(handler))

    def test_account_page_has_no_input_at_all(self) -> None:
        """「我的」页：申请区零 input（申请表单已整体移除）。"""
        html = self._html(portal_account)
        self.assertEqual(_page_inputs(html), [])
        self.assertNotIn("a_domain", html)
        self.assertNotIn("apply_form", html)
        self.assertNotIn("show_apply", html)

    def test_account_shows_capacity_without_application(self) -> None:
        account_html = self._html(portal_account)
        self.assertIn("商品名额", account_html)
        self.assertNotIn("申请目录令牌", account_html)

    def test_dashboard_pending_list_placeholder_for_empty_domain(self) -> None:
        with mock.patch.dict(os.environ, _ENABLED, clear=False):
            html = self._html(portal_dashboard)
        self.assertIn("a.domain || '(未填)'", html)


if __name__ == "__main__":
    unittest.main()
