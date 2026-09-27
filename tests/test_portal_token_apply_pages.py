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

    def test_home_and_apply_are_one_button_no_writable_input(self) -> None:
        """首页与 /portal/apply：只剩只读展示 input，按钮「申请目录令牌」。"""
        for html in (self._html(portal_home), self._html(portal_apply)):
            inputs = _page_inputs(html)
            self.assertTrue(inputs, "只读的商家 ID/名称展示字段应保留")
            for tag in inputs:
                self.assertIn("readonly", tag, tag)
            self.assertIn("申请目录令牌", html)
            self.assertIn("postJson('/v1/accounts/token-request', {})", html)
            self.assertNotIn("t_domain", html)

    def test_account_page_has_no_input_at_all(self) -> None:
        """「我的」页：申请区零 input（申请表单已整体移除）。"""
        html = self._html(portal_account)
        self.assertEqual(_page_inputs(html), [])
        self.assertNotIn("a_domain", html)
        self.assertNotIn("apply_form", html)
        self.assertNotIn("show_apply", html)

    def test_four_state_branches_present_on_both_pages(self) -> None:
        """四态分支（无工单 / pending / active / 被拒）两页一致。"""
        for html in (self._html(portal_home), self._html(portal_account)):
            self.assertIn("申请目录令牌", html)  # 无令牌无工单：按钮可点
            self.assertIn("审核中", html)  # pending：禁用 + 文案
            self.assertIn("可发布（目录侧）", html)
            self.assertIn("待配置", html)
            self.assertIn("Catalog 无法确认本地配置状态", html)
            self.assertIn("r.token.token", html)  # 仅本人已认证的 /me 页面可见
            self.assertIn("复制令牌", html)
            self.assertIn("token-box", html)
            self.assertIn("重新申请", html)  # 被拒：理由 + 重新申请
            self.assertIn("review_note", html)
            self.assertIn("postJson('/v1/accounts/token-request', {})", html)

    def test_home_keeps_fail_closed_guides(self) -> None:
        """未分配商家 ID / 未填商家名称的禁用与引导保留（服务端 fail-closed 不变）。"""
        html = self._html(portal_home)
        self.assertIn("尚未分配商家 ID", html)
        self.assertIn("尚未填写商家名称", html)
        self.assertIn("/portal/register", html)
        self.assertIn("/portal/account/profile", html)

    def test_dashboard_pending_list_placeholder_for_empty_domain(self) -> None:
        with mock.patch.dict(os.environ, _ENABLED, clear=False):
            html = self._html(portal_dashboard)
        self.assertIn("a.domain || '(未填)'", html)


if __name__ == "__main__":
    unittest.main()
