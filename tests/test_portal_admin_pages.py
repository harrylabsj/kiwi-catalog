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

"""运营 portal 页面测试（2026-09-26 增强）。

覆盖：
- 商家详情页 /portal/merchant/<id>：可下钻、带 token 面板与报告渲染器，且
  **不把 merchant_id 注入 HTML**（JS 从 location.pathname 取，零注入面）；
- 某日搜索页 /portal/day/<day>：日期选择器 + buyer-day API 调用；
- 两页在 env 开关关闭时 404（与其它 admin 页一致）；
- Dashboard：商家列表含「注册邮箱」列与详情链接、日期可点、同页报告卡片已移除；
- 共享的 admin token 面板（记住/修改/清除）出现在各 admin 页。
"""

from __future__ import annotations

import os
import unittest
from unittest import mock

from kiwi_catalog.api.handlers.portal import (
    portal_admin,
    portal_admin_searches,
    portal_dashboard,
    portal_day,
    portal_merchant,
)

_ENABLED = {"KIWI_CATALOG_PORTAL_ADMIN_ENABLED": "1"}


class PortalPageTest(unittest.TestCase):
    def _html(self, handler, *args) -> str:
        page = handler(*args)
        self.assertIn("__html__", page, page)
        return page["__html__"]

    def _assert_404_when_disabled(self, handler, *args) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("KIWI_CATALOG_PORTAL_ADMIN_ENABLED", None)
            page = handler(*args)
        self.assertEqual(page.get("__status__"), 404)
        self.assertIn("页面不存在", page.get("__html__", ""))

    # ── 商家详情页 ────────────────────────────────────────────────────────

    def test_merchant_page_renders_and_does_not_embed_id(self) -> None:
        with mock.patch.dict(os.environ, _ENABLED, clear=False):
            html = self._html(portal_merchant, "mkt_acme_abc123")
        self.assertIn("商家详情", html)
        self.assertIn("/v1/admin/merchants/", html)  # 走的仍是同一条 admin API
        self.assertIn("reportHtml", html)  # 复用 dashboard 的报告渲染器
        self.assertIn('href="/portal/dashboard"', html)  # 可返回
        # 零注入面：merchant_id 由 JS 从路径取，不出现在 HTML 里
        self.assertNotIn("mkt_acme_abc123", html)

    def test_merchant_page_hidden_by_default(self) -> None:
        self._assert_404_when_disabled(portal_merchant, "mkt_acme_abc123")

    # ── 某日搜索页 ────────────────────────────────────────────────────────

    def test_day_page_renders_date_picker(self) -> None:
        with mock.patch.dict(os.environ, _ENABLED, clear=False):
            html = self._html(portal_day, "2026-09-25")
        self.assertIn("某日买家搜索", html)
        self.assertIn('id="day_pick"', html)
        self.assertIn("/v1/admin/buyer-day?day=", html)
        self.assertIn("/portal/day/", html)  # 切换日期整页跳转
        self.assertNotIn("2026-09-25", html)  # 同样不注入日期到 HTML
        self.assertIn("events_note", html)  # 裁剪说明的渲染分支存在

    def test_day_page_hidden_by_default(self) -> None:
        self._assert_404_when_disabled(portal_day, "2026-09-25")

    # ── Dashboard 增强 ────────────────────────────────────────────────────

    def test_dashboard_list_has_email_column_and_detail_link(self) -> None:
        with mock.patch.dict(os.environ, _ENABLED, clear=False):
            html = self._html(portal_dashboard)
        self.assertIn("注册邮箱", html)
        self.assertIn("account_email", html)
        self.assertIn('href="/portal/merchant/', html)  # 行末「详情」是链接

    def test_dashboard_dates_are_links(self) -> None:
        with mock.patch.dict(os.environ, _ENABLED, clear=False):
            html = self._html(portal_dashboard)
        self.assertIn('href="/portal/day/', html)

    def test_dashboard_report_card_removed(self) -> None:
        """同页报告卡片已由独立详情页取代，不再残留容器与返回按钮。"""
        with mock.patch.dict(os.environ, _ENABLED, clear=False):
            html = self._html(portal_dashboard)
        self.assertNotIn('id="report_card"', html)
        self.assertNotIn('id="report_back"', html)

    # ── 共享 token 面板 ───────────────────────────────────────────────────

    def test_token_panel_available_on_admin_pages(self) -> None:
        with mock.patch.dict(os.environ, _ENABLED, clear=False):
            for html in (
                self._html(portal_admin),
                self._html(portal_admin_searches),
                self._html(portal_dashboard),
                self._html(portal_merchant, "mkt_x"),
                self._html(portal_day, "2026-09-25"),
            ):
                self.assertIn("mountAdminTokenPanel", html)
                self.assertIn("storedAdminToken", html)
                self.assertIn("adminToken()", html)  # 各页读取统一走它
                # 服务器端轮换入口（2026-09-26）：与"只改本浏览器"的「更换」并存
                self.assertIn("admin_token_rotate_toggle", html)
                self.assertIn("/v1/admin/token/rotate", html)


if __name__ == "__main__":
    unittest.main()
