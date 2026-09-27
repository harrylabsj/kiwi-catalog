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

"""「我的名片」只读页测试（P0；设计 §5.1）。

覆盖：
- 页面 200 且含四块（待确认接入请求 / 名片状态 / 运行时绑定 / 名片内容）
  与「未创建接入记录」空态（创建按钮 + V0 公开资料降级说明）；
- 未登录跳登录（沿用 /v1/accounts/me 检查模式）；CSP nonce 体系；
- 门户不产出内容：无「编辑/生成名片」按钮，唯一的写动作是
  POST /v1/accounts/agents（创建接入记录）；
- 商家后台二级导航四个页面都有「我的名片」入口。
"""

from __future__ import annotations

import re
import unittest

from kiwi_catalog.api.handlers import portal


def _html(handler) -> str:
    page = handler()
    if "__html__" not in page:
        raise AssertionError(f"no __html__ in {page}")
    return str(page["__html__"])


class PortalCardPageTest(unittest.TestCase):
    def test_card_page_has_four_blocks_and_empty_states(self) -> None:
        html = _html(portal.portal_account_card)
        # 四块自上而下
        for block in ("status_card", "binding_card", "content_card"):
            self.assertIn(f'id="{block}"', html)
        self.assertIn("接入方式", html)
        self.assertIn("名片状态", html)
        self.assertIn("运行时绑定", html)
        self.assertIn("名片内容（公开字段）", html)
        # 空态文案齐全：未创建 / 未绑定 / 未发布 / 已发布各态
        self.assertIn("还没有接入记录", html)
        self.assertIn("未绑定运行时", html)
        self.assertIn("还没有发布的名片", html)
        self.assertIn("已发布 ACTIVE", html)
        self.assertIn("已暂停 PAUSED", html)
        self.assertIn("已撤回 WITHDRAWN", html)
        # 无运行时商家的 V0 降级路径（指向公开资料），无「直接生成名片」按钮
        self.assertIn("/portal/publications", html)
        self.assertNotIn("生成名片", html)
        self.assertNotIn("编辑名片", html)
        # 公开字段说明
        self.assertIn("这些字段与公开读地址一致，任何人都能看到", html)

    def test_card_page_create_button_and_apis(self) -> None:
        html = _html(portal.portal_account_card)
        self.assertIn('id="create_agent"', html)
        self.assertIn("创建接入记录", html)
        self.assertIn("postJson('/v1/accounts/agents', {})", html)
        self.assertIn("'/v1/accounts/agents'", html)  # GET 列表
        self.assertIn("/card'", html)  # GET 详情
        # 复制地址 / 查看原始 JSON
        self.assertIn("复制地址", html)
        self.assertIn("查看原始 JSON", html)

    def test_card_page_login_check_and_csp(self) -> None:
        html = _html(portal.portal_account_card)
        # 未登录跳登录（/v1/accounts/me 检查模式，与「我的」一致）
        self.assertIn("/v1/accounts/me", html)
        self.assertIn("/portal/login", html)
        # CSP nonce 体系：meta CSP + 内嵌脚本带 nonce
        self.assertIn("Content-Security-Policy", html)
        self.assertRegex(html, r'script-src \'nonce-[^\' ]+\'')
        self.assertTrue(re.search(r"<script nonce=\"[^\"]+\">", html))

    def test_card_page_dynamic_values_escaped(self) -> None:
        """动态值一律经页面内 esc 转义，不注入 HTML。"""
        html = _html(portal.portal_account_card)
        self.assertIn("function esc(s)", html)
        # 服务端值进 innerHTML 前都过 esc
        self.assertIn("esc(d.card_url)", html)
        self.assertIn("esc(b.runtime_origin)", html)
        self.assertIn("esc(card.name)", html)

    def test_subnav_has_card_link_on_account_pages(self) -> None:
        """商家后台二级导航：基本信息/令牌信息/公开资料/我的关注四页都有「我的名片」。"""
        pages = (
            portal.portal_account,
            portal.portal_account_profile,
            portal.portal_publications,
            portal.portal_follows,
        )
        for handler in pages:
            with self.subTest(page=handler.__name__):
                html = _html(handler)
                self.assertIn('href="/portal/account/card"', html)
                self.assertIn("我的名片", html)
        # 本页高亮
        html = _html(portal.portal_account_card)
        self.assertIn('href="/portal/account/card" class="active"', html)

    def test_governance_buttons_by_state(self) -> None:
        """治理按钮（P1；设计 §5.1）：ACTIVE→暂停+撤回，PAUSED→恢复+撤回，WITHDRAWN→只说明。"""
        html = _html(portal.portal_account_card)
        for marker in ("gov_pause", "gov_resume", "gov_withdraw"):
            self.assertIn(marker, html)
        # 三个治理端点（URL 由 JS 拼接 '/card/' + action）+ CAS 参数
        self.assertIn("'/card/' + action", html)
        for action in ("pause", "resume", "withdraw"):
            self.assertIn(f"'{action}'", html)
        self.assertIn("expected_revision", html)
        # 状态分支显隐逻辑
        self.assertIn("pub.state === 'ACTIVE'", html)
        self.assertIn("pub.state === 'PAUSED'", html)
        self.assertIn("pub.state === 'WITHDRAWN'", html)
        # 撤回的确认提示（不可逆感）
        self.assertIn("window.confirm", html)
        self.assertIn("确认撤回", html)
        # WITHDRAWN 后只有说明，无动作
        self.assertIn("名片已撤回", html)
        self.assertIn("重新上线需要你的运行时重新发布并激活", html)
        # 治理动作回执与错误展示
        self.assertIn("操作失败", html)

    def test_card_page_has_no_second_binding_confirmation(self) -> None:
        """首次绑定授权合并到公开预览确认页。"""
        html = _html(portal.portal_account_card)
        self.assertIn("可从互联网访问的 HTTPS 地址", html)
        self.assertNotIn("确认接入", html)
        self.assertNotIn("/bindings/", html)


if __name__ == "__main__":
    unittest.main()
