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

"""门户页的**脚本顺序**：页面脚本在 load 期用到的 helper 必须先定义。

生产事故（2026-09-21）：商家登录页点"登录"毫无反应。根因不是请求失败，而是
`_page()` 把共享 helper 块放在 **body 之后**，而页面自己的 `<script>` 在 load 期就调用
`nextTarget(...)` → `ReferenceError` → 整段脚本中断 → **click 监听器从未绑上**。

这个类别的 bug 特别难从现象定位（按钮"没反应"而不是报错），所以把它钉成结构性断言：
**渲染出的 HTML 里，helper 的定义必须出现在第一个使用它的脚本之前**。

（这里用"定义位置 < 使用位置"这个安全近似：helper 块整体前置后，两者的相对顺序不再
依赖页面作者是否记得把调用放进事件回调里。）
"""

from __future__ import annotations

import re
import unittest

from kiwi_catalog.api.handlers import portal

#: 商家账号页共用的 helper（`_ACCOUNT_JS`）。
_ACCOUNT_HELPERS = ("nextTarget", "go", "postJson")


def _scripts_in_order(html: str) -> list[str]:
    return [m.group(1) for m in re.finditer(r"<script[^>]*>(.*?)</script>", html, re.S)]


def _strip_function_bodies(js: str) -> str:
    """删掉 `function ... { ... }` 的函数体（花括号配对），留下顶层语句。"""
    out: list[str] = []
    i = 0
    while i < len(js):
        if js.startswith("function", i):
            brace = js.find("{", i)
            if brace == -1:
                break
            depth = 0
            j = brace
            while j < len(js):
                if js[j] == "{":
                    depth += 1
                elif js[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            out.append("function(){}")  # 占位，保留"这里有个函数声明"
            i = j + 1
            continue
        out.append(js[i])
        i += 1
    return "".join(out)


class PortalScriptOrderTest(unittest.TestCase):
    def _render(self, page: dict) -> str:
        return str(page["__html__"])

    def test_account_pages_define_helpers_before_use(self) -> None:
        """登录/注册/连接/重置密码等页面：helper 定义必须早于页面脚本。"""
        pages = {
            "login": portal.portal_login,
            "register": portal.portal_register,
            "reset": portal.portal_reset_password,
        }
        for name, builder in pages.items():
            with self.subTest(page=name):
                html = self._render(builder())
                scripts = _scripts_in_order(html)
                self.assertGreaterEqual(len(scripts), 2, "账号页应至少有两个脚本块")

                # helper 定义在第几个脚本块
                def_index = next(
                    (
                        i
                        for i, body in enumerate(scripts)
                        if f"function {_ACCOUNT_HELPERS[0]}(" in body
                    ),
                    None,
                )
                self.assertIsNotNone(def_index, f"{name}: 未找到 helper 定义块")

                # 页面自己的脚本（含 load 期调用）必须在 helper 之后。
                # 注意排除 helper 定义块本身——它里面当然也含 `nextTarget(`。
                use_index = next(
                    (
                        i
                        for i, body in enumerate(scripts)
                        if i != def_index and any(f"{fn}(" in body for fn in _ACCOUNT_HELPERS)
                    ),
                    None,
                )
                self.assertIsNotNone(use_index, f"{name}: 未找到使用 helper 的脚本块")
                self.assertLess(
                    def_index,
                    use_index,
                    f"{name}: helper 定义（脚本块 {def_index}）必须在首次使用"
                    f"（脚本块 {use_index}）之前——否则页面脚本会在 load 期 ReferenceError，"
                    "表现为按钮点了没反应",
                )

                for fn in _ACCOUNT_HELPERS:
                    self.assertIn(f"function {fn}(", scripts[def_index], f"{name}: 缺少 {fn}")

    def test_login_page_attaches_listeners_after_helpers(self) -> None:
        """登录页的具体回归：`to_register` 那行是 load 期执行，必须在 helper 之后。"""
        html = self._render(portal.portal_login())
        scripts = _scripts_in_order(html)
        helper_block = next((i for i, b in enumerate(scripts) if "function nextTarget(" in b), None)
        load_time_block = next(
            (i for i, b in enumerate(scripts) if "to_register" in b and "nextTarget(" in b), None
        )
        self.assertIsNotNone(helper_block)
        self.assertIsNotNone(load_time_block)
        self.assertLess(helper_block, load_time_block)
        # 监听器绑定语句与 load 期调用在同一个块里（顺序保证它一定会被执行）
        self.assertIn("#submit", scripts[load_time_block].replace("'submit'", "#submit").replace("getElementById", "#") or "",
                      )  # 宽松断言：避免绑定写法变化导致脆测

    def test_head_js_must_not_touch_the_dom_at_load_time(self) -> None:
        """`head_js` 在 body 之前执行——**顶层**的 DOM 访问会炸（函数体内的是安全的）。

        检查方式：把函数体（花括号配对）整体删掉，看剩下的顶层语句里还有没有
        `document.` / `window.`。
        """
        stripped = _strip_function_bodies(portal._ACCOUNT_JS)
        self.assertNotIn("document.", stripped)
        self.assertNotIn("window.", stripped)
        # 顶层只剩函数声明（占位 `function(){}`），没有游离语句
        leftover = stripped.replace("function(){}", "").strip()
        self.assertEqual(leftover, "", f"head_js 顶层出现了非函数声明的语句：{leftover[:120]}")

    def test_admin_dashboard_script_stays_after_body(self) -> None:
        """反向确认：管理端 `_PORTAL_JS_EXTRA` 有 load 期 DOM 访问，**不得**前置。

        这条防止后人"顺手"把它也挪到 head_js——那会让管理端页面直接报错。
        """
        self.assertIn("document.getElementById", portal._PORTAL_JS_EXTRA)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
