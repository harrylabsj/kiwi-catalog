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

"""admin token 校验口径的静态守卫（开源仓侧）。

admin token 的轮换端点与运营 API 已移至私有扩展 kiwi-catalog-admin
（docs/extensions.md），轮换语义测试随之迁入私有仓。本仓保留的 admin
token 使用面只有 moderation 路径（agent_catalog suspend/reinstate/verify/
claim、listings owner 豁免、cloud_binding 运维兜底、merchants self 的
admin 分支），它们读同一凭据口径（api/auth.py effective_admin_digest：
轮换行 > env 引导）。

静态检查守住：所有 ``require_admin_token`` 调用点必须带第二个参数
（db_path 或 conn）——漏传 = 该端点只认 env 引导值，凭据一旦轮换就
口径分裂。
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


class RequireAdminTokenCallSiteGuard(unittest.TestCase):
    def test_every_require_admin_token_call_passes_db_context(self) -> None:
        """所有调用点都必须带第二个参数（db_path 或 conn）。

        漏传 = 该端点只认 env 引导值 → 轮换后旧值在那条路径上复活。这是
        **静态**检查（不依赖端点数得全），先例：仓库里的双栈路由 parity 断言。
        """
        root = Path(__file__).resolve().parent.parent / "kiwi_catalog"
        offenders: list[str] = []
        call = re.compile(r"require_admin_token\(([^)]*)\)")
        for path in root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for match in call.finditer(text):
                args = match.group(1).strip()
                if args.endswith("payload") or args.endswith("auth_payload") or args.endswith("{}"):
                    offenders.append(f"{path.relative_to(root.parent)}: {match.group(0)}")
        self.assertEqual(offenders, [], "这些 require_admin_token 调用点漏传了 db 上下文")


if __name__ == "__main__":
    unittest.main()
