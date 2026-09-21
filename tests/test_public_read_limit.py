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

"""M3 公开读地址的限流（计划 B3）。

稳定读地址是匿名可读的，所以预算按**客户端 IP** 分桶；绑定声明这一侧尤其重要——
每次读取都要做一次 Ed25519 签名。配置缺失或误配（0/负数/非数字）一律回退默认，
绝不因为环境变量写错而静默关闭限流。
"""

from __future__ import annotations

import os
import tempfile
import unittest

from kiwi_catalog.a2a.public_read_limit import (
    enforce_public_read_limit,
    public_read_limit_per_minute,
)
from kiwi_catalog.core.errors import RateLimitError
from kiwi_catalog.db.session import db_session


class PublicReadLimitTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = os.path.join(self.tmp.name, "catalog.sqlite")
        # 建表（真实会话会跑迁移）
        with db_session(self.db):
            pass

    def test_missing_or_misconfigured_env_falls_back_to_default(self) -> None:
        from kiwi_catalog.a2a.public_read_limit import _DEFAULT_PER_MINUTE

        for env in ({}, {"KIWI_CATALOG_PUBLIC_READ_RATE_LIMIT_PER_MINUTE": ""}, {"KIWI_CATALOG_PUBLIC_READ_RATE_LIMIT_PER_MINUTE": "0"}, {"KIWI_CATALOG_PUBLIC_READ_RATE_LIMIT_PER_MINUTE": "-5"}, {"KIWI_CATALOG_PUBLIC_READ_RATE_LIMIT_PER_MINUTE": "abc"}):
            with self.subTest(env=env):
                self.assertEqual(public_read_limit_per_minute(env), _DEFAULT_PER_MINUTE)

    def test_configured_limit_is_honored(self) -> None:
        self.assertEqual(
            public_read_limit_per_minute({"KIWI_CATALOG_PUBLIC_READ_RATE_LIMIT_PER_MINUTE": "7"}),
            7,
        )

    def test_budget_is_bucketed_per_client_ip(self) -> None:
        with db_session(self.db) as conn:
            for _ in range(3):
                enforce_public_read_limit(
                    conn, {"_client_ip": "203.0.113.7"}, surface="agent-card read", limit=3
                )
            with self.assertRaises(RateLimitError):
                enforce_public_read_limit(
                    conn, {"_client_ip": "203.0.113.7"}, surface="agent-card read", limit=3
                )
            # 另一个 IP 有自己的桶，不受影响
            enforce_public_read_limit(
                conn, {"_client_ip": "203.0.113.8"}, surface="agent-card read", limit=3
            )

    def test_surfaces_do_not_share_a_bucket(self) -> None:
        with db_session(self.db) as conn:
            enforce_public_read_limit(conn, {"_client_ip": "10.0.0.1"}, surface="a", limit=1)
            # 另一个 surface 独立计数
            enforce_public_read_limit(conn, {"_client_ip": "10.0.0.1"}, surface="b", limit=1)

    def test_missing_client_ip_still_counts(self) -> None:
        """缺 IP **不等于**无限额：退化为 unknown 桶，仍受同一预算约束。"""
        with db_session(self.db) as conn:
            enforce_public_read_limit(conn, {}, surface="runtime-binding read", limit=2)
            enforce_public_read_limit(conn, None, surface="runtime-binding read", limit=2)
            with self.assertRaises(RateLimitError):
                enforce_public_read_limit(conn, {}, surface="runtime-binding read", limit=2)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
