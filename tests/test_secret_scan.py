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

"""scan_secrets 隔离上限回归测试（审查 P1-1）。

cap 命中必须 fail-closed：第 65 个起的 secret 字段一旦被静默放行，
`_skip()` 判「未隔离」→ 凭据进入 public 投影并落库（泄漏路径）。
"""

from __future__ import annotations

import unittest

from kiwi_catalog.discovery._validation import ProfileValidationError, scan_secrets


def _service(name: str) -> dict:
    return {"name": name, "description": f"sk-{'A' * 24}"}


class SecretScanTest(unittest.TestCase):
    def test_within_cap_returns_all_paths(self) -> None:
        profile = {"services": [_service(f"s{i}") for i in range(64)]}
        paths = scan_secrets(profile)
        self.assertEqual(len(paths), 64)
        self.assertEqual(paths[0], "services.0.description")

    def test_at_cap_exactly_does_not_raise(self) -> None:
        profile = {"services": [_service(f"s{i}") for i in range(64)]}
        self.assertEqual(len(scan_secrets(profile)), 64)

    def test_over_cap_dict_fails_closed(self) -> None:
        profile = {"services": [_service(f"s{i}") for i in range(65)]}
        with self.assertRaises(ProfileValidationError):
            scan_secrets(profile)

    def test_over_cap_across_list_fails_closed(self) -> None:
        # 64 个 secret 在 dict 分支 + 1 个在 list 分支：两处 cap 检查都必须生效
        profile = {
            "services": [_service(f"s{i}") for i in range(64)],
            "endpoints": [{"access": {"token": "Bearer AAAABBBB"}}],
        }
        with self.assertRaises(ProfileValidationError):
            scan_secrets(profile)

    def test_no_secrets_returns_empty(self) -> None:
        self.assertEqual(scan_secrets({"name": "x", "services": [{"name": "y"}]}), [])

    def test_custom_cap_honored(self) -> None:
        profile = {"services": [_service(f"s{i}") for i in range(3)]}
        with self.assertRaises(ProfileValidationError):
            scan_secrets(profile, max_secrets=2)
        self.assertEqual(len(scan_secrets(profile, max_secrets=3)), 3)


if __name__ == "__main__":
    unittest.main()
