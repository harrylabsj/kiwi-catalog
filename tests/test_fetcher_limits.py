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

"""fetcher 异常面回归测试（审查 P1-2）。

恶意源站可触发的两类未捕获异常（深嵌套 JSON 的 RecursionError、非法端口
URL 的 ValueError）必须映射为类型化错误，不得以 500 逃逸验证管线。
"""

from __future__ import annotations

import http.client
import unittest
from unittest import mock

from kiwi_catalog.discovery.fetcher import (
    FetchLimitError,
    ProfileFetcher,
    SSRFBlockError,
    _port_of,
)
from kiwi_catalog.discovery.trust import TrustPolicy


class PortHelperTest(unittest.TestCase):
    def test_invalid_port_raises_ssrf_error_not_valueerror(self) -> None:
        import urllib.parse

        parsed = urllib.parse.urlparse("https://host.example:abc/")
        with self.assertRaises(SSRFBlockError):
            _port_of(parsed, "https")

    def test_valid_port_and_defaults(self) -> None:
        import urllib.parse

        self.assertEqual(_port_of(urllib.parse.urlparse("https://h.example:8443/"), "https"), 8443)
        self.assertEqual(_port_of(urllib.parse.urlparse("https://h.example/"), "https"), 443)
        self.assertEqual(_port_of(urllib.parse.urlparse("http://h.example/"), "http"), 80)


class DeepNestedJsonTest(unittest.TestCase):
    def test_deeply_nested_json_maps_to_fetch_limit_error(self) -> None:
        """审查 P1-2：深度防护在 parse 之后，解析阶段的 RecursionError 必须
        映射为 FetchLimitError（此前逐级逃逸成 500）。"""
        depth = 300_000  # Python 3.14 约 25 万层即触发 RecursionError
        body = ("[" * depth + "]" * depth).encode()

        class _FakeResponse:
            status = 200

            def getheaders(self) -> list[tuple[str, str]]:
                return [("content-type", "application/json")]

            def read(self, _n: int = -1) -> bytes:
                return body

        fetcher = ProfileFetcher(TrustPolicy.defaults())
        with mock.patch(
            "kiwi_catalog.discovery.fetcher._read_limited", return_value=body
        ):
            with self.assertRaises(FetchLimitError):
                fetcher._process_response(_FakeResponse(), "https://h.example/x.json", 0.0)


if __name__ == "__main__":
    unittest.main()
