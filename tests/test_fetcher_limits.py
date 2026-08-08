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


class HttpSchemeSupportTest(unittest.TestCase):
    def test_http_scheme_has_a_real_handler(self) -> None:
        """审查 P2（http 支持真实化）：opener 必须注册 HTTP 处理器——此前
        恒走 UnknownHandler（``unknown url type: http``），permissive_local
        声明的 http:// 实际永远失败。

        SSRF 校验器用 stub（blocklist 对 loopback 是绝对策略，即便
        permissive_local 也拦截——此处只验证协议接线，不绕过校验语义）。
        """
        import http.server
        import ipaddress
        import threading

        from kiwi_catalog.discovery.fetcher import _build_opener

        body = b'{"name": "local-agent", "version": "1.0"}'

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: Any) -> None:  # noqa: A002
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]

            def _stub_validator(_url: str) -> ipaddress.IPv4Address:
                return ipaddress.IPv4Address("127.0.0.1")

            opener = _build_opener(
                initial_verified_ip="127.0.0.1",
                initial_hostname="127.0.0.1",
                initial_port=port,
                redirect_limit=5,
                redirect_validator=_stub_validator,
            )
            with opener.open(f"http://127.0.0.1:{port}/card.json", timeout=5) as resp:
                self.assertEqual(resp.status, 200)
                self.assertEqual(resp.read(), body)
        finally:
            server.shutdown()
            server.server_close()


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
