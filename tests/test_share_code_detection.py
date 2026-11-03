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

"""分享码 URL 判定的服务端回归测试（全部使用合成值，不含真实凭据）。

覆盖：大小写、片段、有界重复百分号编码、嵌套 URL（编码后的第二个
``?sharecode=``），以及 ``safe_public_shop_url`` / ``sanitize_share_code_urls``
的读侧兜底。
"""

from __future__ import annotations

import json
import unittest

from kiwi_catalog.services.merchant_publications import (
    contains_share_code_link,
    contains_share_code_payload,
    contains_share_code_url,
    safe_public_shop_url,
    sanitize_share_code_urls,
)

SECRET = "SYNTH-SHARE-CODE-ONLY"


class ShareCodeDetectionTest(unittest.TestCase):
    def test_case_variants_and_fragment(self) -> None:
        for url in (
            f"https://shop.example.com/item?sharecode={SECRET}",
            f"https://shop.example.com/item?share_code={SECRET}",
            f"https://shop.example.com/item?share-code={SECRET}",
            f"https://shop.example.com/item?ShareCode={SECRET}",
            f"https://shop.example.com/item?SHARE_CODE={SECRET}",
            f"https://shop.example.com/item#sharecode={SECRET}",
            f"https://shop.example.com/item#x?Share-Code={SECRET}",
        ):
            self.assertTrue(contains_share_code_url(url), url)
            self.assertEqual(safe_public_shop_url(url), "", url)

    def test_bounded_repeated_percent_encoding(self) -> None:
        encoded = "%73harecode"  # sharecode
        double = "%2573harecode"
        triple = "%252573harecode"
        for url in (
            f"https://shop.example.com/item?{encoded}={SECRET}",
            f"https://shop.example.com/{double}/{SECRET}",
            f"https://shop.example.com/item?{triple}={SECRET}",
            f"https://shop.example.com/item?share%5Fcode={SECRET}",
            f"https://shop.example.com/item?share%2Dcode={SECRET}",
        ):
            self.assertTrue(contains_share_code_url(url), url)
            self.assertEqual(safe_public_shop_url(url), "", url)

    def test_over_decode_limit_fails_closed(self) -> None:
        """超过解码层数上限仍可解码 → 按危险处理（不猜剩余内容）。"""
        six = "%73harecode"
        for _ in range(5):
            six = six.replace("%", "%25")
        seven = six.replace("%", "%25")
        ten = seven
        for _ in range(3):
            ten = ten.replace("%", "%25")
        nested = f"https%3A%2F%2Fgate.example%2F%3Fsharecode%3D{SECRET}"
        deep_nested = nested
        for _ in range(7):
            deep_nested = deep_nested.replace("%", "%25")
        for url in (
            f"https://shop.example.com/item?{six}={SECRET}",
            f"https://shop.example.com/item?{seven}={SECRET}",
            f"https://shop.example.com/item?{ten}={SECRET}",
            f"https://shop.example.com/redirect?next={deep_nested}",
            f"https://shop.example.com/redirect#next={deep_nested}",
        ):
            self.assertTrue(contains_share_code_url(url), url)
            self.assertEqual(safe_public_shop_url(url), "", url)

    def test_mixed_and_multi_round_encoding(self) -> None:
        for url in (
            f"https://shop.example.com/item?s%68are%63ode={SECRET}",
            f"https://shop.example.com/item?share%5fcode={SECRET}",
            f"https://shop.example.com/item?next=%253Fsharecode%253D{SECRET}",
            f"https://shop.example.com/%252573harecode/{SECRET}",
        ):
            self.assertTrue(contains_share_code_url(url), url)
            self.assertEqual(safe_public_shop_url(url), "", url)

    def test_decode_input_length_is_bounded(self) -> None:
        oversized_url = "https://shop.example.com/item?id=" + "a" * 300_000
        self.assertTrue(contains_share_code_url(oversized_url))
        self.assertTrue(contains_share_code_link(oversized_url))
        self.assertEqual(safe_public_shop_url(oversized_url), "")

    def test_nested_url_and_encoded_second_query(self) -> None:
        nested = f"https%3A%2F%2Fgate.example%2F%3Fsharecode%3D{SECRET}"
        double_nested = nested.replace("%", "%25")
        for url in (
            f"https://shop.example.com/redirect?next={nested}",
            f"https://shop.example.com/redirect?next={double_nested}",
            f"https://shop.example.com/redirect#next={nested}",
        ):
            self.assertTrue(contains_share_code_url(url), url)
            self.assertEqual(safe_public_shop_url(url), "", url)

    def test_plain_public_urls_remain_valid(self) -> None:
        for url in (
            "https://shop.example.com/item/1?id=42",
            "https://shop.example.com/item/1#details",
            "https://shop.example.com/shareholder/report",
        ):
            self.assertFalse(contains_share_code_url(url), url)
            self.assertEqual(safe_public_shop_url(url), url)

    def test_text_and_payload_sanitizers(self) -> None:
        bad = f"https://shop.example.com/a?sharecode={SECRET}"
        text = f"详情见 {bad}。"
        self.assertTrue(contains_share_code_link(text))
        self.assertTrue(contains_share_code_payload({"nested": [{"url": bad}]}))
        cleaned = sanitize_share_code_urls(
            {"summary": text, "handoff": bad, "normal": "https://shop.example.com/item/1"}
        )
        rendered = json.dumps(cleaned)
        self.assertNotIn(SECRET, rendered)
        self.assertEqual(cleaned["handoff"], "")
        self.assertIn("[链接已移除]", cleaned["summary"])
        self.assertEqual(cleaned["normal"], "https://shop.example.com/item/1")


if __name__ == "__main__":
    unittest.main()
