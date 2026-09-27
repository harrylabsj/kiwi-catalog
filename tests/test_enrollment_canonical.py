# Copyright 2026 harrylabsj
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""跨语言接入摘要固定向量与拒绝边界；向量由实际 TS canonicalize 对照。"""

import hashlib
import unittest

from kiwi_catalog.a2a.enrollment_canonical import canonical_bytes, canonical_digest
from kiwi_catalog.core.errors import ValidationError


class EnrollmentCanonicalTest(unittest.TestCase):
    def test_unicode_uses_utf16_key_order_and_literal_unicode(self):
        value = {"\ue000": "last", "😀": "商家\u2028\u2029", "a": 'quote"\n\\'}
        expected = '{"a":"quote\\\"\\n\\\\","😀":"商家\u2028\u2029","\ue000":"last"}'.encode()
        self.assertEqual(canonical_bytes(value), expected)
        self.assertEqual(canonical_digest(value), "sha256:" + hashlib.sha256(expected).hexdigest())

    def test_numbers_match_kiwi_wire_convention(self):
        values = [0, -0.0, 1.0, 1e-6, 1e-7, 1.234e-7, 333333333.33333329,
                  9007199254740991, 1e15, 5e-324, True, None]
        self.assertEqual(
            canonical_bytes(values),
            b'[0,-0,1,0.000001,1e-7,1.234e-7,333333333.3333333,9007199254740991,1000000000000000,5e-324,true,null]',
        )

    def test_invalid_values_rejected(self):
        for value in [float("nan"), float("inf"), 2**53, 1e20, "\ud800", {1: "bad"}, object()]:
            with self.subTest(value=repr(value)), self.assertRaises(ValidationError):
                canonical_bytes(value)

    def test_nesting_limit(self):
        value = None
        for _ in range(34):
            value = [value]
        with self.assertRaises(ValidationError):
            canonical_bytes(value)

    def test_object_order_is_irrelevant_but_value_changes_are_not(self):
        self.assertEqual(canonical_digest({"z": 2, "a": 1}), canonical_digest({"a": 1, "z": 2}))
        self.assertNotEqual(canonical_digest({"a": 1}), canonical_digest({"a": 2}))
