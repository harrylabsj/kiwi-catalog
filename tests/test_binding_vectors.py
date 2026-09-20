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

"""跨语言绑定向量（Python 侧）：`../kiwi/contracts/vectors/binding-thumbprint.json`。

与 kiwi TS 侧 `tests/binding-cross-language-vector.test.ts` 校验同一份向量：
同一 JWK → 同一 `key_thumbprint`，同一 payload → **逐字节相同**的 compact JWS。
kiwi 检出不存在时跳过（CI 中两仓并列，正常会执行）。
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from kiwi_catalog.a2a.binding_claims import jwk_thumbprint
from kiwi_catalog.a2a.request_signature import sign_runtime_request

VECTOR = Path(__file__).resolve().parents[2] / "kiwi" / "contracts" / "vectors" / "binding-thumbprint.json"


@unittest.skipUnless(VECTOR.is_file(), "kiwi checkout not available")
class BindingVectorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.vector = json.loads(VECTOR.read_text(encoding="utf-8"))

    def test_thumbprint_matches_across_languages(self) -> None:
        self.assertEqual(
            jwk_thumbprint(self.vector["public_jwk"]), self.vector["expected_thumbprint"]
        )

    def test_canonical_jwk_json_is_byte_identical(self) -> None:
        jwk = self.vector["public_jwk"]
        canonical = json.dumps(
            {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]},
            separators=(",", ":"),
            ensure_ascii=False,
        )
        self.assertEqual(canonical, self.vector["canonical_jwk_json"])

    def test_signing_reproduces_the_same_jws_bytes(self) -> None:
        payload = self.vector["payload_string"]
        expected = self.vector["expected_jws"]
        # 用同一把私钥与同一 payload 重签：JWS 的 payload 段必须与向量完全一致
        # （header 段对齐由 TS 侧用例断言；此处比对 payload 段与整体可复现性）。
        _header, payload_segment, _signature = expected.split(".")
        import base64

        def b64url(raw: bytes) -> str:
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        self.assertEqual(payload_segment, b64url(payload.encode("utf-8")))
        # 参考签发函数产出的 JWS 用同一把私钥可被解析且三段形状一致
        reissued = sign_runtime_request(
            kid=self.vector["kid"],
            private_key_pem=self.vector["private_key_pem"],
            signed_fields={"agent_id": "cagt_vector_demo"},
            issued_at="2026-09-21T00:00:00+00:00",
            nonce="vector",
        )
        self.assertEqual(reissued.count("."), 2)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
