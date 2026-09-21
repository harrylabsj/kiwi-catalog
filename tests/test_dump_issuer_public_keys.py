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

"""SIG-04 的**受控分发面**：导出发行者公钥集合（脚本行为）。

买方验签需要 kid → 公钥，而设计明确这份信任根必须来自受控渠道。因此这个脚本的
每条失败路径都必须是"退出并说清原因"，绝不允许：

  - 未配置时输出一份空集合冒充成功；
  - 输出里带上任何私钥痕迹；
  - 往不存在的目录写文件（静默换路径 = 分发物料去了别处）。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/dump_issuer_public_keys.py"


def _run(env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


class DumpIssuerPublicKeysTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        kids = []
        entries = []
        for index in range(2):
            key = Ed25519PrivateKey.generate()
            key_path = self.dir / f"issuer-{index}.pem"
            key_path.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
            entries.append(
                {
                    "kid": f"issuer-{index}",
                    "state": ["ACTIVE", "RETIRED"][index],
                    "private_key_file": str(key_path),
                }
            )
            kids.append(f"issuer-{index}")
        self.keys_file = self.dir / "issuer-keys.json"
        self.keys_file.write_text(json.dumps({"keys": entries}), encoding="utf-8")
        self.kids = kids

    def _env(self, **overrides: str) -> dict[str, str]:
        env = {
            "PATH": os.environ.get("PATH", ""),
            "KIWI_CATALOG_ISSUER_KEYS_FILE": str(self.keys_file),
            **overrides,
        }
        return env

    def test_emits_only_public_material(self) -> None:
        result = _run(self._env())
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(result.stdout)
        self.assertEqual(sorted(document["keys"]), self.kids)
        for kid, entry in document["keys"].items():
            self.assertIn(entry["state"], ("ACTIVE", "RETIRED"))
            self.assertEqual(sorted(entry["jwk"]), ["crv", "kty", "x"])
            self.assertEqual(entry["jwk"]["crv"], "Ed25519")
        for forbidden in ("PRIVATE KEY", '"d"', "private_key_file", self.tmp.name):
            self.assertNotIn(forbidden, result.stdout)

    def test_writes_to_explicit_out_path(self) -> None:
        out = self.dir / "public-keys.json"
        result = _run(self._env(), "--out", str(out))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(out.is_file())
        self.assertEqual(sorted(json.loads(out.read_text())["keys"]), self.kids)

    def test_unconfigured_exits_nonzero_without_emitting_anything(self) -> None:
        result = _run({"PATH": os.environ.get("PATH", "")})
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("not usable", result.stderr)

    def test_missing_output_directory_is_refused(self) -> None:
        out = self.dir / "nope" / "public-keys.json"
        result = _run(self._env(), "--out", str(out))
        self.assertEqual(result.returncode, 2)
        self.assertFalse(out.exists())

    def test_single_key_env_still_works(self) -> None:
        """单密钥 env 形态（M3 现有部署）也能导出——否则分发面只覆盖一半部署。"""
        key_path = self.dir / "single.pem"
        key_path.write_bytes(
            Ed25519PrivateKey.generate().private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            )
        )
        result = _run(
            {
                "PATH": os.environ.get("PATH", ""),
                "KIWI_CATALOG_ISSUER_KEY_FILE": str(key_path),
                "KIWI_CATALOG_ISSUER_KID": "single-kid",
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(result.stdout)
        self.assertEqual(list(document["keys"]), ["single-kid"])
        self.assertEqual(document["keys"]["single-kid"]["state"], "ACTIVE")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
