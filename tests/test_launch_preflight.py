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

"""上线预检（A40-3）测试：issuer 身份与 KIWI_CATALOG_PUBLIC_ORIGIN 缺失/非法
必须**显式失败可见**（固定 code + 可读 detail），消除签发静默 403 盲区。

覆盖：
  - 双项全过：报告 OK 且带 kid/thumbprint/origin 公开元数据；
  - 缺 origin（A37 事故形态）→ PUBLIC_ORIGIN_REJECTED，detail 指明 env 名；
  - origin 非法（http / 带路径）→ PUBLIC_ORIGIN_REJECTED；
  - 缺 issuer → ISSUER_KEY_REJECTED；密钥集合无 ACTIVE → ISSUER_KEY_REJECTED；
  - 预检自身不抛异常（任何配置问题都折叠为报告项）；
  - CLI：`--check-config` 通过退出 0 / 失败退出 1。
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from kiwi_catalog.a2a.binding_claims import (
    ISSUER_KEY_FILE_ENV,
    ISSUER_KID_ENV,
    ISSUER_KEYS_FILE_ENV,
    PUBLIC_ORIGIN_ENV,
)
from kiwi_catalog.a2a.launch_preflight import (
    ISSUER_KEY_CHECK,
    ISSUER_KEY_REJECTED,
    PUBLIC_ORIGIN_CHECK,
    PUBLIC_ORIGIN_REJECTED,
    format_preflight_lines,
    issuance_preflight,
    preflight_failed,
)

ORIGIN = "https://catalog.example"


def _write_key(dir_path: Path, name: str) -> Path:
    key = Ed25519PrivateKey.generate()
    path = dir_path / name
    path.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    return path


def _ok_env(dir_path: Path) -> dict[str, str]:
    return {
        ISSUER_KEY_FILE_ENV: str(_write_key(dir_path, "issuer.pem")),
        ISSUER_KID_ENV: "kid-preflight-01",
        PUBLIC_ORIGIN_ENV: ORIGIN,
    }


class IssuancePreflightTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def _check(self, checks: list[dict], name: str) -> dict:
        matches = [check for check in checks if check["check"] == name]
        self.assertEqual(len(matches), 1, f"expected exactly one {name} check: {checks}")
        return matches[0]

    def test_all_configured_passes_with_public_metadata(self) -> None:
        checks = issuance_preflight(_ok_env(self.dir))
        self.assertFalse(preflight_failed(checks))
        issuer = self._check(checks, ISSUER_KEY_CHECK)
        self.assertTrue(issuer["ok"])
        self.assertEqual(issuer["kid"], "kid-preflight-01")
        self.assertTrue(issuer["thumbprint"].startswith("sha256:"))
        origin = self._check(checks, PUBLIC_ORIGIN_CHECK)
        self.assertTrue(origin["ok"])
        self.assertEqual(origin["origin"], ORIGIN)

    def test_missing_public_origin_fails_explicitly(self) -> None:
        env = _ok_env(self.dir)
        del env[PUBLIC_ORIGIN_ENV]
        checks = issuance_preflight(env)
        self.assertTrue(preflight_failed(checks))
        origin = self._check(checks, PUBLIC_ORIGIN_CHECK)
        self.assertFalse(origin["ok"])
        self.assertEqual(origin["code"], PUBLIC_ORIGIN_REJECTED)
        self.assertIn(PUBLIC_ORIGIN_ENV, origin["detail"])
        # issuer 项不受影响，仍通过（逐项独立，便于一次看清全部缺口）。
        self.assertTrue(self._check(checks, ISSUER_KEY_CHECK)["ok"])

    def test_invalid_public_origin_fails_explicitly(self) -> None:
        for bad in ("http://catalog.example", "https://catalog.example/v1/", "not a url"):
            with self.subTest(bad=bad):
                checks = issuance_preflight({**_ok_env(self.dir), PUBLIC_ORIGIN_ENV: bad})
                origin = self._check(checks, PUBLIC_ORIGIN_CHECK)
                self.assertFalse(origin["ok"])
                self.assertEqual(origin["code"], PUBLIC_ORIGIN_REJECTED)

    def test_missing_issuer_fails_explicitly(self) -> None:
        env = _ok_env(self.dir)
        del env[ISSUER_KEY_FILE_ENV]
        checks = issuance_preflight(env)
        self.assertTrue(preflight_failed(checks))
        issuer = self._check(checks, ISSUER_KEY_CHECK)
        self.assertFalse(issuer["ok"])
        self.assertEqual(issuer["code"], ISSUER_KEY_REJECTED)
        self.assertTrue(self._check(checks, PUBLIC_ORIGIN_CHECK)["ok"])

    def test_key_set_without_active_key_fails_explicitly(self) -> None:
        key_path = _write_key(self.dir, "retired.pem")
        keys_file = self.dir / "issuer-keys.json"
        keys_file.write_text(
            json.dumps({"keys": [{"kid": "kid-old", "state": "RETIRED", "private_key_file": str(key_path)}]}),
            encoding="utf-8",
        )
        checks = issuance_preflight(
            {**_ok_env(self.dir), ISSUER_KEYS_FILE_ENV: str(keys_file)}
        )
        issuer = self._check(checks, ISSUER_KEY_CHECK)
        self.assertFalse(issuer["ok"])
        self.assertEqual(issuer["code"], ISSUER_KEY_REJECTED)

    def test_report_lines_contain_no_secret_material(self) -> None:
        checks = issuance_preflight(_ok_env(self.dir))
        text = "\n".join(format_preflight_lines(checks))
        self.assertIn("[OK]", text)
        # 私钥文件路径绝不进入报告（detail 只含签发路径的拒签文本）。
        self.assertNotIn(".pem", text)

    def test_empty_env_never_raises(self) -> None:
        checks = issuance_preflight({})
        self.assertTrue(preflight_failed(checks))
        self.assertEqual(len(checks), 2)


class CheckConfigCliTest(unittest.TestCase):
    """`kiwi-catalog-api --check-config` 的退出码契约。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def _run(self, env: dict[str, str]) -> int:
        import io
        from contextlib import redirect_stdout
        from unittest import mock

        from kiwi_catalog.scripts import kiwi_catalog_api

        buf = io.StringIO()
        with mock.patch.dict("os.environ", env, clear=False):
            with mock.patch("sys.argv", ["kiwi-catalog-api", "--check-config"]):
                with redirect_stdout(buf):
                    try:
                        kiwi_catalog_api.main()
                    except SystemExit as exc:
                        return int(exc.code or 0)
        return 0

    def test_exit_zero_when_configured(self) -> None:
        self.assertEqual(self._run(_ok_env(self.dir)), 0)

    def test_exit_one_when_origin_missing(self) -> None:
        env = _ok_env(self.dir)
        del env[PUBLIC_ORIGIN_ENV]
        self.assertEqual(self._run(env), 1)


if __name__ == "__main__":
    unittest.main()
