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

"""A16：enrollment 绑定拒绝/失败的固定诊断码与超时包装回归。

生产 0.5.3 事件（08:31:41Z 授权成功后 bind 连续 403、挑战出口 TLS 握手超时
漏成未处理 500）暴露两个缺口：

1. 服务端对 403 拒绝不落任何应用级日志——线上无法定责到具体分支；
2. ``ProfileFetcher._make_request`` 不收敛 ``urllib.error.URLError``，
   TLS/连接层失败漏成 500（``_fetch`` 的 GET 路径有收敛，POST 没有）。

本文件只断言：每个拒绝分支落**固定自有码 + 安全阶段**、不泄漏 grant/JWS；
网络错误被包装为既有 FetchError → 409；响应体不含异常原文；真实绑定成功
回归不被破坏。
"""

from __future__ import annotations

import hashlib
import json
import time
import unittest
import urllib.error
from datetime import UTC, datetime, timedelta
from unittest import mock

from kiwi_catalog.a2a.enrollment_canonical import canonical_digest
from kiwi_catalog.discovery import fetcher as fetcher_module
from kiwi_catalog.discovery.fetcher import FetchError, FetchResult, ProfileFetcher

from tests.test_cloud_binding import _call, _jws
from tests.test_enrollment_security import (
    A2A_ENDPOINT,
    RUNTIME_ORIGIN,
    EnrollmentFixture,
)

_LOG_NAME = "kiwi_catalog.api.handlers.cloud_binding"


class EnrollmentBindDenialDiagnosticsTest(EnrollmentFixture):
    """403 各拒绝分支：状态码、响应文案不变；日志落固定码 + 阶段；无秘密泄漏。"""

    def _signed_bind_body(self, enrollment_id: str, grant: str, **binding_overrides):
        binding = {
            "runtime_origin": RUNTIME_ORIGIN,
            "a2a_endpoint": A2A_ENDPOINT,
            "key_jwk": self.jwk,
            "key_id": RUNTIME_ORIGIN,
            "generation": 1,
            "service_epoch": 7,
            **binding_overrides,
        }
        body = {"enrollment_id": enrollment_id, "grant": grant, "binding": binding}
        binding_sig = _jws(self.private_pem, RUNTIME_ORIGIN, {
            "method": "POST", "path": f"/v1/agents/{self.agent_id}/runtime-bindings",
            "audience": "kiwi-catalog", "body_digest": canonical_digest(body),
            "enrollment_id": enrollment_id,
            "grant_hash": hashlib.sha256(grant.encode()).hexdigest(),
            "catalog_agent_id": self.agent_id, "key_id": RUNTIME_ORIGIN,
            "key_thumbprint": self.thumbprint, "runtime_origin": binding["runtime_origin"],
            "a2a_endpoint": binding["a2a_endpoint"],
            "generation": int(binding["generation"]), "service_epoch": int(binding["service_epoch"]),
            "authorization_epoch": 1,
            "exp": (datetime.now(UTC) + timedelta(seconds=30)).isoformat(),
        })
        return body, binding_sig

    def _assert_deny(self, cm, code: str, stage: str) -> None:
        record = next(r for r in cm.records if "runtime binding denied" in r.getMessage())
        message = record.getMessage()
        self.assertIn(f"code={code}", message)
        self.assertIn(f"stage={stage}", message)
        self.assertIn(f"agent={self.agent_id}", message)
        # 日志不得包含 grant、请求 JWS、密钥材料。
        self.assertNotIn("grant=", message)
        self.assertNotIn("cagt_", message.replace(self.agent_id, "<self>"))

    def test_grant_expired_denial_logs_fixed_code(self) -> None:
        enrollment_id = "enr_diag_grant_expired"
        _, device_hash = self._insert_enrollment(
            enrollment_id=enrollment_id,
            grant_expires_at=(datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
        )
        grant = cloud_binding_enrollment_grant(enrollment_id, device_hash)
        body, sig = self._signed_bind_body(enrollment_id, grant)
        with self.assertLogs(_LOG_NAME, level="WARNING") as cm:
            status, result = _call(self.app, "POST",
                                   f"/v1/agents/{self.agent_id}/runtime-bindings", body, signature=sig)
        self.assertEqual(status, 403, result)
        self.assertEqual(result, {"ok": False, "error": "enrollment grant is expired or unavailable"})
        self._assert_deny(cm, "BIND_GRANT_UNAVAILABLE", "validate_grant")

    def test_wrong_grant_denial_logs_fixed_code(self) -> None:
        enrollment_id = "enr_diag_wrong_grant"
        self._insert_enrollment(enrollment_id=enrollment_id)
        body, sig = self._signed_bind_body(enrollment_id, "cagt_wronggrantvalue")
        with self.assertLogs(_LOG_NAME, level="WARNING") as cm:
            status, result = _call(self.app, "POST",
                                   f"/v1/agents/{self.agent_id}/runtime-bindings", body, signature=sig)
        self.assertEqual(status, 403, result)
        self.assertEqual(result, {"ok": False, "error": "invalid enrollment grant"})
        self._assert_deny(cm, "BIND_GRANT_MISMATCH", "validate_grant")

    def test_material_mismatch_denial_logs_fixed_code(self) -> None:
        enrollment_id = "enr_diag_material"
        _, device_hash = self._insert_enrollment(enrollment_id=enrollment_id)
        grant = cloud_binding_enrollment_grant(enrollment_id, device_hash)
        body, sig = self._signed_bind_body(enrollment_id, grant,
                                           runtime_origin="https://tampered.security.example")
        with self.assertLogs(_LOG_NAME, level="WARNING") as cm:
            status, result = _call(self.app, "POST",
                                   f"/v1/agents/{self.agent_id}/runtime-bindings", body, signature=sig)
        self.assertEqual(status, 403, result)
        self.assertEqual(result, {"ok": False,
                                  "error": "binding material does not match approved enrollment"})
        self._assert_deny(cm, "BIND_MATERIAL_MISMATCH", "validate_material")

    def test_generation_mismatch_denial_logs_fixed_code(self) -> None:
        enrollment_id = "enr_diag_generation"
        _, device_hash = self._insert_enrollment(enrollment_id=enrollment_id)
        grant = cloud_binding_enrollment_grant(enrollment_id, device_hash)
        body, sig = self._signed_bind_body(enrollment_id, grant, generation=2)
        with self.assertLogs(_LOG_NAME, level="WARNING") as cm:
            status, result = _call(self.app, "POST",
                                   f"/v1/agents/{self.agent_id}/runtime-bindings", body, signature=sig)
        self.assertEqual(status, 403, result)
        self.assertEqual(result, {"ok": False,
                                  "error": "binding generation does not match approved enrollment"})
        self._assert_deny(cm, "BIND_GENERATION_MISMATCH", "validate_generation")

    def test_scope_missing_denial_logs_fixed_code(self) -> None:
        enrollment_id = "enr_diag_scope"
        _, device_hash = self._insert_enrollment(
            enrollment_id=enrollment_id, scopes=["card:publish", "heartbeat"],
        )
        grant = cloud_binding_enrollment_grant(enrollment_id, device_hash)
        body, sig = self._signed_bind_body(enrollment_id, grant)
        with self.assertLogs(_LOG_NAME, level="WARNING") as cm:
            status, result = _call(self.app, "POST",
                                   f"/v1/agents/{self.agent_id}/runtime-bindings", body, signature=sig)
        self.assertEqual(status, 403, result)
        self.assertEqual(result, {"ok": False,
                                  "error": "enrollment grant does not include runtime:bind"})
        self._assert_deny(cm, "BIND_SCOPE_MISSING", "validate_scope")


class ChallengeEgressDiagnosticsTest(EnrollmentFixture):
    """挑战出口：FetchError → 既有 409；非 200 → 403 固定码；不泄漏异常原文。"""

    def _ready_bind(self):
        enrollment_id = "enr_diag_challenge"
        _, device_hash = self._insert_enrollment(enrollment_id=enrollment_id)
        grant = cloud_binding_enrollment_grant(enrollment_id, device_hash)
        binding = {
            "runtime_origin": RUNTIME_ORIGIN, "a2a_endpoint": A2A_ENDPOINT,
            "key_jwk": self.jwk, "key_id": RUNTIME_ORIGIN,
            "generation": 1, "service_epoch": 7,
        }
        body = {"enrollment_id": enrollment_id, "grant": grant, "binding": binding}
        sig = _jws(self.private_pem, RUNTIME_ORIGIN, {
            "method": "POST", "path": f"/v1/agents/{self.agent_id}/runtime-bindings",
            "audience": "kiwi-catalog", "body_digest": canonical_digest(body),
            "enrollment_id": enrollment_id,
            "grant_hash": hashlib.sha256(grant.encode()).hexdigest(),
            "catalog_agent_id": self.agent_id, "key_id": RUNTIME_ORIGIN,
            "key_thumbprint": self.thumbprint, "runtime_origin": RUNTIME_ORIGIN,
            "a2a_endpoint": A2A_ENDPOINT, "generation": 1, "service_epoch": 7,
            "authorization_epoch": 1,
            "exp": (datetime.now(UTC) + timedelta(seconds=30)).isoformat(),
        })
        return enrollment_id, grant, body, sig

    def test_challenge_fetch_failure_is_conflict_with_fixed_code(self) -> None:
        _enrollment_id, _grant, body, sig = self._ready_bind()
        with mock.patch.object(ProfileFetcher, "post_json",
                               side_effect=FetchError("TLS handshake timed out")):
            with self.assertLogs(_LOG_NAME, level="WARNING") as cm:
                status, result = _call(self.app, "POST",
                                       f"/v1/agents/{self.agent_id}/runtime-bindings", body, signature=sig)
        self.assertEqual(status, 409, result)
        # 响应体保持既有固定文案，不反射异常原文。
        self.assertEqual(result, {"ok": False, "error":
            "runtime endpoint challenge failed; retry when the public HTTPS service is reachable"})
        message = cm.records[0].getMessage()
        self.assertIn("BIND_CHALLENGE_DELIVERY_FAILED", message)
        self.assertIn("stage=challenge_delivery", message)
        self.assertIn("error_type=FetchError", message)
        self.assertNotIn("TLS", message)

    def test_challenge_non_200_denial_logs_fixed_code(self) -> None:
        _enrollment_id, _grant, body, sig = self._ready_bind()

        def _respond(url, payload, *, timeout):
            return FetchResult(url=url, status_code=502, body="", fetched_at=time.time())

        with mock.patch.object(ProfileFetcher, "post_json", side_effect=_respond):
            with self.assertLogs(_LOG_NAME, level="WARNING") as cm:
                status, result = _call(self.app, "POST",
                                       f"/v1/agents/{self.agent_id}/runtime-bindings", body, signature=sig)
        self.assertEqual(status, 403, result)
        self.assertEqual(result, {"ok": False, "error": "runtime endpoint challenge failed"})
        message = cm.records[0].getMessage()
        self.assertIn("BIND_CHALLENGE_REJECTED", message)
        self.assertIn("stage=challenge_delivery", message)
        self.assertIn("detail=status=502", message)

    def test_enrollment_binding_success_regression(self) -> None:
        """真实绑定成功回归：mock 挑战端点回签正确挑战响应 → 200 bound。"""
        enrollment_id, _grant, body, sig = self._ready_bind()

        def _respond(url, payload, *, timeout):
            # 真实运行时会原样回签 challenge 字段（含 issued_at），_jws 会覆盖
            # issued_at，所以这里用逐字段精确签名，不做任何注入。
            from uuid import uuid4

            from cryptography.hazmat.primitives.serialization import load_pem_private_key

            from tests.test_cloud_binding import _b64url

            response = {**payload, "key_id": RUNTIME_ORIGIN}
            sign_payload = {**{k: response[k] for k in payload},
                            "key_id": RUNTIME_ORIGIN, "purpose": "kiwi-binding-challenge",
                            "nonce": f"nonce-{uuid4().hex}"}
            header_segment = _b64url(json.dumps({"alg": "EdDSA", "kid": RUNTIME_ORIGIN},
                                                separators=(",", ":")).encode())
            payload_segment = _b64url(json.dumps(sign_payload, separators=(",", ":"),
                                                 ensure_ascii=False).encode())
            key = load_pem_private_key(self.private_pem.encode(), password=None)
            signature = key.sign(f"{header_segment}.{payload_segment}".encode("ascii"))
            response["signature"] = f"{header_segment}.{payload_segment}.{_b64url(signature)}"
            return FetchResult(url=url, status_code=200,
                               body=json.dumps(response), fetched_at=time.time())

        with mock.patch.object(ProfileFetcher, "post_json", side_effect=_respond):
            status, result = _call(self.app, "POST",
                                   f"/v1/agents/{self.agent_id}/runtime-bindings", body, signature=sig)
        self.assertEqual(status, 200, result)
        self.assertEqual(result["status"], "bound")
        self.assertEqual(result["enrollment_id"], enrollment_id)


def cloud_binding_enrollment_grant(enrollment_id: str, device_hash: str) -> str:
    from kiwi_catalog.services import enrollments as enrollment_service

    return enrollment_service._stable_grant(enrollment_id, device_hash)


class FetcherUrlErrorConvergenceTest(unittest.TestCase):
    """post_json/_make_request 把 URLError（TLS 握手超时形态）收敛为 FetchError。"""

    def _opener_raising(self, exc: Exception):
        opener = mock.Mock()
        opener.open.side_effect = exc
        return opener

    def test_make_request_wraps_urlerror_as_fetch_error(self) -> None:
        fetcher = ProfileFetcher.__new__(ProfileFetcher)  # 不触发网络/DNS
        opener = self._opener_raising(
            urllib.error.URLError(TimeoutError("_ssl.c:983: The handshake operation timed out")))
        with mock.patch.object(fetcher_module, "_build_opener", return_value=opener):
            with self.assertRaises(FetchError) as ctx:
                fetcher._make_request(
                    "https://runtime.example/.well-known/kiwi-binding-challenge",
                    "93.184.216.34", "runtime.example", 443,
                    None, None, time.time(),
                    method="POST", data=b"{}", timeout=5, redirect_limit=0,
                )
        self.assertIsInstance(ctx.exception.__cause__, urllib.error.URLError)

    def test_post_json_converges_urlerror_end_to_end(self) -> None:
        """真实 post_json 路径：URL 校验/端口/DNS 之外，连接层 URLError → FetchError。"""
        fetcher = ProfileFetcher(fetcher_module.TrustPolicy.defaults(), timeout=5)
        opener = self._opener_raising(urllib.error.URLError(OSError("network unreachable")))
        with mock.patch.object(fetcher_module, "_resolve_and_validate",
                               return_value="93.184.216.34"), \
             mock.patch.object(fetcher_module, "_build_opener", return_value=opener):
            with self.assertRaises(FetchError):
                fetcher.post_json("https://runtime.example/challenge", {"a": 1})

    def test_http_error_still_passes_through_status(self) -> None:
        """HTTPError（URLError 子类）仍透传状态码语义——不被误包成 FetchError。"""
        fetcher = ProfileFetcher.__new__(ProfileFetcher)
        body = b'{"error":"challenge rejected"}'
        http_error = urllib.error.HTTPError(
            "https://runtime.example/challenge", 409, "Conflict", {}, None)
        http_error.fp = mock.Mock()
        http_error.fp.read.side_effect = [body, b""]
        http_error.headers = {}
        opener = mock.Mock()
        opener.open.side_effect = http_error
        with mock.patch.object(fetcher_module, "_build_opener", return_value=opener):
            with self.assertRaises(urllib.error.HTTPError):
                fetcher._make_request(
                    "https://runtime.example/challenge",
                    "93.184.216.34", "runtime.example", 443,
                    None, None, time.time(),
                    method="POST", data=b"{}", timeout=5, redirect_limit=0,
                )


if __name__ == "__main__":
    unittest.main()
