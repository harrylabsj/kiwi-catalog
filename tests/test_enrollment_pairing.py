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

"""配对授权页的服务端配对码校验（门户先行 + 后端分阶段收紧）。

覆盖：
- 新门户流程：商家从自己的工作台读出配对码、手工输入，服务端校验而不是只靠
  前端禁用按钮；错码/缺码（收紧后）都不改变 enrollment 状态；
- 兼容流程：默认 ``optional`` 下，旧授权页不带码仍可确认；``required`` 下
  缺码一律拒绝；
- 保留既有边界：过期、账号/请求限流、同源、会话、换钥接管、重复授权幂等；
- 配对码只认 JSON 请求体，不认 URL 查询串；预览/响应/访问日志都不出现它。
"""

from __future__ import annotations

import hashlib
import json
import os
import unittest
from datetime import UTC, datetime, timedelta
from unittest import mock

from kiwi_catalog.db.session import db_session

from tests.test_enrollment_security import EnrollmentFixture


class EnrollmentPairingCodeTest(EnrollmentFixture):
    def _user_code(self, enrollment_id: str) -> str:
        return "S" + hashlib.sha256(enrollment_id.encode()).hexdigest()[:7].upper()

    def _authorize(self, enrollment_id: str, body: dict, *, origin: str = "https://localhost"):
        return self.client.post(
            f"/v1/accounts/enrollments/{enrollment_id}/authorize",
            json=body,
            headers={"Origin": origin},
        )

    def _status_of(self, enrollment_id: str) -> str:
        with db_session(self.db_path) as conn:
            return str(
                conn.execute(
                    "select status from enrollments where enrollment_id=?", (enrollment_id,)
                ).fetchone()["status"]
            )

    def _audit_count(self, enrollment_id: str) -> int:
        with db_session(self.db_path) as conn:
            rows = conn.execute(
                "select details_json from audit_events where event='runtime_enrollment_authorized'"
            ).fetchall()
        return sum(1 for row in rows if enrollment_id in str(row["details_json"]))

    def _register_second_merchant(self, email: str = "pairing-second@example.test") -> None:
        issued = self.client.post("/v1/accounts/register/code", json={"email": email})
        self.assertEqual(issued.status_code, 200, issued.text)
        ticket = self.client.post("/v1/accounts/register/verify", json={
            "email": email, "code": issued.json()["verification_code"],
        })
        self.assertEqual(ticket.status_code, 200, ticket.text)
        registered = self.client.post("/v1/accounts/register", json={
            "merchant_name": "Security Merchant B",
            "email": email,
            "password": "strong-password-456",
            "phone": "+1 555 0201",
            "verification_ticket": ticket.json()["verification_ticket"],
        })
        self.assertEqual(registered.status_code, 200, registered.text)

    def test_backend_validates_code_and_keeps_authorization_idempotent(self) -> None:
        enrollment_id = "enr_pairing_backend"
        self._insert_enrollment(status="ready_for_authorization", enrollment_id=enrollment_id)
        code = self._user_code(enrollment_id)

        # 前端把码传上来了，但服务端才是判据：错码拒绝且不改状态。
        wrong = self._authorize(enrollment_id, {"user_code": "00000000"})
        self.assertEqual(wrong.status_code, 409, wrong.text)
        self.assertEqual(self._status_of(enrollment_id), "ready_for_authorization")

        accepted = self._authorize(enrollment_id, {"user_code": code})
        self.assertEqual(accepted.status_code, 200, accepted.text)
        self.assertEqual(accepted.json()["status"], "authorized")
        self.assertNotIn(code, accepted.text)
        self.assertNotIn("grant", accepted.text)

        # 同一商家、同一配对码重试 = 幂等：不产生第二次授权审计。
        replay = self._authorize(enrollment_id, {"user_code": code})
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(replay.json()["status"], "authorized")
        self.assertEqual(self._audit_count(enrollment_id), 1)

    def test_required_mode_rejects_missing_or_query_only_code(self) -> None:
        enrollment_id = "enr_pairing_required"
        self._insert_enrollment(status="ready_for_authorization", enrollment_id=enrollment_id)
        code = self._user_code(enrollment_id)

        with mock.patch.dict(
            os.environ, {"KIWI_CATALOG_ENROLLMENT_PAIRING_MODE": "required"}, clear=False
        ):
            missing = self._authorize(enrollment_id, {})
            self.assertEqual(missing.status_code, 409, missing.text)

            # 查询串里的同名字段不参与授权：显式 400，而不是静默当作缺省码。
            query_only = self.client.post(
                f"/v1/accounts/enrollments/{enrollment_id}/authorize?user_code={code}",
                json={},
                headers={"Origin": "https://localhost"},
            )
            self.assertEqual(query_only.status_code, 400, query_only.text)
            self.assertIn("JSON request body", query_only.text)
            self.assertEqual(self._status_of(enrollment_id), "ready_for_authorization")

            accepted = self._authorize(enrollment_id, {"user_code": code.lower()})
            self.assertEqual(accepted.status_code, 200, accepted.text)
            self.assertEqual(accepted.json()["status"], "authorized")

    def test_query_only_code_is_rejected_even_in_compatibility_mode(self) -> None:
        """兼容模式只放宽「缺码」，不放宽「码走 URL」：查询串一律拒绝。"""
        enrollment_id = "enr_pairing_query_compat"
        self._insert_enrollment(status="ready_for_authorization", enrollment_id=enrollment_id)
        with mock.patch.dict(
            os.environ, {"KIWI_CATALOG_ENROLLMENT_PAIRING_MODE": "optional"}, clear=False
        ):
            rejected = self.client.post(
                f"/v1/accounts/enrollments/{enrollment_id}/authorize?user_code={self._user_code(enrollment_id)}",
                json={},
                headers={"Origin": "https://localhost"},
            )
        self.assertEqual(rejected.status_code, 400, rejected.text)
        self.assertEqual(self._status_of(enrollment_id), "ready_for_authorization")

    def test_default_and_unknown_modes_require_a_pairing_code(self) -> None:
        """审查 P2：缺省/拼错的开关都按 required 处理（fail-closed）。"""
        for index, raw in enumerate(("", "legacy", "garbage")):
            with self.subTest(mode=raw):
                enrollment_id = f"enr_pairing_required_default_{index}"
                self._insert_enrollment(
                    status="ready_for_authorization", enrollment_id=enrollment_id
                )
                with mock.patch.dict(
                    os.environ,
                    {"KIWI_CATALOG_ENROLLMENT_PAIRING_MODE": raw},
                    clear=False,
                ):
                    denied = self._authorize(enrollment_id, {})
                self.assertEqual(denied.status_code, 409, denied.text)

    def test_explicit_optional_mode_keeps_old_authorization_pages_working(self) -> None:
        """过渡期部署显式设置 optional 时，旧页面不传码仍可放行。"""
        for index, raw in enumerate(("optional", "off", "0")):
            with self.subTest(mode=raw):
                enrollment_id = f"enr_pairing_legacy_page_{index}"
                self._insert_enrollment(
                    status="ready_for_authorization", enrollment_id=enrollment_id
                )
                with mock.patch.dict(
                    os.environ,
                    {"KIWI_CATALOG_ENROLLMENT_PAIRING_MODE": raw},
                    clear=False,
                ):
                    legacy = self._authorize(enrollment_id, {})
                self.assertEqual(legacy.status_code, 200, legacy.text)
                self.assertEqual(legacy.json()["status"], "authorized")

    def test_expired_enrollment_is_rejected_even_with_the_right_code(self) -> None:
        enrollment_id = "enr_pairing_expired"
        past = (datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=1)).isoformat()
        self._insert_enrollment(
            status="ready_for_authorization", enrollment_id=enrollment_id, expires_at=past
        )
        with mock.patch.dict(
            os.environ, {"KIWI_CATALOG_ENROLLMENT_PAIRING_MODE": "required"}, clear=False
        ):
            denied = self._authorize(enrollment_id, {"user_code": self._user_code(enrollment_id)})
        self.assertEqual(denied.status_code, 409, denied.text)

    def test_cross_origin_and_anonymous_requests_cannot_authorize_with_code(self) -> None:
        enrollment_id = "enr_pairing_origin"
        self._insert_enrollment(status="ready_for_authorization", enrollment_id=enrollment_id)
        code = self._user_code(enrollment_id)

        cross_origin = self._authorize(enrollment_id, {"user_code": code}, origin="https://evil.example")
        self.assertEqual(cross_origin.status_code, 403, cross_origin.text)

        self.client.cookies.clear()
        anonymous = self._authorize(enrollment_id, {"user_code": code})
        self.assertEqual(anonymous.status_code, 403, anonymous.text)
        self.assertEqual(self._status_of(enrollment_id), "ready_for_authorization")

    def test_pairing_attempts_are_rate_limited(self) -> None:
        enrollment_id = "enr_pairing_limited"
        self._insert_enrollment(status="ready_for_authorization", enrollment_id=enrollment_id)
        for attempt in range(10):
            denied = self._authorize(enrollment_id, {"user_code": f"BADCODE{attempt}"})
            self.assertEqual(denied.status_code, 409, (attempt, denied.text))
        blocked = self._authorize(enrollment_id, {"user_code": self._user_code(enrollment_id)})
        self.assertEqual(blocked.status_code, 429, blocked.text)
        self.assertEqual(self._status_of(enrollment_id), "ready_for_authorization")

    def test_pairing_budget_is_per_enrollment_not_just_per_account(self) -> None:
        """换账号也不能重置同一待授权请求的猜测预算。"""
        enrollment_id = "enr_pairing_cross_account"
        self._insert_enrollment(status="ready_for_authorization", enrollment_id=enrollment_id)
        for attempt in range(5):
            denied = self._authorize(enrollment_id, {"user_code": f"BADCODE{attempt}"})
            self.assertEqual(denied.status_code, 409, (attempt, denied.text))
        # 第二个账号在自己的 10 次预算内（只用了 6 次），但同一 enrollment 的
        # 10 次预算已用尽 → 429。
        self._register_second_merchant()
        for attempt in range(5):
            denied = self._authorize(enrollment_id, {"user_code": f"BADCODE{attempt}"})
            self.assertEqual(denied.status_code, 409, (attempt, denied.text))
        blocked = self._authorize(enrollment_id, {"user_code": self._user_code(enrollment_id)})
        self.assertEqual(blocked.status_code, 429, blocked.text)
        self.assertEqual(self._status_of(enrollment_id), "ready_for_authorization")

    def test_active_binding_cannot_be_replaced_by_another_key_even_with_code(self) -> None:
        enrollment_id = "enr_pairing_takeover"
        self._insert_enrollment(status="ready_for_authorization", enrollment_id=enrollment_id)
        with db_session(self.db_path) as conn:
            conn.execute(
                "insert into runtime_bindings(binding_id, catalog_agent_id, merchant_id, runtime_origin,"
                " a2a_endpoint, key_id, key_thumbprint, key_jwk_json, binding_version, service_epoch,"
                " status, created_at, updated_at) values('bind_pairing_existing', ?, ?,"
                " 'https://merchant.security.example', 'https://merchant.security.example/a2a',"
                " 'kid-existing', 'sha256:tp', '{}', 1, 1, 'active', ?, '')",
                (self.agent_id, self.merchant_id, "2026-10-28T09:00:00+00:00"),
            )
        denied = self._authorize(enrollment_id, {"user_code": self._user_code(enrollment_id)})
        self.assertEqual(denied.status_code, 409, denied.text)
        self.assertIn("already has an active Runtime binding", denied.text)
        self.assertEqual(self._status_of(enrollment_id), "ready_for_authorization")

    def test_code_never_appears_in_preview_response_or_access_log(self) -> None:
        enrollment_id = "enr_pairing_no_echo"
        self._insert_enrollment(status="ready_for_authorization", enrollment_id=enrollment_id)
        code = self._user_code(enrollment_id)

        preview = self.client.get(f"/v1/accounts/enrollments/{enrollment_id}")
        self.assertEqual(preview.status_code, 200, preview.text)
        self.assertNotIn("user_code", preview.json())
        self.assertNotIn(code, preview.text)

        accepted = self._authorize(enrollment_id, {"user_code": code})
        self.assertEqual(accepted.status_code, 200, accepted.text)
        self.assertNotIn(code, accepted.text)

        with db_session(self.db_path) as conn:
            rows = conn.execute("select * from access_log").fetchall()
        self.assertTrue(rows)
        rendered = json.dumps([dict(row) for row in rows], ensure_ascii=False)
        self.assertNotIn(code, rendered)
        self.assertNotIn("user_code", rendered)


if __name__ == "__main__":
    unittest.main()
