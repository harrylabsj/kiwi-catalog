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

"""Local HTTP flow for login return, frozen preview, and one-click authorization."""

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from unittest import mock

from fastapi.testclient import TestClient

from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.db.session import db_session


class PortalEnrollmentFlowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp.name, "catalog.sqlite")
        self.env = mock.patch.dict(os.environ, {
            "KIWI_CATALOG_PUBLIC_BASE_URL": "https://localhost",
            "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
            "KIWI_CATALOG_OWNER_TOKEN_SECRET": "portal-flow-test-secret",
        }, clear=False)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.addCleanup(self.temp.cleanup)
        self.client = TestClient(create_catalog_app(self.db_path), base_url="https://localhost")

    def register_and_login(self, email: str, name: str) -> None:
        registered = self.client.post("/v1/accounts/register", json={
            "merchant_name": name, "email": email, "password": "strong-password-123",
            "phone": "+1 555 0100",
        })
        self.assertEqual(registered.status_code, 200, registered.text)
        code = registered.json()["verification_code"]
        verified = self.client.post("/v1/accounts/verify-email", json={"email": email, "code": code})
        self.assertEqual(verified.status_code, 200, verified.text)
        self.assertIn("kiwi_session", self.client.cookies)
        # Verification creates the account; clear that session and exercise the
        # actual login endpoint before following the same-origin next path.
        self.client.cookies.clear()
        logged_in = self.client.post("/v1/accounts/login", json={
            "email": email, "password": "strong-password-123",
        })
        self.assertEqual(logged_in.status_code, 200, logged_in.text)
        self.assertIn("kiwi_session", self.client.cookies)

    def seed_enrollment(self) -> tuple[str, str]:
        enrollment_id = "enr_e2e_test_001"
        user_code = "A1B2C3D4"
        device_code = "test-device-code-that-is-long-enough-for-hash-only"
        now = datetime.now(UTC).replace(microsecond=0)
        with db_session(self.db_path) as conn:
            conn.execute(
                "insert into enrollments(enrollment_id,device_code_hash,user_code,status,key_id,key_thumbprint,"
                "key_jwk_json,runtime_origin,a2a_endpoint,generation,service_epoch,public_preview_json,"
                "public_profile_revision,expected_binding_version,created_at,expires_at) "
                "values(?,?,?,'ready_for_authorization',?,?,?,?,?,1,1,?,?,1,?,?)",
                (enrollment_id, hashlib.sha256(device_code.encode()).hexdigest(), user_code,
                 "kid-test", "thumb-test", '{"kty":"OKP","crv":"Ed25519","x":"public"}',
                 "https://merchant.example", "https://merchant.example/a2a",
                 '{"name":"Example Shop","description":"公开简介","skills":[{"id":"quote","name":"询价"}]}',
                 "profile-v1", now.isoformat(), (now + timedelta(minutes=10)).isoformat()),
            )
        return enrollment_id, user_code

    def test_login_next_preview_and_explicit_authorize(self) -> None:
        enrollment_id, user_code = self.seed_enrollment()
        portal_path = f"/portal/connect/{enrollment_id}"
        next_url = portal_path

        # Anonymous entry serves the page shell; its authenticated preview request
        # returns 403 and the page carries a same-origin login return path.
        page = self.client.get(portal_path)
        self.assertEqual(page.status_code, 200)
        self.assertIn("/portal/login?next=", page.text)
        self.client.cookies.clear()
        anonymous_preview = self.client.get(f"/v1/accounts/enrollments/{enrollment_id}")
        self.assertEqual(anonymous_preview.status_code, 403)

        login_page = self.client.get("/portal/login", params={"next": next_url})
        self.assertEqual(login_page.status_code, 200)
        self.assertIn("nextTarget", login_page.text)
        self.assertIn("startsWith('//')", login_page.text)
        self.register_and_login("merchant-a@example.test", "商家 A")

        # The login page redirects to this same-origin path after the authenticated
        # login/verification response; then the portal fetches the private preview.
        returned_page = self.client.get(next_url)
        self.assertEqual(returned_page.status_code, 200)
        preview = self.client.get(f"/v1/accounts/enrollments/{enrollment_id}")
        self.assertEqual(preview.status_code, 200, preview.text)
        self.assertEqual(preview.json()["user_code"], user_code)
        self.assertEqual(preview.json()["public_preview"]["name"], "Example Shop")
        self.assertNotIn("device_code", preview.text)
        self.assertNotIn("key_jwk", preview.text)
        self.assertNotIn("grant", preview.text)

        authorized = self.client.post(
            f"/v1/accounts/enrollments/{enrollment_id}/authorize",
            json={"user_code": user_code},
            headers={"Origin": "https://localhost"},
        )
        self.assertEqual(authorized.status_code, 200, authorized.text)
        self.assertEqual(authorized.json()["status"], "authorized")
        self.assertNotIn("grant", authorized.text)
        replay = self.client.post(
            f"/v1/accounts/enrollments/{enrollment_id}/authorize",
            json={"user_code": user_code},
            headers={"Origin": "https://localhost"},
        )
        self.assertEqual(replay.status_code, 200, replay.text)

        final_preview = self.client.get(f"/v1/accounts/enrollments/{enrollment_id}")
        self.assertEqual(final_preview.status_code, 200)
        self.assertEqual(final_preview.json()["status"], "authorized")

    def test_authorize_rejects_cross_origin_and_wrong_code(self) -> None:
        enrollment_id, user_code = self.seed_enrollment()
        self.register_and_login("merchant-b@example.test", "商家 B")
        cross_origin = self.client.post(
            f"/v1/accounts/enrollments/{enrollment_id}/authorize",
            json={"user_code": user_code}, headers={"Origin": "https://evil.example"},
        )
        self.assertEqual(cross_origin.status_code, 403, cross_origin.text)
        wrong_code = self.client.post(
            f"/v1/accounts/enrollments/{enrollment_id}/authorize",
            json={"user_code": "00000000"}, headers={"Origin": "https://localhost"},
        )
        self.assertIn(wrong_code.status_code, (400, 409), wrong_code.text)
        still_ready = self.client.get(f"/v1/accounts/enrollments/{enrollment_id}")
        self.assertEqual(still_ready.status_code, 200)
        self.assertEqual(still_ready.json()["status"], "ready_for_authorization")


if __name__ == "__main__":
    unittest.main()
