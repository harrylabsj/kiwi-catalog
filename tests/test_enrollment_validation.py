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

"""Input validation and expiry semantics for Runtime enrollment requests."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from kiwi_catalog.a2a.binding_claims import jwk_thumbprint
from kiwi_catalog.db.session import db_session
from kiwi_catalog.services import enrollments as enrollment_service

from tests.test_cloud_binding import _b64url, _call, _jws
from tests.test_enrollment_security import EnrollmentFixture, RUNTIME_ORIGIN


class EnrollmentValidationTest(EnrollmentFixture):
    def _device_body(self, *, binding_overrides: dict | None = None,
                     key_jwk: dict | None = None) -> dict:
        binding = {
            "runtime_origin": "https://merchant.security.example",
            "a2a_endpoint": "https://merchant.security.example/a2a",
            "key_jwk": key_jwk or self.jwk,
            "key_id": "https://merchant.security.example",
            "generation": 1,
            "service_epoch": 7,
        }
        if binding_overrides:
            binding.update(binding_overrides)
        return {
            "binding": binding,
            "public_preview": {
                "name": "Security Merchant A",
                "description": "Public merchant card",
                "version": "1.0.0",
                "url": binding["runtime_origin"],
                "supportedInterfaces": [{
                    "url": binding["a2a_endpoint"],
                    "protocolBinding": "JSONRPC",
                    "protocolVersion": "1.0",
                }],
                "capabilities": {"extensions": []},
            },
            "public_profile_revision": "profile-v1",
        }

    def _create_device(self, body: dict, signature: str = "test-signature") -> tuple[int, dict]:
        return _call(self.app, "POST", "/v1/enrollments/device", body, signature=signature)

    def test_create_rejects_private_jwk_and_wrong_field_types(self) -> None:
        private_d = _b64url(self.private_key.private_bytes(
            encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption(),
        ))
        cases = [
            ("private JWK d", self._device_body(key_jwk={**self.jwk, "d": private_d})),
            ("key_id type", self._device_body(binding_overrides={"key_id": 12})),
            ("runtime_origin type", self._device_body(binding_overrides={"runtime_origin": 7})),
            ("a2a_endpoint type", self._device_body(binding_overrides={"a2a_endpoint": False})),
            ("generation bool", self._device_body(binding_overrides={"generation": True})),
        ]
        for label, body in cases:
            with self.subTest(case=label):
                status, result = self._create_device(body)
                self.assertEqual(status, 400, result)
        with db_session(self.db_path) as conn:
            self.assertEqual(conn.execute("select count(*) from enrollments").fetchone()[0], 0)

    def test_bind_rejects_private_jwk_even_when_public_thumbprint_matches(self) -> None:
        enrollment_id = "enr_bind_private_jwk"
        _, device_hash = self._insert_enrollment(status="authorized", enrollment_id=enrollment_id)
        grant = enrollment_service._stable_grant(enrollment_id, device_hash)
        private_d = _b64url(self.private_key.private_bytes(
            encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption(),
        ))
        body = {
            "enrollment_id": enrollment_id,
            "grant": grant,
            "binding": {
                "runtime_origin": "https://merchant.security.example",
                "a2a_endpoint": "https://merchant.security.example/a2a",
                "key_jwk": {**self.jwk, "d": private_d},
                "key_id": RUNTIME_ORIGIN,
                "generation": 1,
                "service_epoch": 7,
            },
        }
        # The canonical public thumbprint is still identical; validation must
        # reject the extra private member before any network challenge.
        self.assertEqual(jwk_thumbprint({**self.jwk, "d": private_d}), self.thumbprint)
        status, result = _call(
            self.app, "POST", f"/v1/agents/{self.agent_id}/runtime-bindings",
            body, signature="nonempty-but-never-parsed",
        )
        self.assertEqual(status, 400, result)
        self.assertIn("only canonical public-key fields", result.get("error", ""))

    def test_create_rejects_boolean_generation_as_integer(self) -> None:
        # Isolated assertion also locks in the bool/int edge case explicitly.
        body = self._device_body(binding_overrides={"generation": True})
        status, result = self._create_device(body)
        self.assertEqual(status, 400, result)

    def test_authorized_poll_uses_grant_expiry_not_original_session_expiry(self) -> None:
        now = datetime.now(UTC).replace(microsecond=0)
        device_code, _ = self._insert_enrollment(
            status="authorized",
            enrollment_id="enr_authorized_grant_live",
            expires_at=(now - timedelta(minutes=1)).isoformat(),
            grant_expires_at=(now + timedelta(minutes=5)).isoformat(),
        )
        signed = _jws(self.private_pem, RUNTIME_ORIGIN, {
            "method": "POST", "path": "/v1/enrollments/device/token",
            "audience": "kiwi-catalog",
            "device_code_hash": hashlib.sha256(device_code.encode()).hexdigest(),
            "key_id": RUNTIME_ORIGIN,
            "key_thumbprint": self.thumbprint,
            "exp": (now + timedelta(seconds=30)).isoformat(),
        })
        status, result = _call(
            self.app, "POST", "/v1/enrollments/device/token",
            {"device_code": device_code}, signature=signed,
        )
        self.assertEqual(status, 200, result)
        self.assertEqual(result["enrollment_id"], "enr_authorized_grant_live")
        self.assertTrue(result["grant"])

    def test_expired_original_ttl_does_not_hide_bound_or_published_details(self) -> None:
        past = (datetime.now(UTC) - timedelta(minutes=1)).replace(microsecond=0).isoformat()
        for state in ("bound", "published"):
            enrollment_id = f"enr_expired_{state}"
            self._insert_enrollment(
                status=state, enrollment_id=enrollment_id,
                expires_at=past, grant_expires_at=past,
            )
            with self.subTest(state=state):
                response = self.client.get(f"/v1/accounts/enrollments/{enrollment_id}")
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(response.json()["status"], state)


if __name__ == "__main__":
    import unittest
    unittest.main()
