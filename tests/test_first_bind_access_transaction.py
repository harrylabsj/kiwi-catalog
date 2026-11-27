"""首绑访问配置事务重排的验收钉（challenge → commit 同事务暂存/激活）。

契约（2026-11-01 事务重排）：
  - 随绑凭据**不再**在挑战前落库：挑战失败磁盘上零 `runtime_access_configs` 行，
    head 不被失败尝试占用，同 enrollment 可直接重试成功；
  - 提交事务内二次校验（enrollment 状态/代次/绑定版本 CAS）任一失败 → 整事务
    回滚，凭据行与绑定行都不残留；
  - 目录已有 active/invalid/pending head → 按版本冲突跳过随绑凭据：绑定照常
    完成、旧密文不覆盖、回执给 `head_version/head_status` 明确恢复状态；
  - stage 时 CAS 又被推进 → 降级为跳过（绝不覆盖对方）；其余 ConflictError
    （如代管总开关关闭）保持原语义——绑定失败、整事务回滚；
  - `access_config_outcome` 是白名单结果：applied 分支与 skipped 分支各有固定
    键集，响应体不含任何凭据材料。
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import unittest
from datetime import UTC, datetime, timedelta
from unittest import mock

from kiwi_catalog.db.session import db_session
from kiwi_catalog.discovery.fetcher import FetchResult, ProfileFetcher
from kiwi_catalog.services import runtime_access as runtime_access_service

from tests.test_cloud_binding import _b64url, _call, _jws
from tests.test_enrollment_security import A2A_ENDPOINT, ADMIN_TOKEN, RUNTIME_ORIGIN, EnrollmentFixture

ACCESS_CONFIG = {
    "provider": "workbuddy",
    "access_mode": "share_parameter",
    "parameter_name": "sharecode",
    "secret_value": "tx-secret-alpha",
    "adapter_version": "workbuddy-share-v1",
    "auth_mode": "signature",
    "expected_version": 0,
    "consent": {"terms_version": "workbuddy-share-v1-2026-10-27", "granted": True},
}


def _insert_head_row(conn, *, agent_id: str, version: int, status: str, secret: str) -> None:
    conn.execute(
        "insert into runtime_access_configs (catalog_agent_id, config_version, provider,"
        " access_mode, parameter_name, secret_ciphertext, key_id, adapter_version, auth_mode,"
        " status, validated_at, created_at, updated_at)"
        " values (?, ?, 'workbuddy', 'share_parameter', 'sharecode', ?, 'key-1',"
        " 'workbuddy-share-v1', 'signature', ?, '', 't', 't')",
        (agent_id, version, secret, status),
    )


class FirstBindAccessTransactionTest(EnrollmentFixture):
    def setUp(self) -> None:
        super().setUp()
        # 成功路径要真正落密文：注入代管加密密钥环境（与 test_runtime_access_api 同款）。
        import base64

        fernet_key = base64.urlsafe_b64encode(os.urandom(32)).decode()
        self._fernet_env = mock.patch.dict(os.environ, {
            "KIWI_CATALOG_ACCESS_CONFIG_KEYS_JSON": json.dumps({"ka-tx-v1": fernet_key}),
            "KIWI_CATALOG_ACCESS_CONFIG_ACTIVE_KEY_ID": "ka-tx-v1",
        }, clear=False)
        self._fernet_env.start()
        self.addCleanup(self._fernet_env.stop)
        self.access_config = json.loads(json.dumps(ACCESS_CONFIG))

    # ── 夹具 ─────────────────────────────────────────────────────────────
    def _enrollment(self, enrollment_id: str, expected_binding_version: int = 1) -> str:
        """插入 authorized enrollment,返回可直接使用的 grant。"""
        device_code, device_hash = self._insert_enrollment(status="authorized", enrollment_id=enrollment_id)
        if expected_binding_version != 1:
            with db_session(self.db_path) as conn:
                conn.execute("update enrollments set expected_binding_version=? where enrollment_id=?",
                             (expected_binding_version, enrollment_id))
        return enrollment_service_grant(enrollment_id, device_hash)

    def _bind(self, enrollment_id: str, grant: str, *, with_config: bool = True):
        body = {
            "enrollment_id": enrollment_id,
            "grant": grant,
            "binding": {
                "runtime_origin": RUNTIME_ORIGIN,
                "a2a_endpoint": A2A_ENDPOINT,
                "key_jwk": self.jwk,
                "key_id": RUNTIME_ORIGIN,
                "generation": 1,
                "service_epoch": 7,
            },
        }
        if with_config:
            body["access_config"] = self.access_config
        signature = _jws(self.private_pem, RUNTIME_ORIGIN, {
            "method": "POST", "path": f"/v1/agents/{self.agent_id}/runtime-bindings",
            "audience": "kiwi-catalog", "body_digest": __import__(
                "kiwi_catalog.a2a.enrollment_canonical", fromlist=["canonical_digest"]).canonical_digest(body),
            "enrollment_id": enrollment_id,
            "grant_hash": hashlib.sha256(grant.encode()).hexdigest(),
            "catalog_agent_id": self.agent_id, "key_id": RUNTIME_ORIGIN,
            "key_thumbprint": self.thumbprint, "runtime_origin": RUNTIME_ORIGIN,
            "a2a_endpoint": A2A_ENDPOINT, "generation": 1, "service_epoch": 7,
            "authorization_epoch": 1,
            "exp": (datetime.now(UTC) + timedelta(seconds=30)).isoformat(),
        })
        return body, signature

    def _challenge_responder(self, mutate=None):
        def _respond(url, payload, *, timeout):
            from uuid import uuid4

            from cryptography.hazmat.primitives.serialization import load_pem_private_key

            if mutate is not None:
                mutate()
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
            return FetchResult(url=url, status_code=200, body=json.dumps(response), fetched_at=time.time())
        return _respond

    def _access_rows(self) -> list[dict]:
        with db_session(self.db_path) as conn:
            return [dict(row) for row in conn.execute(
                "select config_version,status,secret_ciphertext from runtime_access_configs"
                " where catalog_agent_id=? order by config_version", (self.agent_id,))]

    def _binding_rows(self) -> list[dict]:
        with db_session(self.db_path) as conn:
            return [dict(row) for row in conn.execute(
                "select binding_id,status from runtime_bindings where catalog_agent_id=?",
                (self.agent_id,))]

    # ── 用例 ─────────────────────────────────────────────────────────────
    def test_challenge_failure_leaves_zero_access_rows_and_retry_succeeds(self) -> None:
        enrollment_id = "enr_tx_challenge_fail"
        grant = self._enrollment(enrollment_id)
        body, signature = self._bind(enrollment_id, grant)

        # 第一次：挑战端点拒绝（503）→ 409 + 固定诊断码；磁盘上零凭据行、零绑定行。
        with mock.patch.object(ProfileFetcher, "post_json",
                               return_value=FetchResult(url="https://runtime", status_code=503,
                                                        body="down", fetched_at=time.time())):
            with self.assertLogs("kiwi_catalog.api.handlers.cloud_binding", level="WARNING") as logs:
                status, result = _call(self.app, "POST",
                                       f"/v1/agents/{self.agent_id}/runtime-bindings", body, signature=signature)
        self.assertEqual(status, 403, result)
        self.assertEqual(self._access_rows(), [])
        self.assertEqual(self._binding_rows(), [])
        self.assertIn("BIND_CHALLENGE_REJECTED", "\n".join(logs.output))

        # 第二次：同一 enrollment、同一 expected_version=0。首次尝试已在挑战前
        # 消费绑定请求 nonce（防重放），重试按真实运行时行为重新签名（新 nonce）。
        retried_body, signature = self._bind(enrollment_id, grant)
        self.assertEqual(retried_body, body)
        with mock.patch.object(ProfileFetcher, "post_json", side_effect=self._challenge_responder()):
            status, result = _call(self.app, "POST",
                                   f"/v1/agents/{self.agent_id}/runtime-bindings", body, signature=signature)
        self.assertEqual(status, 200, result)
        self.assertEqual(result["status"], "bound")
        outcome = result["access_config_outcome"]
        self.assertEqual(set(outcome), {"applied", "config_version", "status"})
        self.assertTrue(outcome["applied"])
        rows = self._access_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(outcome["config_version"], rows[0]["config_version"])
        self.assertEqual(outcome["status"], rows[0]["status"])
        self.assertNotIn("tx-secret-alpha", json.dumps(result))

    def test_reenrollment_advances_past_revoked_binding_history(self) -> None:
        self._create_legacy_binding()
        first_binding_id = self.binding_id
        self._create_legacy_binding()
        second_binding_id = self.binding_id
        bind_path = f"/v1/agents/{self.agent_id}/runtime-bindings"
        status, revoked = _call(
            self.app, "POST", f"{bind_path}/{second_binding_id}/revoke", {"admin_token": ADMIN_TOKEN},
        )
        self.assertEqual(status, 200, revoked)
        self.assertEqual(revoked["status"], "revoked")

        enrollment_id = "enr_tx_reconnect"
        _, device_hash = self._insert_enrollment(status="ready_for_authorization", enrollment_id=enrollment_id)
        user_code = "S" + hashlib.sha256(enrollment_id.encode()).hexdigest()[:7].upper()
        authorized = self.client.post(
            f"/v1/accounts/enrollments/{enrollment_id}/authorize",
            json={"user_code": user_code}, headers={"Origin": "https://localhost"},
        )
        self.assertEqual(authorized.status_code, 200, authorized.text)
        self.assertEqual(authorized.json()["status"], "authorized")

        grant = enrollment_service_grant(enrollment_id, device_hash)
        body, signature = self._bind(enrollment_id, grant, with_config=False)
        with mock.patch.object(ProfileFetcher, "post_json", side_effect=self._challenge_responder()):
            status, result = _call(self.app, "POST", bind_path, body, signature=signature)
        self.assertEqual(status, 200, result)
        self.assertEqual(result["status"], "bound")
        self.assertEqual(result["binding_version"], 3)
        self.assertIsNone(result["superseded_binding_id"])

        with db_session(self.db_path) as conn:
            bindings = conn.execute(
                "select binding_id, binding_version, status from runtime_bindings"
                " where catalog_agent_id=? order by binding_version", (self.agent_id,),
            ).fetchall()
            enrollment = conn.execute(
                "select status, expected_binding_version, binding_id, consumed_at from enrollments"
                " where enrollment_id=?", (enrollment_id,),
            ).fetchone()
        self.assertEqual([tuple(row) for row in bindings], [
            (first_binding_id, 1, "revoked"),
            (second_binding_id, 2, "revoked"),
            (result["binding_id"], 3, "active"),
        ])
        self.assertEqual(enrollment["status"], "bound")
        self.assertEqual(enrollment["expected_binding_version"], 3)
        self.assertEqual(enrollment["binding_id"], result["binding_id"])
        self.assertTrue(enrollment["consumed_at"])

    def test_reenrollment_binds_while_previous_card_stays_withdrawn(self) -> None:
        """卸载后重新接入：旧名片撤回不能卡死新绑定。

        卸载 = 撤销绑定 + 撤回名片（WITHDRAWN）。重新配对通过持钥证明与端点
        挑战后，绑定回执只发给这台 Runtime，不是买家公开读：旧名片保持
        WITHDRAWN 也必须完成绑定，否则卸载过的商家永远接不回来。回执如实给出
        WITHDRAWN 与当前版本号（Runtime 重新发布时用它做 CAS 期望值），不引用
        已撤回名片的 ETag；买家公开读在 Runtime 重新发布前仍拒签（SIG-02 不变）。
        """
        self._create_legacy_binding()
        self._create_legacy_binding()
        old_binding_id = self.binding_id
        old_revision = self._publish()
        bind_path = f"/v1/agents/{self.agent_id}/runtime-bindings"
        status, revoked = _call(
            self.app, "POST", f"{bind_path}/{old_binding_id}/revoke", {"admin_token": ADMIN_TOKEN},
        )
        self.assertEqual(status, 200, revoked)
        with db_session(self.db_path) as conn:
            publication = conn.execute(
                "select publication_state, active_revision from card_publications"
                " where catalog_agent_id=?",
                (self.agent_id,),
            ).fetchone()
        self.assertEqual(
            (publication["publication_state"], int(publication["active_revision"])),
            ("WITHDRAWN", old_revision),
        )

        enrollment_id = "enr_tx_reconnect_withdrawn"
        _, device_hash = self._insert_enrollment(
            status="ready_for_authorization", enrollment_id=enrollment_id,
        )
        user_code = "S" + hashlib.sha256(enrollment_id.encode()).hexdigest()[:7].upper()
        authorized = self.client.post(
            f"/v1/accounts/enrollments/{enrollment_id}/authorize",
            json={"user_code": user_code}, headers={"Origin": "https://localhost"},
        )
        self.assertEqual(authorized.status_code, 200, authorized.text)

        grant = enrollment_service_grant(enrollment_id, device_hash)
        body, signature = self._bind(enrollment_id, grant)
        with mock.patch.object(ProfileFetcher, "post_json", side_effect=self._challenge_responder()):
            status, result = _call(self.app, "POST", bind_path, body, signature=signature)
        self.assertEqual(status, 200, result)
        self.assertEqual(result["status"], "bound")
        self.assertEqual(result["binding_version"], 3)
        receipt = result["binding_claim"]
        self.assertEqual(receipt["governance"]["publication_state"], "WITHDRAWN")
        self.assertEqual(receipt["card_revision"], old_revision)
        self.assertIsNone(receipt["card_etag"])
        self.assertTrue(result["access_config_outcome"]["applied"])
        with db_session(self.db_path) as conn:
            enrollment = conn.execute(
                "select status, binding_id from enrollments where enrollment_id=?", (enrollment_id,),
            ).fetchone()
        self.assertEqual(
            (enrollment["status"], enrollment["binding_id"]), ("bound", result["binding_id"]),
        )

        # 买家公开读：Runtime 重新发布前，旧名片仍是 WITHDRAWN → 拒签不变。
        status, _claims = _call(self.app, "GET", f"/v1/agents/{self.agent_id}/runtime-binding")
        self.assertEqual(status, 403)

        self._assert_clean_republication(enrollment_id, result["binding_id"], old_revision)

    def test_reenrollment_replaces_binding_when_legacy_card_is_quarantined(self) -> None:
        self._create_legacy_binding()
        old_binding_id = self.binding_id
        old_revision = self._publish()
        # 模拟隔离规则引入之前发布的存量名片；后续操作全部走真实授权、绑定和发布端点。
        from kiwi_catalog.a2a.card_store import compute_etag
        from kiwi_catalog.a2a.enrollment_canonical import canonical_digest

        marker = "historical-fixture-value"
        with db_session(self.db_path) as conn:
            version = conn.execute(
                "select canonical_bytes from agent_card_versions where catalog_agent_id=? and card_revision=?",
                (self.agent_id, old_revision),
            ).fetchone()
            legacy = json.loads(version["canonical_bytes"])
            legacy["description"] = f"https://fixture.example/app?sharecode={marker}"
            conn.execute("update agent_card_versions set canonical_bytes=?, digest=? "
                         "where catalog_agent_id=? and card_revision=?",
                         (json.dumps(legacy), canonical_digest(legacy), self.agent_id, old_revision))
            conn.execute("update card_publications set etag=? where catalog_agent_id=?",
                         (compute_etag(legacy), self.agent_id))
        base = f"/v1/agents/{self.agent_id}"
        for path, expected in (("/agent-card.json", 410), ("/runtime-binding", 403)):
            status, result = _call(self.app, "GET", base + path)
            self.assertEqual(status, expected, result)
            self.assertNotIn(marker, json.dumps(result))

        enrollment_id = "enr_tx_replace_quarantined"
        _, device_hash = self._insert_enrollment(status="ready_for_authorization", enrollment_id=enrollment_id)
        user_code = "S" + hashlib.sha256(enrollment_id.encode()).hexdigest()[:7].upper()
        authorized = self.client.post(
            f"/v1/accounts/enrollments/{enrollment_id}/authorize",
            json={"user_code": user_code}, headers={"Origin": "https://localhost"},
        )
        self.assertEqual(authorized.status_code, 200, authorized.text)
        grant = enrollment_service_grant(enrollment_id, device_hash)
        body, signature = self._bind(enrollment_id, grant, with_config=False)
        # Even a failure after the endpoint challenge must leave the old binding
        # and quarantine untouched; the already-authorized Runtime can retry.
        from kiwi_catalog.core.errors import PermissionDenied

        with (mock.patch.object(ProfileFetcher, "post_json", side_effect=self._challenge_responder()),
              mock.patch("kiwi_catalog.a2a.binding_claims.load_issuer_key_set",
                         side_effect=PermissionDenied("test issuer unavailable"))):
            status, failure = _call(self.app, "POST", base + "/runtime-bindings", body, signature=signature)
        self.assertEqual(status, 403, failure)
        self.assertEqual(failure["error"], "test issuer unavailable")
        self.assertEqual(self._binding_rows(), [{"binding_id": old_binding_id, "status": "active"}])
        with db_session(self.db_path) as conn:
            publication = conn.execute("select publication_state from card_publications where catalog_agent_id=?",
                                       (self.agent_id,)).fetchone()
            self.assertEqual(publication["publication_state"], "ACTIVE")
            self.assertIsNone(conn.execute(
                "select 1 from audit_events where event='card_publication_withdrawn' and actor=?",
                (f"enrollment:{enrollment_id}",),
            ).fetchone())

        body, signature = self._bind(enrollment_id, grant, with_config=False)
        with mock.patch.object(ProfileFetcher, "post_json", side_effect=self._challenge_responder()) as challenge:
            status, result = _call(self.app, "POST", base + "/runtime-bindings", body, signature=signature)
        challenge.assert_called_once()
        self.assertEqual(status, 200, result)
        self.assertEqual(result["status"], "bound")
        self.assertEqual(result["binding_version"], 2)
        self.assertEqual(result["superseded_binding_id"], old_binding_id)
        self.assertNotIn(marker, json.dumps(result))
        new_binding_id = result["binding_id"]
        self.assertEqual(self._binding_rows(), [
            {"binding_id": old_binding_id, "status": "revoked"},
            {"binding_id": new_binding_id, "status": "active"},
        ])
        # 丢失响应后的重试要复用绑定，不重新挑战、不再生成版本。
        body, signature = self._bind(enrollment_id, grant, with_config=False)
        with mock.patch.object(ProfileFetcher, "post_json") as challenge:
            status, replay = _call(self.app, "POST", base + "/runtime-bindings", body, signature=signature)
        challenge.assert_not_called()
        self.assertEqual(status, 200, replay)
        self.assertEqual(replay["binding_id"], new_binding_id)
        for response in (result, replay):
            receipt = response["binding_claim"]
            self.assertEqual(receipt["governance"]["publication_state"], "WITHDRAWN")
            self.assertEqual(receipt["card_revision"], old_revision)
            self.assertIsNone(receipt["card_etag"])
        with db_session(self.db_path) as conn:
            version = conn.execute(
                "select canonical_bytes, digest from agent_card_versions where catalog_agent_id=? and card_revision=?",
                (self.agent_id, old_revision),
            ).fetchone()
            self.assertEqual(json.loads(version["canonical_bytes"]), legacy)
            self.assertEqual(version["digest"], canonical_digest(legacy))
            publication = conn.execute("select etag from card_publications where catalog_agent_id=?",
                                       (self.agent_id,)).fetchone()
            self.assertEqual(publication["etag"], compute_etag(legacy))
            self.assertIsNone(conn.execute(
                "select 1 from agent_endpoints where catalog_agent_id=? and kind in ('a2a', 'agent_card')",
                (self.agent_id,),
            ).fetchone())
            audit = conn.execute(
                "select details_json from audit_events where event='card_publication_withdrawn' and actor=?",
                (f"enrollment:{enrollment_id}",),
            ).fetchall()
            self.assertEqual(len(audit), 1)
            self.assertEqual(json.loads(audit[0]["details_json"])["reason"], "quarantined_card_rebind")
        for path, expected in (("/agent-card.json", 410), ("/runtime-binding", 403)):
            status, payload = _call(self.app, "GET", base + path)
            self.assertEqual(status, expected, payload)
            self.assertNotIn(marker, json.dumps(payload))
        self._assert_clean_republication(enrollment_id, new_binding_id, old_revision)

    def _assert_clean_republication(self, enrollment_id: str, new_binding_id: str, old_revision: int) -> None:
        # Runtime 以回执给出的版本号作为 CAS 期望值，发布商家批准的干净版本。
        with db_session(self.db_path) as conn:
            digest = conn.execute(
                "select approved_card_digest from enrollments where enrollment_id=?", (enrollment_id,),
            ).fetchone()["approved_card_digest"]
        status, created = _call(
            self.app, "POST", f"/v1/agents/{self.agent_id}/card-publications",
            {"publication": {
                "schema_version": "0.1.2", "agent_id": self.agent_id, "binding_id": new_binding_id,
                "generation": 1, "expected_revision": old_revision, "wire_profile": "a2a-1.0",
                "card_digest": digest,
                "agent_card": {
                    "name": "Security Merchant A", "version": "1.0.0", "url": RUNTIME_ORIGIN,
                    "supportedInterfaces": [{
                        "url": A2A_ENDPOINT, "protocolBinding": "JSONRPC", "protocolVersion": "1.0",
                    }],
                },
            }},
            signature=_jws(self.private_pem, RUNTIME_ORIGIN, {
                "agent_id": self.agent_id, "binding_id": new_binding_id, "card_digest": digest,
                "expected_revision": old_revision, "generation": 1,
            }),
        )
        self.assertEqual(status, 200, created)
        self.assertEqual(created["card_revision"], old_revision + 1)
        activate = {
            "binding_id": new_binding_id, "card_revision": created["card_revision"],
            "expected_revision": old_revision,
        }
        status, activated = _call(
            self.app, "POST", f"/v1/agents/{self.agent_id}/publish", activate,
            signature=_jws(self.private_pem, RUNTIME_ORIGIN, {"agent_id": self.agent_id, **activate}),
        )
        self.assertEqual(status, 200, activated)
        self.assertEqual(activated["publication_state"], "ACTIVE")
        status, claims = _call(self.app, "GET", f"/v1/agents/{self.agent_id}/runtime-binding")
        self.assertEqual(status, 200, claims)
        self.assertEqual(claims["claims"]["binding_id"], new_binding_id)
        self.assertEqual(claims["governance"]["publication_state"], "ACTIVE")

    def test_commit_binding_version_cas_failure_rolls_back_everything(self) -> None:
        enrollment_id = "enr_tx_commit_rollback"
        grant = self._enrollment(enrollment_id)
        body, signature = self._bind(enrollment_id, grant)

        # 提交事务的二次校验：挑战窗口内另一绑定把 expected_binding_version 推进，
        # 版本 CAS 失败 → 整事务回滚（凭据行与绑定行都不残留），enrollment 仍可重试。
        def _competing_bind_during_challenge():
            with db_session(self.db_path) as conn:
                conn.execute("update enrollments set expected_binding_version=2 where enrollment_id=?",
                             (enrollment_id,))

        with mock.patch.object(ProfileFetcher, "post_json",
                               side_effect=self._challenge_responder(mutate=_competing_bind_during_challenge)):
            status, result = _call(self.app, "POST",
                                   f"/v1/agents/{self.agent_id}/runtime-bindings", body, signature=signature)
        self.assertGreaterEqual(status, 400, result)
        self.assertEqual(self._access_rows(), [])
        self.assertEqual(self._binding_rows(), [])

    def test_existing_head_active_invalid_pending_never_overwritten(self) -> None:
        for index, head_status in enumerate(("active", "invalid", "pending"), start=1):
            with self.subTest(head_status=head_status):
                old_secret = f"old-ciphertext-{head_status}"
                with db_session(self.db_path) as conn:
                    _insert_head_row(conn, agent_id=self.agent_id, version=index,
                                     status=head_status, secret=old_secret)
                enrollment_id = f"enr_tx_head_{head_status}"
                grant = self._enrollment(enrollment_id, expected_binding_version=index)
                body, signature = self._bind(enrollment_id, grant)

                with mock.patch.object(ProfileFetcher, "post_json", side_effect=self._challenge_responder()):
                    status, result = _call(self.app, "POST",
                                           f"/v1/agents/{self.agent_id}/runtime-bindings", body, signature=signature)
                self.assertEqual(status, 200, result)
                outcome = result["access_config_outcome"]
                self.assertEqual(set(outcome), {"applied", "reason", "head_version", "head_status"})
                self.assertFalse(outcome["applied"])
                self.assertEqual(outcome["reason"], "runtime_access_version_conflict")
                self.assertEqual(outcome["head_version"], index)
                self.assertEqual(outcome["head_status"], head_status)
                rows = self._access_rows()
                self.assertEqual(len(rows), index)  # 没有新增行
                self.assertEqual(rows[index - 1]["secret_ciphertext"], old_secret)  # 旧密文原样
                self.assertEqual(rows[index - 1]["status"], head_status)
                self.assertNotIn("tx-secret-alpha", json.dumps(result))

    def test_stage_cas_race_downgrades_to_skip_and_never_overwrites(self) -> None:
        enrollment_id = "enr_tx_stage_race"
        grant = self._enrollment(enrollment_id)
        body, signature = self._bind(enrollment_id, grant)

        # 白盒注入：head 读取后、stage 执行时 head 已被并发推进（0 → 2/active）。
        # 分支契约：降级为跳过 + 明确回报，绑定照常完成；绝不覆盖对方的更新。
        states = iter([(0, "none"), (2, "active")])
        real_state = runtime_access_service.current_version_state

        with mock.patch.object(runtime_access_service, "current_version_state",
                               side_effect=lambda conn, catalog_agent_id: next(states, real_state(conn, catalog_agent_id))), \
             mock.patch.object(runtime_access_service, "stage_runtime_access",
                               side_effect=runtime_access_service.ConflictError("runtime access version conflict")):
            with mock.patch.object(ProfileFetcher, "post_json", side_effect=self._challenge_responder()):
                status, result = _call(self.app, "POST",
                                       f"/v1/agents/{self.agent_id}/runtime-bindings", body, signature=signature)
        self.assertEqual(status, 200, result)
        outcome = result["access_config_outcome"]
        self.assertEqual(outcome, {"applied": False, "reason": "runtime_access_version_conflict",
                                   "head_version": 2, "head_status": "active"})
        self.assertEqual(self._access_rows(), [])  # 本请求没有写任何凭据行

    def test_custody_disabled_fails_whole_bind_without_rows(self) -> None:
        enrollment_id = "enr_tx_custody_off"
        grant = self._enrollment(enrollment_id)
        body, signature = self._bind(enrollment_id, grant)

        env = {runtime_access_service.CUSTODY_ENV: "0"}
        with mock.patch.dict(os.environ, env), \
             mock.patch.object(ProfileFetcher, "post_json", side_effect=self._challenge_responder()):
            status, result = _call(self.app, "POST",
                                   f"/v1/agents/{self.agent_id}/runtime-bindings", body, signature=signature)
        self.assertGreaterEqual(status, 400, result)
        self.assertEqual(self._access_rows(), [])   # 非 CAS 冲突的 ConflictError：整事务回滚
        self.assertEqual(self._binding_rows(), [])  # 绑定同样未落库
        # enrollment 仍为 authorized：商家恢复代管开关后可原样重试。
        with db_session(self.db_path) as conn:
            row = conn.execute("select status from enrollments where enrollment_id=?", (enrollment_id,)).fetchone()
        self.assertEqual(row["status"], "authorized")

    def test_outcome_never_carries_credential_material(self) -> None:
        enrollment_id = "enr_tx_whitelist"
        grant = self._enrollment(enrollment_id)
        body, signature = self._bind(enrollment_id, grant)
        with mock.patch.object(ProfileFetcher, "post_json", side_effect=self._challenge_responder()):
            status, result = _call(self.app, "POST",
                                   f"/v1/agents/{self.agent_id}/runtime-bindings", body, signature=signature)
        self.assertEqual(status, 200, result)
        # 成功与跳过两分支的键集都是白名单；整个响应不含 secret / 密文。
        self.assertEqual(set(result["access_config_outcome"]), {"applied", "config_version", "status"})
        serialized = json.dumps(result)
        self.assertNotIn("tx-secret-alpha", serialized)


def enrollment_service_grant(enrollment_id: str, device_hash: str) -> str:
    from kiwi_catalog.services import enrollments as enrollment_service

    return enrollment_service._stable_grant(enrollment_id, device_hash)


if __name__ == "__main__":
    unittest.main()
