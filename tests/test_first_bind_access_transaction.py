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
from tests.test_enrollment_security import A2A_ENDPOINT, RUNTIME_ORIGIN, EnrollmentFixture

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
