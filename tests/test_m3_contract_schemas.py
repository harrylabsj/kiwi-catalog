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

"""M3 云端契约（v0.1.2）：**Catalog 真实产出**必须满足已并入契约锁的 schema。

与 kiwi 侧 `tests/cloud-contracts.test.ts` 校验同一批文件；此处的作用是防止
"实现悄悄偏离契约"——用真实的 `read_runtime_binding()` 产出与真实的请求形状
（而不是手写的近似样例）去校验。

kiwi 检出不存在时跳过（CI 中两仓并列，正常会执行）。
"""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

import jsonschema

CONTRACTS = Path(__file__).resolve().parents[2] / "kiwi" / "contracts"
CLAIMS_SCHEMA = CONTRACTS / "runtime-binding" / "0.1.2" / "claims.schema.json"
DOCUMENT_SCHEMA = CONTRACTS / "runtime-binding" / "0.1.2" / "document.schema.json"
BINDING_REQUEST_SCHEMA = CONTRACTS / "runtime-binding" / "0.1.2" / "binding-request.schema.json"
PUBLICATION_REQUEST_SCHEMA = CONTRACTS / "card-publication" / "0.1.2" / "request.schema.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@unittest.skipUnless(CLAIMS_SCHEMA.is_file(), "kiwi checkout not available")
class M3ContractSchemaTest(unittest.TestCase):
    def setUp(self) -> None:
        self.claims_schema = _load(CLAIMS_SCHEMA)
        self.document_schema = _load(DOCUMENT_SCHEMA)

    # ── claims：与 TS 侧同一口径 ────────────────────────────────
    def test_real_issuance_output_satisfies_both_schemas(self) -> None:
        """用**生产签发路径本身**（`read_runtime_binding`）的产出校验，而不是手写样例。"""
        import tempfile

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        from kiwi_catalog.a2a.binding_claims import read_runtime_binding
        from kiwi_catalog.agent_catalog.sqlite_repository import (
            new_catalog_agent_id,
            upsert_catalog_agent,
        )
        from kiwi_catalog.db.session import db_session

        with tempfile.TemporaryDirectory() as tmp:
            issuer_path = Path(tmp) / "issuer.pem"
            issuer_path.write_bytes(
                Ed25519PrivateKey.generate().private_bytes(
                    Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
                )
            )
            env = {
                "KIWI_CATALOG_ISSUER_KEY_FILE": str(issuer_path),
                "KIWI_CATALOG_ISSUER_KID": "kid_contract",
                "KIWI_CATALOG_PUBLIC_ORIGIN": "https://catalog.example",
            }
            agent_id = new_catalog_agent_id()
            with db_session(Path(tmp) / "catalog.sqlite") as conn:
                upsert_catalog_agent(
                    conn,
                    agent_id,
                    merchant_id="mkt_contract_1",
                    display_name="Contract Merchant",
                    canonical_domain="merchant.example",
                )
                conn.execute(
                    "insert into runtime_bindings (binding_id, catalog_agent_id, merchant_id,"
                    " runtime_origin, a2a_endpoint, key_id, key_thumbprint, key_jwk_json,"
                    " binding_version, service_epoch, status, expires_at, created_at, updated_at)"
                    " values ('binding_contract_1', ?, 'mkt_contract_1',"
                    " 'https://pilot.example.host', 'https://pilot.example.host/a2a',"
                    " 'https://pilot.example.host', ?, '{}', 1, 7, 'active', '', '', '')",
                    (agent_id, "sha256:" + "a" * 64),
                )
                conn.execute(
                    "insert into agent_card_versions (catalog_agent_id, card_revision,"
                    " wire_profile, canonical_bytes, digest, created_by, created_at)"
                    " values (?, 1, 'a2a-1.0', '{}', 'sha256:x', 'test', '')",
                    (agent_id,),
                )
                conn.execute(
                    "insert into card_publications (catalog_agent_id, active_revision,"
                    " publication_state, etag, updated_at)"
                    " values (?, 1, 'ACTIVE', '\"e1\"', '')",
                    (agent_id,),
                )
                document = read_runtime_binding(
                    conn, agent_id, now=datetime.now(timezone.utc), env=env
                )
                # 真实签发路径的产出必须同时满足 claims schema 与读响应 schema
                jsonschema.validate(document["claims"], self.claims_schema)
                jsonschema.validate(document, self.document_schema)
                self.assertEqual(
                    document["claims"]["card_url"],
                    f"https://catalog.example/v1/agents/{agent_id}/agent-card.json",
                )

    def test_claims_schema_rejects_the_shapes_we_deliberately_exclude(self) -> None:
        base = {
            "schema_version": "0.1.2",
            "binding_id": "binding_demo",
            "binding_version": 1,
            "merchant_id": "merchant_demo",
            "agent_id": "agent_demo",
            "workload_ref": "workload_demo",
            "runtime_origin": "https://merchant-demo.example",
            "a2a_endpoint": "https://merchant-demo.example/a2a",
            "card_url": "https://catalog.example/v1/agents/cagt_demo/agent-card.json",
            "key_id": "key_demo",
            "key_thumbprint": "sha256:" + "0" * 64,
            "service_epoch": 1,
            "issued_at": "2026-09-20T07:00:00Z",
            "expires_at": "2026-09-20T07:15:00Z",
            "issuer": "catalog_demo",
            "scope": "a2a-runtime",
            "status": "active",
        }
        jsonschema.validate(base, self.claims_schema)
        for override in (
            {"card_url": "/v1/agents/cagt_demo/agent-card.json"},  # 相对路径（M3 修掉的真实缺陷）
            {"key_thumbprint": "sha256:short"},
            {"scope": "other"},
            {"extra": 1},
        ):
            with self.subTest(override=override):
                with self.assertRaises(jsonschema.ValidationError):
                    jsonschema.validate({**base, **override}, self.claims_schema)
        missing = {key: value for key, value in base.items() if key != "card_url"}
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(missing, self.claims_schema)

    # ── 请求形状：与 handler 实际接受的字段一致 ──────────────────
    def test_request_schemas_match_what_the_handlers_accept(self) -> None:
        binding_request = _load(BINDING_REQUEST_SCHEMA)
        publication_request = _load(PUBLICATION_REQUEST_SCHEMA)
        jsonschema.validate(
            {
                "binding": {
                    "runtime_origin": "https://merchant-demo.example",
                    "a2a_endpoint": "https://merchant-demo.example/a2a",
                    "key_jwk": {"kty": "OKP", "crv": "Ed25519", "x": "abc"},
                    "key_id": "key_demo",
                    "generation": 1,
                    "service_epoch": 7,
                },
                "admin_token": "admin-token-m3",
            },
            binding_request,
        )
        jsonschema.validate(
            {
                "publication": {
                    "schema_version": "0.1.2",
                    "agent_id": "cagt_demo",
                    "binding_id": "binding_demo",
                    "generation": 1,
                    "expected_revision": 0,
                    "wire_profile": "a2a-1.0",
                    "card_digest": "sha256:" + "b" * 64,
                    "agent_card": {
                        "name": "Demo Merchant",
                        "version": "1.0.0",
                        "url": "https://merchant-demo.example",
                        "supportedInterfaces": [
                            {
                                "url": "https://merchant-demo.example/a2a",
                                "protocolBinding": "JSONRPC",
                                "protocolVersion": "1.0",
                            }
                        ],
                    },
                }
            },
            publication_request,
        )

    def test_document_schema_inlined_claims_stays_in_sync(self) -> None:
        """读响应 schema 里内联的 claims 必须与独立 claims schema 逐字段一致。"""
        inlined = self.document_schema["properties"]["claims"]
        standalone = {k: v for k, v in self.claims_schema.items() if k not in ("$id", "$schema")}
        self.assertEqual(inlined, standalone)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
