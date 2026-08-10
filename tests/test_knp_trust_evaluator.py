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

"""审查 P1-04：KNP trust evaluator 回归测试。

一个 UCP profile 只要以 **Kiwi negotiation capability namespace** 声明
（``kiwi.negotiation`` / ``com.kiwi:negotiation`` / ``urn:kiwi:negotiation`` /
裸 ``knp``）即构成 KNP claim——service endpoint protocol 写成 ``a2a`` 不能
绕过 KNP 治理。KNP claim 的 version / allowlist / spec / schema 缺任一项
不得 COMMERCE_VERIFIED。

KNP claim 的版本来源：KNP-protocol endpoint 的 ``version`` 或 service
``specifications`` 的 ``version``；都不带版本 = 缺声明版本。a2a endpoint 的
``version`` 是 A2A 传输版本，不当作 KNP 版本。
"""

from __future__ import annotations

import unittest

from kiwi_catalog.discovery.agent_card import AgentCardResult
from kiwi_catalog.discovery.trust import TrustPolicy
from kiwi_catalog.discovery.ucp import UcpProfileResult
from kiwi_catalog.discovery.verifier import TrustEvaluator

_COMMERCE_CAP = {"namespace": "com.example", "capability_id": "checkout"}
# KNP 声明 service：capability namespace = kiwi negotiation，endpoint protocol 写 a2a
#（bypass 场景），带 A2A 传输版本但无 KNP 版本/无 spec/schema。
_KIWI_SERVICE = {
    "id": "svc-checkout",
    "type": "commerce",
    "capabilities": ["kiwi.negotiation", "com.example:checkout"],
    "endpoints": [{"uri": "https://merchant.example/knp", "protocol": "a2a", "version": "1.0"}],
}
# KNP spec reference（version = KNP 版本，specUrl = specification 引用）。
_KNP_SPEC = {
    "id": "knp-spec",
    "label": "Kiwi Negotiation",
    "version": "1.0",
    "specUrl": "https://merchant.example/knp-spec",
}


def _card(capabilities=()) -> AgentCardResult:
    return AgentCardResult(version="1.0.0", capabilities=capabilities)


def _ucp(services, *, capabilities=(_COMMERCE_CAP,), **public_extra) -> UcpProfileResult:
    public = {"services": services}
    public.update(public_extra)
    return UcpProfileResult(
        specification_version="2026-04-08",
        capabilities=capabilities,
        public=public,
    )


def _evaluate(ucp: UcpProfileResult, *, knp_versions=("1.0",)) -> tuple[bool, str]:
    policy = TrustPolicy(allowed_knp_versions=knp_versions)
    evaluator = TrustEvaluator(policy)
    evidence = evaluator.evaluate_commerce_capabilities(_card(), ucp, "merchant.example")
    return evidence.passed, evidence.reason


def _with_spec(service: dict, *, version: str = "1.0") -> dict:
    """给 service 加 KNP spec reference（提供 KNP 版本），但不加 schema。"""
    return {**service, "specifications": [{**_KNP_SPEC, "version": version}]}


def _with_spec_schema(service: dict, *, version: str = "1.0") -> dict:
    """spec + schema（documentationUri）齐全。"""
    return {**service, "specifications": [{**_KNP_SPEC, "version": version}],
            "documentationUri": "https://merchant.example/knp-doc"}


class KnpTrustEvaluatorTest(unittest.TestCase):
    def test_kiwi_negotiation_capability_namespace_is_knp_claim(self) -> None:
        """BYPASS 回归：capability namespace 声明 = KNP claim，a2a protocol 不能绕过。

        a2a endpoint + kiwi.negotiation capability + spec（版本 1.0 在 allowlist）
        但缺 schema → 不通过（修复前只看 endpoint protocol，识别不到 KNP，
        该 profile 会被放行到 COMMERCE_VERIFIED）。
        """
        passed, reason = _evaluate(_ucp([_with_spec(_KIWI_SERVICE)]), knp_versions=("1.0",))
        self.assertFalse(passed)
        self.assertIn("specification/schema reference", reason)

    def test_knp_claim_version_not_in_allowlist_fails(self) -> None:
        """capability namespace 声明的 KNP 版本（spec version）不在 allowlist → 不通过。"""
        service = _with_spec_schema(_KIWI_SERVICE, version="2.0")
        passed, reason = _evaluate(_ucp([service]), knp_versions=("1.0",))
        self.assertFalse(passed)
        self.assertIn("KNP version 2.0 is not allowed", reason)

    def test_knp_claim_allowlist_empty_fails(self) -> None:
        """KNP claim 但 policy allowlist 为空 → 不通过。"""
        passed, reason = _evaluate(_ucp([_with_spec_schema(_KIWI_SERVICE)]), knp_versions=())
        self.assertFalse(passed)
        self.assertIn("allows no KNP versions", reason)

    def test_knp_claim_missing_version_fails(self) -> None:
        """KNP claim 缺声明版本（无 KNP endpoint version、无 spec version）→ 不通过。"""
        service = dict(_KIWI_SERVICE)  # a2a endpoint version 不当作 KNP 版本
        passed, reason = _evaluate(_ucp([service]), knp_versions=("1.0",))
        self.assertFalse(passed)
        self.assertIn("missing a declared version", reason)

    def test_knp_claim_missing_spec_schema_fails(self) -> None:
        """KNP claim 缺 spec/schema → 不通过（版本/allowlist 都合规）。"""
        service = {
            **_KIWI_SERVICE,
            "endpoints": [{"uri": "https://merchant.example/knp", "protocol": "knp", "version": "1.0"}],
        }  # knp endpoint 提供版本；无 specifications/documentationUri
        passed, reason = _evaluate(_ucp([service]), knp_versions=("1.0",))
        self.assertFalse(passed)
        self.assertIn("specification/schema reference", reason)

    def test_knp_claim_version_schema_without_spec_url_fails(self) -> None:
        """P1-04 回归：KNP claim 有 version + schemaUrl 但无 specUrl → 不通过。

        修复前 has_spec = bool(knp_specs) or bool(knp_endpoints)——KNP spec
        条目或 KNP endpoint 存在即算有 spec 引用，无 specUrl 的声明可绕过
        spec 治理进 COMMERCE_VERIFIED。
        """
        service = {
            **_KIWI_SERVICE,
            "specifications": [
                {
                    "id": "knp-spec",
                    "label": "Kiwi Negotiation",
                    "version": "1.0",
                    "schemaUrl": "https://merchant.example/knp-schema.json",
                }
            ],
        }
        passed, reason = _evaluate(_ucp([service]), knp_versions=("1.0",))
        self.assertFalse(passed)
        self.assertIn("specification/schema reference", reason)

    def test_knp_claim_version_schema_and_spec_url_passes(self) -> None:
        """防过紧：version + schemaUrl + specUrl 齐全 → 通过。"""
        service = {
            **_KIWI_SERVICE,
            "specifications": [
                {
                    "id": "knp-spec",
                    "label": "Kiwi Negotiation",
                    "version": "1.0",
                    "specUrl": "https://merchant.example/knp-spec",
                    "schemaUrl": "https://merchant.example/knp-schema.json",
                }
            ],
        }
        passed, reason = _evaluate(_ucp([service]), knp_versions=("1.0",))
        self.assertTrue(passed, reason)

    def test_proper_knp_claim_passes(self) -> None:
        """capability namespace 声明 + 版本在 allowlist + spec/schema 齐全 → 通过。"""
        passed, reason = _evaluate(_ucp([_with_spec_schema(_KIWI_SERVICE)]), knp_versions=("1.0",))
        self.assertTrue(passed, reason)

    def test_knp_protocol_endpoint_still_detected(self) -> None:
        """knp-protocol endpoint 仍是 KNP claim（原检测路径保留）。"""
        service = {
            **_with_spec_schema(_KIWI_SERVICE),
            "endpoints": [{"uri": "https://merchant.example/knp", "protocol": "knp", "version": "1.0"}],
        }
        passed, reason = _evaluate(_ucp([service]), knp_versions=("1.0",))
        self.assertTrue(passed, reason)

    def test_plain_commerce_capability_not_knp_passes_without_allowlist(self) -> None:
        """非 Kiwi negotiation 的 commerce capability 不是 KNP claim——不触发
        allowlist/spec/schema 强制（普通 commerce 能力行为不变）。"""
        service = {
            "id": "svc-checkout",
            "type": "commerce",
            "capabilities": ["com.example:checkout"],
            "endpoints": [{"uri": "https://merchant.example/checkout", "protocol": "a2a"}],
        }
        passed, reason = _evaluate(_ucp([service]), knp_versions=())
        self.assertTrue(passed, reason)

    def test_urn_kiwi_negotiation_capability_is_knp(self) -> None:
        """URN 形式的 Kiwi negotiation capability（urn:kiwi:negotiation）也计为
        KNP claim——缺 spec/schema 时被拒（若未识别为 KNP 会被放行）。"""
        service = {
            **_KIWI_SERVICE,
            "capabilities": ["urn:kiwi:negotiation"],
            "endpoints": [{"uri": "https://merchant.example/knp", "protocol": "knp", "version": "1.0"}],
        }
        passed, reason = _evaluate(_ucp([service]), knp_versions=("1.0",))
        self.assertFalse(passed)
        self.assertIn("specification/schema reference", reason)

    def test_top_level_openapi_counts_as_schema(self) -> None:
        """顶层 specifications.openAPIDocument 满足 KNP schema 引用（无需
        service.documentationUri）。"""
        service = {**_with_spec(_KIWI_SERVICE), "documentationUri": ""}
        ucp = _ucp(
            [service],
            specifications=[
                {"id": "knp-openapi", "label": "KNP", "version": "1.0",
                 "openAPIDocument": "https://merchant.example/knp-openapi.json"}
            ],
        )
        passed, reason = _evaluate(ucp, knp_versions=("1.0",))
        self.assertTrue(passed, reason)

    # ── 验收：com.harrylabsj.kiwi.shopping.negotiation + protocol='a2a' ──

    def test_exact_kiwi_shopping_negotiation_id_is_knp_claim(self) -> None:
        """验收：capability ``com.harrylabsj.kiwi.shopping.negotiation`` +
        endpoint protocol='a2a' 即 KNP claim——缺 schema 时 trust evaluation 失败。"""
        service = {
            "id": "svc-checkout",
            "type": "commerce",
            "capabilities": ["com.harrylabsj.kiwi.shopping.negotiation"],
            "endpoints": [{"uri": "https://merchant.example/knp", "protocol": "a2a", "version": "1.0"}],
            "specifications": [{"id": "knp-spec", "label": "Kiwi Negotiation", "version": "1.0"}],
        }  # 有 spec（提供版本 1.0，allowlist 通过）但无 schema
        passed, reason = _evaluate(_ucp([service]), knp_versions=("1.0",))
        self.assertFalse(passed)
        self.assertIn("specification/schema reference", reason)

    def test_exact_kiwi_shopping_negotiation_missing_version_fails(self) -> None:
        """验收：a2a protocol + exact id、无任何 KNP 版本声明 → 失败（缺版本）。"""
        service = {
            "id": "svc-checkout",
            "type": "commerce",
            "capabilities": ["com.harrylabsj.kiwi.shopping.negotiation"],
            "endpoints": [{"uri": "https://merchant.example/knp", "protocol": "a2a"}],
        }
        passed, reason = _evaluate(_ucp([service]), knp_versions=("1.0",))
        self.assertFalse(passed)
        self.assertIn("missing a declared version", reason)

    def test_exact_kiwi_shopping_negotiation_unsupported_version_fails(self) -> None:
        """验收：exact id + 版本不在 allowlist → 失败（unsupported version）。"""
        service = {
            "id": "svc-checkout",
            "type": "commerce",
            "capabilities": ["com.harrylabsj.kiwi.shopping.negotiation"],
            "endpoints": [{"uri": "https://merchant.example/knp", "protocol": "a2a", "version": "1.0"}],
            "specifications": [{"id": "knp-spec", "label": "Kiwi Negotiation", "version": "2.0"}],
            "documentationUri": "https://merchant.example/knp-doc",
        }
        passed, reason = _evaluate(_ucp([service]), knp_versions=("1.0",))
        self.assertFalse(passed)
        self.assertIn("KNP version 2.0 is not allowed", reason)

    def test_exact_kiwi_shopping_negotiation_valid_passes(self) -> None:
        """验收：exact id + 版本在 allowlist + spec/schema 齐全 → 通过。"""
        service = {
            "id": "svc-checkout",
            "type": "commerce",
            "capabilities": ["com.harrylabsj.kiwi.shopping.negotiation"],
            "endpoints": [{"uri": "https://merchant.example/knp", "protocol": "a2a", "version": "1.0"}],
            "specifications": [
                {
                    "id": "knp-spec",
                    "label": "Kiwi Negotiation",
                    "version": "1.0",
                    "specUrl": "https://merchant.example/knp-spec",
                }
            ],
            "documentationUri": "https://merchant.example/knp-doc",
        }
        passed, reason = _evaluate(_ucp([service]), knp_versions=("1.0",))
        self.assertTrue(passed, reason)


class CanonicalKiwiUcpAdapterTest(unittest.TestCase):
    """审查 P2：Kiwi build 输出的 canonical UCP 模型（顶层 ``ucp`` + services/
    capabilities map）→ 标准解析器适配——per-capability version/spec/schema 注入
    内部 service，_knp_claims 据此执行 KNP 治理（缺 metadata / 版本不支持 → 拒）。"""

    POLICY = TrustPolicy(allowed_knp_versions=("1.0",))

    @staticmethod
    def _parse(canonical: dict, *, policy=None):
        from kiwi_catalog.discovery.ucp import UcpProfileParser

        parser = UcpProfileParser(policy or CanonicalKiwiUcpAdapterTest.POLICY)
        return parser.parse(canonical, source_url="https://merchant.example/.well-known/ucp")

    @staticmethod
    def _canonical(capabilities_map: dict, *, services: dict | None = None, version: str = "2026-04-08") -> dict:
        return {
            "ucp": {
                "version": version,
                "serviceIdentity": {"id": "https://merchant.example/identity", "name": "Merchant"},
                "services": services
                or {
                    "svc-checkout": {
                        "type": "commerce",
                        "capabilities": ["com.example:checkout", "kiwi.negotiation"],
                        "endpoints": [
                            {"uri": "https://merchant.example/knp", "protocol": "a2a", "version": "1.0"}
                        ],
                    }
                },
                "capabilities": capabilities_map,
            }
        }

    @staticmethod
    def _vendor_profile(capabilities_map: dict) -> dict:
        """exact Kiwi ``buildKiwiVendorProfile`` 形状：服务声明只有
        ``{version, spec, transport, endpoint}``（无 capabilities/endpoints
        列表）；capability 是 root capabilities map 里以 service id 为前缀的键。"""
        return {
            "ucp": {
                "version": "2026-04-08",
                "serviceIdentity": {"id": "https://merchant.example/identity", "name": "Merchant"},
                "services": {
                    "com.harrylabsj.kiwi.shopping": {
                        "version": "1.0",
                        "spec": "https://kiwi.harrylabsj.com/shopping/spec",
                        "transport": "a2a",
                        "endpoint": "https://merchant.example/knp",
                    }
                },
                "capabilities": capabilities_map,
            }
        }

    def _evaluate(self, canonical: dict) -> tuple[bool, str]:
        evaluator = TrustEvaluator(self.POLICY)
        evidence = evaluator.evaluate_commerce_capabilities(
            _card(), self._parse(canonical), "merchant.example"
        )
        return evidence.passed, evidence.reason

    def test_canonical_ucp_adapter_parses_kiwi_build(self) -> None:
        """canonical 模型 → 标准形状：services map → list、capabilities map →
        per-capability version/spec/schema 注入 specifications。"""
        canonical = self._canonical(
            {
                "kiwi.negotiation": {
                    "version": "1.0",
                    "spec": "https://kiwi.harrylabsj.com/knp/spec",
                    "schema": "https://kiwi.harrylabsj.com/knp/schema.json",
                }
            }
        )
        result = self._parse(canonical)
        self.assertEqual(result.specification_version, "2026-04-08")
        svc = result.public["services"][0]
        self.assertEqual(svc["id"], "svc-checkout")
        self.assertEqual(svc["capabilities"], ["com.example:checkout", "kiwi.negotiation"])
        # kiwi.negotiation 的 per-capability metadata 注入 specifications。
        spec = next(s for s in svc["specifications"] if s["id"] == "kiwi.negotiation")
        self.assertEqual(spec["version"], "1.0")
        self.assertEqual(spec["specUrl"], "https://kiwi.harrylabsj.com/knp/spec")
        self.assertEqual(spec["schemaUrl"], "https://kiwi.harrylabsj.com/knp/schema.json")
        # capabilities 行：单点名（kiwi.negotiation）按 split_capability_id 现有
        # 语义归到 default_namespace（canonical 域）；_knp_claims 对原始 capability
        # 字符串（非拆分行）识别 Kiwi negotiation（commerce evaluator 测试验证）。
        ids = [(c["namespace"], c["capability_id"]) for c in result.capabilities]
        self.assertIn(("com.example", "checkout"), ids)
        self.assertIn(("merchant.example", "kiwi.negotiation"), ids)

    def test_canonical_kiwi_knp_accepted_when_policy_allows(self) -> None:
        """canonical 完整 metadata + KNP 版本在 allowlist → 通过。"""
        passed, reason = self._evaluate(
            self._canonical(
                {
                    "kiwi.negotiation": {
                        "version": "1.0",
                        "spec": "https://kiwi.harrylabsj.com/knp/spec",
                        "schema": "https://kiwi.harrylabsj.com/knp/schema.json",
                    }
                }
            )
        )
        self.assertTrue(passed, reason)

    def test_canonical_kiwi_knp_missing_metadata_rejected(self) -> None:
        """canonical capability 无 version/spec/schema → 拒（缺声明版本）。"""
        passed, reason = self._evaluate(self._canonical({"kiwi.negotiation": {}}))
        self.assertFalse(passed)
        self.assertIn("missing a declared version", reason)

    def test_canonical_kiwi_knp_has_version_but_no_schema_rejected(self) -> None:
        """canonical capability 有 version 但缺 spec/schema → 拒（spec/schema）。"""
        passed, reason = self._evaluate(self._canonical({"kiwi.negotiation": {"version": "1.0"}}))
        self.assertFalse(passed)
        self.assertIn("specification/schema reference", reason)

    def test_kiwi_build_vendor_profile_maps_to_non_empty_standard(self) -> None:
        """exact ``buildKiwiVendorProfile`` 形状（{version,spec,transport,endpoint}
        服务声明 + root capabilities map）→ 非空 endpoints/capabilities/
        specifications（修复前 capabilities=[] / endpoints=[] → _validate_services
        拒、KNP metadata 丢失）。"""
        profile = self._vendor_profile(
            {
                "com.harrylabsj.kiwi.shopping.negotiation": {
                    "version": "1.0",
                    "spec": "https://kiwi.harrylabsj.com/knp/spec",
                    "schema": "https://kiwi.harrylabsj.com/knp/schema.json",
                }
            }
        )
        result = self._parse(profile)
        svc = result.public["services"][0]
        # endpoint 从 service 声明构建（非空）。
        self.assertEqual(
            svc["endpoints"],
            [{"uri": "https://merchant.example/knp", "protocol": "a2a", "version": "1.0"}],
        )
        # capability id 从 root capabilities map 前缀派生（非空）。
        self.assertEqual(svc["capabilities"], ["com.harrylabsj.kiwi.shopping.negotiation"])
        # per-capability version/spec/schema 注入 specifications（非空）。
        spec = svc["specifications"][0]
        self.assertEqual(spec["id"], "com.harrylabsj.kiwi.shopping.negotiation")
        self.assertEqual(spec["version"], "1.0")
        self.assertEqual(spec["specUrl"], "https://kiwi.harrylabsj.com/knp/spec")
        self.assertEqual(spec["schemaUrl"], "https://kiwi.harrylabsj.com/knp/schema.json")
        # extract 出的 capability 行含 (com.harrylabsj.kiwi.shopping, negotiation)。
        ids = [(c["namespace"], c["capability_id"]) for c in result.capabilities]
        self.assertIn(("com.harrylabsj.kiwi.shopping", "negotiation"), ids)

    def test_kiwi_build_vendor_profile_knp_accepted_when_policy_allows(self) -> None:
        """exact vendor profile + 完整 metadata + KNP 版本在 allowlist → 通过。"""
        profile = self._vendor_profile(
            {
                "com.harrylabsj.kiwi.shopping.negotiation": {
                    "version": "1.0",
                    "spec": "https://kiwi.harrylabsj.com/knp/spec",
                    "schema": "https://kiwi.harrylabsj.com/knp/schema.json",
                }
            }
        )
        passed, reason = self._evaluate(profile)
        self.assertTrue(passed, reason)

    def test_kiwi_build_vendor_profile_missing_metadata_rejected(self) -> None:
        """exact vendor profile：capability 键存在但 metadata 缺失 → KNP trust
        失败（缺声明版本），不得静默消失。"""
        profile = self._vendor_profile({"com.harrylabsj.kiwi.shopping.negotiation": {}})
        passed, reason = self._evaluate(profile)
        self.assertFalse(passed)
        self.assertIn("missing a declared version", reason)

    def test_kiwi_build_vendor_profile_has_version_but_no_schema_rejected(self) -> None:
        """exact vendor profile：有 version 但缺 spec/schema → 拒（spec/schema）。"""
        profile = self._vendor_profile(
            {"com.harrylabsj.kiwi.shopping.negotiation": {"version": "1.0"}}
        )
        passed, reason = self._evaluate(profile)
        self.assertFalse(passed)
        self.assertIn("specification/schema reference", reason)

    def test_kiwi_build_vendor_profile_unsupported_knp_version_rejected(self) -> None:
        """exact vendor profile：capability version 不在 allowlist → 拒。"""
        profile = self._vendor_profile(
            {
                "com.harrylabsj.kiwi.shopping.negotiation": {
                    "version": "2.0",
                    "spec": "https://kiwi.harrylabsj.com/knp/spec",
                    "schema": "https://kiwi.harrylabsj.com/knp/schema.json",
                }
            }
        )
        passed, reason = self._evaluate(profile)
        self.assertFalse(passed)
        self.assertIn("KNP version 2.0 is not allowed", reason)

    def test_canonical_kiwi_unsupported_version_rejected(self) -> None:
        """canonical ``version`` 不在 pinned UCP 版本 → 解析即拒。"""
        from kiwi_catalog.discovery._validation import ProfileValidationError

        canonical = self._canonical({}, version="2099-01-01")
        with self.assertRaises(ProfileValidationError):
            self._parse(canonical)

    def test_canonical_kiwi_knp_unsupported_knp_version_rejected(self) -> None:
        """canonical capability version 不在 KNP allowlist → 拒。"""
        passed, reason = self._evaluate(
            self._canonical(
                {
                    "kiwi.negotiation": {
                        "version": "2.0",
                        "spec": "https://kiwi.harrylabsj.com/knp/spec",
                        "schema": "https://kiwi.harrylabsj.com/knp/schema.json",
                    }
                }
            )
        )
        self.assertFalse(passed)
        self.assertIn("KNP version 2.0 is not allowed", reason)

    # ── Kiwi verbatim 发布形状：Record<string, Declaration[]>（array-valued maps）──

    _KIWI_VERBATIM = {
        "ucp": {
            "version": "2026-04-08",
            "services": {
                "com.harrylabsj.kiwi.shopping": [
                    {
                        "version": "1.0",
                        "spec": "https://kiwi.harrylabsj.com/a2a/extensions/negotiation/1.0",
                        "transport": "a2a",
                        "endpoint": "https://kiwi.test/.well-known/agent-card.json",
                    }
                ]
            },
            "capabilities": {
                "com.harrylabsj.kiwi.shopping.negotiation": [
                    {
                        "version": "1.0",
                        "spec": "https://kiwi.harrylabsj.com/a2a/extensions/negotiation/1.0",
                        "schema": "https://kiwi.harrylabsj.com/schemas/negotiation/1.0/schema.json",
                    }
                ]
            },
        }
    }

    def test_kiwi_verbatim_array_valued_maps_parse_and_pass_knp(self) -> None:
        """Kiwi canonical 类型是 ``Record<string, Declaration[]>``（validate.ts
        requireArray fail-closed）——verbatim publish 输出必须解析成功，per-
        capability version/spec/schema 从数组声明注入 specifications，KNP
        claim 携带 version + spec + schema 通过 commerce 评估。

        （修复前：array-valued service → ProfileValidationError；array-valued
        capability metadata → 静默丢弃 → 缺 spec/schema 被误拒。）
        """
        from kiwi_catalog.discovery.ucp import UcpProfileParser

        result = UcpProfileParser(self.POLICY).parse(
            self._KIWI_VERBATIM, source_url="https://kiwi.test/.well-known/ucp"
        )
        svc = result.public["services"][0]
        self.assertEqual(svc["id"], "com.harrylabsj.kiwi.shopping")
        self.assertEqual(svc["capabilities"], ["com.harrylabsj.kiwi.shopping.negotiation"])
        self.assertEqual(
            svc["endpoints"],
            [
                {
                    "uri": "https://kiwi.test/.well-known/agent-card.json",
                    "protocol": "a2a",
                    "version": "1.0",
                }
            ],
        )
        # KNP capability 的 per-capability metadata（数组首个声明）注入 specifications。
        spec = next(
            s for s in svc["specifications"] if s["id"] == "com.harrylabsj.kiwi.shopping.negotiation"
        )
        self.assertEqual(spec["version"], "1.0")
        self.assertEqual(spec["specUrl"], "https://kiwi.harrylabsj.com/a2a/extensions/negotiation/1.0")
        self.assertEqual(
            spec["schemaUrl"], "https://kiwi.harrylabsj.com/schemas/negotiation/1.0/schema.json"
        )
        ids = [(c["namespace"], c["capability_id"]) for c in result.capabilities]
        self.assertIn(("com.harrylabsj.kiwi.shopping", "negotiation"), ids)
        # KNP claim：version 在 allowlist + spec/schema 齐全 → commerce 通过。
        evaluator = TrustEvaluator(self.POLICY)
        evidence = evaluator.evaluate_commerce_capabilities(_card(), result, "kiwi.test")
        self.assertTrue(evidence.passed, evidence.reason)

    def test_kiwi_array_valued_maps_still_fail_closed(self) -> None:
        """数组形式不改变 fail-closed：非 object/空数组的 service 声明 →
        ProfileValidationError；空数组 capability metadata → id/label-only
        条目 → KNP 缺声明版本被拒。"""
        from kiwi_catalog.discovery._validation import ProfileValidationError
        from kiwi_catalog.discovery.ucp import UcpProfileParser

        for bad_services in (
            {"com.harrylabsj.kiwi.shopping": "not-a-declaration"},
            {"com.harrylabsj.kiwi.shopping": []},
        ):
            profile = {
                **self._KIWI_VERBATIM,
                "ucp": {**self._KIWI_VERBATIM["ucp"], "services": bad_services},
            }
            with self.assertRaises(ProfileValidationError):
                UcpProfileParser(self.POLICY).parse(
                    profile, source_url="https://kiwi.test/.well-known/ucp"
                )
        empty_caps = {
            **self._KIWI_VERBATIM,
            "ucp": {
                **self._KIWI_VERBATIM["ucp"],
                "capabilities": {"com.harrylabsj.kiwi.shopping.negotiation": []},
            },
        }
        result = UcpProfileParser(self.POLICY).parse(
            empty_caps, source_url="https://kiwi.test/.well-known/ucp"
        )
        evaluator = TrustEvaluator(self.POLICY)
        evidence = evaluator.evaluate_commerce_capabilities(_card(), result, "kiwi.test")
        self.assertFalse(evidence.passed)
        self.assertIn("missing a declared version", evidence.reason)


class CanonicalKiwiPipelineTest(unittest.TestCase):
    """build → parse → verify(commerce stage)：canonical Kiwi build 输出缺
    metadata 不得 COMMERCE_VERIFIED；完整 metadata + 策略允许才晋升。"""

    _CANONICAL = {
        "ucp": {
            "version": "2026-04-08",
            "serviceIdentity": {"id": "https://merchant.example/identity", "name": "Merchant"},
            "services": {
                "svc-checkout": {
                    "type": "commerce",
                    "capabilities": ["com.example:checkout", "kiwi.negotiation"],
                    "endpoints": [
                        {"uri": "https://merchant.example/knp", "protocol": "a2a", "version": "1.0"}
                    ],
                }
            },
            "capabilities": {
                "kiwi.negotiation": {
                    "version": "1.0",
                    "spec": "https://kiwi.harrylabsj.com/knp/spec",
                    "schema": "https://kiwi.harrylabsj.com/knp/schema.json",
                }
            },
        }
    }

    def setUp(self) -> None:
        import tempfile
        from pathlib import Path

        from kiwi_catalog.db.session import open_connection

        self.tmp = tempfile.mkdtemp()
        db = Path(self.tmp) / "catalog.sqlite"
        self.conn = open_connection(db)
        from kiwi_catalog.services.agent_catalog_writes import register_catalog_agent

        self.agent = register_catalog_agent(
            self.conn, domain="merchant.example", merchant_id="mrc-1", actor="test"
        )
        self.conn.commit()
        self.cid = self.agent["catalog_agent_id"]

    def tearDown(self) -> None:
        self.conn.close()

    def _commerce_outcome(self, capabilities_map: dict, *, knp_versions=("1.0",)) -> str:
        from kiwi_catalog.discovery.ucp import UcpProfileParser
        from kiwi_catalog.services.agent_verification import VerificationService
        from kiwi_catalog.services.verification_profile_policy import Profiles

        canonical = dict(self._CANONICAL)
        canonical["ucp"]["capabilities"] = capabilities_map
        ucp = UcpProfileParser(TrustPolicy(allowed_knp_versions=knp_versions)).parse(
            canonical, source_url="https://merchant.example/.well-known/ucp"
        )
        card = _card()
        profiles = Profiles(
            card=card,
            ucp=ucp,
            urls={
                "agent_card": "https://merchant.example/.well-known/agent-card.json",
                "ucp_profile": "https://merchant.example/.well-known/ucp",
            },
            snapshot_ids=(1, 2),
        )
        service = VerificationService(self.conn, policy=TrustPolicy(allowed_knp_versions=knp_versions))
        stage = service._stage_commerce(self.cid, "agent_verified", "test", profiles)
        return stage.outcome

    def test_canonical_kiwi_build_parse_verify_accepted(self) -> None:
        """canonical build + 完整 metadata + allowlist 通过 → commerce passed。"""
        outcome = self._commerce_outcome(
            {
                "kiwi.negotiation": {
                    "version": "1.0",
                    "spec": "https://kiwi.harrylabsj.com/knp/spec",
                    "schema": "https://kiwi.harrylabsj.com/knp/schema.json",
                }
            }
        )
        self.assertEqual(outcome, "passed")

    def test_canonical_kiwi_build_parse_verify_missing_metadata_rejected(self) -> None:
        """canonical build + 缺 metadata → commerce rejected（不得 COMMERCE_VERIFIED）。"""
        outcome = self._commerce_outcome({"kiwi.negotiation": {}})
        self.assertEqual(outcome, "rejected")

    def test_canonical_kiwi_build_parse_verify_unsupported_knp_rejected(self) -> None:
        """canonical build + KNP 版本不在 allowlist → commerce rejected。"""
        outcome = self._commerce_outcome(
            {
                "kiwi.negotiation": {
                    "version": "2.0",
                    "spec": "https://kiwi.harrylabsj.com/knp/spec",
                    "schema": "https://kiwi.harrylabsj.com/knp/schema.json",
                }
            }
        )
        self.assertEqual(outcome, "rejected")

    def _vendor_outcome(self, capabilities_map: dict) -> str:
        """exact ``buildKiwiVendorProfile`` 形状 build→parse→verify(commerce stage)。"""
        import json  # noqa: F401

        from kiwi_catalog.discovery.ucp import UcpProfileParser
        from kiwi_catalog.services.agent_verification import VerificationService
        from kiwi_catalog.services.verification_profile_policy import Profiles

        profile = CanonicalKiwiUcpAdapterTest._vendor_profile(capabilities_map)
        policy = TrustPolicy(allowed_knp_versions=("1.0",))
        ucp = UcpProfileParser(policy).parse(
            profile, source_url="https://merchant.example/.well-known/ucp"
        )
        profiles = Profiles(
            card=_card(),
            ucp=ucp,
            urls={
                "agent_card": "https://merchant.example/.well-known/agent-card.json",
                "ucp_profile": "https://merchant.example/.well-known/ucp",
            },
            snapshot_ids=(1, 2),
        )
        service = VerificationService(self.conn, policy=policy)
        return service._stage_commerce(self.cid, "agent_verified", "test", profiles).outcome

    def test_kiwi_build_vendor_profile_pipeline_accepted(self) -> None:
        """exact vendor profile：完整 metadata + allowlist 通过 → commerce passed。"""
        outcome = self._vendor_outcome(
            {
                "com.harrylabsj.kiwi.shopping.negotiation": {
                    "version": "1.0",
                    "spec": "https://kiwi.harrylabsj.com/knp/spec",
                    "schema": "https://kiwi.harrylabsj.com/knp/schema.json",
                }
            }
        )
        self.assertEqual(outcome, "passed")

    def test_kiwi_build_vendor_profile_pipeline_missing_metadata_rejected(self) -> None:
        """exact vendor profile：缺 metadata → commerce rejected（不得消失）。"""
        outcome = self._vendor_outcome({"com.harrylabsj.kiwi.shopping.negotiation": {}})
        self.assertEqual(outcome, "rejected")


class KiwiPipelineRegressionTest(unittest.TestCase):
    """Pipeline 级回归（不是 parser 单测）：Kiwi UCP profile 经
    VerificationService commerce stage——缺版本/spec/schema 或版本不支持
    时不得晋升 COMMERCE_VERIFIED；有效声明 + allowlist 通过才晋升。"""

    _KIWI_SERVICE = {
        "id": "svc-checkout",
        "type": "commerce",
        "capabilities": ["com.harrylabsj.kiwi.shopping.negotiation", "com.example:checkout"],
        "endpoints": [{"uri": "https://merchant.example/knp", "protocol": "a2a", "version": "1.0"}],
    }

    @staticmethod
    def _profiles(service: dict, *, specifications=()) -> "object":
        from kiwi_catalog.discovery.agent_card import AgentCardResult
        from kiwi_catalog.discovery.ucp import UcpProfileResult
        from kiwi_catalog.services.verification_profile_policy import Profiles

        public = {"services": [service]}
        if specifications:
            public["specifications"] = specifications
        ucp = UcpProfileResult(
            specification_version="2026-04-08",
            capabilities=(
                {"namespace": "com.example", "capability_id": "checkout"},
                {"namespace": "com.harrylabsj.kiwi.shopping", "capability_id": "negotiation"},
            ),
            public=public,
        )
        card = AgentCardResult(
            version="1.0.0",
            capabilities=({"namespace": "com.example", "capability_id": "checkout"},),
        )
        return Profiles(
            card=card,
            ucp=ucp,
            urls={
                "agent_card": "https://merchant.example/.well-known/agent-card.json",
                "ucp_profile": "https://merchant.example/.well-known/ucp",
            },
            snapshot_ids=(1, 2),
        )

    def setUp(self) -> None:
        import tempfile
        from pathlib import Path

        from kiwi_catalog.db.session import open_connection

        self.tmp = tempfile.mkdtemp()
        db = Path(self.tmp) / "catalog.sqlite"
        self.conn = open_connection(db)
        from kiwi_catalog.services.agent_catalog_writes import register_catalog_agent

        self.agent = register_catalog_agent(
            self.conn, domain="merchant.example", merchant_id="mrc-1", actor="test"
        )
        self.conn.commit()
        self.cid = self.agent["catalog_agent_id"]

    def tearDown(self) -> None:
        self.conn.close()

    def _commerce_outcome(self, service: dict, *, knp_versions=("1.0",), specifications=()) -> str:
        from kiwi_catalog.discovery.trust import TrustPolicy
        from kiwi_catalog.services.agent_verification import VerificationService

        policy = TrustPolicy(allowed_knp_versions=knp_versions)
        svc = VerificationService(self.conn, policy=policy)
        stage = svc._stage_commerce(
            self.cid, "agent_verified", "test", self._profiles(service, specifications=specifications)
        )
        return stage.outcome

    def test_pipeline_denies_kiwi_claim_missing_metadata(self) -> None:
        """a2a protocol + exact id、缺 version/spec/schema → commerce stage rejected。"""
        outcome = self._commerce_outcome(self._KIWI_SERVICE)
        self.assertEqual(outcome, "rejected")

    def test_pipeline_denies_kiwi_claim_unsupported_version(self) -> None:
        """exact id + 版本 2.0 不在 allowlist → rejected。"""
        service = {
            **self._KIWI_SERVICE,
            "specifications": [{"id": "knp-spec", "label": "Kiwi Negotiation", "version": "2.0"}],
            "documentationUri": "https://merchant.example/knp-doc",
        }
        outcome = self._commerce_outcome(service, knp_versions=("1.0",))
        self.assertEqual(outcome, "rejected")

    def test_pipeline_accepts_valid_kiwi_claim(self) -> None:
        """exact id + 版本在 allowlist + spec/schema 齐全 → passed。"""
        service = {
            **self._KIWI_SERVICE,
            "specifications": [
                {
                    "id": "knp-spec",
                    "label": "Kiwi Negotiation",
                    "version": "1.0",
                    "specUrl": "https://merchant.example/knp-spec",
                }
            ],
            "documentationUri": "https://merchant.example/knp-doc",
        }
        outcome = self._commerce_outcome(service, knp_versions=("1.0",))
        self.assertEqual(outcome, "passed")

    def test_pipeline_accepts_valid_kiwi_claim_with_top_level_schema(self) -> None:
        """exact id + 顶层 specifications.openAPIDocument 满足 schema → passed。"""
        service = {
            **self._KIWI_SERVICE,
            "specifications": [
                {
                    "id": "knp-spec",
                    "label": "Kiwi Negotiation",
                    "version": "1.0",
                    "specUrl": "https://merchant.example/knp-spec",
                }
            ],
        }
        outcome = self._commerce_outcome(
            service,
            knp_versions=("1.0",),
            specifications=[
                {"id": "knp-openapi", "label": "KNP", "version": "1.0",
                 "openAPIDocument": "https://merchant.example/knp-openapi.json"}
            ],
        )
        self.assertEqual(outcome, "passed")


if __name__ == "__main__":
    unittest.main()
