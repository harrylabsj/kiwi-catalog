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

"""Listing 域词表 + publish 契约校验测试（升级计划 §11；测试计划 v0.3 §7）。

覆盖：
- 词表单一来源（listing_type / publication_state / listing_freshness_state）；
- publish payload 白名单：未知字段 / 私有字段 / secret-like 拒绝；
- per-type 规则：product→source_product_ref 必填；capability 不得带 SKU 与
  handoff_destination_types；fresh_until 时区/未来/上限；
- commercial_hints 七键白名单；attributes 标量类型与路径注入防护。
"""

from __future__ import annotations

import unittest

from kiwi_catalog.core.errors import ValidationError
from kiwi_catalog.listings.contracts import validate_publish_payload
from kiwi_catalog.listings.domain import (
    COMMERCIAL_HINTS_KEYS,
    LISTING_FRESHNESS_STATES,
    LISTING_TYPES,
    PUBLICATION_STATES,
)

PRODUCT_PAYLOAD = {
    "listing_type": "product",
    "owner_agent_id": "cagt_01JABC",
    "merchant_id": "mrc_01JABC",
    "source_product_ref": "SKU-001",
    "title": "21.5 inch Industrial Touch Display",
    "category": "industrial-display",
    "brand": "Example Display Co.",
    "attributes": {"screen_size": "21.5", "ip_rating": "IP67"},
    "regions": ["CN", "EU"],
    "tags": ["touch"],
    "commercial_hints": {"moq": 50, "supports_bulk_quote": True},
    "handoff_destination_types": ["external_checkout_url"],
}


class ListingDomainVocabularyTest(unittest.TestCase):
    def test_listing_types_are_product_and_capability(self) -> None:
        self.assertEqual(LISTING_TYPES, ("product", "capability"))

    def test_publication_states_uppercase(self) -> None:
        self.assertEqual(PUBLICATION_STATES, ("ACTIVE", "WITHDRAWN", "SUSPENDED"))

    def test_listing_freshness_states_two_uppercase_values(self) -> None:
        self.assertEqual(LISTING_FRESHNESS_STATES, ("FRESH", "STALE"))

    def test_commercial_hints_allowlist_is_v04_41_seven_keys(self) -> None:
        self.assertEqual(
            COMMERCIAL_HINTS_KEYS,
            frozenset(
                {
                    "moq",
                    "price_range_hint",
                    "availability_hint",
                    "lead_time_hint",
                    "supports_bulk_quote",
                    "supports_customization",
                    "fulfillment_regions",
                }
            ),
        )


class PublishContractTest(unittest.TestCase):
    def test_valid_product_payload_canonicalizes(self) -> None:
        canonical = validate_publish_payload(PRODUCT_PAYLOAD)
        self.assertEqual(canonical["listing_type"], "product")
        self.assertEqual(canonical["source_product_ref"], "SKU-001")
        self.assertEqual(canonical["commercial_hints"]["moq"], 50)

    def test_valid_capability_payload_without_sku(self) -> None:
        payload = {
            "listing_type": "capability",
            "owner_agent_id": "cagt_01JABC",
            "merchant_id": "mrc_01JABC",
            "publisher_listing_key": "touch-display-mfg",
            "title": "Touch Display Manufacturing",
            "category": "industrial-manufacturing",
            "commercial_hints": {"moq": 100, "supports_customization": True},
        }
        canonical = validate_publish_payload(payload)
        self.assertNotIn("source_product_ref", canonical)
        self.assertEqual(canonical["publisher_listing_key"], "touch-display-mfg")

    def test_product_missing_source_product_ref_rejected(self) -> None:
        payload = dict(PRODUCT_PAYLOAD)
        del payload["source_product_ref"]
        with self.assertRaises(ValidationError):
            validate_publish_payload(payload)

    def test_capability_carrying_source_product_ref_rejected(self) -> None:
        payload = {
            "listing_type": "capability",
            "owner_agent_id": "cagt_01JABC",
            "merchant_id": "mrc_01JABC",
            "source_product_ref": "SKU-999",
            "title": "Capability",
            "category": "x",
        }
        with self.assertRaises(ValidationError):
            validate_publish_payload(payload)

    def test_capability_carrying_handoff_destination_types_rejected(self) -> None:
        payload = {
            "listing_type": "capability",
            "owner_agent_id": "cagt_01JABC",
            "merchant_id": "mrc_01JABC",
            "title": "Capability",
            "category": "x",
            "handoff_destination_types": ["external_checkout_url"],
        }
        with self.assertRaises(ValidationError):
            validate_publish_payload(payload)

    def test_unknown_fields_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            validate_publish_payload({**PRODUCT_PAYLOAD, "mystery_field": "x"})

    def test_forbidden_private_fields_rejected(self) -> None:
        for field in ("floor_price", "cost", "credentials", "principal_memory"):
            with self.assertRaises(ValidationError, msg=field):
                validate_publish_payload({**PRODUCT_PAYLOAD, field: "secret"})

    def test_secret_like_content_rejected(self) -> None:
        # scan_secrets 值模式：sk- 后至少 20 字符
        with self.assertRaises(ValidationError):
            validate_publish_payload({**PRODUCT_PAYLOAD, "title": f"sk-{'A' * 24}"})
        # 字段名模式：token 类字段名即使值普通也拒绝
        with self.assertRaises(ValidationError):
            validate_publish_payload({**PRODUCT_PAYLOAD, "summary": "no secret here", "attributes": {"api_key": "x"}})

    def test_unknown_handoff_destination_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            validate_publish_payload(
                {**PRODUCT_PAYLOAD, "handoff_destination_types": ["supports_checkout"]}
            )

    def test_unknown_commercial_hint_key_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            validate_publish_payload({**PRODUCT_PAYLOAD, "commercial_hints": {"fake_hint": 1}})

    def test_moq_must_be_positive_integer(self) -> None:
        for bad in (0, -1, 1.5, "50"):
            with self.assertRaises(ValidationError, msg=str(bad)):
                validate_publish_payload(
                    {**PRODUCT_PAYLOAD, "commercial_hints": {"moq": bad}}
                )

    def test_attributes_values_scalar_only(self) -> None:
        with self.assertRaises(ValidationError):
            validate_publish_payload({**PRODUCT_PAYLOAD, "attributes": {"nested": {"a": 1}}})
        with self.assertRaises(ValidationError):
            validate_publish_payload({**PRODUCT_PAYLOAD, "attributes": {"list": [1, 2]}})

    def test_fresh_until_must_be_future_iso_with_tz_and_bounded(self) -> None:
        with self.assertRaises(ValidationError):
            validate_publish_payload({**PRODUCT_PAYLOAD, "fresh_until": "2026-08-06T00:00:00Z"})  # past
        with self.assertRaises(ValidationError):
            validate_publish_payload({**PRODUCT_PAYLOAD, "fresh_until": "2026-08-08"})  # no tz
        with self.assertRaises(ValidationError):
            validate_publish_payload(
                {**PRODUCT_PAYLOAD, "fresh_until": "2027-08-08T00:00:00Z"}  # > 30 days
            )

    def test_fresh_until_accepted_within_ttl(self) -> None:
        canonical = validate_publish_payload(
            {**PRODUCT_PAYLOAD, "fresh_until": "2026-08-08T00:00:00Z"}
        )
        self.assertIn("fresh_until", canonical)

    def test_missing_required_title_or_category_rejected(self) -> None:
        for field in ("title", "category", "owner_agent_id", "merchant_id"):
            payload = dict(PRODUCT_PAYLOAD)
            del payload[field]
            with self.assertRaises(ValidationError, msg=field):
                validate_publish_payload(payload)


if __name__ == "__main__":
    unittest.main()
