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

"""买家识别与交易回执 · C2 独立事实计算测试。

覆盖 B1（单方/双边/错配样本）、B2（入口早于协议）、B3（订单去重与
访问控制）、B4（迟到/反序/多次投递）、B5（三组错误组合零确认）。
用固定回执驱动，验证状态投影；与 Kiwi 真实出站的联调由 Kiwi 仓测试覆盖。
"""

from __future__ import annotations

import os
import tempfile
import unittest

from kiwi_catalog.core.tokens import token_digest
from kiwi_catalog.db.session import open_connection
from kiwi_catalog.services import commerce_facts


def _make_merchant_token(conn, merchant_id: str, token: str) -> None:
    conn.execute(
        "insert into merchant_tokens (merchant_id, token_hash, status, issued_at)"
        " values (?, ?, 'active', '2026-11-01T00:00:00+00:00')",
        (merchant_id, token_digest(token)),
    )
    conn.commit()


def _insert_receipt(
    conn,
    *,
    event_id: str,
    event_type: str,
    reporter_role: str,
    merchant_id: str,
    reporter_identity: str,
    assurance: str,
    negotiation_id: str = "",
    merchant_agreement_id: str = "",
    accepted_offer_id: str = "",
    terms_digest: str = "",
    buyer_binding: str = "",
    entry_type: str = "",
    quote_ref: dict | None = None,
    handoff_ref: str = "",
    order_channel: str = "",
    order_ref: str = "",
    order_evidence: dict | None = None,
    occurred_at: str,
    received_at: str,
) -> None:
    import json

    conn.execute(
        """insert into commerce_receipts(
            protocol_version, event_id, event_type, reporter_role, merchant_id,
            negotiation_id, merchant_agreement_id, accepted_offer_id, terms_digest,
            buyer_binding, entry_type, quote_ref_json, handoff_ref,
            order_channel, order_ref, order_evidence_json,
            occurred_at, received_at, reporter_identity, assurance,
            content_hash, payload_json, created_at)
           values ('1.0', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            'sha256:test', '{}', ?)""",
        (
            event_id,
            event_type,
            reporter_role,
            merchant_id,
            negotiation_id,
            merchant_agreement_id,
            accepted_offer_id,
            terms_digest,
            buyer_binding,
            entry_type,
            json.dumps(quote_ref or {}, sort_keys=True),
            handoff_ref,
            order_channel,
            order_ref,
            json.dumps(order_evidence or {}, sort_keys=True),
            occurred_at,
            received_at,
            reporter_identity,
            assurance,
            received_at,
        ),
    )
    conn.commit()


def _intent(
    merchant_id: str = "mkt-alpha",
    negotiation_id: str = "neg-1",
    agreement: str = "agr-1",
    offer: str = "off-1",
    digest: str = "sha256:" + "a" * 64,
    binding: str = "kiwi-inquiry-session-v1:buyerkey",
) -> dict:
    return {
        "merchant_id": merchant_id,
        "negotiation_id": negotiation_id,
        "merchant_agreement_id": agreement,
        "accepted_offer_id": offer,
        "terms_digest": digest,
        "buyer_binding": binding,
    }


class CommerceFactsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "catalog.sqlite")
        self.conn = open_connection(self.db_path)
        _make_merchant_token(self.conn, "mkt-alpha", "tok-alpha")
        _make_merchant_token(self.conn, "mkt-beta", "tok-beta")

    def tearDown(self) -> None:
        self.conn.close()

    # ── B1 双方意向 ────────────────────────────────────────────────────────

    def test_single_side_report_then_both_merge_exactly_once(self) -> None:
        base = _intent()
        _insert_receipt(
            self.conn, event_id="m1", event_type="merchant_agreement_issued",
            reporter_role="merchant", reporter_identity="merchant_token:mkt-alpha",
            assurance="verified", received_at="2026-11-18T08:00:00+00:00",
            occurred_at="2026-11-18T08:00:00+00:00", **base,
        )
        intents = commerce_facts.compute_intents(self.conn, "mkt-alpha")
        self.assertEqual([item["status"] for item in intents], ["merchant_reported"])
        self.assertFalse(intents[0]["verified_enterprise"])

        # 顺序交换重做：先买方后商家同样恰好一笔。
        _insert_receipt(
            self.conn, event_id="b1", event_type="buyer_agreement_accepted",
            reporter_role="buyer", reporter_identity="buyer:tp1",
            assurance="self_signed", received_at="2026-11-18T08:00:05+00:00",
            occurred_at="2026-11-18T08:00:05+00:00",
            **base,
        )
        intents = commerce_facts.compute_intents(self.conn, "mkt-alpha")
        confirmed = [item for item in intents if item["status"] == "confirmed"]
        self.assertEqual(len(confirmed), 1)
        self.assertTrue(confirmed[0]["buyers_reported"])
        self.assertTrue(confirmed[0]["merchant_reported"])
        # 自签回执匹配 → 企业未核验；已核验企业指标为 0。
        self.assertEqual(confirmed[0]["buyer_assurance"], "self_signed")
        self.assertFalse(confirmed[0]["verified_enterprise"])
        summary = commerce_facts.query_facts(self.conn, {}, "mkt-alpha")["summary"]
        self.assertEqual(summary["confirmed_intents"], 1)
        self.assertEqual(summary["verified_enterprise_intents"], 0)

    def test_mismatched_samples_do_not_merge(self) -> None:
        # 报价不一致 / 摘要不一致 / 凭据绑定不一致：均不合并。
        cases = [
            {"accepted_offer_id": "off-other"},
            {"terms_digest": "sha256:" + "b" * 64},
            {"buyer_binding": "kiwi-inquiry-session-v1:otherkey"},
        ]
        for index, mutation in enumerate(cases):
            conn = open_connection(self.db_path.replace(".sqlite", f"-{index}.sqlite"))
            try:
                merchant_row = _intent()
                buyer_row = dict(_intent())
                _insert_receipt(
                    conn, event_id="m", event_type="merchant_agreement_issued",
                    reporter_role="merchant", reporter_identity="merchant_token:mkt-alpha",
                    assurance="verified", occurred_at="2026-11-18T08:00:00+00:00",
                    received_at="2026-11-18T08:00:00+00:00", **merchant_row,
                )
                _insert_receipt(
                    conn, event_id="b", event_type="buyer_agreement_accepted",
                    reporter_role="buyer", reporter_identity="buyer:tp",
                    assurance="self_signed", occurred_at="2026-11-18T08:00:01+00:00",
                    received_at="2026-11-18T08:00:01+00:00", **{**buyer_row, **mutation},
                )
                intents = commerce_facts.compute_intents(conn, "mkt-alpha")
                self.assertNotIn(
                    "confirmed", [item["status"] for item in intents],
                    f"mutation {mutation} must not merge",
                )
            finally:
                conn.close()

    def test_conflicting_same_agreement_reports_pending_review(self) -> None:
        # 同（商家,磋商,协议号）但摘要不同：保留待核对，暂停合并。
        _insert_receipt(
            self.conn, event_id="m1", event_type="merchant_agreement_issued",
            reporter_role="merchant", reporter_identity="merchant_token:mkt-alpha",
            assurance="verified", occurred_at="2026-11-18T08:00:00+00:00",
            received_at="2026-11-18T08:00:00+00:00", **_intent(digest="sha256:" + "a" * 64),
        )
        _insert_receipt(
            self.conn, event_id="m2", event_type="merchant_agreement_issued",
            reporter_role="merchant", reporter_identity="merchant_token:mkt-alpha",
            assurance="verified", occurred_at="2026-11-18T08:01:00+00:00",
            received_at="2026-11-18T08:01:00+00:00", **_intent(digest="sha256:" + "c" * 64),
        )
        intents = commerce_facts.compute_intents(self.conn, "mkt-alpha")
        self.assertIn("needs_review", [item["status"] for item in intents])

    def test_conflicting_third_receipt_suspends_exact_match(self) -> None:
        stamp = "2026-11-18T08:00:00+00:00"
        for event_id, role, digest in [("m1", "merchant", "a"), ("b1", "buyer", "a"), ("m2", "merchant", "c")]:
            _insert_receipt(
                self.conn, event_id=event_id, reporter_role=role, reporter_identity=role,
                event_type="merchant_agreement_issued" if role == "merchant" else "buyer_agreement_accepted",
                assurance="verified" if role == "merchant" else "self_signed",
                received_at=stamp, occurred_at=stamp, **_intent(digest="sha256:" + digest * 64),
            )
        result = commerce_facts.query_facts(self.conn, {}, "mkt-alpha")
        self.assertEqual(result["summary"]["confirmed_intents"], 0)
        self.assertIn("needs_review", [fact["status"] for fact in result["facts"]])

    # ── B5 三组错误组合零确认 ──────────────────────────────────────────────

    def test_b5_error_combinations_produce_zero_confirmed_intents(self) -> None:
        entry_of = {"negotiation_id": "neg-e", "offer_id": "off-e"}
        # 组1：只上报双方的入口事件。
        _insert_receipt(
            self.conn, event_id="me1", event_type="merchant_entry_offered",
            reporter_role="merchant", reporter_identity="merchant_token:mkt-alpha",
            assurance="verified", entry_type="quote_handoff", quote_ref=entry_of,
            occurred_at="2026-11-18T07:00:00+00:00", received_at="2026-11-18T07:00:00+00:00",
            merchant_id="mkt-alpha",
        )
        _insert_receipt(
            self.conn, event_id="bh1", event_type="buyer_handoff_generated",
            reporter_role="buyer", reporter_identity="buyer:tp",
            assurance="self_signed", entry_type="handoff_record", quote_ref=entry_of,
            handoff_ref="handoff-1", occurred_at="2026-11-18T07:01:00+00:00",
            received_at="2026-11-18T07:01:00+00:00", merchant_id="mkt-alpha",
        )
        intents = commerce_facts.compute_intents(self.conn, "mkt-alpha")
        self.assertEqual([item for item in intents if item["status"] == "confirmed"], [])

        # 组2：只上报买方交接与商家意向（缺买方意向回执）。
        _insert_receipt(
            self.conn, event_id="m-ix", event_type="merchant_agreement_issued",
            reporter_role="merchant", reporter_identity="merchant_token:mkt-alpha",
            assurance="verified", occurred_at="2026-11-18T08:00:00+00:00",
            received_at="2026-11-18T08:00:00+00:00", **_intent(negotiation_id="neg-2", agreement="agr-2"),
        )
        intents = commerce_facts.compute_intents(self.conn, "mkt-alpha")
        confirmed = [item for item in intents if item["status"] == "confirmed"]
        self.assertEqual(confirmed, [])

        # 组3：同报价、别笔谈判的买方意向（六元组不一致）不合并。
        _insert_receipt(
            self.conn, event_id="b-other", event_type="buyer_agreement_accepted",
            reporter_role="buyer", reporter_identity="buyer:tp",
            assurance="self_signed", occurred_at="2026-11-18T08:05:00+00:00",
            received_at="2026-11-18T08:05:00+00:00",
            **_intent(negotiation_id="neg-3", agreement="agr-3"),
        )
        intents = commerce_facts.compute_intents(self.conn, "mkt-alpha")
        self.assertEqual([item for item in intents if item["status"] == "confirmed"], [])

        # 最后送正确回执 → 恰为一笔（组2 的商家意向 + 匹配买方回执）。
        _insert_receipt(
            self.conn, event_id="b-right", event_type="buyer_agreement_accepted",
            reporter_role="buyer", reporter_identity="buyer:tp",
            assurance="self_signed", occurred_at="2026-11-18T08:06:00+00:00",
            received_at="2026-11-18T08:06:00+00:00",
            **_intent(negotiation_id="neg-2", agreement="agr-2"),
        )
        intents = commerce_facts.compute_intents(self.conn, "mkt-alpha")
        confirmed = [item for item in intents if item["status"] == "confirmed"]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0]["negotiation_id"], "neg-2")

    # ── B2 入口早于协议 ────────────────────────────────────────────────────

    def test_entry_precedes_agreement_and_lists_sides_separately(self) -> None:
        entry_of = {"negotiation_id": "neg-x", "offer_id": "off-x", "terms_digest": "sha256:" + "d" * 64}
        _insert_receipt(
            self.conn, event_id="ent-1", event_type="merchant_entry_offered",
            reporter_role="merchant", reporter_identity="merchant_token:mkt-alpha",
            assurance="verified", entry_type="quote_handoff", quote_ref=entry_of,
            occurred_at="2026-11-18T06:00:00+00:00", received_at="2026-11-18T06:00:00+00:00",
            merchant_id="mkt-alpha",
        )
        entries = commerce_facts.compute_entries(self.conn, "mkt-alpha")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["status"], "merchant_offered")
        # 入口事实独立存在（无任何意向回执）。
        intents = commerce_facts.compute_intents(self.conn, "mkt-alpha")
        self.assertEqual(intents, [])
        # 买家授权交接后独立出现买方交接事实。
        _insert_receipt(
            self.conn, event_id="ent-2", event_type="buyer_handoff_generated",
            reporter_role="buyer", reporter_identity="buyer:tp",
            assurance="self_signed", entry_type="handoff_record", quote_ref=entry_of,
            handoff_ref="handoff-xyz", occurred_at="2026-11-18T06:05:00+00:00",
            received_at="2026-11-18T06:05:00+00:00", merchant_id="mkt-alpha",
        )
        entries = commerce_facts.compute_entries(self.conn, "mkt-alpha")
        statuses = sorted(item["status"] for item in entries)
        self.assertEqual(statuses, ["buyer_generated", "merchant_offered"])

    # ── B3 订单去重、独立计数与访问控制 ─────────────────────────────────────

    def test_order_dedup_and_independent_second_order(self) -> None:
        stamp = "2026-11-18T08:00:00+00:00"
        _insert_receipt(
            self.conn, event_id="m1", event_type="merchant_agreement_issued",
            reporter_role="merchant", reporter_identity="merchant_token:mkt-alpha",
            assurance="verified", occurred_at=stamp, received_at=stamp,
            **_intent(agreement="agr-9"),
        )
        evidence = {"merchant_agreement_ref": "agr-9"}
        _insert_receipt(
            self.conn, event_id="ord-1", event_type="merchant_order_created",
            reporter_role="merchant", reporter_identity="merchant_token:mkt-alpha",
            assurance="verified", order_channel="channel-x", order_ref="SO-1",
            order_evidence=evidence, occurred_at="2026-11-18T09:00:00+00:00",
            received_at="2026-11-18T09:00:00+00:00", merchant_id="mkt-alpha",
        )
        # 成功回调重复投递（同渠道订单引用，不同 event_id）→ 只计一次。
        _insert_receipt(
            self.conn, event_id="ord-1-retry", event_type="merchant_order_created",
            reporter_role="merchant", reporter_identity="merchant_token:mkt-alpha",
            assurance="verified", order_channel="channel-x", order_ref="SO-1",
            order_evidence=evidence, occurred_at="2026-11-18T09:00:10+00:00",
            received_at="2026-11-18T09:00:20+00:00", merchant_id="mkt-alpha",
        )
        # 同一协议的第二笔有效订单独立计数。
        _insert_receipt(
            self.conn, event_id="ord-2", event_type="merchant_order_created",
            reporter_role="merchant", reporter_identity="merchant_token:mkt-alpha",
            assurance="verified", order_channel="channel-x", order_ref="SO-2",
            order_evidence=evidence, occurred_at="2026-11-18T09:05:00+00:00",
            received_at="2026-11-18T09:05:00+00:00", merchant_id="mkt-alpha",
        )
        orders = commerce_facts.compute_orders(self.conn, "mkt-alpha")
        self.assertEqual(len(orders), 2)
        self.assertEqual(sorted(o["order_ref"] for o in orders), ["SO-1", "SO-2"])
        self.assertTrue(all(o["status"] == "confirmed" for o in orders))

    def test_order_without_verifiable_evidence_stays_pending(self) -> None:
        _insert_receipt(
            self.conn, event_id="ord-bad", event_type="merchant_order_created",
            reporter_role="merchant", reporter_identity="merchant_token:mkt-alpha",
            assurance="verified", order_channel="channel-y", order_ref="SO-9",
            order_evidence={"checkout_session_ref": "unknown-checkout"}, occurred_at="2026-11-18T09:00:00+00:00",
            received_at="2026-11-18T09:00:00+00:00", merchant_id="mkt-alpha",
        )
        orders = commerce_facts.compute_orders(self.conn, "mkt-alpha")
        self.assertEqual(orders[0]["status"], "needs_review")

    def test_order_arriving_before_intent_receipts_is_independent(self) -> None:
        # B4 乱序分支：订单回执先到，无意向回执——订单事实独立成立。
        _insert_receipt(
            self.conn, event_id="ord-first", event_type="merchant_order_created",
            reporter_role="order_adapter", reporter_identity="order_adapter:test-fixture",
            assurance="adapter_delegated", order_channel="channel-x", order_ref="SO-0",
            order_evidence={"checkout_session_ref": "early-checkout", "channel_evidence": "checkout-order-SO-0"},
            occurred_at="2026-11-18T05:00:00+00:00", received_at="2026-11-18T05:00:00+00:00",
            merchant_id="mkt-alpha",
        )
        orders = commerce_facts.compute_orders(self.conn, "mkt-alpha")
        self.assertEqual(orders[0]["status"], "confirmed")
        self.assertEqual(commerce_facts.compute_intents(self.conn, "mkt-alpha"), [])

    def test_legacy_operator_order_has_no_scoped_channel_proof(self) -> None:
        stamp = "2026-11-18T08:00:00+00:00"
        _insert_receipt(
            self.conn, event_id="ord-legacy", event_type="merchant_order_created",
            reporter_role="order_adapter", reporter_identity="operator:admin",
            assurance="adapter_delegated", order_channel="channel-x", order_ref="legacy",
            order_evidence={"checkout_session_ref": "cs-legacy", "channel_evidence": "legacy"},
            merchant_id="mkt-alpha", occurred_at=stamp, received_at=stamp,
        )
        self.assertEqual(commerce_facts.compute_orders(self.conn, "mkt-alpha")[0]["status"], "needs_review")

    def test_other_merchant_cannot_read_facts(self) -> None:
        _insert_receipt(
            self.conn, event_id="i-1", event_type="merchant_agreement_issued",
            reporter_role="merchant", reporter_identity="merchant_token:mkt-alpha",
            assurance="verified", occurred_at="2026-11-18T08:00:00+00:00",
            received_at="2026-11-18T08:00:00+00:00", **_intent(),
        )
        alpha = commerce_facts.compute_intents(self.conn, "mkt-alpha")
        beta = commerce_facts.compute_intents(self.conn, "mkt-beta")
        self.assertEqual(len(alpha), 1)
        self.assertEqual(beta, [])


if __name__ == "__main__":
    unittest.main()
