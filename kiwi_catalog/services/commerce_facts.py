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

"""买家识别与交易回执 · C2：独立计算意向、入口和订单事实。

按事件类型白名单独立计算三个事实（设计 §3 意向判定）：

- 购买意向（非约束性）：只匹配商家“协议已签发”与买方“已接受并提交”两条
  **独立来源**的有效回执——（商家、磋商号、商家协议号、被接受报价号、
  条款摘要、本次买方凭据绑定）全部相同才计一笔已确认意向。入口、点击、
  交接授权、订单和 A2A task completed 即使携带相同协议号，也不能补任一侧
  的意向证据。分开保存事实，不用事件先后或单个状态字段推断。
- 交易入口：商家发出与买方生成**分列**；入口可在协议形成前按报价引用关联。
- 实际订单：按（商家、渠道内订单引用）去重；只有来源可信且关联可验证
  （可验证的协议引用或结账会话引用）时才确认“订单已创建”。订单已创建
  不推断已付款；一个协议可对应多个真实订单。

冲突处理：同笔磋商/协议的两侧回执字段不一致 → 保留“待核对”，暂停合并。
自签 agent 回执匹配的意向显示“企业未核验”；已核验企业指标只计入具有
独立买方企业凭据绑定的记录。

只读：本模块只查询 `commerce_receipts`；逐笔事实只对有权查看本笔交易的
参与方（商家 token / 运营 admin）可见。
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from kiwi_catalog.core.errors import ValidationError

_INTENT_MERCHANT = "merchant_agreement_issued"
_INTENT_BUYER = "buyer_agreement_accepted"
_INTENT_KEY_FIELDS = (
    "merchant_id",
    "negotiation_id",
    "merchant_agreement_id",
    "accepted_offer_id",
    "terms_digest",
    "buyer_binding",
)


def _intent_key(row: sqlite3.Row) -> tuple[str, ...]:
    return tuple(str(row[field] or "") for field in _INTENT_KEY_FIELDS)


def _soft_key(row: sqlite3.Row) -> tuple[str, str, str]:
    """磋商/协议级的软键：用于冲突检测与单方展示的去重。"""
    return (
        str(row["merchant_id"] or ""),
        str(row["negotiation_id"] or ""),
        str(row["merchant_agreement_id"] or ""),
    )


def _times(row: sqlite3.Row) -> dict[str, str]:
    return {"occurred_at": str(row["occurred_at"]), "received_at": str(row["received_at"])}


def _is_self_signed(row: sqlite3.Row) -> bool:
    return str(row["assurance"]) == "self_signed"


def compute_intents(conn: sqlite3.Connection, merchant_id: str | None = None,
                   group: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    sql = """select r.* from commerce_receipts r where event_type in ('merchant_agreement_issued','buyer_agreement_accepted')"""
    args: list[Any] = []
    if merchant_id is not None:
        sql += " and r.merchant_id=?"
        args.append(merchant_id)
    if group:
        sql += " and negotiation_id=? and merchant_agreement_id=?"
        args.extend(group)
    rows = conn.execute(sql + " order by received_at, receipt_id", args)
    merchant_side: dict[tuple[str, ...], sqlite3.Row] = {}
    buyer_side: dict[tuple[str, ...], sqlite3.Row] = {}
    soft_variants: dict[tuple[str, str, str], set[tuple[str, ...]]] = {}
    merchant_bindings: dict[tuple[str, str, str], set[str]] = {}
    for row in rows:
        key = _intent_key(row)
        if str(row["event_type"]) == _INTENT_MERCHANT:
            merchant_side.setdefault(key, row)
            soft = _soft_key(row)
            soft_variants.setdefault(soft, set()).add(key)
            merchant_bindings.setdefault(soft, set()).add(key[5])
        else:
            buyer_side.setdefault(key, row)

    # Only the buyer key named by the merchant can dispute that agreement.
    for key, buyer_variant in buyer_side.items():
        soft = _soft_key(buyer_variant)
        if key[5] in merchant_bindings.get(soft, ()):
            soft_variants[soft].add(key)

    intents: list[dict[str, Any]] = []
    matched_keys: set[tuple[str, ...]] = set()
    # 已确认：两条独立来源六元组全等。
    for key, merchant_row in merchant_side.items():
        buyer_row = buyer_side.get(key)
        if buyer_row is None or len(soft_variants[_soft_key(merchant_row)]) != 1:
            continue
        matched_keys.add(key)
        intents.append({
            "fact": "intent",
            "status": "confirmed",
            "merchant_id": key[0],
            "negotiation_id": key[1],
            "merchant_agreement_id": key[2],
            "accepted_offer_id": key[3],
            "terms_digest": key[4],
            "buyers_reported": True,
            "merchant_reported": True,
            # 免注册身份的证据上限：自签回执匹配 → 企业未核验。
            "buyer_assurance": "self_signed" if _is_self_signed(buyer_row) else str(buyer_row["assurance"]),
            "verified_enterprise": not _is_self_signed(buyer_row) and not _is_self_signed(merchant_row),
            "times": {
                "merchant": _times(merchant_row),
                "buyer": _times(buyer_row),
            },
            "confirmed_at": max(
                str(merchant_row["received_at"]),
                str(buyer_row["received_at"]),
            ),
        })

    # 单方：只显示报告方（入口/订单不能补意向证据）。
    for key, merchant_row in merchant_side.items():
        if key in matched_keys:
            continue
        intents.append({
            "fact": "intent",
            "status": "merchant_reported",
            "merchant_id": key[0],
            "negotiation_id": key[1],
            "merchant_agreement_id": key[2],
            "accepted_offer_id": key[3],
            "terms_digest": key[4],
            "buyers_reported": False,
            "merchant_reported": True,
            "verified_enterprise": False,
            "times": {"merchant": _times(merchant_row)},
        })
    for key, buyer_row in buyer_side.items():
        if key in matched_keys:
            continue
        intents.append({
            "fact": "intent",
            "status": "buyer_reported",
            "merchant_id": key[0],
            "negotiation_id": key[1],
            "merchant_agreement_id": key[2],
            "accepted_offer_id": key[3],
            "terms_digest": key[4],
            "buyers_reported": True,
            "merchant_reported": False,
            "verified_enterprise": False,
            "times": {"buyer": _times(buyer_row)},
        })

    # 冲突待核对：同一（商家、磋商、协议号）被报了不同六元组——报价/摘要/
    # 凭据不一致，暂停合并，保留人工核对。错配样本仍各自显示单方来源。
    for soft, variants in sorted(soft_variants.items()):
        if len(variants) < 2:
            continue
        intents.append({
            "fact": "intent",
            "status": "needs_review",
            "merchant_id": soft[0],
            "negotiation_id": soft[1],
            "merchant_agreement_id": soft[2],
            "variants": len(variants),
            "buyers_reported": any(v in buyer_side for v in variants),
            "merchant_reported": any(v in merchant_side for v in variants),
            "verified_enterprise": False,
            "note": "同笔磋商/协议的回执字段不一致：保留待核对，暂停合并",
        })
    intents.sort(key=lambda item: (item["status"] != "confirmed", str(item.get("confirmed_at", ""))))
    return intents


def compute_entries(conn: sqlite3.Connection, merchant_id: str | None = None,
                   group: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    sql = """select r.* from commerce_receipts r where event_type in ('merchant_entry_offered','buyer_handoff_generated')"""
    args: list[Any] = []
    if merchant_id is not None:
        sql += " and r.merchant_id=?"
        args.append(merchant_id)
    if group:
        sql += " and receipt_id=?"
        args.extend(group)
    rows = conn.execute(sql + " order by received_at, receipt_id", args)
    entries: list[dict[str, Any]] = []
    for row in rows:
        quote_ref = json.loads(str(row["quote_ref_json"] or "{}"))
        entries.append({
            "fact": "entry",
            "status": "merchant_offered" if str(row["event_type"]) == "merchant_entry_offered" else "buyer_generated",
            "merchant_id": str(row["merchant_id"]),
            "negotiation_id": str(quote_ref.get("negotiation_id", "") or ""),
            "offer_id": str(quote_ref.get("offer_id", "") or ""),
            "quote_ref": quote_ref,
            "entry_type": str(row["entry_type"]),
            "handoff_ref": str(row["handoff_ref"] or ""),
            "reporter_role": str(row["reporter_role"]),
            "assurance": str(row["assurance"]),
            "times": _times(row),
        })
    return entries


def compute_orders(conn: sqlite3.Connection, merchant_id: str | None = None,
                   group: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    sql = """select r.*, exists (select 1 from commerce_receipts a where a.merchant_id=r.merchant_id
        and a.merchant_agreement_id=json_extract(r.order_evidence_json,'$.merchant_agreement_ref')
        and a.merchant_agreement_id<>'' and a.event_type='merchant_agreement_issued'
        and a.reporter_role='merchant' and a.assurance='verified') as linked_agreement from commerce_receipts r where event_type in ('merchant_order_created')"""
    args: list[Any] = []
    if merchant_id is not None:
        sql += " and r.merchant_id=?"
        args.append(merchant_id)
    if group:
        sql += " and order_channel=? and order_ref=?"
        args.extend(group)
    rows = conn.execute(sql + " order by received_at, receipt_id", args)
    orders: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        dedup_key = (
            str(row["merchant_id"]),
            str(row["order_channel"]),
            str(row["order_ref"]),
        )
        evidence = json.loads(str(row["order_evidence_json"] or "{}"))
        checkout = evidence.get("checkout_session_ref")
        channel_evidence = evidence.get("channel_evidence")
        linked_agreement = bool(row["linked_agreement"])
        # Scoped channel adapters attest the checkout association independently of intent.
        confirmed = (
            row["reporter_role"] == "merchant" and row["assurance"] == "verified" and linked_agreement
        ) or (
            row["reporter_role"] == "order_adapter" and row["assurance"] == "adapter_delegated"
            and str(row["reporter_identity"]).startswith("order_adapter:")
            and isinstance(channel_evidence, str) and bool(channel_evidence.strip())
            and (linked_agreement or (isinstance(checkout, str) and bool(checkout.strip())))
        )
        existing = orders.get(dedup_key)
        if existing is None:
            orders[dedup_key] = {
                "fact": "order",
                "status": "confirmed" if confirmed else "needs_review",
                "merchant_id": dedup_key[0],
                "order_channel": dedup_key[1],
                "order_ref": dedup_key[2],
                "order_evidence": evidence,
                "assurance": str(row["assurance"]),
                "times": _times(row),
                "note": None if confirmed else "来源不可信或缺少可验证关联：待核对",
            }
        elif confirmed and existing["status"] != "confirmed":
            # 重复投递中先到的是不可确认副本：以可确认证据为准（不倒退）。
            existing.update({
                "status": "confirmed",
                "order_evidence": evidence,
                "assurance": str(row["assurance"]),
                "times": _times(row),
                "note": None,
            })
    # 订单先于意向回执到达（乱序）：订单事实独立成立，不被意向缺失阻塞。
    return list(orders.values())


def _replace_group(conn: sqlite3.Connection, merchant: str, kind: str, key: tuple[Any, ...],
                   facts: list[dict[str, Any]]) -> None:
    group_key = json.dumps(key, separators=(",", ":"))
    conn.execute("delete from commerce_fact_rows where merchant_id=? and kind=? and group_key=?",
                 (merchant, kind, group_key))
    for index, fact in enumerate(facts):
        fact_key = json.dumps([merchant, kind, *key, index], separators=(",", ":"))
        confirmed = kind == "intent" and fact["status"] == "confirmed"
        conn.execute("insert into commerce_fact_rows(fact_key, merchant_id, kind, group_key, confirmed, verified, payload)"
                     " values(?,?,?,?,?,?,?)",
                     (fact_key, merchant, kind, group_key, int(confirmed),
                      int(confirmed and fact["verified_enterprise"]), json.dumps(fact)))


def refresh_receipt(conn: sqlite3.Connection, receipt_id: int) -> None:
    row = conn.execute("select event_type, merchant_id, negotiation_id, merchant_agreement_id, order_channel,"
                       " order_ref from commerce_receipts where receipt_id=?", (receipt_id,)).fetchone()
    kind, merchant, negotiation, agreement, channel, ref = row
    if kind in (_INTENT_MERCHANT, _INTENT_BUYER):
        group = (negotiation, agreement)
        _replace_group(conn, merchant, "intent", group, compute_intents(conn, merchant, group))
        if kind == _INTENT_MERCHANT:
            # An agreement arriving after its orders may confirm those orders.
            orders = conn.execute("select distinct order_channel, order_ref from commerce_receipts"
                                  " where merchant_id=? and event_type='merchant_order_created'"
                                  " and json_extract(order_evidence_json,'$.merchant_agreement_ref')=?",
                                  (merchant, agreement))
            for channel, ref in orders:
                key = (channel, ref)
                _replace_group(conn, merchant, "order", key, compute_orders(conn, merchant, key))
    elif kind == "merchant_order_created":
        key = (channel, ref)
        _replace_group(conn, merchant, "order", key, compute_orders(conn, merchant, key))
    else:
        _replace_group(conn, merchant, "entry", (receipt_id,), compute_entries(conn, merchant, (receipt_id,)))


def query_facts(conn: sqlite3.Connection, query: dict[str, Any], merchant_id: str | None) -> dict[str, Any]:
    kind = str(query.get("fact_type") or "").strip()
    if kind and kind not in ("intent", "entry", "order"):
        raise ValidationError(f"unknown fact_type: {kind}")
    try:
        limit = int(str(query.get("limit", 50)))
    except ValueError as exc:
        raise ValidationError("limit must be an integer") from exc
    if not 1 <= limit <= 200:
        raise ValidationError("limit must be between 1 and 200")
    where = " where 1=1"
    args = []
    if merchant_id is not None:
        where += " and merchant_id=?"
        args.append(merchant_id)
    if kind:
        where += " and kind=?"
        args.append(kind)
    cursor = str(query.get("cursor") or "")
    if len(cursor) > 8192:
        raise ValidationError("invalid fact cursor")
    # One SQLite statement gives the page and its global counts a common snapshot.
    rows = conn.execute(
        "with totals as (select coalesce(sum(total),0) as n, coalesce(sum(confirmed),0) as intents,"
        " coalesce(sum(verified),0) as enterprises from commerce_fact_totals" + where + "),"
        " page as (select fact_key,payload from commerce_fact_rows" + where
        + " and fact_key>? order by fact_key limit ?)"
        " select totals.*,page.* from totals left join page on true order by fact_key",
        (*args, *args, cursor, limit + 1),
    ).fetchall()
    counts = rows[0]
    return {
        "ok": True,
        "facts": [json.loads(row["payload"]) for row in rows[:limit] if row["payload"] is not None],
        "next_cursor": rows[limit - 1]["fact_key"] if len(rows) > limit else None,
        "summary": {"total": counts["n"], "confirmed_intents": counts["intents"],
                    "verified_enterprise_intents": counts["enterprises"]},
    }
