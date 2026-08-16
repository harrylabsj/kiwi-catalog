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

"""Agent Catalog write service — registration and claim (§10.2, §10.4, §6.2).

This module holds the *shared* write use-cases used by both the API handlers
(``shopping_cli/api/handlers/agent_catalog.py``) and the CLI
(``shopping_cli/cli_agent_catalog_commands.py``).  It performs persistence and
writes §23 audit events; it does NOT enforce transport-level idempotency,
rate limiting, or auth — those live in the API layer.

The register/claim proof rules come from design §6.2:

    hosted          → existing merchant/admin identity is proof
    self_registered → HTTPS domain-control challenge
    discovered      → UNCLAIMED → claim → same HTTPS domain-control challenge

"Knowing the Agent Card URL" is never proof of ownership — the domain must
actually serve the standard well-known locations over HTTPS.
"""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from kiwi_catalog.agent_catalog.sqlite_repository import (
    append_catalog_audit,
    list_catalog_agents_by_merchant,
    list_endpoints,
    new_catalog_agent_id,
    replace_capabilities,
    replace_skills,
    require_catalog_agent,
    set_catalog_agent_merchant,
    set_state_domains,
    upsert_catalog_agent,
    upsert_profile_endpoints,
)
from kiwi_catalog.agent_catalog.state_domains import HANDOFF_DESTINATION_TYPES
from kiwi_catalog.core.errors import ConflictError, PermissionDenied, ValidationError
from kiwi_catalog.discovery._validation import canonical_domain_of, is_http_url, is_same_authority
from kiwi_catalog.services.agent_catalog import get_catalog_agent_write_detail
from kiwi_catalog.services.catalog_runtime_metrics import record_funnel

# 行政处置终态：可被重新注册恢复（v0.3 §7.3——REJECTED / SUSPENDED 属
# administrative_state；legacy 折叠值同义）。重注册 = 复活治理处置，必须
# 由 admin 或既有绑定商户的 owner token 发起（审查 P1-4b），匿名不得触发。
RE_REGISTERABLE_ADMIN = frozenset({"rejected", "suspended"})


def _ensure_merchant_shadow(conn: Any, merchant_id: str, display_name: str) -> None:
    """注册时自维护 merchants 影子行（搜索 join 投影的 merchant 展示名）。

    影子表语义：catalog 侧弱引用投影。INSERT OR IGNORE——首次注册创建，
    不覆盖外部已同步的 merchants 业务字段（city/service_area 等）。
    """
    from kiwi_catalog.db.session import now_iso

    now = now_iso()
    conn.execute(
        "insert or ignore into merchants(id, name, created_at, updated_at) values (?, ?, ?, ?)",
        (merchant_id, display_name or merchant_id, now, now),
    )

# hosting_mode canonical（v0.3）→ legacy 存储值（catalog_agents CHECK 只收
# legacy 4 值；wire schema 两种都收，存储归一化后消费方不受影响）。
_CANONICAL_HOSTING_MODE: dict[str, str] = {
    "direct_only": "direct",
    "hosted_only": "hosted",
}


def normalize_hosting_mode(mode: str) -> str:
    """把 canonical hosting_mode 归一化为 legacy 存储值（非法值原样返回，
    由 DB CHECK / schema 兜底拒绝）。"""
    return _CANONICAL_HOSTING_MODE.get(mode, mode)

# Bare-hostname shape: letters/digits/hyphen/dot, at least one dot.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\.?$")


def normalize_canonical_domain(domain: Any) -> str:
    """Validate and normalize a bare canonical domain.

    Rejects scheme/path/port forms — a canonical domain is a bare hostname
    (``merchant.example``), never a URL.
    """
    text = str(domain or "").strip().lower().rstrip(".")
    if not text:
        raise ValidationError("domain is required")
    if "/" in text or ":" in text or " " in text:
        raise ValidationError(f"invalid canonical domain: {domain!r}")
    if not _HOSTNAME_RE.match(text):
        raise ValidationError(f"invalid canonical domain: {domain!r}")
    return text


def _default_identity_verifier() -> Any:
    from kiwi_catalog.discovery.fetcher import ProfileFetcher
    from kiwi_catalog.discovery.trust import TrustPolicy
    from kiwi_catalog.discovery.verifier import IdentityVerifier

    policy = TrustPolicy.defaults()
    return IdentityVerifier(ProfileFetcher(policy), policy)


def _declared_profile_urls(conn: Any, catalog_agent_id: str) -> dict[str, str]:
    declared: dict[str, str] = {}
    for ep in list_endpoints(conn, catalog_agent_id):
        kind = str(ep.get("kind", ""))
        url = str(ep.get("url", "")).strip()
        if kind in ("agent_card", "ucp_profile") and url:
            declared[kind] = url
    return declared


def _purge_domain_bound_claims(conn: Any, catalog_agent_id: str) -> None:
    """审查 P1-01：换域名时清除旧域名绑定的派生声明与证据。

    商家重注册换新域名后，capabilities/skills（源自旧域名 profile 或旧注册
    声明）、``agent_profile_snapshots``（旧域名 source_url）与
    ``agent_verifications``（旧域名验证证据）不得继续绑定新域名——全部清除，
    在新域名上重新验证。证据删除后 v0.3 §7.1 证据重算找不到旧 passed 行，
    级别停在 DISCOVERED，旧域名证据无法把已验证级别复活到新域名下。
    """
    conn.execute(
        "delete from agent_capabilities where catalog_agent_id = ?", (catalog_agent_id,)
    )
    conn.execute(
        "delete from agent_skills where catalog_agent_id = ?", (catalog_agent_id,)
    )
    conn.execute(
        "delete from agent_profile_snapshots where catalog_agent_id = ?", (catalog_agent_id,)
    )
    conn.execute(
        "delete from agent_verifications where catalog_agent_id = ?", (catalog_agent_id,)
    )


def _purge_stale_profile_endpoints(conn: Any, catalog_agent_id: str, canonical: str) -> None:
    """审查 P1-01：删除全部端点中不属于 canonical 域的旧行（任一 kind）。

    与验证管线的 authority 语义一致（``is_same_authority`` 允许多级子域）：
    换域名后旧端点在注册事务内立即清除，验证阶段不会再抓取旧域名 profile，
    也不残留指向旧域名的路由端点。本次注册提供的、位于新域名（或其子域）
    下的端点保留。
    """
    rows = conn.execute(
        "select endpoint_id, url from agent_endpoints where catalog_agent_id = ?",
        (catalog_agent_id,),
    ).fetchall()
    stale: list[tuple[int]] = []
    for r in rows:
        url = str(r["url"] or "").strip()
        if not url or not is_http_url(url):
            stale.append((int(r["endpoint_id"]),))
            continue
        if not is_same_authority(canonical_domain_of(url), canonical):
            stale.append((int(r["endpoint_id"]),))
    if stale:
        conn.executemany("delete from agent_endpoints where endpoint_id = ?", stale)


def register_catalog_agent(
    conn: Any,
    *,
    domain: str,
    agent_card_url: str = "",
    ucp_profile_url: str = "",
    merchant_id: str = "",
    actor: str = "cli",
    display_name: str = "",
    hosting_mode: str = "",
    handoff_destination_types: list[str] | None = None,
    capabilities: list[str] | None = None,
    skills: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Create (or re-open) a DISCOVERED self_registered catalog agent (§10.2).

    v0.3 扩展字段：display_name / hosting_mode / handoff_destination_types
    （KTH destination_type 词表）/ capabilities（全限定 fqid）/ skills 均
    public-only（完成定义 #8）。

    Returns the public detail (§8.2 contract).  Verification is deliberately
    NOT run here — the API layer enqueues it into the bounded verification
    queue (§25 Phase 2) and the CLI lets the caller run ``agent catalog verify``
    explicitly.
    """
    canonical = normalize_canonical_domain(domain)
    merchant_id = str(merchant_id or "").strip()
    # 审查 P1-01：换域名 = 信任边界重置——记录被更新 agent 的原 canonical_domain，
    # 域名变更时清除旧域名绑定的派生数据（见下方 _purge_*）。
    prior_domain: str | None = None

    # 注册规则（2026-08-10 用户要求）：**一个域名可注册多个商家，一个商家
    # 只能有一个 agent**。
    # - 商家注册（merchant_id 非空）：以 merchant 为主键。商家名下已有 active
    #   agent → **原地更新**（换域名 / card URL 都是合法 upsert，重注册不再 409）；
    #   已有 suspended/rejected → 重新打开（审查 P3 语义）；无 → 新建。
    #   域名不再全局唯一——不同商家可注册同一域名（schema v17 删域名唯一索引）。
    # - 匿名注册（merchant_id 空）：无商家身份，保持一域一 agent（防匿名刷
    #   同域名重复行）。
    if merchant_id:
        owned, _ = list_catalog_agents_by_merchant(conn, merchant_id)
        target = next(
            (a for a in owned if a.get("administrative_state") == "active"),
            next(
                (a for a in owned if a.get("administrative_state") in RE_REGISTERABLE_ADMIN),
                None,
            ),
        )
        if target is not None:
            prior_domain = str(target.get("canonical_domain") or "").strip() or None
        catalog_agent_id = (
            str(target["catalog_agent_id"]) if target is not None else new_catalog_agent_id()
        )
    else:
        # 审查 P2（v17 删域名唯一索引后）：匿名/域名级路径不能选中「最新任意
        # merchant 行」（created_at 同秒时顺序不确定，且一域多商家后无法定义
        # "该域名的 agent"）。显式冲突规则：
        # - 域名下已有 merchant 绑定行 → ConflictError（商家域名，匿名不得
        #   注册/复活，也不得经任意行抹除商家绑定）；
        # - 仅匿名（未绑定）行：任一 active → Conflict（一域一 agent，防匿名
        #   刷同域名重复行）；governed（suspended/rejected）唯一行 → 复用重开
        #   （无 merchant 可抢绑；复活需 admin，handler 侧把关）。
        rows = conn.execute(
            "select * from catalog_agents where canonical_domain = ?", (canonical,)
        ).fetchall()
        if any(str(r["merchant_id"] or "").strip() for r in rows):
            raise ConflictError(f"domain {canonical} is already registered by a merchant")
        active_anon = [
            r for r in rows if str(r["administrative_state"]) not in RE_REGISTERABLE_ADMIN
        ]
        if active_anon:
            raise ConflictError(f"domain {canonical} is already registered")
        existing = max(rows, key=lambda r: str(r["created_at"])) if rows else None
        if existing is not None:
            prior_domain = str(existing["canonical_domain"] or "").strip() or None
        catalog_agent_id = (
            str(existing["catalog_agent_id"]) if existing is not None else new_catalog_agent_id()
        )
    try:
        upsert_catalog_agent(
            conn,
            catalog_agent_id=catalog_agent_id,
            merchant_id=merchant_id,
            hosted_runtime_agent_id="",
            display_name=display_name or canonical,
            provider_name="",
            canonical_domain=canonical,
            agent_type="commerce",
            source_type="self_registered",
            lifecycle_status="active",
            verification_status="discovered",
            hosting_mode=normalize_hosting_mode(hosting_mode) or "direct",
        )
    except sqlite3.IntegrityError as exc:
        # 审查 P2：check-then-act 竞态窗口由数据层唯一索引兜底（v7 merchant
        # 唯一索引；v11 域名唯一索引已于 v17 删除）——映射为 ConflictError
        # 而非未类型化 500。
        raise ConflictError("concurrent duplicate registration") from exc
    # 重注册 = 重新打开：治理态（suspended/rejected）显式复位为 active——
    # update 路径（_update_catalog_agent）不写 administrative_state，不复位
    # 则商家重注册无法恢复自己的 agent（审查 P3「重新打开」语义）。
    conn.execute(
        "update catalog_agents set administrative_state = 'active'"
        " where catalog_agent_id = ?",
        (catalog_agent_id,),
    )
    # 审查 P1-01：域名变更 → 清除旧域名绑定的声明/证据。先清 capabilities/
    # skills/snapshots/verifications（下方 public 字段块会重新写入本次注册
    # 提供的 fresh 值）；agent_card/ucp_profile 旧端点延迟到 endpoints 块
    # 之后清除（只删不属于新域名的旧行，保留本次新端点）。
    domain_changed = prior_domain is not None and prior_domain != canonical
    if domain_changed:
        _purge_domain_bound_claims(conn, catalog_agent_id)
    # merchants 影子行自维护（D4 修复）：搜索结果的 merchant 投影依赖它；
    # 无影子行时 projection 为空串、schema 校验失败（minLength 1）。
    if merchant_id:
        _ensure_merchant_shadow(conn, merchant_id, display_name or canonical)
    # v0.3 public 扩展字段（全部 public-only，完成定义 #8）：
    # handoff_destination_types 必须是 KTH destination_type 词表成员
    # （单一来源，禁止 supports_* 平行词表）。
    if handoff_destination_types:
        invalid = [d for d in handoff_destination_types if d not in HANDOFF_DESTINATION_TYPES]
        if invalid:
            raise ValidationError(
                f"invalid handoff_destination_types (must be KTH destination_type "
                f"values): {invalid}"
            )
        set_state_domains(conn, catalog_agent_id, handoff_destination_types=list(handoff_destination_types))
    if capabilities:
        replace_capabilities(
            conn,
            catalog_agent_id,
            [
                {"namespace": (c.split(":", 1)[0] if ":" in c else ""), "capability_id": (c.split(":", 1)[1] if ":" in c else c)}
                for c in capabilities
            ],
        )
    if skills:
        replace_skills(
            conn,
            catalog_agent_id,
            [
                {
                    "skill_id": str(s.get("skill_id") or ""),
                    "name": str(s.get("name") or ""),
                    "description": str(s.get("description") or ""),
                    # 审查 P3：tags 客户端可传 list——写边界归一化为
                    # JSON 字符串（此前 sqlite3 绑定 list 抛 ProgrammingError
                    # → 500，未转换为 ValidationError）。
                    # 审查 L5：wire 字段名是 schema 声明的 `tags`（additionalProperties
                    # :false），此前误读 `tags_json`（schema 拒绝该字段）→ tags 被
                    # 静默丢弃。
                    "tags_json": (
                        s["tags"]
                        if isinstance(s.get("tags"), str)
                        else json.dumps(s.get("tags") or [], ensure_ascii=False)
                    ),
                }
                for s in skills
            ],
        )

    endpoints: list[dict[str, Any]] = []
    if str(agent_card_url or "").strip():
        endpoints.append({
            "kind": "agent_card",
            "url": str(agent_card_url).strip(),
            "protocol": "a2a",
            "protocol_version": "",
            "preference": 1,
        })
    if str(ucp_profile_url or "").strip():
        endpoints.append({
            "kind": "ucp_profile",
            "url": str(ucp_profile_url).strip(),
            "protocol": "ucp",
            "protocol_version": "",
            "preference": 1,
        })
    if endpoints:
        upsert_profile_endpoints(conn, catalog_agent_id, endpoints)
    # 审查 P1-01：新端点已 upsert——现在清除全部端点中不属于新 canonical 域
    # 的旧端点（保留本次提供的新域名端点）。
    if domain_changed:
        _purge_stale_profile_endpoints(conn, catalog_agent_id, canonical)

    append_catalog_audit(
        conn,
        catalog_agent_id,
        actor,
        "catalog_agent_registered",
        {
            "canonical_domain": canonical,
            "source_type": "self_registered",
            "merchant_id": merchant_id or None,
            "agent_card_url_present": bool(endpoints and any(e["kind"] == "agent_card" for e in endpoints)),
            "ucp_profile_url_present": bool(endpoints and any(e["kind"] == "ucp_profile" for e in endpoints)),
        },
    )
    if domain_changed:
        # 审查 P1-01：换域名清除旧域名绑定数据 → 记录审计（旧域名、新域名、
        # 清除的工件）。audit_events 保留清除事实，被删证据行仍可追溯。
        append_catalog_audit(
            conn,
            catalog_agent_id,
            actor,
            "catalog_agent_domain_changed",
            {
                "previous_domain": prior_domain,
                "canonical_domain": canonical,
                "purged": [
                    "agent_card_endpoints",
                    "ucp_profile_endpoints",
                    "capabilities",
                    "skills",
                    "profile_snapshots",
                    "verifications",
                ],
            },
        )
    # §24 funnel: a successful registration is the discovery event.
    record_funnel("discovery")
    return get_catalog_agent_write_detail(conn, catalog_agent_id)


def claim_catalog_agent(
    conn: Any,
    *,
    catalog_agent_id: str,
    merchant_id: str,
    actor: str,
    identity_verifier: Any | None = None,
) -> dict[str, Any]:
    """Claim ownership of a catalog agent (§10.4, §6.2).

    *hosted* agents are proven by the caller's merchant/admin identity (already
    enforced by the API auth layer).  *self_registered* / *discovered* agents
    require an HTTPS domain-control challenge against the canonical domain —
    merely knowing the Agent Card URL is never sufficient proof.

    On success the agent is bound to *merchant_id* and a ``catalog_agent_claimed``
    audit event is written.  Returns the public detail.
    """
    catalog_agent_id = str(catalog_agent_id or "").strip()
    merchant_id = str(merchant_id or "").strip()
    if not merchant_id:
        raise ValidationError("merchant_id is required to claim a catalog agent")

    # 一商家一 agent：目标 merchant 已认领其他 agent 时拒绝（当前 agent
    # 已在 claim 流程中，不受影响）。
    owned, _ = list_catalog_agents_by_merchant(conn, merchant_id)
    owned = [a for a in owned if a["catalog_agent_id"] != catalog_agent_id]
    if owned:
        raise ConflictError(
            f"merchant {merchant_id} already has a catalog agent "
            f"({owned[0]['catalog_agent_id']})"
        )

    agent = require_catalog_agent(conn, catalog_agent_id)
    canonical = str(agent.get("canonical_domain") or "").strip()
    if not canonical:
        raise ValidationError(f"catalog agent {catalog_agent_id} has no canonical_domain to claim")

    source_type = str(agent.get("source_type") or "")
    claim_method = "hosted_identity"
    if source_type != "hosted":
        # §6.2: HTTPS domain-control challenge — proof of domain control, not
        # knowledge of the Agent Card URL.
        verifier = identity_verifier or _default_identity_verifier()
        # 审查 P1-5：抓取前提交，关闭写事务——well-known 抓取（10s 级网络
        # I/O）期间不持有 SQLite 写锁（idempotency claim 行已持久化，失败时
        # handler 的 clear 独立生效；merchant 绑定写入由迁移 v7 唯一索引兜底）。
        conn.commit()
        evidence = verifier.verify_domain_control(canonical, declared=_declared_profile_urls(conn, catalog_agent_id))
        if not evidence.passed:
            raise PermissionDenied(f"claim denied: {evidence.reason}")
        claim_method = "https_domain_control"

    current_merchant = str(agent.get("merchant_id") or "").strip()
    if current_merchant and current_merchant != merchant_id:
        raise ConflictError(f"catalog agent {catalog_agent_id} is already claimed by merchant {current_merchant}")

    try:
        set_catalog_agent_merchant(conn, catalog_agent_id, merchant_id)
    except sqlite3.IntegrityError as exc:
        # 审查 P2：claim 的「一商家一 agent」是读-改-写竞态（两个 merchant
        # 并发认领同一 agent / 同 merchant 并发认领两个 agent），由迁移 v7
        # 部分唯一索引兜底——映射为 ConflictError 而非未类型化 500。
        raise ConflictError(
            f"merchant {merchant_id} already has a catalog agent (concurrent claim)"
        ) from exc
    append_catalog_audit(
        conn,
        catalog_agent_id,
        actor,
        "catalog_agent_claimed",
        {
            "merchant_id": merchant_id,
            "claim_method": claim_method,
            "canonical_domain": canonical,
        },
    )
    return get_catalog_agent_write_detail(conn, catalog_agent_id)
