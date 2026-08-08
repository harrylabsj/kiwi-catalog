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

"""kiwi-catalog standalone schema (阶段 2 独立库).

Catalog domain DDL extracted from shopping-cli db/models.py (10 tables,
foreign keys to merchants/agents dropped — 弱引用) plus minimal shadow
tables (merchants public fields for the join projection, audit_events for
catalog audit) and meta.  a2a_inbound_idempotency and
verification_queue_tasks live in migrations (v5/v6), matching the
shopping-cli v14/v15 split.

Extraction date: 2026-08-06.  Keep in sync with the shopping-cli DDL
until the repos diverge intentionally (phase 3+).
"""

SCHEMA = [
    """
create table if not exists catalog_agents (
        catalog_agent_id text primary key,
        merchant_id text,
        hosted_runtime_agent_id text,
        display_name text not null,
        provider_name text not null default '',
        canonical_domain text not null default '',
        agent_type text not null default '',
        source_type text not null
            check(source_type in ('hosted','self_registered','discovered','imported','admin_curated')),
        lifecycle_status text not null default 'active'
            check(lifecycle_status in ('active','inactive','deprecated')),
        verification_status text not null default 'discovered'
            check(verification_status in (
                'discovered','profile_valid','domain_verified','agent_verified',
                'commerce_verified','stale','rejected','suspended','unreachable'
            )),
        verification_level text not null default 'discovered'
            check(verification_level in (
                'discovered','profile_valid','domain_verified','agent_verified',
                'commerce_verified'
            )),
        freshness_state text not null default 'fresh'
            check(freshness_state in ('fresh','stale','unreachable')),
        administrative_state text not null default 'active'
            check(administrative_state in ('active','suspended','rejected')),
        handoff_destination_types text not null default '[]',
        last_refresh_attempt_at text not null default '',
        last_refresh_result text not null default '',
        hosting_mode text not null default 'unknown'
            check(hosting_mode in ('direct','hosted','hybrid','unknown')),
        first_seen_at text not null,
        last_seen_at text not null,
        last_verified_at text not null default '',
        created_at text not null,
        updated_at text not null
    )

    """,
    """
create table if not exists agent_endpoints (
        endpoint_id integer primary key autoincrement,
        catalog_agent_id text not null,
        kind text not null check(kind in ('a2a','agent_card','ucp_profile','hosted_gateway')),
        url text not null default '',
        protocol text not null default '',
        protocol_version text not null default '',
        preference integer not null default 0,
        auth_summary_json text not null default '{}',
        status text not null default 'active',
        last_checked_at text not null default ''
    )
    
    """,
    """
create table if not exists agent_capabilities (
        catalog_agent_id text not null,
        namespace text not null,
        capability_id text not null,
        version text not null default '',
        required integer not null default 0,
        source text not null default '',
        schema_url text not null default '',
        spec_url text not null default '',
        last_verified_at text not null default '',
        primary key (catalog_agent_id, namespace, capability_id)
    )
    
    """,
    """
create table if not exists agent_skills (
        catalog_agent_id text not null,
        skill_id text not null,
        name text not null,
        description text not null default '',
        tags_json text not null default '[]',
        input_modes_json text not null default '[]',
        output_modes_json text not null default '[]',
        primary key (catalog_agent_id, skill_id)
    )
    
    """,
    """
create table if not exists agent_profile_snapshots (
        snapshot_id integer primary key autoincrement,
        catalog_agent_id text not null,
        profile_type text not null check(profile_type in ('agent_card','ucp')),
        source_url text not null default '',
        etag text not null default '',
        last_modified text not null default '',
        content_hash text not null default '',
        raw_json text not null default '{}',
        fetched_at text not null default '',
        fresh_until text not null default '',
        validation_status text not null default 'pending'
    )
    
    """,
    """
create table if not exists agent_verifications (
        verification_id integer primary key autoincrement,
        catalog_agent_id text not null,
        verification_type text not null,
        result text not null default '',
        evidence_json text not null default '{}',
        checked_at text not null default '',
        expires_at text not null default ''
    )
    
    """,
    """
create table if not exists agent_catalog_register_limits (
        canonical_domain text not null,
        window_start text not null,
        request_count integer not null default 0,
        updated_at text not null,
        primary key (canonical_domain, window_start)
    )
    
    """,
    """
create table if not exists agent_catalog_write_idempotency (
        endpoint text not null,
        actor_key text not null,
        idempotency_key text not null,
        request_hash text not null,
        status text not null,
        response_json text not null default '{}',
        created_at text not null,
        updated_at text not null,
        primary key (endpoint, actor_key, idempotency_key)
    )
    
    """,
    """
create table if not exists agent_catalog_write_rate_limits (
        actor_key text not null,
        window_start text not null,
        request_count integer not null default 0,
        updated_at text not null,
        primary key (actor_key, window_start)
    )
    
    """,
    """
create table if not exists agent_trust_observations (
        observation_id integer primary key autoincrement,
        catalog_agent_id text not null,
        kind text not null
            check(kind in (
                'protocol_compliance','timeout_rate','schema_error_rate',
                'successful_exchange','local_asserted_dispute'
            )),
        value real not null,
        source text not null default '',
        evidence_ref text not null default '',
        observed_at text not null,
        expires_at text not null default ''
    )
    
    """,
    """
create table if not exists merchants (
        id text primary key,
        name text not null,
        city text not null default '',
        service_area text not null default '',
        contact text not null default '',
        hours text not null default '',
        automation_boundaries text not null default '',
        tags_json text not null default '[]',
        created_at text not null,
        updated_at text not null
    )
    """,
    # v12 — merchant token 分发（docs/kiwi-catalog-token-portal-design-v0.1 §3）。
    # merchant_tokens：每 merchant 至多一条 active 行；token_hash = SHA-256(明文)，
    # token_encrypted = Fernet 加密明文（v14 起，登录后"我的"可查）；明文不进
    # 日志。merchant_applications：申请工单，approve 时平台签发 mkt_<rand>
    # merchant_id 并原子写入三张表；account_id（v14）归属注册账号。
    """
create table if not exists merchant_tokens (
        merchant_id text primary key,
        token_hash text not null,
        token_encrypted text not null default '',
        status text not null default 'active'
            check(status in ('active','revoked')),
        issued_at text not null,
        rotated_at text not null default '',
        revoked_at text not null default ''
    ) without rowid
    """,
    """
create table if not exists merchant_applications (
        application_id integer primary key autoincrement,
        status text not null default 'pending'
            check(status in ('pending','approved','rejected')),
        domain text not null,
        agent_name text not null,
        contact_email text not null,
        purpose text not null default '',
        phone text not null default '',
        merchant_id text not null default '',
        review_note text not null default '',
        account_id integer not null default 0,
        created_at text not null,
        reviewed_at text not null default ''
    )
    """,
    """
create table if not exists merchant_application_limits (
        actor_key text not null,
        window_start text not null,
        request_count integer not null default 0,
        updated_at text not null,
        primary key (actor_key, window_start)
    )
    """,
    # v13 — 运营埋点（dashboard 数据源）。metric × day 每日计数，原子
    # INSERT ON CONFLICT +1；day 为 UTC 日期（YYYY-MM-DD）。
    """
create table if not exists usage_metrics (
        metric text not null,
        day text not null,
        count integer not null default 0,
        updated_at text not null,
        primary key (metric, day)
    )
    """,
    # v14 — 账号体系（docs §account）。merchant_accounts：注册即建账号，
    # merchant_id 审批签发后回填；account_sessions：登录会话（随机
    # session token 落库 SHA-256 + 过期）；merchant_tokens.token_encrypted：
    # Fernet 加密的明文 token（登录后"我的"可查——解决签发即丢失）；
    # merchant_applications.account_id：注册自动建工单的归属账号。
    # v15 — 邮箱验证：email_verified（0/1）、verification_code_hash（6 位
    # 验证码 SHA-256）、verification_expires_at（15 分钟过期）。
    # v16 — 账户基本信息：merchant_name（商家名称）、phone（电话，选填）；
    # merchant_applications.phone（申请工单电话，选填）。
    """
create table if not exists merchant_accounts (
        account_id integer primary key autoincrement,
        email text not null unique,
        password_hash text not null,
        email_verified integer not null default 0,
        verification_code_hash text not null default '',
        verification_expires_at text not null default '',
        merchant_name text not null default '',
        phone text not null default '',
        merchant_id text not null default '',
        application_id integer not null default 0,
        status text not null default 'active'
            check(status in ('active','suspended')),
        created_at text not null,
        updated_at text not null
    )
    """,
    """
create table if not exists account_sessions (
        session_token_hash text primary key,
        account_id integer not null,
        expires_at text not null,
        created_at text not null
    )
    """,
    """
create table if not exists audit_events (
        id integer primary key autoincrement,
        conversation_id text not null default '',
        actor text not null,
        event text not null,
        details_json text not null default '{}',
        created_at text not null
    )
    """,
    """
create table if not exists meta (
        key text primary key,
        value text not null default ''
    )
    """,
    # v10 — commerce listings（产品文档 kiwi-catalog v0.4 §4/§5/§14；升级计划 §3）
    # listing_freshness_state 对应升级计划的 freshness_state 列，wire 层与
    # agent 域 freshness_state 拼写区分（评审 P2-7；M1 listing-record.schema.json）。
    # 幂等 upsert key：ProductListing→source_product_ref（必填）、
    # CapabilityListing→publisher_listing_key（publisher 稳定 external key；
    # 缺省按 id 幂等=每次 publish 新建行）。两个 partial unique index 兜底
    # 行级唯一（NULL 行不参与，弱引用无 FK 约定）。
    """
create table if not exists commerce_listings (
        id integer primary key autoincrement,
        listing_id text not null unique,
        listing_type text not null
            check(listing_type in ('product','capability')),
        owner_agent_id text not null,
        merchant_id text not null,
        source_product_ref text,
        publisher_listing_key text,
        source_revision text not null default '',
        title text not null,
        summary text not null default '',
        category text not null,
        brand text not null default '',
        attributes_json text not null default '{}',
        regions_json text not null default '[]',
        tags_json text not null default '[]',
        commercial_hints_json text not null default '{}',
        handoff_destination_types_json text not null default '[]',
        listing_digest text not null,
        publication_state text not null default 'ACTIVE'
            check(publication_state in ('ACTIVE','WITHDRAWN','SUSPENDED')),
        listing_freshness_state text not null default 'FRESH'
            check(listing_freshness_state in ('FRESH','STALE')),
        published_at text not null,
        updated_at text not null,
        fresh_until text not null,
        created_at text not null
    )

    """,
    """
create index if not exists idx_commerce_listings_owner
        on commerce_listings(owner_agent_id)

    """,
    """
create index if not exists idx_commerce_listings_type_category
        on commerce_listings(listing_type, category)

    """,
    """
create index if not exists idx_commerce_listings_publication_freshness
        on commerce_listings(publication_state, listing_freshness_state)

    """,
    """
create index if not exists idx_commerce_listings_updated
        on commerce_listings(updated_at, id)

    """,
    """
create index if not exists idx_commerce_listings_fresh_until
        on commerce_listings(fresh_until) where listing_freshness_state = 'FRESH'

    """,
    """
create unique index if not exists idx_commerce_listings_product_ref_unique
        on commerce_listings(owner_agent_id, listing_type, source_product_ref)
        where source_product_ref is not null

    """,
    """
create unique index if not exists idx_commerce_listings_publisher_key_unique
        on commerce_listings(owner_agent_id, listing_type, publisher_listing_key)
        where publisher_listing_key is not null

    """,
]


INDEXES: list[str] = []  # catalog 搜索是 WHERE 过滤，无 marketplace 索引依赖
