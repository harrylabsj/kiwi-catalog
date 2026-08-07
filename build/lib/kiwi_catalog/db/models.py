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
]


INDEXES: list[str] = []  # catalog 搜索是 WHERE 过滤，无 marketplace 索引依赖
