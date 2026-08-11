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

"""kiwi-catalog fallback route table (阶段 2 独立库).

The executable route table and its handler wrappers, extracted verbatim from
api/app.py.  The app facade keeps payload validation, error mapping and the
FastAPI/fallback selection; this module owns the pure route table that both
stacks dispatch through (``resolve_route`` walks it for the middleware and
fallback route resolver).  Move-only split: no route, handler or status
semantics changed.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kiwi_catalog.api.handlers import accounts as accounts_handlers
from kiwi_catalog.api.handlers import admin as admin_handlers
from kiwi_catalog.api.handlers import agent_catalog as agent_catalog_handlers
from kiwi_catalog.api.handlers import discovery_entries as discovery_entries_handlers
from kiwi_catalog.api.handlers import hosted_publication as hosted_publication_handlers
from kiwi_catalog.api.handlers import listings as listings_handlers
from kiwi_catalog.api.handlers import merchants as merchants_handlers
from kiwi_catalog.api.handlers import portal as portal_handlers
from kiwi_catalog.api.route_matching import match_path as _match_path


def _health(db_path: str | Path) -> dict[str, Any]:
    return {"ok": True, "service": "kiwi-catalog", "db": str(db_path)}


@dataclass(frozen=True)
class RouteEntry:
    methods: set[str]
    path_template: str
    handler: Any


_ROUTE_TABLE: tuple[RouteEntry, ...] = (
RouteEntry({"GET"}, "/health", lambda db_path, payload, query, **kw: _health(db_path)),
RouteEntry(
        {"GET"},
        "/v1/agent-catalog/agents",
        lambda db_path, payload, query, **kw: _list_catalog_agents(db_path, payload, query),
    ),
RouteEntry(
        {"GET"},
        "/v1/agent-catalog/agents/search",
        lambda db_path, payload, query, **kw: _search_agent_catalog(db_path, payload, query),
    ),
RouteEntry(
        {"GET"},
        "/v1/agent-catalog/agents/{catalog_agent_id}",
        lambda db_path, payload, query, catalog_agent_id: _get_catalog_agent(
            db_path, catalog_agent_id=catalog_agent_id
        ),
    ),
RouteEntry(
        {"GET"},
        "/v1/agent-catalog/merchants/{merchant_id}/agents",
        lambda db_path, payload, query, merchant_id: _list_merchant_catalog_agents(
            db_path, merchant_id=merchant_id, query=query or {}
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/agent-catalog/agents/register",
        lambda db_path, payload, query, **kw: _register_catalog_agent(db_path, payload),
    ),
RouteEntry(
        {"POST"},
        "/v1/agent-catalog/agents/{catalog_agent_id}/refresh",
        lambda db_path, payload, query, catalog_agent_id: _refresh_catalog_agent(
            db_path, catalog_agent_id, payload
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/agent-catalog/agents/{catalog_agent_id}/verify",
        lambda db_path, payload, query, catalog_agent_id: _verify_catalog_agent(
            db_path, catalog_agent_id, payload
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/agent-catalog/agents/{catalog_agent_id}/claim",
        lambda db_path, payload, query, catalog_agent_id: _claim_catalog_agent(
            db_path, catalog_agent_id, payload
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/agent-catalog/agents/{catalog_agent_id}/suspend",
        lambda db_path, payload, query, catalog_agent_id: _suspend_catalog_agent(
            db_path, catalog_agent_id, payload
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/agent-catalog/agents/{catalog_agent_id}/reinstate",
        lambda db_path, payload, query, catalog_agent_id: _reinstate_catalog_agent(
            db_path, catalog_agent_id, payload
        ),
    ),
RouteEntry(
        {"GET"},
        "/v1/agents",
        lambda db_path, payload, query, **kw: _v1_list_agents(db_path, payload, query),
    ),
RouteEntry(
        {"GET"},
        "/v1/agents/search",
        lambda db_path, payload, query, **kw: _v1_search_agents(db_path, payload, query),
    ),
RouteEntry(
        {"GET"},
        "/v1/agents/{catalog_agent_id}",
        lambda db_path, payload, query, catalog_agent_id: _v1_get_agent(
            db_path, catalog_agent_id=catalog_agent_id
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/agents/register",
        lambda db_path, payload, query, **kw: _v1_register_agent(db_path, payload),
    ),
RouteEntry(
        {"POST"},
        "/v1/agents/{catalog_agent_id}/refresh",
        lambda db_path, payload, query, catalog_agent_id: _v1_refresh_agent(
            db_path, catalog_agent_id, payload
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/agents/{catalog_agent_id}/verify",
        lambda db_path, payload, query, catalog_agent_id: _v1_verify_agent(
            db_path, catalog_agent_id, payload
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/agents/{catalog_agent_id}/claim",
        lambda db_path, payload, query, catalog_agent_id: _v1_claim_agent(
            db_path, catalog_agent_id, payload
        ),
    ),
RouteEntry(
        {"GET"},
        "/v1/hosted/agents/{catalog_agent_id}/agent-card.json",
        lambda db_path, payload, query, catalog_agent_id: _hosted_agent_card_document(
            db_path, catalog_agent_id
        ),
    ),
RouteEntry(
        {"GET"},
        "/v1/hosted/agents/{catalog_agent_id}/ucp",
        lambda db_path, payload, query, catalog_agent_id: _hosted_ucp_profile_document(
            db_path, catalog_agent_id
        ),
    ),
# ── /v1/listings（v0.4 新 API：Product-first Commerce Discovery）────────────
# 顺序约束：/v1/listings/search 必须先于 /v1/listings/{listing_id}
#（_match_path 顺序匹配；与 /v1/agents/search 先例一致）。
RouteEntry(
        {"GET"},
        "/v1/listings/search",
        lambda db_path, payload, query, **kw: _v1_search_listings(db_path, payload, query),
    ),
RouteEntry(
        {"GET"},
        "/v1/listings/{listing_id}",
        lambda db_path, payload, query, listing_id: _v1_get_listing(
            db_path, listing_id=listing_id
        ),
    ),
RouteEntry(
        {"GET"},
        "/v1/agents/{catalog_agent_id}/listings",
        lambda db_path, payload, query, catalog_agent_id: _v1_list_agent_listings(
            db_path, catalog_agent_id, query or {}, payload or {}
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/listings/publish",
        lambda db_path, payload, query, **kw: _v1_publish_listing(db_path, payload),
    ),
RouteEntry(
        {"POST"},
        "/v1/listings/{listing_id}/withdraw",
        lambda db_path, payload, query, listing_id: _v1_withdraw_listing(
            db_path, listing_id, payload
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/listings/{listing_id}/reinstate",
        lambda db_path, payload, query, listing_id: _v1_reinstate_listing(
            db_path, listing_id, payload
        ),
    ),
# ── /v1/discovery（公开发现目录检索：买家 agent，匿名 + 限流）───────────────
RouteEntry(
        {"GET"},
        "/v1/discovery/search",
        lambda db_path, payload, query, **kw: _v1_search_discovery(db_path, query, payload),
    ),
# ── /v1/merchants（token 分发，docs/kiwi-catalog-token-portal-design-v0.1 §4）──
# 顺序约束：/v1/merchants/applications 先于 /v1/merchants/{merchant_id}/rotate
#（_match_path 顺序匹配，全路径正则无参数冲突；method 也不同）。
RouteEntry(
        {"POST"},
        "/v1/merchants/applications",
        lambda db_path, payload, query, **kw: _v1_submit_application(db_path, payload),
    ),
RouteEntry(
        {"GET"},
        "/v1/merchants/applications",
        lambda db_path, payload, query, **kw: _v1_list_applications(db_path, payload, query),
    ),
RouteEntry(
        {"POST"},
        "/v1/merchants/applications/{application_id}/approve",
        lambda db_path, payload, query, application_id: _v1_approve_application(
            db_path, application_id, payload
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/merchants/applications/{application_id}/reject",
        lambda db_path, payload, query, application_id: _v1_reject_application(
            db_path, application_id, payload
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/merchants/{merchant_id}/rotate",
        lambda db_path, payload, query, merchant_id: _v1_rotate_token(
            db_path, merchant_id, payload
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/merchants/{merchant_id}/revoke",
        lambda db_path, payload, query, merchant_id: _v1_revoke_token(
            db_path, merchant_id, payload
        ),
    ),
RouteEntry(
        {"POST"},
        "/v1/merchants/{merchant_id}/discovery-entries",
        lambda db_path, payload, query, merchant_id: _v1_merchant_discovery_entry_create(
            db_path, merchant_id, payload
        ),
    ),
RouteEntry(
        {"GET"},
        "/v1/merchants/{merchant_id}/discovery-entries",
        lambda db_path, payload, query, merchant_id: _v1_merchant_discovery_entries_list(
            db_path, merchant_id, payload
        ),
    ),
RouteEntry(
        {"DELETE"},
        "/v1/merchants/{merchant_id}/discovery-entries/{entry_id}",
        lambda db_path, payload, query, merchant_id, entry_id: _v1_merchant_discovery_entry_delete(
            db_path, merchant_id, entry_id, payload
        ),
    ),
RouteEntry(
        {"GET"},
        "/v1/merchants/self",
        lambda db_path, payload, query, **kw: _v1_merchant_self(db_path, payload, query),
    ),
# ── /v1/accounts（商家账号，docs/accounts.md）───────────────────────────────
RouteEntry(
        {"POST"},
        "/v1/accounts/register",
        lambda db_path, payload, query, **kw: _v1_account_register(db_path, payload),
    ),
RouteEntry(
        {"POST"},
        "/v1/accounts/login",
        lambda db_path, payload, query, **kw: _v1_account_login(db_path, payload),
    ),
RouteEntry(
        {"POST"},
        "/v1/accounts/logout",
        lambda db_path, payload, query, **kw: _v1_account_logout(db_path, payload),
    ),
RouteEntry(
        {"POST"},
        "/v1/accounts/verify-email",
        lambda db_path, payload, query, **kw: _v1_account_verify_email(db_path, payload),
    ),
RouteEntry(
        {"POST"},
        "/v1/accounts/resend-code",
        lambda db_path, payload, query, **kw: _v1_account_resend_code(db_path, payload),
    ),
RouteEntry(
        {"GET"},
        "/v1/accounts/me",
        lambda db_path, payload, query, **kw: _v1_account_me(db_path, payload, query),
    ),
RouteEntry(
        {"POST"},
        "/v1/accounts/token-request",
        lambda db_path, payload, query, **kw: _v1_account_token_request(db_path, payload, query),
    ),
RouteEntry(
        {"POST"},
        "/v1/accounts/profile",
        lambda db_path, payload, query, **kw: _v1_account_profile(db_path, payload),
    ),
# ── /v1/admin（运营 dashboard，docs §dashboard；admin token 保护）────────
RouteEntry(
        {"GET"},
        "/v1/admin/dashboard",
        lambda db_path, payload, query, **kw: _v1_admin_dashboard(db_path, payload, query),
    ),
RouteEntry(
        {"GET"},
        "/v1/admin/merchants",
        lambda db_path, payload, query, **kw: _v1_admin_merchants(db_path, payload, query),
    ),
RouteEntry(
        {"GET"},
        "/v1/admin/merchants/{merchant_id}/report",
        lambda db_path, payload, query, merchant_id: _v1_admin_merchant_report(
            db_path, merchant_id, payload, query
        ),
    ),
RouteEntry(
        {"GET"},
        "/v1/admin/searches",
        lambda db_path, payload, query, **kw: _v1_admin_searches(db_path, payload, query),
    ),
# ── /portal（门户页面，docs §6；fallback 栈渲染 HTML）────────────────────
RouteEntry(
        {"GET"},
        "/portal",
        lambda db_path, payload, query, **kw: _portal_home(),
    ),
RouteEntry(
        {"GET"},
        "/portal/apply",
        lambda db_path, payload, query, **kw: _portal_apply(),
    ),
RouteEntry(
        {"GET"},
        "/portal/admin",
        lambda db_path, payload, query, **kw: _portal_admin(),
    ),
RouteEntry(
        {"GET"},
        "/portal/admin/searches",
        lambda db_path, payload, query, **kw: _portal_admin_searches(),
    ),
RouteEntry(
        {"GET"},
        "/portal/dashboard",
        lambda db_path, payload, query, **kw: _portal_dashboard(),
    ),
RouteEntry(
        {"GET"},
        "/portal/register",
        lambda db_path, payload, query, **kw: _portal_register(),
    ),
RouteEntry(
        {"GET"},
        "/portal/login",
        lambda db_path, payload, query, **kw: _portal_login(),
    ),
RouteEntry(
        {"GET"},
        "/portal/account",
        lambda db_path, payload, query, **kw: _portal_account(),
    ),
RouteEntry(
        {"GET"},
        "/portal/account/profile",
        lambda db_path, payload, query, **kw: _portal_account_profile(),
    ),
RouteEntry(
        {"GET"},
        "/portal/products",
        lambda db_path, payload, query, **kw: _portal_products(),
    ),
)

def _list_catalog_agents(db_path, payload, query):
    return agent_catalog_handlers.list_catalog_agents(db_path, query)


def _search_agent_catalog(db_path, payload, query):
    return agent_catalog_handlers.search_agent_catalog(db_path, query)


def _get_catalog_agent(db_path, catalog_agent_id, payload=None, query=None):
    return agent_catalog_handlers.get_catalog_agent(db_path, catalog_agent_id)


def _list_merchant_catalog_agents(db_path, merchant_id, payload=None, query=None):
    return agent_catalog_handlers.list_merchant_catalog_agents(db_path, merchant_id, query or {})


def _register_catalog_agent(db_path, payload):
    return agent_catalog_handlers.register_catalog_agent(db_path, payload)


def _refresh_catalog_agent(db_path, catalog_agent_id, payload=None, query=None):
    return agent_catalog_handlers.refresh_catalog_agent(db_path, catalog_agent_id, payload or {})


def _verify_catalog_agent(db_path, catalog_agent_id, payload=None, query=None):
    return agent_catalog_handlers.verify_catalog_agent(db_path, catalog_agent_id, payload or {})


def _claim_catalog_agent(db_path, catalog_agent_id, payload=None, query=None):
    return agent_catalog_handlers.claim_catalog_agent(db_path, catalog_agent_id, payload or {})


def _suspend_catalog_agent(db_path, catalog_agent_id, payload=None, query=None):
    return agent_catalog_handlers.suspend_catalog_agent(db_path, catalog_agent_id, payload or {})


def _reinstate_catalog_agent(db_path, catalog_agent_id, payload=None, query=None):
    return agent_catalog_handlers.reinstate_catalog_agent(db_path, catalog_agent_id, payload or {})


def _hosted_agent_card_document(db_path, catalog_agent_id, payload=None, query=None):
    return hosted_publication_handlers.hosted_agent_card(db_path, catalog_agent_id)


def _hosted_ucp_profile_document(db_path, catalog_agent_id, payload=None, query=None):
    return hosted_publication_handlers.hosted_ucp_profile(db_path, catalog_agent_id)


# ── /v1/agents（v0.3 新 API：三正交状态域 record）──────────────────────────


def _v1_list_agents(db_path, payload, query):
    return agent_catalog_handlers.v1_list_agents(db_path, query)


def _v1_search_agents(db_path, payload, query):
    return agent_catalog_handlers.v1_search_agents(db_path, query)


def _v1_get_agent(db_path, catalog_agent_id, payload=None, query=None):
    return agent_catalog_handlers.v1_get_agent(db_path, catalog_agent_id)


def _v1_register_agent(db_path, payload):
    return agent_catalog_handlers.v1_register_agent(db_path, payload)


def _v1_refresh_agent(db_path, catalog_agent_id, payload=None, query=None):
    return agent_catalog_handlers.v1_refresh_agent(db_path, catalog_agent_id, payload or {})


def _v1_verify_agent(db_path, catalog_agent_id, payload=None, query=None):
    return agent_catalog_handlers.v1_verify_agent(db_path, catalog_agent_id, payload or {})


def _v1_claim_agent(db_path, catalog_agent_id, payload=None, query=None):
    return agent_catalog_handlers.v1_claim_agent(db_path, catalog_agent_id, payload or {})


# ── /v1/listings wrapper（v0.4）────────────────────────────────────────────


def _v1_search_listings(db_path, payload, query):
    return listings_handlers.v1_search_listings(db_path, query or {})


def _v1_search_discovery(db_path, query, payload=None):
    merged = dict(query or {})
    # fallback 栈经 payload 透传 _client_ip（限流 per-IP 分桶，审查 P3-06）；
    # FastAPI 栈在路由层直接注入 query。
    client_ip = str((payload or {}).get("_client_ip") or "").strip()
    if client_ip:
        merged["_client_ip"] = client_ip
    return discovery_entries_handlers.search_discovery(db_path, merged)


# ── /v1/merchants wrapper（token 分发）────────────────────────────────────


def _v1_submit_application(db_path, payload):
    return merchants_handlers.submit_application(db_path, payload)


def _v1_list_applications(db_path, payload, query):
    return merchants_handlers.list_applications(db_path, payload, query or {})


def _v1_approve_application(db_path, application_id, payload):
    return merchants_handlers.approve_application(db_path, application_id, payload)


def _v1_reject_application(db_path, application_id, payload):
    return merchants_handlers.reject_application(db_path, application_id, payload)


def _v1_rotate_token(db_path, merchant_id, payload):
    return merchants_handlers.rotate_token(db_path, merchant_id, payload)


def _v1_revoke_token(db_path, merchant_id, payload):
    return merchants_handlers.revoke_token(db_path, merchant_id, payload)


def _v1_merchant_discovery_entry_create(db_path, merchant_id, payload):
    return discovery_entries_handlers.create_entry(db_path, merchant_id, payload)


def _v1_merchant_discovery_entries_list(db_path, merchant_id, payload):
    return discovery_entries_handlers.list_entries(db_path, merchant_id, payload)


def _v1_merchant_discovery_entry_delete(db_path, merchant_id, entry_id, payload):
    return discovery_entries_handlers.delete_entry(db_path, merchant_id, entry_id, payload)


def _v1_merchant_self(db_path, payload, query):
    return merchants_handlers.self_status(db_path, payload, query or {})


# ── /v1/accounts wrapper（商家账号）──────────────────────────────────────


def _v1_account_register(db_path, payload):
    return accounts_handlers.register(db_path, payload)


def _v1_account_login(db_path, payload):
    return accounts_handlers.login(db_path, payload)


def _v1_account_logout(db_path, payload):
    return accounts_handlers.logout(db_path, payload)


def _v1_account_verify_email(db_path, payload):
    return accounts_handlers.verify_email(db_path, payload)


def _v1_account_resend_code(db_path, payload):
    return accounts_handlers.resend_code(db_path, payload)


def _v1_account_me(db_path, payload, query):
    return accounts_handlers.me(db_path, payload, query or {})


def _v1_account_token_request(db_path, payload, query):
    return accounts_handlers.token_request(db_path, payload, query or {})


def _v1_account_profile(db_path, payload):
    return accounts_handlers.profile(db_path, payload)


# ── /v1/admin wrapper（运营 dashboard）────────────────────────────────────


def _v1_admin_dashboard(db_path, payload, query):
    return admin_handlers.dashboard(db_path, payload, query or {})


def _v1_admin_merchants(db_path, payload, query):
    return admin_handlers.merchant_list(db_path, payload, query or {})


def _v1_admin_merchant_report(db_path, merchant_id, payload, query):
    return admin_handlers.merchant_report(db_path, merchant_id, payload, query or {})


def _v1_admin_searches(db_path, payload, query):
    return admin_handlers.search_events(db_path, payload, query or {})


# ── /portal wrapper（门户页面）────────────────────────────────────────────


def _portal_home():
    return portal_handlers.portal_home()


def _portal_apply():
    return portal_handlers.portal_apply()


def _portal_admin():
    return portal_handlers.portal_admin()


def _portal_admin_searches():
    return portal_handlers.portal_admin_searches()


def _portal_dashboard():
    return portal_handlers.portal_dashboard()


def _portal_register():
    return portal_handlers.portal_register()


def _portal_login():
    return portal_handlers.portal_login()


def _portal_account():
    return portal_handlers.portal_account()


def _portal_account_profile():
    return portal_handlers.portal_account_profile()


def _portal_products():
    return portal_handlers.portal_products()


def _v1_get_listing(db_path, listing_id, payload=None, query=None):
    return listings_handlers.v1_get_listing(db_path, listing_id)


def _v1_list_agent_listings(db_path, catalog_agent_id, query, auth_payload=None):
    return listings_handlers.v1_list_agent_listings(
        db_path, catalog_agent_id, query, auth_payload or {}
    )


def _v1_publish_listing(db_path, payload):
    return listings_handlers.v1_publish_listing(db_path, payload)


def _v1_withdraw_listing(db_path, listing_id, payload=None, query=None):
    return listings_handlers.v1_withdraw_listing(db_path, listing_id, payload or {})


def _v1_reinstate_listing(db_path, listing_id, payload=None, query=None):
    return listings_handlers.v1_reinstate_listing(db_path, listing_id, payload or {})


def resolve_route(
    method: str, path: str, routes: tuple[RouteEntry, ...] | list[Any] | None = None
) -> tuple[bool, bool]:
    """Return (path_known, method_allowed) without parsing the request body."""
    table = _ROUTE_TABLE if routes is None else tuple(routes)
    path_known = False
    for route in table:
        template = getattr(route, "path_template", None) or getattr(route, "path", "")
        # 动态 route 模板严格收窄为 str；非 str（异常值）fail-closed：不视为匹配，
        # 绝不把 Any/None 强转成可能错误的字符串去匹配。
        if not isinstance(template, str):
            continue
        if _match_path(template, path) is None:
            continue
        path_known = True
        if method.upper() in route.methods:
            return True, True
    return path_known, False
