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

"""目录托管的公开商家主页（无外部 shop_url 的商家也能被打开）。

页面只读、匿名可访问，数据全部来自既有公开投影：

- ``merchant_publications``：published 且未过期的商家公开资料（商家声明）；
- ``commerce_listings``：``publication_state='ACTIVE'`` 的已发布商品。

不展示注册账号、联系人、凭据、分享码、门面密文或任何私有表字段；外部店铺
链接与文本内链接统一经 ``merchant_publications`` 的读侧白名单（普通商品
链接保留，WorkBuddy/分享码/Agent 端点拒绝）。页面无可公开内容时 404，不给
空壳主页。
"""

from __future__ import annotations

import html
import json
import sqlite3
from pathlib import Path
from typing import Any

from kiwi_catalog.core.errors import NotFoundError, ValidationError
from kiwi_catalog.db.session import db_session, now_iso
from kiwi_catalog.services import merchant_publications as publications_service

_MAX_PRODUCTS = 50
_MAX_LISTINGS = 50


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _public_listings(
    conn: sqlite3.Connection,
    merchant_id: str,
    *,
    limit: int = _MAX_LISTINGS,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], bool]:
    from kiwi_catalog.listings.quarantine import public_visible_rows
    from kiwi_catalog.listings.sqlite_repository import _row_to_listing

    safe_limit = max(1, min(int(limit), 100))
    safe_offset = max(0, int(offset))
    # 多取 1 行只用于判断“是否还有下一页”，**不参与本页投影**：否则第
    # 51 条（下一页的第一条）会被补进本页、又在下一页重复。先按原始行边界
    # 截断到 safe_limit，再做纯读过滤；过滤后空页由调用方渲染“下一页”。
    rows = conn.execute(
        "select * from commerce_listings"
        " where merchant_id = ? and publication_state = 'ACTIVE'"
        " and coalesce(governance_hold, 0) = 0"
        " and not exists (select 1 from catalog_agents ca"
        "   where ca.catalog_agent_id = commerce_listings.owner_agent_id"
        "   and ca.administrative_state in ('suspended','rejected'))"
        " order by updated_at desc, id desc limit ? offset ?",
        (merchant_id, safe_limit + 1, safe_offset),
    ).fetchall()
    has_more = len(rows) > safe_limit
    rows = rows[:safe_limit]
    decoded = [_row_to_listing(row) for row in rows]
    # 纯读过滤：不写 publication_state/governance_hold；危险行只在本次
    # 公开主页响应里隐藏。offset 按原始行前进（不跳过、不重复）。
    visible = public_visible_rows(decoded)
    return visible[:safe_limit], has_more


def _merchant_name(conn: sqlite3.Connection, merchant_id: str) -> str:
    row = conn.execute(
        "select name from merchants where id = ?", (merchant_id,)
    ).fetchone()
    return str(row["name"] or "") if row is not None else ""


def _published_profile(
    conn: sqlite3.Connection, merchant_id: str
) -> dict[str, Any] | None:
    """已发布商家名片里的公开简介（仅 name/description/skills，不含服务地址）。"""
    row = conn.execute(
        "select ca.display_name, v.canonical_bytes"
        " from catalog_agents ca"
        " join card_publications cp on cp.catalog_agent_id = ca.catalog_agent_id"
        " join agent_card_versions v on v.catalog_agent_id = ca.catalog_agent_id"
        "   and v.card_revision = cp.active_revision"
        " where ca.merchant_id = ?"
        " and cp.publication_state in ('ACTIVE','PAUSED')"
        " and ca.administrative_state = 'active'"
        " order by ca.updated_at desc limit 1",
        (merchant_id,),
    ).fetchone()
    if row is None:
        return None
    try:
        card = json.loads(str(row["canonical_bytes"] or "{}"))
    except (TypeError, ValueError):
        card = {}
    if not isinstance(card, dict):
        card = {}
    from kiwi_catalog.a2a.card_store import card_contains_share_code

    if card_contains_share_code(card):
        # 已签名名片不能读侧原地清洗；污染版本由公开读隔离，主页不投影。
        return None
    display_name = publications_service.redact_public_text(
        str(card.get("name") or row["display_name"] or "")
    )
    description = publications_service.redact_public_text(
        str(card.get("description") or "")
    )
    skills: list[str] = []
    for item in card.get("skills") or []:
        if isinstance(item, dict):
            label = item.get("name") or item.get("id")
        else:
            label = item
        if label:
            skills.append(publications_service.redact_public_text(str(label)))
    if not display_name and not description and not skills:
        return None
    return {"name": display_name, "description": description, "skills": skills}


def _product_card(publication: dict[str, Any]) -> str:
    faq = publication.get("faq") or []
    faq_html = ""
    if faq:
        items = "".join(
            "<details><summary>"
            + _esc(item.get("question"))
            + "</summary><p>"
            + _esc(item.get("answer"))
            + "</p></details>"
            for item in faq
        )
        faq_html = f'<div class="faq">{items}</div>'
    shop_url = str(publication.get("shop_url") or "")
    shop_link = (
        f'<a class="shop-link" href="{_esc(shop_url)}" target="_blank"'
        ' rel="noopener noreferrer nofollow">访问商家店铺</a>'
        if shop_url
        else ""
    )
    meta = " · ".join(
        part
        for part in (
            _esc(publication.get("category")),
            _esc(publication.get("shop_platform")),
        )
        if part
    )
    return (
        '<article class="product">'
        f'<h3>{_esc(publication.get("title"))}</h3>'
        + (f'<p class="meta">{meta}</p>' if meta else "")
        + (
            f'<p>{_esc(publication.get("summary"))}</p>'
            if str(publication.get("summary") or "")
            else ""
        )
        + faq_html
        + shop_link
        + "</article>"
    )


def _listing_card(listing: dict[str, Any]) -> str:
    title = publications_service.redact_public_text(str(listing.get("title") or ""))
    category = publications_service.redact_public_text(str(listing.get("category") or ""))
    summary = publications_service.redact_public_text(str(listing.get("summary") or ""))
    brand = publications_service.redact_public_text(str(listing.get("brand") or ""))
    meta = " · ".join(part for part in (_esc(category), _esc(brand)) if part)
    return (
        '<article class="product">'
        f"<h3>{_esc(title)}</h3>"
        + (f'<p class="meta">{meta}</p>' if meta else "")
        + (f"<p>{_esc(summary)}</p>" if summary else "")
        + "</article>"
    )


def _render_home(
    *,
    merchant_id: str,
    display_name: str,
    home_url: str,
    profile: dict[str, Any] | None,
    publications: list[dict[str, Any]],
    listings: list[dict[str, Any]],
    page: int = 1,
    has_next: bool = False,
) -> str:
    merchant_name = publications_service.redact_public_text(display_name) or "商家"
    cards = [_product_card(item) for item in publications]
    cards.extend(_listing_card(item) for item in listings)
    products = "".join(cards) or '<p class="muted">商家暂未发布公开商品。</p>'
    pager_links: list[str] = []
    if page > 1:
        pager_links.append(
            f'<a class="pager-link" rel="prev" href="?page={page - 1}">上一页</a>'
        )
    if has_next:
        pager_links.append(
            f'<a class="pager-link" rel="next" href="?page={page + 1}">下一页</a>'
        )
    pager = f'<nav class="pager">{"".join(pager_links)}</nav>' if pager_links else ""
    profile_html = ""
    if profile and (profile.get("description") or profile.get("skills")):
        services = "、".join(_esc(item) for item in profile.get("skills") or [])
        profile_html = (
            '<section class="profile"><h2>商家介绍</h2>'
            + (
                f'<p>{_esc(profile.get("description"))}</p>'
                if profile.get("description")
                else ""
            )
            + (f'<p class="meta">提供的服务：{services}</p>' if services else "")
            + "</section>"
        )
    return (
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        f'<link rel="canonical" href="{_esc(home_url)}">'
        f"<title>{_esc(merchant_name)} · Kiwi 商家主页</title>"
        "<style>"
        ":root{--ink:#1a1f1a;--muted:#5b655b;--line:#dde5dd;--green:#1b5e20;"
        "--soft:#f6f8f6}*{box-sizing:border-box}body{margin:0;font-family:system-ui,"
        "-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;color:var(--ink);"
        "line-height:1.65;background:#fff}header{background:var(--green);color:#fff;"
        "padding:44px 20px}header .inner,main,footer .inner{max-width:860px;margin:0 auto}"
        ".kicker{font-size:.8rem;letter-spacing:.08em;text-transform:uppercase;opacity:.85}"
        "h1{margin:8px 0 6px;font-size:clamp(1.8rem,4vw,2.6rem);line-height:1.15}"
        ".lead{margin:0;color:rgba(255,255,255,.88)}main{padding:32px 20px 48px}"
        "h2{font-size:1.25rem;margin:0 0 14px}.profile{margin:0 0 26px;"
        "padding-bottom:18px;border-bottom:1px solid var(--line)}"
        ".profile p{margin:6px 0;color:#39423a}.product{border:1px solid var(--line);"
        "border-radius:14px;padding:20px;margin:0 0 14px;background:#fff}"
        ".product h3{margin:0 0 6px;font-size:1.1rem}.meta{color:var(--muted);"
        "font-size:.86rem;margin:0 0 8px}.product p{margin:6px 0;color:#39423a}"
        ".shop-link{display:inline-block;margin-top:10px;color:var(--green);"
        "font-weight:600}.faq{margin-top:10px;border-top:1px dashed var(--line);"
        "padding-top:10px}.faq summary{cursor:pointer;font-weight:600}"
        ".faq p{color:var(--muted)}.muted{color:var(--muted)}footer{border-top:1px solid "
        "var(--line);background:var(--soft);padding:22px 20px;color:var(--muted);"
        "font-size:.9rem}.pager{display:flex;gap:12px;margin:18px 0 4px}"
        ".pager-link{display:inline-block;padding:8px 14px;border:1px solid var(--line);"
        "border-radius:10px;color:var(--green);font-weight:600}"
        "code{font-family:ui-monospace,Menlo,monospace}"
        "</style></head><body>"
        '<header><div class="inner"><div class="kicker">Kiwi 目录</div>'
        f"<h1>{_esc(merchant_name)}</h1>"
        '<p class="lead">商家公开主页 · 只展示商家已公开发布的资料与商品</p>'
        "</div></header><main>"
        f"{profile_html}"
        "<h2>已发布商品</h2>"
        f"{products}"
        f"{pager}"
        "</main><footer><div class=\"inner\">"
        "本页由 Kiwi 目录根据商家已公开的资料生成，不代表 Kiwi 对商家的背书；"
        "不展示联系人、账号、凭据或分享码。"
        f'<br><span class="muted">商家标识：<code>{_esc(merchant_id)}</code></span>'
        "</div></footer></body></html>"
    )


def public_merchant_home(
    db_path: str | Path,
    merchant_id: str,
    payload: dict[str, Any] | None = None,
    query: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """GET /m/{merchant_id}（匿名公开）——目录托管的商家主页。

    匿名读按客户端 IP 限流；``?page=N`` 让超过单页 50 件的商家内容仍可访问。
    """
    merchant_id = str(merchant_id or "").strip()
    if not merchant_id:
        raise ValidationError("merchant_id is required")
    raw_page = str((query or {}).get("page") or "1").strip() or "1"
    try:
        page = int(raw_page)
    except (TypeError, ValueError) as exc:
        raise ValidationError("page must be an integer") from exc
    if page < 1:
        raise ValidationError("page must be >= 1")
    page_size = _MAX_PRODUCTS
    offset = (page - 1) * page_size
    with db_session(db_path) as conn:
        from kiwi_catalog.a2a.public_read_limit import enforce_public_read_limit

        enforce_public_read_limit(conn, payload, surface="merchant home")
        # 解除连接后旧应用留下的内容不再对外展示：没有活动绑定时主页整体
        # 404，不再通过直链暴露旧商品/旧名片。
        if not publications_service.merchant_has_active_binding(conn, merchant_id):
            raise NotFoundError(f"Unknown merchant page: {merchant_id}")
        now = now_iso()
        # 多取一条判断是否还有下一页；展示仍严格限制在 50 件/页。
        publications = publications_service.list_public_publications(
            conn, merchant_id, now=now, limit=page_size + 1, offset=offset
        )
        listings, listings_more = _public_listings(
            conn, merchant_id, limit=page_size, offset=offset
        )
        has_next = (
            len(publications) > page_size
            or len(listings) > page_size
            or listings_more
        )
        publications = publications[:page_size]
        listings = listings[:page_size]
        # 商家介绍只在第一页重复展示，避免翻页时冗余。
        profile = _published_profile(conn, merchant_id) if page == 1 else None
        if not publications and not listings and profile is None and not has_next:
            raise NotFoundError(f"Unknown merchant page: {merchant_id}")
        display_name = (
            str(publications[0].get("merchant_display_name") or "")
            if publications
            else (
                str((profile or {}).get("name") or "")
                or _merchant_name(conn, merchant_id)
            )
        )
        home_url = publications_service.public_merchant_home_url(merchant_id)
        page_html = _render_home(
            merchant_id=merchant_id,
            display_name=display_name,
            home_url=home_url,
            profile=profile,
            publications=[
                publications_service.public_projection(item) for item in publications
            ],
            listings=listings,
            page=page,
            has_next=has_next,
        )
        return {"__html__": page_html}
