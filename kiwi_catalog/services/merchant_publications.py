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

"""商家公开资料（M0 工作包 A，kiwi 仓 merchant-buddy 第 0 版设计 §4）。

已验证商家账号**会话**（非 owner token）发布的 public-only 声明快照：

- 状态域：draft（私有草稿）→ published（公开可搜）→ withdrawn（撤回，终态）；
- ``source_kind`` 恒为 ``merchant_declared``——商家声明内容，不是 Kiwi 背书；
- public-only 白名单：注册账户的电话/邮箱/凭据绝不进入公开投影；写入侧对
  公开字段做私密字段扫描（明显的邮箱/手机号模式直接拒绝 + 审计）；
- 幂等：同一商家同名商品的重复发布更新 published 行；草稿单独保存，不能
  覆盖当前 published 快照；部分唯一索引数据层兜底；
- 不产生虚假能力：无 Agent Card、无 A2A 端点、无实时报价——搜索/详情投影
  恒带 ``inquiry_available=false``（第 1 版商家走既有 Agent/Listing 链路）。
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import sqlite3
import urllib.parse
from datetime import UTC, datetime
from typing import Any

from kiwi_catalog.core.errors import NotFoundError, ValidationError
from kiwi_catalog.db.session import decode_json, encode_json, now_iso
from kiwi_catalog.services import merchant_public_events as events_service

SOURCE_KIND = "merchant_declared"
STATUSES = ("draft", "published", "withdrawn")

# ── 内容长度上限（公开资料是声明快照，不是全文商品库）────────────────────
_MAX_DISPLAY_NAME = 200
_MAX_TITLE = 200
_MAX_CATEGORY = 100
_MAX_PLATFORM = 100
_MAX_SHOP_URL = 500
_MAX_SUMMARY = 2000
_MAX_FAQ_ITEMS = 20
_MAX_FAQ_QUESTION = 300
_MAX_FAQ_ANSWER = 1000

# ── 私密字段扫描（写入侧 fail-closed）────────────────────────────────────
# 至少拒绝明显的邮箱/手机号模式进入公开字段（注册账户的联系方式不得经商家
# 误填进入公开投影）。扫描对象：display_name/title/category/summary/faq。
_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
_CN_MOBILE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
_INTL_PHONE_RE = re.compile(r"\+\d[\d\s\-()]{7,}\d")

_PUBLIC_TEXT_FIELDS = (
    "merchant_display_name",
    "title",
    "category",
    "summary",
    "shop_platform",
)

# 公开文本里出现的 http(s) 链接也要过与 shop_url 同一套公开放行规则：
# 普通商品/店铺链接保留，WorkBuddy 门禁链接、Agent 端点与分享码 URL 拒绝。
_TEXT_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_URL_TRAILING_PUNCTUATION = ".,;:!?)]}，。；：！？）》】\"'"

#: 分享码参数/路径段的统一识别：大小写不敏感，兼容 ``sharecode`` /
#: ``share_code`` / ``share-code`` / ``ShareCode``。判定只看解码后的
#: path/query/fragment（不看主机名），避免把普通域名误判成门禁链接。
_SHARE_CODE_RE = re.compile(r"share[-_]?code", re.IGNORECASE)
#: 百分号编码最多解开这么多层。攻击者可以叠很多层，但解析必须是**有界**的；
#: 5 层覆盖 `%252573harecode` 等常见叠编码绕过，又不引入解码炸弹。
_MAX_PERCENT_DECODE_ROUNDS = 5
#: 单次解码输入/中间值的长度上限。超限按危险处理（fail-closed），避免
#: 超长文本被反复 unquote 拖垮读路径。
_MAX_PERCENT_DECODE_LENGTH = 65_536
#: 文本/URL 判定的总长度上限。超限按危险处理，避免对超大字符串反复做
#: urlsplit/regex/unquote；正常公开字段远小于此值。
_MAX_SHARE_CODE_TEXT_LENGTH = 262_144


def _decode_percent_bounded(
    value: str, rounds: int = _MAX_PERCENT_DECODE_ROUNDS
) -> tuple[str, bool]:
    """有界重复百分号解码 → (文本, 是否仍未解尽/超限)。

    达到层数上限后还会再探测一次：如果仍能继续解码，返回 ``exhausted=True``
    （调用方必须 fail-closed），而不是把半解码文本当安全输入。只做
    ``unquote``（不是 ``unquote_plus``）：query 里的 ``+`` 是否代表空格由
    调用方按各自语义处理，分享码判定只关心参数名。
    """
    current = str(value or "")
    if len(current) > _MAX_PERCENT_DECODE_LENGTH:
        return "", True
    for _ in range(max(0, rounds)):
        try:
            decoded = urllib.parse.unquote(current)
        except (TypeError, ValueError):
            return "", True
        if decoded == current:
            return current, False
        current = decoded
        if len(current) > _MAX_PERCENT_DECODE_LENGTH:
            return "", True
    try:
        still_decodable = urllib.parse.unquote(current)
    except (TypeError, ValueError):
        return "", True
    if still_decodable != current:
        # 超过层数上限仍可继续解码：不能猜剩余内容是否含分享码，直接危险。
        return current, True
    return current, False


def _url_has_share_code(raw: str) -> bool:
    """URL 的 path/query/fragment 中是否出现分享码（含重复编码/嵌套 URL）。"""
    try:
        parsed = urllib.parse.urlsplit(str(raw or ""))
    except ValueError:
        return True
    for component in (parsed.path, parsed.query, parsed.fragment):
        decoded, exhausted = _decode_percent_bounded(component)
        if exhausted or _SHARE_CODE_RE.search(decoded):
            return True
    return False


def contains_share_code_payload(value: Any) -> bool:
    """递归判断任意 JSON 值里是否含分享码 URL（用于已签名/摘要记录隔离）。"""
    if isinstance(value, dict):
        return any(contains_share_code_payload(item) for item in value.values())
    if isinstance(value, list):
        return any(contains_share_code_payload(item) for item in value)
    if isinstance(value, str):
        return contains_share_code_link(value)
    return False


def _public_text_pairs(canonical: dict[str, Any]) -> list[tuple[str, str]]:
    texts: list[tuple[str, str]] = [
        (field, str(canonical.get(field) or "")) for field in _PUBLIC_TEXT_FIELDS
    ]
    for i, item in enumerate(canonical.get("faq") or []):
        texts.append((f"faq[{i}].question", str(item.get("question") or "")))
        texts.append((f"faq[{i}].answer", str(item.get("answer") or "")))
    return texts


def _text_urls(text: str) -> list[str]:
    """抽取文本中的 http(s) 链接（去掉句末标点，避免把中文标点算进 URL）。"""
    urls: list[str] = []
    for match in _TEXT_URL_RE.finditer(str(text or "")):
        raw = match.group(0)
        while raw and raw[-1] in _URL_TRAILING_PUNCTUATION:
            raw = raw[:-1]
        if raw:
            urls.append(raw)
    return urls


def _redact_unsafe_text_links(text: str) -> str:
    """历史数据兜底：把公开文本里不安全的链接替换为固定占位符。"""

    def _replace(match: re.Match[str]) -> str:
        raw = match.group(0)
        trailing = ""
        while raw and raw[-1] in _URL_TRAILING_PUNCTUATION:
            trailing = raw[-1] + trailing
            raw = raw[:-1]
        if not raw or safe_public_shop_url(raw):
            return match.group(0)
        return "[链接已移除]" + trailing

    return _TEXT_URL_RE.sub(_replace, str(text or ""))


def scan_unsafe_public_links(canonical: dict[str, Any]) -> list[str]:
    """返回公开文本中出现的不安全链接所在字段（空 = 通过）。"""
    hits: list[str] = []
    for label, text in _public_text_pairs(canonical):
        if any(not safe_public_shop_url(url) for url in _text_urls(text)):
            hits.append(label)
    return hits


def redact_public_text(text: str) -> str:
    """公开投影读侧兜底：移除不安全链接与明显的联系方式，普通商品链接保持原样。"""
    redacted = _redact_unsafe_text_links(text)
    redacted = _EMAIL_RE.sub("[已隐藏]", redacted)
    redacted = _CN_MOBILE_RE.sub("[已隐藏]", redacted)
    redacted = _INTL_PHONE_RE.sub("[已隐藏]", redacted)
    return redacted


def sanitize_public_payload(payload: Any) -> Any:
    """递归清理历史公开事件 payload：shop_url 与文本里的危险链接一律不投影。"""
    if isinstance(payload, dict):
        cleaned: dict[str, Any] = {}
        for key, value in payload.items():
            if key == "shop_url":
                cleaned[key] = safe_public_shop_url(str(value or ""))
            elif key in {"question", "answer"} and isinstance(value, str):
                cleaned[key] = redact_public_text(value)
            elif isinstance(value, str) and key in _PUBLIC_TEXT_FIELDS:
                cleaned[key] = redact_public_text(value)
            else:
                cleaned[key] = sanitize_public_payload(value)
        return cleaned
    if isinstance(payload, list):
        return [sanitize_public_payload(item) for item in payload]
    if isinstance(payload, str):
        return _redact_share_code_text(payload)
    return payload


def new_publication_id() -> str:
    return "mpub_" + secrets.token_urlsafe(12)


def scan_private_fields(canonical: dict[str, Any]) -> list[str]:
    """返回命中私密模式的字段名列表（空 = 通过）。"""
    hits: list[str] = []
    for label, text in _public_text_pairs(canonical):
        if _EMAIL_RE.search(text) or _CN_MOBILE_RE.search(text) or _INTL_PHONE_RE.search(text):
            hits.append(label)
    return hits


def validate_shop_url(raw: str) -> str:
    """公开店铺链接安全校验：仅 http/https；拒绝内网/环回/保留地址字面量。

    空串合法（选填）。host 为 IP 字面量时必须全局可路由；域名不解析
    （写路径不做网络 IO）——长度与 scheme/字符集约束兜底。
    """
    url = str(raw or "").strip()
    if not url:
        return ""
    if len(url) > _MAX_SHOP_URL:
        raise ValidationError("shop_url too long")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValidationError("shop_url must be an http or https URL")
    host = parsed.hostname or ""
    if not host:
        raise ValidationError("shop_url must include a host")
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        ip = None
    if ip is not None and not ip.is_global:
        raise ValidationError("shop_url must not point to a private or internal address")
    return url


#: 商家公开店铺页不接受这些地址：它们不是「商家自己的外部公开店铺页」。
#: WorkBuddy 的 ``*.workbuddy.host`` 是商家服务/门禁入口，不是店铺页；目录
#: 自身 base（含 hosted A2A）也不是公开商家页；``/a2a`` 与 well-known 是
#: Agent 服务端点。分享码参数/路径段则可能是门禁凭据，不能当公开链接。
_WORKBUDDY_HOST_SUFFIXES = (".workbuddy.host", ".workbuddy.cn")
_WORKBUDDY_HOSTS = ("workbuddy.host", "workbuddy.cn")
#: 平台官网/目录域：不是某个商家的公开店铺页。目录 API 基址另由 env 提供。
_FIRST_PARTY_HOST_SUFFIXES = (".kiwi.harrylabsj.com",)
_FIRST_PARTY_HOSTS = ("kiwi.harrylabsj.com",)
_DIRECTORY_BASE_ENVS = (
    "KIWI_CATALOG_PUBLIC_BASE_URL",
    "SHOPPING_PUBLIC_BASE_URL",
    "KIWI_CATALOG_HOSTED_A2A_BASE_URL",
    "SHOPPING_HOSTED_A2A_BASE_URL",
)
_SHARE_CODE_PARAM_NAMES = frozenset({"sharecode", "share_code", "share-code"})
_AGENT_PATH_PREFIXES = ("/a2a", "/.well-known/")


def _directory_hosts() -> frozenset[str]:
    """部署配置里的目录/托管基址主机名（大小写不敏感）。"""
    hosts: set[str] = set()
    for env_name in _DIRECTORY_BASE_ENVS:
        raw = str(os.environ.get(env_name) or "").strip()
        if not raw:
            continue
        try:
            host = urllib.parse.urlsplit(raw).hostname
        except ValueError:
            continue
        if host:
            hosts.add(host.lower().rstrip("."))
    return frozenset(hosts)


def _is_workbuddy_host(host: str) -> bool:
    return host in _WORKBUDDY_HOSTS or any(
        host.endswith(suffix) for suffix in _WORKBUDDY_HOST_SUFFIXES
    )


def _is_first_party_host(host: str) -> bool:
    return host in _FIRST_PARTY_HOSTS or any(
        host.endswith(suffix) for suffix in _FIRST_PARTY_HOST_SUFFIXES
    )


def _url_key(raw: str) -> tuple[str, str, str, str, str] | None:
    """归一化 URL 供「是否等于服务地址」精确比较（大小写 host、空 path）。"""
    try:
        parsed = urllib.parse.urlsplit(str(raw or ""))
    except ValueError:
        return None
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    netloc = parsed.hostname.lower().rstrip(".")
    if port is not None:
        netloc = f"{netloc}:{port}"
    return (parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, parsed.fragment)


def safe_public_shop_url(
    raw: str, *, blocked_urls: tuple[str, ...] | list[str] = ()
) -> str:
    """公开店铺页链接的读侧准入（空串 = 不提供跳转）。

    只允许 http(s) 外部页面；拒绝内网 IP、userinfo、控制字符，以及：
    - WorkBuddy 主机（``*.workbuddy.host``）与配置里的目录/托管基址主机；
    - 路径以 ``/a2a`` 或 ``/.well-known/`` 开头的 Agent 服务端点；
    - 路径段/查询串/片段里的 ``sharecode`` 等门禁参数；
    - 与 ``blocked_urls`` 完全相同的地址（服务地址/卡片地址不能当店铺页）。
    """
    try:
        url = validate_shop_url(raw)
    except (ValidationError, ValueError):
        return ""
    if not url:
        return ""
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return ""
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return ""
    if parsed.username or parsed.password:
        return ""
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in url):
        return ""
    host = parsed.hostname.lower().rstrip(".")
    if (
        _is_workbuddy_host(host)
        or _is_first_party_host(host)
        or host in _directory_hosts()
    ):
        return ""
    # 分享码判定在 path/query/fragment 上做**有界重复解码**：覆盖
    # `%2573harecode`、`?next=https%3A%2F%2F…%3Fsharecode%3D…`、片段与大小写。
    if _url_has_share_code(url):
        return ""
    path, path_exhausted = _decode_percent_bounded(parsed.path or "/")
    if path_exhausted or path.startswith(_AGENT_PATH_PREFIXES):
        return ""
    for segment in path.split("/"):
        if not segment:
            continue
        decoded_segment, segment_exhausted = _decode_percent_bounded(segment)
        if segment_exhausted or decoded_segment.lower() in {
            "a2a",
            *_SHARE_CODE_PARAM_NAMES,
        }:
            return ""
    for component in (parsed.query, parsed.fragment):
        for name, _value in urllib.parse.parse_qsl(component, keep_blank_values=True):
            decoded_name, name_exhausted = _decode_percent_bounded(name)
            if name_exhausted or decoded_name.lower() in _SHARE_CODE_PARAM_NAMES:
                return ""
        # 兜底：非标准分隔符形态（如 `;sharecode=`）也不能绕过。
        decoded_component, component_exhausted = _decode_percent_bounded(component)
        if component_exhausted or _SHARE_CODE_RE.search(decoded_component.lower()):
            return ""
    key = _url_key(url)
    if key is None:
        return ""
    for blocked in blocked_urls:
        if blocked and _url_key(str(blocked)) == key:
            return ""
    return url


def contains_share_code_url(value: str) -> bool:
    """URL 是否携带分享码参数/路径段或 userinfo/控制字符。

    用于服务地址这类**允许 WorkBuddy 主机**、但不允许把门禁凭据或 HTTP
    凭据拼进 URL 的字段；普通商品/服务链接不命中。
    """
    raw = str(value or "").strip()
    if not raw or not raw.lower().startswith(("http://", "https://")):
        return False
    if len(raw) > _MAX_SHARE_CODE_TEXT_LENGTH:
        return True
    try:
        parsed = urllib.parse.urlsplit(raw)
    except ValueError:
        return True  # 不可解析的 URL 按危险处理
    if parsed.username or parsed.password:
        return True
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw):
        return True
    # 有界重复解码 + path/query/fragment 全扫：重复编码、嵌套 URL（编码后的
    # 第二个 `?sharecode=`）、片段与任意大小写都在这里收敛。
    return _url_has_share_code(raw)


def contains_share_code_link(text: str) -> bool:
    """文本（含纯 URL）里是否出现携带分享码的 http(s) 链接。"""
    raw = str(text or "")
    if len(raw) > _MAX_SHARE_CODE_TEXT_LENGTH:
        return True
    return contains_share_code_url(raw) or any(
        contains_share_code_url(url) for url in _text_urls(raw)
    )


def _redact_share_code_text(text: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        return "[链接已移除]" if contains_share_code_url(match.group(0)) else match.group(0)

    return _TEXT_URL_RE.sub(_replace, str(text or ""))


def sanitize_share_code_urls(value: Any) -> Any:
    """递归移除携带分享码的 http(s) 链接（保留普通 URL/文本原样）。

    纯 URL 字段清空（保留字段形状）；文本里嵌的门禁链接替换为固定占位符。
    仅用于**非签名/非摘要**的历史公开投影（商家公开资料、事件 payload）；
    已签名名片与 listing digest 记录改用隔离，绝不原地改写。
    """
    if isinstance(value, dict):
        return {key: sanitize_share_code_urls(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_share_code_urls(item) for item in value]
    if isinstance(value, str):
        if contains_share_code_url(value):
            return ""
        return _redact_share_code_text(value)
    return value


# 兼容旧调用名（名片读侧）；语义与 sanitize_share_code_urls 相同。
sanitize_public_card_urls = sanitize_share_code_urls


def latest_public_shop_url(
    conn: sqlite3.Connection,
    merchant_id: str,
    *,
    now: str | None = None,
    blocked_urls: tuple[str, ...] | list[str] = (),
) -> str:
    """最新一条**公开可见**商家资料里的店铺链接（无则空串）。

    这是目录现有数据里唯一能指向「商家自己的公开店铺页」的字段：
    ``merchant_publications.shop_url`` 由商家在公开资料中填写，写入侧已做
    scheme/内网地址校验，搜索/详情也把它作为公开字段投影。读取侧再兜一层：
    只取 published 且未过期的行，并复核 scheme、userinfo、控制字符、WorkBuddy/
    目录主机、Agent 端点与分享码参数，避免旧数据或手工写库把危险 URL 带进
    门户链接。目录自身不托管该页面。
    """
    merchant_id = str(merchant_id or "").strip()
    if not merchant_id:
        return ""
    row = conn.execute(
        "select shop_url from merchant_publications"
        " where merchant_id = ? and status = 'published' and shop_url != ''"
        " and (expires_at = '' or expires_at > ?)"
        " order by updated_at desc, publication_id desc limit 1",
        (merchant_id, now or now_iso()),
    ).fetchone()
    if row is None:
        return ""
    return safe_public_shop_url(str(row["shop_url"] or ""), blocked_urls=blocked_urls)


_PUBLIC_PAGE_BASE_ENVS = (
    "KIWI_CATALOG_PUBLIC_BASE_URL",
    "SHOPPING_PUBLIC_BASE_URL",
    "KIWI_CATALOG_HOSTED_A2A_BASE_URL",
    "SHOPPING_HOSTED_A2A_BASE_URL",
)
_PUBLIC_MERCHANT_PATH = "/m/"


def public_page_base_url() -> str:
    """目录公开页面基址（本地开发回退 http://localhost）。"""
    for env_name in _PUBLIC_PAGE_BASE_ENVS:
        raw = str(os.environ.get(env_name) or "").strip()
        if not raw:
            continue
        try:
            parsed = urllib.parse.urlsplit(raw)
        except ValueError:
            continue
        if (
            parsed.scheme in ("http", "https")
            and parsed.hostname
            and not parsed.username
            and not parsed.password
            and not parsed.query
            and not parsed.fragment
            and not contains_share_code_url(raw)
        ):
            return raw.rstrip("/")
    return "http://localhost"


def public_merchant_home_url(merchant_id: str) -> str:
    """目录托管的公开商家主页 URL（不含任何凭据或分享码）。"""
    return f"{public_page_base_url()}{_PUBLIC_MERCHANT_PATH}{urllib.parse.quote(str(merchant_id), safe='')}"


def has_public_content(
    conn: sqlite3.Connection, merchant_id: str, *, now: str | None = None
) -> bool:
    """是否存在可公开展示的资料（已发布资料 / ACTIVE 商品 / 已发布名片）。"""
    merchant_id = str(merchant_id or "").strip()
    if not merchant_id:
        return False
    cutoff = now or now_iso()
    # 已发布资料本身已是公开投影（读侧会做非签名内容清洗），可直接计入。
    row = conn.execute(
        "select 1 from merchant_publications"
        " where merchant_id = ? and status = 'published'"
        " and (expires_at = '' or expires_at > ?)"
        " limit 1",
        (merchant_id, cutoff),
    ).fetchone()
    if row is not None:
        return True
    # 已发布名片只有在内容干净时才算公开内容：分享码污染的已签名版本会被
    # 公开读隔离，不能据此给商家一个必然 404 的主页链接。
    from kiwi_catalog.a2a.card_store import card_contains_share_code

    card_rows = conn.execute(
        "select v.canonical_bytes from catalog_agents ca"
        " join card_publications cp on cp.catalog_agent_id = ca.catalog_agent_id"
        " join agent_card_versions v on v.catalog_agent_id = ca.catalog_agent_id"
        "   and v.card_revision = cp.active_revision"
        " where ca.merchant_id = ?"
        " and cp.publication_state in ('ACTIVE','PAUSED')"
        " and ca.administrative_state = 'active'"
        " limit 20",
        (merchant_id,),
    ).fetchall()
    for card_row in card_rows:
        try:
            card = json.loads(str(card_row["canonical_bytes"] or ""))
        except (TypeError, ValueError):
            continue
        if isinstance(card, dict) and not card_contains_share_code(card):
            return True
    # ACTIVE listing 同样先排除分享码污染（公开读会隔离这些行）。
    from kiwi_catalog.listings.quarantine import listing_has_share_code

    listing_rows = conn.execute(
        "select * from commerce_listings"
        " where merchant_id = ? and publication_state = 'ACTIVE'"
        " and coalesce(governance_hold, 0) = 0"
        " and not exists (select 1 from catalog_agents ca"
        "   where ca.catalog_agent_id = commerce_listings.owner_agent_id"
        "   and ca.administrative_state in ('suspended','rejected'))"
        " limit 1000",
        (merchant_id,),
    ).fetchall()
    for listing_row in listing_rows:
        if not listing_has_share_code(dict(listing_row)):
            return True
    return False


def public_merchant_home_url_for(
    conn: sqlite3.Connection, merchant_id: str, *, now: str | None = None
) -> str:
    """仅有公开内容时返回主页 URL；否则空串（页面会 404，不该给链接）。"""
    if not has_public_content(conn, merchant_id, now=now):
        return ""
    return public_merchant_home_url(merchant_id)


def list_public_publications(
    conn: sqlite3.Connection,
    merchant_id: str,
    *,
    now: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """某商家的全部公开可见资料（published + 未过期，最新在前）。

    *offset* 用于主页分页：50 件上限之外的内容仍可通过下一页访问。
    """
    merchant_id = str(merchant_id or "").strip()
    if not merchant_id:
        return []
    cutoff = now or now_iso()
    safe_limit = max(1, min(int(limit), 100))
    safe_offset = max(0, int(offset))
    rows = conn.execute(
        "select * from merchant_publications"
        " where merchant_id = ? and status = 'published'"
        " and (expires_at = '' or expires_at > ?)"
        " order by updated_at desc, publication_id desc limit ? offset ?",
        (merchant_id, cutoff, safe_limit, safe_offset),
    ).fetchall()
    return [_row_to_publication(row) for row in rows]


def _normalize_faq(raw: Any) -> list[dict[str, str]]:
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        raise ValidationError("faq must be a list of {question, answer} items")
    if len(raw) > _MAX_FAQ_ITEMS:
        raise ValidationError(f"faq must have at most {_MAX_FAQ_ITEMS} items")
    items: list[dict[str, str]] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValidationError(f"faq[{i}] must be an object")
        question = str(entry.get("question") or "").strip()
        answer = str(entry.get("answer") or "").strip()
        if not question or not answer:
            raise ValidationError(f"faq[{i}] requires non-empty question and answer")
        if len(question) > _MAX_FAQ_QUESTION:
            raise ValidationError(f"faq[{i}].question too long")
        if len(answer) > _MAX_FAQ_ANSWER:
            raise ValidationError(f"faq[{i}].answer too long")
        items.append({"question": question, "answer": answer})
    return items


def _normalize_expires_at(raw: Any) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValidationError("expires_at must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValidationError("expires_at must include a timezone offset")
    # 统一 UTC 秒级文本（与 now_iso 同格式，字符串比较即时间序）
    return parsed.astimezone(UTC).replace(microsecond=0).isoformat()


def validate_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """校验并归一化发布请求 → (canonical, action)。

    action：``draft``（保存草稿，缺省）/ ``publish``（确认发布）。必填：
    merchant_display_name、title（商品名）；其余选填。
    """
    action = str((payload or {}).get("action") or "draft").strip().lower()
    if action not in ("draft", "publish"):
        raise ValidationError("action must be one of ('draft', 'publish')")

    canonical: dict[str, Any] = {}
    for field, limit in (
        ("merchant_display_name", _MAX_DISPLAY_NAME),
        ("title", _MAX_TITLE),
        ("category", _MAX_CATEGORY),
        ("shop_platform", _MAX_PLATFORM),
        ("summary", _MAX_SUMMARY),
    ):
        value = str((payload or {}).get(field) or "").strip()
        if len(value) > limit:
            raise ValidationError(f"{field} too long (max {limit})")
        canonical[field] = value
    for required in ("merchant_display_name", "title"):
        if not canonical[required]:
            raise ValidationError(f"missing required field: {required}")
    shop_url = validate_shop_url(str((payload or {}).get("shop_url") or ""))
    if shop_url and not safe_public_shop_url(shop_url):
        # 新写入 fail-closed：WorkBuddy 服务/门禁链接、Agent 端点、分享码
        # URL 与目录自身地址都不是商家公开店铺页。普通外部商品/店铺链接仍
        # 通过（safe_public_shop_url 只拦上述类别）。
        raise ValidationError(
            "shop_url must not be a WorkBuddy service link, Agent endpoint, "
            "directory URL, or share-code URL"
        )
    canonical["shop_url"] = shop_url
    canonical["faq"] = _normalize_faq((payload or {}).get("faq"))
    canonical["expires_at"] = _normalize_expires_at((payload or {}).get("expires_at"))
    return canonical, action


# ── 行读写 ────────────────────────────────────────────────────────────────


def _row_to_publication(row: sqlite3.Row) -> dict[str, Any]:
    """行 → 公开安全视图（历史危险链接/联系方式在源头就替换）。

    写路径已 fail-closed；这里对旧数据/手工写库再兜一层，让任何读取
    ``merchant_publications`` 的服务都拿不到 WorkBuddy/分享码链接。普通
    商品链接保持原样。
    """
    publication = dict(row)
    raw_faq = decode_json(publication.pop("faq_json", ""), [])
    publication["faq"] = [
        {
            "question": redact_public_text(str(item.get("question") or "")),
            "answer": redact_public_text(str(item.get("answer") or "")),
        }
        for item in raw_faq
        if isinstance(item, dict)
    ]
    for field in _PUBLIC_TEXT_FIELDS:
        if field in publication:
            publication[field] = redact_public_text(str(publication[field] or ""))
    publication["shop_url"] = safe_public_shop_url(
        str(publication.get("shop_url") or "")
    )
    return publication


def get_publication(conn: sqlite3.Connection, publication_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "select * from merchant_publications where publication_id = ?",
        (str(publication_id or "").strip(),),
    ).fetchone()
    return _row_to_publication(row) if row is not None else None


def is_publicly_visible(publication: dict[str, Any], now: str) -> bool:
    """公开可见性：published 且未过期（expires_at 为空或在未来）。"""
    if str(publication.get("status") or "") != "published":
        return False
    expires_at = str(publication.get("expires_at") or "")
    return not expires_at or expires_at > now


def _find_by_merchant_title(
    conn: sqlite3.Connection, merchant_id: str, title: str, *, status: str
) -> dict[str, Any] | None:
    """按状态查找同名资料，避免草稿覆盖当前已发布快照。"""
    row = conn.execute(
        "select * from merchant_publications"
        " where merchant_id = ? and lower(title) = lower(?) and status = ?"
        " order by updated_at desc limit 1",
        (merchant_id, title, status),
    ).fetchone()
    return _row_to_publication(row) if row is not None else None


def _publish_event_type(
    existing: dict[str, Any] | None, canonical: dict[str, Any]
) -> str:
    """发布动作 → 事件类型：新增 product_added；仅 FAQ 变化 faq_updated；其余
    字段变化（含无任何变化的重复发布）product_updated。"""
    if existing is None:
        return "product_added"
    faq_changed = (existing.get("faq") or []) != (canonical.get("faq") or [])
    others_changed = any(
        str(existing.get(field) or "") != str(canonical.get(field) or "")
        for field in (
            "merchant_display_name",
            "shop_platform",
            "shop_url",
            "title",
            "category",
            "summary",
            "expires_at",
        )
    )
    if faq_changed and not others_changed:
        return "faq_updated"
    return "product_updated"


def upsert_publication(
    conn: sqlite3.Connection,
    *,
    merchant_id: str,
    canonical: dict[str, Any],
    action: str,
) -> tuple[dict[str, Any], bool, bool]:
    """写入公开资料 → (row, created, idempotent_replay)。

    同一商家同名商品的重复发布更新既有 published 行；draft 使用独立行，避免
    未确认内容污染公开快照。``publish`` 动作置 published + published_at 并递增版本。
    """
    now = now_iso()
    # 草稿必须是独立行；保存草稿不能改变当前 published 快照。
    existing = _find_by_merchant_title(
        conn, merchant_id, str(canonical["title"]), status="draft" if action == "draft" else "published"
    )
    faq_json = encode_json(canonical["faq"])
    if existing is None:
        publication_id = new_publication_id()
        status = "published" if action == "publish" else "draft"
        published_at = now if action == "publish" else ""
        conn.execute(
            "insert into merchant_publications("
            " publication_id, merchant_id, status, source_kind,"
            " merchant_display_name, shop_platform, shop_url, title, category,"
            " summary, faq_json, published_at, expires_at, version, created_at, updated_at)"
            " values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
            (
                publication_id,
                merchant_id,
                status,
                SOURCE_KIND,
                canonical["merchant_display_name"],
                canonical["shop_platform"],
                canonical["shop_url"],
                canonical["title"],
                canonical["category"],
                canonical["summary"],
                faq_json,
                published_at,
                canonical["expires_at"],
                now,
                now,
            ),
        )
        row = get_publication(conn, publication_id)
        assert row is not None
        if action == "publish":
            # M4 公开事件：发布动态（草稿保存不产生事件）。
            events_service.emit_public_event(
                conn,
                merchant_id=merchant_id,
                publication_id=str(row["publication_id"]),
                event_type="product_added",
                payload=public_projection(row),
            )
        return row, True, False
    # 幂等更新路径：版本仅在（重新）发布时递增——草稿保存不消耗版本号。
    version = int(existing["version"] or 1)
    status = str(existing["status"])
    published_at = str(existing["published_at"] or "")
    if action == "publish":
        version += 1
        status = "published"
        published_at = now
    conn.execute(
        "update merchant_publications set"
        " merchant_display_name = ?, shop_platform = ?, shop_url = ?,"
        " category = ?, summary = ?, faq_json = ?, status = ?,"
        " published_at = ?, expires_at = ?, version = ?, updated_at = ?"
        " where publication_id = ?",
        (
            canonical["merchant_display_name"],
            canonical["shop_platform"],
            canonical["shop_url"],
            canonical["category"],
            canonical["summary"],
            faq_json,
            status,
            published_at,
            canonical["expires_at"],
            version,
            now,
            existing["publication_id"],
        ),
    )
    row = get_publication(conn, str(existing["publication_id"]))
    assert row is not None
    if action == "publish":
        events_service.emit_public_event(
            conn,
            merchant_id=merchant_id,
            publication_id=str(row["publication_id"]),
            event_type=_publish_event_type(existing, canonical),
            payload=public_projection(row),
        )
    return row, False, True


def withdraw_publication(
    conn: sqlite3.Connection, *, publication_id: str, merchant_id: str
) -> dict[str, Any]:
    """撤回公开资料（终态）：行必须存在且归属当前商家。"""
    row = get_publication(conn, publication_id)
    if row is None:
        raise NotFoundError(f"Unknown publication: {publication_id}")
    if str(row["merchant_id"]) != merchant_id:
        from kiwi_catalog.core.errors import PermissionDenied

        raise PermissionDenied("publication belongs to another merchant")
    now = now_iso()
    conn.execute(
        "update merchant_publications set status = 'withdrawn', updated_at = ?"
        " where publication_id = ?",
        (now, row["publication_id"]),
    )
    updated = get_publication(conn, publication_id)
    assert updated is not None
    events_service.emit_public_event(
        conn,
        merchant_id=merchant_id,
        publication_id=str(updated["publication_id"]),
        event_type="publication_withdrawn",
        payload=public_projection(updated),
    )
    return updated


def record_public_view(conn: sqlite3.Connection, publication_id: str) -> None:
    """公开详情浏览计数（非商家本人视角；商家匿名汇总数据源）。"""
    conn.execute(
        "update merchant_publications set view_count = view_count + 1"
        " where publication_id = ?",
        (str(publication_id or "").strip(),),
    )


# ── 公开投影（public-only 白名单）────────────────────────────────────────


def public_projection(publication: dict[str, Any]) -> dict[str, Any]:
    """公开搜索/详情投影：仅公开字段；恒带 inquiry_available=false。

    绝不包含注册账户的电话/邮箱（本表本就不存）；不生成 Agent Card / A2A
    端点 / 实时报价标记。``shop_url`` 与公开文本里的链接都经过读侧兜底：
    历史行或手工写库留下的 WorkBuddy/分享码 URL 不会进入本投影。
    """
    faq = [
        {
            "question": redact_public_text(str(item.get("question") or "")),
            "answer": redact_public_text(str(item.get("answer") or "")),
        }
        for item in (publication.get("faq") or [])
        if isinstance(item, dict)
    ]
    expires_at = str(publication.get("expires_at") or "")
    home_visible = str(publication.get("status") or "") == "published" and (
        not expires_at or expires_at > now_iso()
    )
    return {
        "publication_id": publication["publication_id"],
        "merchant_id": publication["merchant_id"],
        "merchant_display_name": redact_public_text(
            str(publication["merchant_display_name"])
        ),
        "title": redact_public_text(str(publication["title"])),
        "category": redact_public_text(str(publication["category"])),
        "summary": redact_public_text(str(publication["summary"])),
        "shop_platform": redact_public_text(str(publication["shop_platform"])),
        "shop_url": safe_public_shop_url(str(publication.get("shop_url") or "")),
        "public_home_url": (
            public_merchant_home_url(str(publication["merchant_id"]))
            if home_visible
            else ""
        ),
        "faq": faq,
        "source_kind": publication["source_kind"],
        "status": publication["status"],
        "version": publication["version"],
        "published_at": publication["published_at"],
        "expires_at": publication["expires_at"],
        "updated_at": publication["updated_at"],
        "inquiry_available": False,
    }


# ── 公开搜索（沿用 listings 搜索约定：LIKE 转义 + 确定性排序 + cursor）─────

_SEARCH_QUERY_KEYS = frozenset({"q", "category", "merchant_id", "limit", "cursor"})


class SearchQueryError(ValueError):
    """搜索 query 非法（fail-closed：未知键拒绝，不静默忽略）。"""


def _like_escaped(term: str) -> str:
    escaped = str(term).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _encode_cursor(updated_at: str, publication_id: str) -> str:
    return urllib.parse.quote(f"{updated_at}|{publication_id}", safe="")


def _decode_cursor(cursor: str) -> tuple[str, str]:
    parts = urllib.parse.unquote(str(cursor)).split("|")
    if len(parts) != 2:
        raise ValueError("malformed cursor")
    return parts[0], parts[1]


def search_publications(
    conn: sqlite3.Connection, query: dict[str, Any]
) -> tuple[list[dict[str, Any]], str]:
    """公开搜索：仅 published 且未过期；排序 (updated_at desc, publication_id desc)。

    Returns (rows, next_cursor)——rows 为 public_projection 形状。
    """
    unknown = set(query or {}) - _SEARCH_QUERY_KEYS
    if unknown:
        raise SearchQueryError(f"unknown publication search query keys: {sorted(unknown)}")
    limit = 20
    raw_limit = (query or {}).get("limit")
    if raw_limit not in (None, ""):
        try:
            limit = int(raw_limit)
        except (TypeError, ValueError) as exc:
            raise SearchQueryError("limit must be an integer") from exc
        if not 1 <= limit <= 100:
            raise SearchQueryError("limit must be between 1 and 100")

    where: list[str] = ["status = 'published'"]
    values: list[Any] = []
    now = now_iso()
    # 未过期：expires_at 为空或在未来
    where.append("(expires_at = '' or expires_at > ?)")
    values.append(now)

    q = str((query or {}).get("q") or "").strip()
    if q:
        where.append(
            "(title like ? escape '\\' or category like ? escape '\\'"
            " or summary like ? escape '\\' or merchant_display_name like ? escape '\\')"
        )
        pattern = _like_escaped(q)
        values.extend([pattern, pattern, pattern, pattern])

    category = str((query or {}).get("category") or "").strip()
    if category:
        where.append("category = ?")
        values.append(category)

    merchant_id = str((query or {}).get("merchant_id") or "").strip()
    if merchant_id:
        where.append("merchant_id = ?")
        values.append(merchant_id)

    cursor = str((query or {}).get("cursor") or "").strip()
    if cursor:
        try:
            c_updated_at, c_publication_id = _decode_cursor(cursor)
        except ValueError as exc:
            raise SearchQueryError(f"malformed cursor: {exc}") from exc
        where.append(
            "(updated_at < ? or (updated_at = ? and publication_id < ?))"
        )
        values.extend([c_updated_at, c_updated_at, c_publication_id])

    rows = conn.execute(
        f"""
        select * from merchant_publications
        where {' and '.join(where)}
        order by updated_at desc, publication_id desc
        limit ?
        """,
        (*values, limit + 1),
    ).fetchall()

    results = [_row_to_publication(row) for row in rows[:limit]]
    next_cursor = ""
    if len(rows) > limit and results:
        last = results[-1]
        next_cursor = _encode_cursor(str(last["updated_at"]), str(last["publication_id"]))
    return results, next_cursor
