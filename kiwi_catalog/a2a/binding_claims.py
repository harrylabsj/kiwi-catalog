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

"""绑定声明签发与读取（M3；设计 §11.4 / §11.6 的 SIG-02 Catalog 侧）。

- **issuer 私钥**只从受控来源注入（`KIWI_CATALOG_ISSUER_KEY_FILE` 指向 PKCS8 PEM +
  `KIWI_CATALOG_ISSUER_KID`）；**缺失即拒签**——绝不生成临时钥匙、绝不用 Runtime 钥匙
  冒充发行者（§11.6：两类私钥职责分离）。
- **受控签发**：只对「存在有效 runtime_binding + 存在活动名片 + 治理状态未撤回」的
  agent 签发；TTL ≤ 15 分钟（§11.5）；算法固定 EdDSA（拒绝 none/回退）。
- `key_thumbprint` 口径与 kiwi TS 侧**逐字节一致**：规范化公钥 JWK（RFC 7638 必需成员、
  字典序、紧凑分隔符）→ sha256 十六进制，前缀 `sha256:`。跨语言一致性由
  `kiwi/contracts/vectors/binding-thumbprint.json` 两侧测试锁定。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from kiwi_catalog.a2a.card_store import read_active_card
from kiwi_catalog.a2a.endpoint_policy import assert_safe_binding_targets
from kiwi_catalog.core.errors import NotFoundError, PermissionDenied, ValidationError

CLAIMS_SCHEMA_VERSION = "0.1.2"
MAX_CLAIMS_TTL_SECONDS = 15 * 60
DEFAULT_CLAIMS_TTL_SECONDS = 15 * 60
ISSUER_KEY_FILE_ENV = "KIWI_CATALOG_ISSUER_KEY_FILE"
ISSUER_KID_ENV = "KIWI_CATALOG_ISSUER_KID"
ISSUER_NAME_ENV = "KIWI_CATALOG_ISSUER_NAME"
DEFAULT_ISSUER_NAME = "catalog.kiwi"
#: Catalog 对外公开 origin（`https://host[:port]`，无路径/查询/片段）。
#: `card_url` 只从这里派生；未配置即拒签。
PUBLIC_ORIGIN_ENV = "KIWI_CATALOG_PUBLIC_ORIGIN"


def catalog_public_origin(source: Mapping[str, str]) -> str:
    """校验并返回受控配置的公开 origin；缺失/非 https/带路径一律拒签。"""
    raw = str(source.get(PUBLIC_ORIGIN_ENV) or "").strip()
    if not raw:
        raise PermissionDenied(
            f"catalog public origin is not configured ({PUBLIC_ORIGIN_ENV});"
            " refusing to issue claims with a relative card_url"
        )
    try:
        parsed = urlsplit(raw)
    except ValueError as exc:
        raise PermissionDenied(f"catalog public origin is not a valid URL: {raw!r}") from exc
    if parsed.scheme != "https" or not parsed.netloc:
        raise PermissionDenied(f"catalog public origin must be https: {raw!r}")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise PermissionDenied(f"catalog public origin must not include path/query/fragment: {raw!r}")
    if parsed.username or parsed.password:
        raise PermissionDenied("catalog public origin must not embed credentials")
    return f"https://{parsed.netloc}"


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """`sha256:<hex>`：与 kiwi TS 侧 `jwkThumbprint` 同一口径（RFC 7638 必需成员）。"""
    kty = jwk.get("kty")
    if kty == "OKP":
        if jwk.get("crv") != "Ed25519" or not isinstance(jwk.get("x"), str) or not jwk["x"]:
            raise ValidationError("unsupported OKP JWK (expect Ed25519 with x)")
        canonical = json.dumps(
            {"crv": jwk["crv"], "kty": kty, "x": jwk["x"]}, separators=(",", ":"), ensure_ascii=False
        )
    elif kty == "EC":
        if jwk.get("crv") != "P-256" or not isinstance(jwk.get("x"), str) or not isinstance(jwk.get("y"), str):
            raise ValidationError("unsupported EC JWK (expect P-256 with x/y)")
        canonical = json.dumps(
            {"crv": jwk["crv"], "kty": kty, "x": jwk["x"], "y": jwk["y"]},
            separators=(",", ":"),
            ensure_ascii=False,
        )
    else:
        raise ValidationError(f"unsupported JWK kty: {kty!r}")
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class IssuerIdentity:
    """Catalog 发行者身份（kid + 私钥 + 公钥 JWK）。"""

    def __init__(self, kid: str, private_key: Ed25519PrivateKey, public_jwk: dict[str, Any]) -> None:
        self.kid = kid
        self.private_key = private_key
        self.public_jwk = public_jwk

    @property
    def thumbprint(self) -> str:
        return jwk_thumbprint(self.public_jwk)


def load_issuer_identity(env: Mapping[str, str] | None = None) -> IssuerIdentity:
    """从受控来源加载发行者身份；缺失/非法一律拒签（不生成临时钥匙）。"""
    source = env if env is not None else os.environ
    key_file = str(source.get(ISSUER_KEY_FILE_ENV) or "").strip()
    kid = str(source.get(ISSUER_KID_ENV) or "").strip()
    if not key_file or not kid:
        raise PermissionDenied(
            f"catalog issuer key is not configured ({ISSUER_KEY_FILE_ENV}/{ISSUER_KID_ENV})"
        )
    path = Path(key_file)
    if not path.is_file():
        raise PermissionDenied("catalog issuer key file is missing")
    key = load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise PermissionDenied("catalog issuer key must be an Ed25519 PKCS8 private key")
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return IssuerIdentity(kid, key, {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)})


def _sign_claims(claims: dict[str, Any], issuer: IssuerIdentity) -> str:
    header = {"typ": "kiwi-runtime-binding-claims", "alg": "EdDSA", "kid": issuer.kid}
    header_segment = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_segment = _b64url(json.dumps(claims, separators=(",", ":"), ensure_ascii=False).encode())
    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    signature = issuer.private_key.sign(signing_input)
    return f"{header_segment}.{payload_segment}.{_b64url(signature)}"


def _active_binding(conn: sqlite3.Connection, catalog_agent_id: str) -> sqlite3.Row | None:
    return conn.execute(
        "select * from runtime_bindings where catalog_agent_id = ? and status = 'active'"
        " order by binding_version desc limit 1",
        (catalog_agent_id,),
    ).fetchone()


def read_runtime_binding(
    conn: sqlite3.Connection,
    catalog_agent_id: str,
    *,
    now: datetime | None = None,
    ttl_seconds: int = DEFAULT_CLAIMS_TTL_SECONDS,
    env: Mapping[str, str] | None = None,
    public_origin: str | None = None,
) -> dict[str, Any]:
    """签发并返回绑定声明 + 治理状态（公开读；不含平台 appId/用户 ID）。"""
    current = now or datetime.now(timezone.utc)
    if ttl_seconds <= 0 or ttl_seconds > MAX_CLAIMS_TTL_SECONDS:
        raise ValidationError(f"claims ttl must be within 1..{MAX_CLAIMS_TTL_SECONDS} seconds")
    agent = conn.execute(
        "select * from catalog_agents where catalog_agent_id = ?", (catalog_agent_id,)
    ).fetchone()
    if agent is None:
        raise NotFoundError("catalog agent not found")
    binding = _active_binding(conn, catalog_agent_id)
    if binding is None:
        raise NotFoundError("no active runtime binding for this agent")
    expires_at = str(binding["expires_at"] or "")
    if expires_at and datetime.fromisoformat(expires_at) <= current:
        raise PermissionDenied("runtime binding expired; refusing to issue claims")

    # 治理状态：撤回/无活动名片时**不签发**（§11.6 SIG-02）。
    try:
        _card, _etag, publication_state = read_active_card(conn, catalog_agent_id)
    except Exception as exc:  # NotFoundError / GoneError 都视为不可签发
        raise PermissionDenied(f"agent is not publishable: {exc}") from exc
    if publication_state == "WITHDRAWN":
        raise PermissionDenied("publication withdrawn; refusing to issue claims")

    # 纵深防御（T035）：即便库里存了一条不安全目标的绑定，也绝不签发给 Buyer。
    # 创建时已拦一次；签发是第二个出口，同样 fail-closed。
    assert_safe_binding_targets(
        {
            "runtime_origin": str(binding["runtime_origin"]),
            "a2a_endpoint": str(binding["a2a_endpoint"]),
        }
    )

    # 签发走密钥集合：只有 ACTIVE 的 kid 能签；COMPROMISED/RETIRED 一律拒签（SIG-04）。
    # 未配置密钥集合时回退单密钥 env（视为 ACTIVE），行为与本函数既有调用方一致。
    issuer = load_issuer_key_set(env).signing_identity()
    source = env if env is not None else os.environ
    issuer_name = str(source.get(ISSUER_NAME_ENV) or "").strip() or DEFAULT_ISSUER_NAME
    # `card_url` 必须是**绝对 https URL**（Schema 的 `^https://` + 样例
    # `https://catalog.example/v1/agents/cagt_demo/agent-card.json`）。
    # 绝不从入站 Host 推导（Host 可被改写/伪造——Runtime 侧已因平台网关重写
    # Host 踩过同一坑）：只认受控配置的公开 origin；未配置即拒签。
    origin_source: Mapping[str, str] = (
        source if public_origin is None else {PUBLIC_ORIGIN_ENV: public_origin}
    )
    origin = catalog_public_origin(origin_source)
    card_url = f"{origin}/v1/agents/{catalog_agent_id}/agent-card.json"
    claims = {
        "schema_version": CLAIMS_SCHEMA_VERSION,
        "binding_id": str(binding["binding_id"]),
        "binding_version": int(binding["binding_version"]),
        "merchant_id": str(binding["merchant_id"]),
        "agent_id": catalog_agent_id,
        "workload_ref": str(binding["runtime_origin"]).split("//")[-1].split(".")[0][:32] or "runtime",
        "runtime_origin": str(binding["runtime_origin"]),
        "a2a_endpoint": str(binding["a2a_endpoint"]),
        "card_url": card_url,
        "key_id": str(binding["key_id"]),
        "key_thumbprint": str(binding["key_thumbprint"]),
        "service_epoch": int(binding["service_epoch"]),
        "issued_at": current.isoformat(),
        "expires_at": (current + timedelta(seconds=ttl_seconds)).isoformat(),
        "issuer": issuer_name,
        "scope": "a2a-runtime",
        "status": "active",
    }
    publication = conn.execute(
        "select active_revision, etag from card_publications where catalog_agent_id = ?",
        (catalog_agent_id,),
    ).fetchone()
    return {
        "claims": claims,
        "claims_jws": _sign_claims(claims, issuer),
        "issuer_kid": issuer.kid,
        "issuer_thumbprint": issuer.thumbprint,
        "governance": {"publication_state": publication_state},
        # 公开元数据（非敏感）：供 Buyer 按 (来源, card revision, binding_version, 端点)
        # 建立信任缓存（设计 §12.1）。
        "card_revision": int(publication["active_revision"]) if publication is not None else None,
        "card_etag": str(publication["etag"]) if publication is not None else None,
    }


# ---------------------------------------------------------------------------
# SIG-04（最小）：发行者密钥集合与状态机
# ---------------------------------------------------------------------------

ISSUER_KEYS_FILE_ENV = "KIWI_CATALOG_ISSUER_KEYS_FILE"
ISSUER_KEY_STATES = ("PREPARED", "ACTIVE", "VERIFY_ONLY", "RETIRED", "COMPROMISED")
#: 泄漏密钥（COMPROMISED）是**终态**：普通恢复不得把它重新激活（§11.6）。
_TERMINAL_STATES = ("COMPROMISED",)


class IssuerKeySet:
    """发行者公钥集合与状态（kid → state + 公钥；ACTIVE 才用于签发）。

    - 只从受控文件加载（`KIWI_CATALOG_ISSUER_KEYS_FILE`）；文件缺失时回退到
      单密钥 env 形态（视为 ACTIVE）。
    - **未知 kid 不得触发到任意外部 URL 下载信任根**：本类不做任何网络访问；
      公钥集合由受控发布渠道/管理员提供。
    """

    def __init__(
        self,
        entries: dict[str, dict[str, Any]],
        *,
        source_path: Path | None = None,
    ) -> None:
        self._entries = entries
        #: 本实例是从哪个受控文件加载的（单密钥 env 回退时为 None）。
        #: `persist()` 只写回它——绝不往一个"不知道原来长什么样"的路径写状态。
        self._source_path = source_path

    @property
    def kids(self) -> list[str]:
        return sorted(self._entries)

    def state_of(self, kid: str) -> str | None:
        entry = self._entries.get(kid)
        return None if entry is None else str(entry["state"])

    def public_keys(self) -> dict[str, dict[str, Any]]:
        """kid → {state, jwk}（供可信发布渠道分发；不含私钥）。"""
        return {
            kid: {"state": str(entry["state"]), "jwk": dict(entry["jwk"])}
            for kid, entry in self._entries.items()
        }

    def signing_identity(self) -> IssuerIdentity:
        """选取 ACTIVE 的签发身份；没有 ACTIVE 即拒签（不降级、不复用失效密钥）。"""
        active = [kid for kid in self.kids if self._entries[kid]["state"] == "ACTIVE"]
        if not active:
            raise PermissionDenied("no ACTIVE catalog issuer key (rotation in progress or all retired)")
        if len(active) > 1:
            raise PermissionDenied("multiple ACTIVE catalog issuer keys; exactly one expected")
        entry = self._entries[active[0]]
        return IssuerIdentity(active[0], entry["private_key"], entry["jwk"])

    def transition(self, kid: str, state: str) -> str:
        """状态迁移（**仅本实例**；受控文件仍是权威，见 `persist()`）。

        COMPROMISED 是终态，任何"恢复"尝试都被拒绝。
        """
        if state not in ISSUER_KEY_STATES:
            raise ValidationError(f"unknown issuer key state: {state}")
        entry = self._entries.get(kid)
        if entry is None:
            raise NotFoundError(f"unknown issuer kid: {kid}")
        current = str(entry["state"])
        if current in _TERMINAL_STATES and state != current:
            raise PermissionDenied(f"issuer key {kid} is {current}; transitions out of it are refused")
        entry["state"] = state
        return state

    def persist(self) -> Path:
        """把当前**状态**写回受控文件（原子替换：临时文件 + rename）。

        为什么必须有这个方法：`transition()` 只改内存。若调用方以为"标记 COMPROMISED
        就等于生效"，下一次 `load_issuer_key_set()` 会从文件把旧状态读回来——**被泄漏
        的密钥原地复活**。这是安全相关的语义，不能靠"记得手改文件"。

        - 只写回 `state`；`kid` / `private_key_file` 等原样保留，绝不改写私钥路径，
          更不把任何私钥材料写进这个文件。
        - 单密钥 env 回退形态（无来源文件）没有可写回的集合 → 明确拒绝，而不是
          伪造一个文件出来。
        """
        if self._source_path is None:
            raise PermissionDenied(
                "issuer key set was not loaded from a keys file; nothing to persist"
            )
        payload = json.loads(self._source_path.read_text(encoding="utf-8"))
        for item in payload.get("keys", []):
            kid = str(item.get("kid") or "").strip()
            if kid in self._entries:
                item["state"] = str(self._entries[kid]["state"])
        tmp_path = self._source_path.with_name(f".{self._source_path.name}.tmp")
        tmp_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        tmp_path.replace(self._source_path)
        return self._source_path


def load_issuer_key_set(env: Mapping[str, str] | None = None) -> IssuerKeySet:
    """从受控文件加载密钥集合；未配置时回退单密钥 env（state=ACTIVE）。"""
    source = env if env is not None else os.environ
    keys_file = str(source.get(ISSUER_KEYS_FILE_ENV) or "").strip()
    if keys_file:
        path = Path(keys_file)
        if not path.is_file():
            raise PermissionDenied("catalog issuer keys file is missing")
        payload = json.loads(path.read_text(encoding="utf-8"))
        entries: dict[str, dict[str, Any]] = {}
        for item in payload.get("keys", []):
            kid = str(item.get("kid") or "").strip()
            state = str(item.get("state") or "").strip()
            key_file = str(item.get("private_key_file") or "").strip()
            if not kid or state not in ISSUER_KEY_STATES or not key_file:
                raise PermissionDenied("issuer keys file entry is malformed")
            key_path = Path(key_file)
            if not key_path.is_file():
                raise PermissionDenied(f"issuer key file missing for kid {kid}")
            key = load_pem_private_key(key_path.read_bytes(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise PermissionDenied(f"issuer key {kid} must be an Ed25519 PKCS8 private key")
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

            raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            entries[kid] = {
                "state": state,
                "private_key": key,
                "jwk": {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)},
            }
        if not entries:
            raise PermissionDenied("issuer keys file contains no keys")
        return IssuerKeySet(entries, source_path=path)
    single = load_issuer_identity(source)
    return IssuerKeySet(
        {
            single.kid: {
                "state": "ACTIVE",
                "private_key": single.private_key,
                "jwk": single.public_jwk,
            }
        }
    )
