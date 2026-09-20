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
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from kiwi_catalog.a2a.card_store import read_active_card
from kiwi_catalog.core.errors import NotFoundError, PermissionDenied, ValidationError

CLAIMS_SCHEMA_VERSION = "0.1.2"
MAX_CLAIMS_TTL_SECONDS = 15 * 60
DEFAULT_CLAIMS_TTL_SECONDS = 15 * 60
ISSUER_KEY_FILE_ENV = "KIWI_CATALOG_ISSUER_KEY_FILE"
ISSUER_KID_ENV = "KIWI_CATALOG_ISSUER_KID"
ISSUER_NAME_ENV = "KIWI_CATALOG_ISSUER_NAME"
DEFAULT_ISSUER_NAME = "catalog.kiwi"


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


def load_issuer_identity(env: dict[str, str] | None = None) -> IssuerIdentity:
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
    env: dict[str, str] | None = None,
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

    issuer = load_issuer_identity(env)
    source = env if env is not None else os.environ
    issuer_name = str(source.get(ISSUER_NAME_ENV) or "").strip() or DEFAULT_ISSUER_NAME
    card_url = f"/v1/agents/{catalog_agent_id}/agent-card.json"
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
    return {
        "claims": claims,
        "claims_jws": _sign_claims(claims, issuer),
        "issuer_kid": issuer.kid,
        "issuer_thumbprint": issuer.thumbprint,
        "governance": {"publication_state": publication_state},
    }
