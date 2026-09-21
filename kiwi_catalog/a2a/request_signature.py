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

"""绑定 Runtime 的**请求签名**（M3；设计 §11.6 / §14.1）。

控制面写接口（card-publications）不允许把 owner token 放进 JSON 体；身份来自
**绑定 Runtime 的私钥对请求的签名**：

    payload = {"binding_id", "agent_id", "card_digest", "expected_revision", "generation",
               "issued_at", "nonce"}
    JWS     = compact JWS（EdDSA/Ed25519），头部携带 kid

**绑定语义字段而非字节流**：HTTP 层只把解析后的 JSON 交给 handler（无原始字节），
因此签名覆盖的是**被签名的语义字段**，验证时逐个与请求体中的同名字段比对。
对本接口来说这等价于绑定请求内容——商家身份来自路由 + agent_id、发布内容由
card_digest 摘要、并发保护由 expected_revision、代次由 generation。

验证顺序（任一失败即拒绝，返回 403）：
  1. 解析 JWS 头 → kid；按 (agent, kid) 找**active** 绑定（找不到 → 拒绝）；
  2. 绑定未过期（expires_at 为空视为长期有效）；
  3. 用绑定里存的**公钥 JWK** 验签（算法固定 EdDSA，拒绝 none/其它 alg）；
  4. 负载里的每个**被签名语义字段**必须与请求体一致；
  5. `issued_at` 在允许时钟偏移内（缺省 ±300s）。

**nonce 重放保护**（SIG-04）：验签与时间窗都通过后，`(key_id, nonce)` 会被写入
`control_plane_nonces` 并以其为主键消费一次；同一密钥重复使用同一 nonce 即冲突 →
403。记录只在时钟偏移窗口内保留（`expires_at = issued_at + window`），过窗行会惰性
清理——窗口外的请求本来就被时间窗拒绝，不必留更久。

消费发生在**全部校验之后**：验签失败的请求不会烧掉 nonce（否则攻击者可以用无效签名
把合法请求的 nonce 提前占掉，等于拒绝服务）。
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from kiwi_catalog.core.errors import PermissionDenied, ValidationError

#: 允许的时钟偏移（秒）。
DEFAULT_CLOCK_SKEW_SECONDS = 300
#: nonce 的合理长度（太短会撞车、太长是无界键空间的借口）。
MIN_NONCE_LENGTH = 8
MAX_NONCE_LENGTH = 128
#: 惰性清理频率（每消费 N 次顺带删过期行，避免重放表只增不删）。
_PRUNE_EVERY = 64
ALLOWED_JWS_ALGS = ("EdDSA",)


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _public_key_from_jwk(jwk: dict[str, Any]) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise PermissionDenied("binding key is not an Ed25519 public JWK")
    x = jwk.get("x")
    if not isinstance(x, str) or x == "":
        raise PermissionDenied("binding key JWK missing x")
    return Ed25519PublicKey.from_public_bytes(_b64url_decode(x))


def body_sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _find_binding(
    conn: sqlite3.Connection, catalog_agent_id: str, kid: str
) -> sqlite3.Row:
    row = conn.execute(
        "select * from runtime_bindings where catalog_agent_id = ? and key_id = ?"
        " and status = 'active' order by binding_version desc limit 1",
        (catalog_agent_id, kid),
    ).fetchone()
    if row is None:
        # 未知 kid / 非 active 绑定：不区分原因（不做存在性 oracle）。
        raise PermissionDenied("no active binding for this key")
    return row


def verify_runtime_request(
    conn: sqlite3.Connection,
    *,
    catalog_agent_id: str,
    jws: str,
    expected_fields: dict[str, Any],
    now: datetime | None = None,
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
) -> dict[str, Any]:
    """验签并返回负载。`expected_fields` 是请求体里应被签名覆盖的字段（键名一致）。

    失败一律 PermissionDenied（403）；缺字段或类型不符返回 ValidationError（400）。
    """
    if not isinstance(jws, str) or jws.count(".") != 2:
        raise PermissionDenied("missing or malformed request signature")
    header_segment, payload_segment, signature_segment = jws.split(".")
    try:
        header = json.loads(_b64url_decode(header_segment))
        payload = json.loads(_b64url_decode(payload_segment))
        signature = _b64url_decode(signature_segment)
    except (ValueError, json.JSONDecodeError) as exc:  # pragma: no cover - 防御性
        raise PermissionDenied(f"malformed request signature: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise PermissionDenied("malformed request signature")
    alg = header.get("alg")
    if alg not in ALLOWED_JWS_ALGS:
        # 固定算法：拒绝 none 与任何回退（设计 §11.4）。
        raise PermissionDenied(f"unsupported JWS alg: {alg!r}")
    kid = header.get("kid")
    if not isinstance(kid, str) or kid == "":
        raise PermissionDenied("request signature missing kid")

    binding = _find_binding(conn, catalog_agent_id, kid)
    current = now or datetime.now(timezone.utc)
    expires_at = str(binding["expires_at"] or "")
    if expires_at:
        try:
            if datetime.fromisoformat(expires_at) <= current:
                raise PermissionDenied("runtime binding expired")
        except ValueError as exc:
            raise PermissionDenied(f"binding expiry is malformed: {expires_at}") from exc

    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    public_key = _public_key_from_jwk(json.loads(str(binding["key_jwk_json"])))
    try:
        public_key.verify(signature, signing_input)
    except InvalidSignature as exc:
        raise PermissionDenied("request signature verification failed") from exc

    # 被签名字段必须与请求体逐项一致（防止签名被挪用到别的发布）。
    if str(payload.get("binding_id", "")) != str(binding["binding_id"]):
        raise PermissionDenied("signature binding_id mismatch")
    for field, actual in expected_fields.items():
        if field not in payload:
            raise ValidationError(f"request signature does not cover required field: {field}")
        if _normalize(payload[field]) != _normalize(actual):
            raise PermissionDenied(f"signature field mismatch: {field}")
    issued_at = str(payload.get("issued_at", ""))
    try:
        issued = datetime.fromisoformat(issued_at)
    except ValueError as exc:
        raise ValidationError(f"signature issued_at is malformed: {issued_at}") from exc
    if issued.tzinfo is None:
        issued = issued.replace(tzinfo=timezone.utc)
    if abs((current - issued).total_seconds()) > clock_skew_seconds:
        raise PermissionDenied("request signature outside the allowed clock skew window")

    # 全部校验通过后才消费 nonce：无效签名不得"占掉"合法请求的 nonce（DoS 面）。
    nonce = payload.get("nonce")
    if not isinstance(nonce, str) or nonce == "":
        raise ValidationError("request signature missing nonce")
    consume_request_nonce(
        conn,
        key_id=str(binding["key_id"]),
        nonce=nonce,
        issued_at=issued_at,
        now=current,
        window_seconds=clock_skew_seconds,
    )
    return payload


def consume_request_nonce(
    conn: sqlite3.Connection,
    *,
    key_id: str,
    nonce: str,
    issued_at: str,
    now: datetime | None = None,
    window_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
) -> None:
    """消费一次 `(key_id, nonce)`；已被消费过即拒绝（重放）。

    用主键冲突做判定，而不是"先查后插"：并发下先查后插会双放行。
    """
    text = str(nonce)
    if len(text) < MIN_NONCE_LENGTH or len(text) > MAX_NONCE_LENGTH:
        raise ValidationError(
            f"request nonce length must be within {MIN_NONCE_LENGTH}..{MAX_NONCE_LENGTH}"
        )
    current = now or datetime.now(timezone.utc)
    try:
        issued = datetime.fromisoformat(str(issued_at))
    except ValueError as exc:
        raise ValidationError(f"signature issued_at is malformed: {issued_at}") from exc
    if issued.tzinfo is None:
        issued = issued.replace(tzinfo=timezone.utc)
    expires_at = (issued + timedelta(seconds=window_seconds)).isoformat()
    cursor = conn.execute(
        "insert into control_plane_nonces (key_id, nonce, issued_at, expires_at, created_at)"
        " values (?, ?, ?, ?, ?) on conflict(key_id, nonce) do nothing",
        (str(key_id), text, str(issued_at), expires_at, current.isoformat()),
    )
    if cursor.rowcount == 0:
        raise PermissionDenied("request signature replayed (nonce already used)")
    if _prune_counter[0] % _PRUNE_EVERY == 0:
        conn.execute("delete from control_plane_nonces where expires_at < ?", (current.isoformat(),))
    _prune_counter[0] += 1


#: 惰性清理计数器（模块级；进程内单调递增即可，不需要持久化）。
_prune_counter = [0]


def _normalize(value: Any) -> str:
    """被签名字段的比较口径：整数与等价字符串视为相同，其余按字符串比较。"""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return str(value)


def verify_binding_possession(
    *,
    jws: str,
    public_jwk: dict[str, Any],
    expected_fields: dict[str, Any],
    now: datetime | None = None,
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
) -> dict[str, Any]:
    """**首次绑定**的持钥证明：请求体自带公钥，验签必须用该公钥并通过。

    与 ``verify_runtime_request`` 的区别：这里没有"已知绑定"可查——信任来自
    「只有私钥持有者能对请求签名」+ 调用方另行给出的商家授权/管理员凭据。
    """
    if not isinstance(jws, str) or jws.count(".") != 2:
        raise PermissionDenied("missing or malformed possession proof")
    header_segment, payload_segment, signature_segment = jws.split(".")
    header = json.loads(_b64url_decode(header_segment))
    payload = json.loads(_b64url_decode(payload_segment))
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise PermissionDenied("malformed possession proof")
    if header.get("alg") not in ALLOWED_JWS_ALGS:
        raise PermissionDenied(f"unsupported JWS alg: {header.get('alg')!r}")
    kid = header.get("kid")
    if not isinstance(kid, str) or kid == "":
        raise PermissionDenied("possession proof missing kid")
    public_key = _public_key_from_jwk(public_jwk)
    try:
        public_key.verify(
            _b64url_decode(signature_segment), f"{header_segment}.{payload_segment}".encode("ascii")
        )
    except InvalidSignature as exc:
        raise PermissionDenied("possession proof verification failed") from exc
    if str(payload.get("key_id", "")) != kid:
        raise PermissionDenied("possession proof kid does not match the bound key_id")
    for field, actual in expected_fields.items():
        if field not in payload:
            raise ValidationError(f"possession proof does not cover required field: {field}")
        if _normalize(payload[field]) != _normalize(actual):
            raise PermissionDenied(f"possession proof field mismatch: {field}")
    issued_at = str(payload.get("issued_at", ""))
    try:
        issued = datetime.fromisoformat(issued_at)
    except ValueError as exc:
        raise ValidationError(f"possession proof issued_at is malformed: {issued_at}") from exc
    if issued.tzinfo is None:
        issued = issued.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    if abs((current - issued).total_seconds()) > clock_skew_seconds:
        raise PermissionDenied("possession proof outside the allowed clock skew window")
    return payload


# ---------------------------------------------------------------------------
# 参考签发（测试与本地联调用；生产签名方是 Runtime 自己）
# ---------------------------------------------------------------------------


def sign_runtime_request(
    *,
    kid: str,
    private_key_pem: str,
    signed_fields: dict[str, Any],
    issued_at: str,
    nonce: str,
) -> str:
    """用 Runtime 私钥签一个 compact JWS（EdDSA）；与 kiwi TS 侧 `signCompactJws` 同形状。"""
    header = {"alg": "EdDSA", "kid": kid}
    payload = {**signed_fields, "issued_at": issued_at, "nonce": nonce}
    header_segment = base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).rstrip(b"=").decode()
    payload_segment = (
        base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=").decode()
    )
    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    key = load_pem_private_key(private_key_pem.encode(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValidationError("signing key must be an Ed25519 private key")
    signature = key.sign(signing_input)
    signature_segment = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    return f"{header_segment}.{payload_segment}.{signature_segment}"
