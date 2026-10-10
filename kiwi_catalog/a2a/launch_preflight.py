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

"""上线预检（A40-3）：绑定签发必需配置的显式校验。

背景（A37）：`KIWI_CATALOG_PUBLIC_ORIGIN` 缺失时，签发路径按设计 fail-closed
（PermissionDenied → runtime-bindings 403），但历史部署在启动期没有任何信号，
91 次 403 只能事后翻日志定责。本模块把「签发必需配置」抽成可在启动期/部署期
运行的显式检查，消除静默失败盲区：

- `issuance_preflight()` 逐项返回结构化结果（固定 code，不抛异常）；
- `kiwi-catalog-api --check-config` 全部通过才退出 0（可接 systemd ExecStartPre
  或部署清单）； serving 启动路径只**警告**不阻断（签发仍是运行时 fail-closed，
  语义不变）。

红线：本检查只读受控配置，不访问网络、不生成密钥、不输出任何私钥材料；
kid/thumbprint/origin 都是公开元数据。
"""

from __future__ import annotations

import os
from typing import Any, Mapping

from kiwi_catalog.a2a.binding_claims import catalog_public_origin, load_issuer_key_set

#: 预检项与固定 code（fail-closed 语义与签发路径一致，只做"提前可见"）。
ISSUER_KEY_CHECK = "issuer_key"
PUBLIC_ORIGIN_CHECK = "public_origin"
ISSUER_KEY_OK = "ISSUER_KEY_OK"
ISSUER_KEY_REJECTED = "ISSUER_KEY_REJECTED"
PUBLIC_ORIGIN_OK = "PUBLIC_ORIGIN_OK"
PUBLIC_ORIGIN_REJECTED = "PUBLIC_ORIGIN_REJECTED"


def issuance_preflight(env: Mapping[str, str] | None = None) -> list[dict[str, Any]]:
    """校验绑定签发必需的 issuer 身份与公开 origin；返回逐项结果。

    每项形如 ``{"check", "ok", "code", ...}``：通过时附带 kid/thumbprint（issuer）
    或 origin（public_origin）等公开元数据；失败时附带签发路径会抛出的同一
    `detail` 文本。任何异常（含配置缺失、文件损坏、非 Ed25519）都折叠为对应
    检查项的失败，而不是让预检本身崩溃。
    """
    checks: list[dict[str, Any]] = []
    try:
        issuer = load_issuer_key_set(env).signing_identity()
        checks.append(
            {
                "check": ISSUER_KEY_CHECK,
                "ok": True,
                "code": ISSUER_KEY_OK,
                "kid": issuer.kid,
                "thumbprint": issuer.thumbprint,
            }
        )
    except Exception as exc:  # 预检边界：任何失败都转成显式报告项。
        checks.append(
            {
                "check": ISSUER_KEY_CHECK,
                "ok": False,
                "code": ISSUER_KEY_REJECTED,
                "detail": str(exc),
            }
        )
    source = env if env is not None else os.environ
    try:
        origin = catalog_public_origin(source)
        checks.append(
            {
                "check": PUBLIC_ORIGIN_CHECK,
                "ok": True,
                "code": PUBLIC_ORIGIN_OK,
                "origin": origin,
            }
        )
    except Exception as exc:  # 同上：fail-closed 文本原样透出，便于定责。
        checks.append(
            {
                "check": PUBLIC_ORIGIN_CHECK,
                "ok": False,
                "code": PUBLIC_ORIGIN_REJECTED,
                "detail": str(exc),
            }
        )
    return checks


def preflight_failed(checks: list[dict[str, Any]]) -> bool:
    return any(not check.get("ok") for check in checks)


def format_preflight_lines(checks: list[dict[str, Any]]) -> list[str]:
    """人类可读的逐行报告（不含任何私钥/凭据材料）。"""
    lines: list[str] = []
    for check in checks:
        status = "OK" if check.get("ok") else "FAIL"
        detail = "" if check.get("ok") else f" — {check.get('detail', '')}"
        extra = ""
        if check.get("code") == ISSUER_KEY_OK:
            extra = f" kid={check.get('kid')} thumbprint={check.get('thumbprint')}"
        elif check.get("code") == PUBLIC_ORIGIN_OK:
            extra = f" origin={check.get('origin')}"
        lines.append(f"[{status}] {check.get('check')}: {check.get('code')}{extra}{detail}")
    return lines
