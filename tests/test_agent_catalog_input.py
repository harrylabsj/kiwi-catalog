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

"""Characterization tests for the extracted register-input validation leaf
(T8 pure-structure split of ``handlers/agent_catalog.py``).

These tests lock the pure CD #8 register-input contract validation and the
optional ``reason`` field shaping that previously lived in the handler module:
required/unknown/type/enum/extra-field rejection (``additionalProperties:
false``), auth/idempotency field stripping before validation, the
``register payload invalid: …`` error copy, and the cached
``Draft7Validator`` identity.  The facade delegation tests prove
``handlers/agent_catalog`` still re-exports the same function objects, so the
module-private compat surface and call order are preserved.
"""

from __future__ import annotations

import jsonschema
import pytest

from kiwi_catalog.api import agent_catalog_input
from kiwi_catalog.api.agent_catalog_input import (
    _payload_reason,
    _register_input_schema,
    _validate_register_input,
)
from kiwi_catalog.core.errors import ValidationError


# ── Module surface + facade identity ─────────────────────────────────────────


def test_agent_catalog_input_module_exports_only_input_surface() -> None:
    assert set(agent_catalog_input.__all__) == {
        "_register_input_schema",
        "_validate_register_input",
        "_payload_reason",
    }


def test_agent_catalog_input_names_reexported_from_handler_facade() -> None:
    from kiwi_catalog.api.handlers import agent_catalog

    assert agent_catalog._validate_register_input is _validate_register_input
    assert agent_catalog._payload_reason is _payload_reason
    assert agent_catalog._register_input_schema is _register_input_schema


def test_register_input_schema_is_cached_draft7_validator() -> None:
    validator = _register_input_schema()
    assert isinstance(validator, jsonschema.Draft7Validator)
    # 惰性加载缓存：同一模块全局返回同一个 validator 实例（identity 保留）。
    assert _register_input_schema() is validator


# ── _validate_register_input: required / unknown / type / enum / extra ───────


def test_validate_register_input_accepts_minimal_domain() -> None:
    _validate_register_input({"domain": "merchant.example"})


def test_validate_register_input_rejects_missing_required_domain() -> None:
    with pytest.raises(ValidationError, match=r"^register payload invalid: .*'domain'"):
        _validate_register_input({})
    with pytest.raises(ValidationError, match=r"^register payload invalid:"):
        _validate_register_input({"display_name": "Acme"})


def test_validate_register_input_rejects_unknown_extra_field() -> None:
    # CD #8：additionalProperties:false —— 未知字段/私有经营数据在 schema 层拒绝。
    with pytest.raises(ValidationError, match=r"^register payload invalid: .*'bogus_field'"):
        _validate_register_input({"domain": "merchant.example", "bogus_field": "x"})


def test_validate_register_input_rejects_private_business_field() -> None:
    with pytest.raises(ValidationError, match=r"^register payload invalid:"):
        _validate_register_input(
            {"domain": "merchant.example", "floor_price": {"currency": "CNY", "amount_minor": 100}}
        )


def test_validate_register_input_rejects_wrong_type() -> None:
    # type 错误的 message 只报值不报字段名（42 is not of type 'string'）。
    with pytest.raises(ValidationError, match=r"^register payload invalid:"):
        _validate_register_input({"domain": 42})


def test_validate_register_input_rejects_invalid_hosting_mode_enum() -> None:
    with pytest.raises(ValidationError, match=r"^register payload invalid:"):
        _validate_register_input({"domain": "merchant.example", "hosting_mode": "bogus"})


def test_validate_register_input_accepts_hosting_mode_alias() -> None:
    # schema 允许 legacy 4 值 + canonical alias（direct_only/hosted_only 归一化）。
    for mode in ("direct", "hosted", "hybrid", "unknown", "direct_only", "hosted_only"):
        _validate_register_input({"domain": "merchant.example", "hosting_mode": mode})


def test_validate_register_input_rejects_invalid_handoff_destination_type() -> None:
    with pytest.raises(
        ValidationError, match=r"^register payload invalid: .*'not_a_destination'"
    ):
        _validate_register_input(
            {"domain": "merchant.example", "handoff_destination_types": ["not_a_destination"]}
        )


def test_validate_register_input_accepts_known_handoff_destination_type() -> None:
    _validate_register_input(
        {"domain": "merchant.example", "handoff_destination_types": ["ucp_checkout"]}
    )


def test_validate_register_input_rejects_extra_field_in_nested_skill() -> None:
    # 嵌套 skills 项同样 additionalProperties:false——未知字段硬拒。
    with pytest.raises(ValidationError, match=r"^register payload invalid: .*'bogus'"):
        _validate_register_input(
            {
                "domain": "merchant.example",
                "skills": [{"skill_id": "s", "name": "n", "bogus": 1}],
            }
        )


def test_validate_register_input_rejects_missing_nested_skill_required() -> None:
    with pytest.raises(ValidationError, match=r"^register payload invalid: .*'name'"):
        _validate_register_input(
            {"domain": "merchant.example", "skills": [{"skill_id": "s"}]}
        )


def test_validate_register_input_strips_auth_and_idempotency_fields() -> None:
    # 认证/幂等字段在校验前剥离——带全量字段的合法注册不受影响。
    _validate_register_input(
        {
            "domain": "merchant.example",
            "owner_token": "t",
            "_auth_token": "t",
            "admin_token": "t",
            "idempotency_key": "k",
            "_idempotency_key": "k",
        }
    )


def test_validate_register_input_none_payload_behaves_like_empty_object() -> None:
    # (payload or {}) 防御：None 输入等价于空对象 → required 校验失败（非 TypeError）。
    with pytest.raises(ValidationError, match=r"^register payload invalid:"):
        _validate_register_input(None)


# ── _payload_reason: trim / default / boundary ──────────────────────────────


def test_payload_reason_defaults_to_empty_string() -> None:
    assert _payload_reason(None) == ""
    assert _payload_reason({}) == ""
    assert _payload_reason({"reason": None}) == ""
    assert _payload_reason({"reason": ""}) == ""


def test_payload_reason_trims_whitespace() -> None:
    assert _payload_reason({"reason": "   "}) == ""
    assert _payload_reason({"reason": "  policy violation  "}) == "policy violation"


def test_payload_reason_strips_only_ends() -> None:
    assert _payload_reason({"reason": "line1\nline2"}) == "line1\nline2"


def test_payload_reason_coerces_non_string_values() -> None:
    # str() 强制转换：非字符串 reason 变为其字符串形态。
    assert _payload_reason({"reason": 123}) == "123"


def test_payload_reason_falsy_values_fall_back_to_default() -> None:
    # (reason or "") 语义：falsy 值（0 / False）按缺省处理为空串。
    assert _payload_reason({"reason": 0}) == ""
    assert _payload_reason({"reason": False}) == ""
