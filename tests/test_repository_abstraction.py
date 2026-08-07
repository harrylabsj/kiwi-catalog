"""CatalogRepository abstraction contract tests (§19.2, extraction phase 2).

固化 CatalogRepository 契约与 SQLite 现状实现函数的映射关系，防止接口
漂移（Conversation/Audit 契约属 marketplace 域——切割分水岭，不在本仓）：

1. Protocol 声明的每个方法都有 SQLite 实现函数（显式映射表）；
2. 反向检查：``sqlite_repository`` 的全部公开函数（除 ID 生成纯函数
   ``new_catalog_agent_id`` 与 re-export 的 ``now_iso``）必须被映射表覆盖。

契约方法名与 SQLite 实现函数名允许不同（如 Protocol ``search`` ↔
``search_catalog_agents``）。
"""

from __future__ import annotations

import inspect
import unittest

from kiwi_catalog.agent_catalog import repository, sqlite_repository

# Protocol 方法名 → SQLite 现状实现函数名（catalog 域）。
_CATALOG_MAPPING: dict[str, str] = {
    "upsert_catalog_agent": "upsert_catalog_agent",
    "require_catalog_agent": "require_catalog_agent",
    "get_catalog_agent": "get_catalog_agent_with_merchant",
    "get_catalog_agent_by_domain": "get_catalog_agent_by_domain",
    "list_catalog_agents": "list_catalog_agents",
    "list_catalog_agents_by_merchant": "list_catalog_agents_by_merchant",
    "set_verification_status": "set_verification_status",
    "set_state_domains": "set_state_domains",
    "set_catalog_agent_merchant": "set_catalog_agent_merchant",
    "list_capabilities": "list_capabilities",
    "upsert_capabilities": "replace_capabilities",
    "list_endpoints": "list_endpoints",
    "upsert_profile_endpoints": "upsert_profile_endpoints",
    "replace_skills": "replace_skills",
    "list_skills": "list_skills",
    "insert_profile_snapshot": "insert_profile_snapshot",
    "latest_profile_snapshot": "latest_profile_snapshot",
    "list_profile_snapshots": "list_profile_snapshots",
    "insert_verification": "insert_verification",
    "latest_verification": "latest_verification",
    "list_verifications": "list_verifications",
    "insert_trust_observation": "insert_trust_observation",
    "list_trust_observations": "list_trust_observations",
    "count_trust_observations": "count_trust_observations",
    "trust_observation_counts_by_kind": "trust_observation_counts_by_kind",
    "search": "search_catalog_agents",
    "append_audit": "append_catalog_audit",
    "enforce_catalog_register_domain_limit": "enforce_catalog_register_domain_limit",
}

# sqlite_repository 中非持久化操作的函数，反向检查豁免：
# - new_catalog_agent_id: ID 生成纯函数（不读不写）；
# - now_iso: 从 db.session re-export 的时间工具（inspect 误报为本地函数）。
_NON_PERSISTENCE_FUNCTIONS = frozenset({"new_catalog_agent_id", "now_iso"})


def _protocol_methods(protocol: type) -> set[str]:
    return {name for name in dir(protocol) if not name.startswith("_")}


def _public_functions(module: object) -> set[str]:
    return {
        name
        for name, member in inspect.getmembers(module, inspect.isfunction)
        if not name.startswith("_")
    }


class CatalogRepositoryMappingTest(unittest.TestCase):
    def test_every_protocol_method_has_sqlite_implementation(self) -> None:
        missing = sorted(set(_CATALOG_MAPPING) - _protocol_methods(repository.CatalogRepository))
        self.assertEqual(missing, [])
        for protocol_method, impl_name in _CATALOG_MAPPING.items():
            self.assertTrue(
                callable(getattr(sqlite_repository, impl_name, None)),
                f"{impl_name!r} (impl of {protocol_method!r}) not found in sqlite_repository",
            )

    def test_every_sqlite_catalog_function_is_covered(self) -> None:
        uncovered = sorted(
            _public_functions(sqlite_repository)
            - set(_CATALOG_MAPPING.values())
            - _NON_PERSISTENCE_FUNCTIONS
        )
        self.assertEqual(
            uncovered, [], "sqlite_repository functions missing from the CatalogRepository mapping"
        )


if __name__ == "__main__":
    unittest.main()
