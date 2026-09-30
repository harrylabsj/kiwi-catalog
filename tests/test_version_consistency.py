"""版本一致性：源码常量与发布元数据必须同步。

0.5.2 的主线只把 pyproject 提到 0.5.2，``kiwi_catalog.VERSION`` 仍是 0.5.0
（把常量同步到 0.5.1 的提交只存在于未合并的发布分支上），于是
``kiwi-catalog --version`` 在 0.5.2 安装里报旧版本号。这里把两者锁死。
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from kiwi_catalog import VERSION

ROOT = Path(__file__).resolve().parents[1]


def test_version_constant_matches_pyproject() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = pyproject["project"]["version"]
    assert VERSION == declared, (
        f"kiwi_catalog.VERSION ({VERSION!r}) 与 pyproject.toml ({declared!r}) 不一致；"
        "发版时必须同步 kiwi_catalog/__init__.py"
    )
