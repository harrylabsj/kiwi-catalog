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

"""kiwi-catalog standalone service entry point (阶段 1 裁剪原型).

只暴露 Agent Catalog 域（注册/验证/搜索/治理 + hosted 发布面）——见
``shopping_cli.api.app.create_catalog_app``。  DB 文件首次启动自动初始化。

用法::

    python scripts/kiwi_catalog_api.py --db catalog.sqlite --host 127.0.0.1 --port 8600

需要 ``shopping-cli[api]``（uvicorn）。  FastAPI 未安装时回退到纯 ASGI
serve（同样经 uvicorn 运行 fallback app）。

上线预检（A40-3）::

    kiwi-catalog-api --check-config

校验绑定签发必需配置（issuer 身份 + ``KIWI_CATALOG_PUBLIC_ORIGIN``），全部
通过才退出 0，失败退出 1 并逐项打印固定 code——可接 systemd ExecStartPre 或
部署清单；消除「配置缺失 → 签发静默 403」盲区。
"""

from __future__ import annotations

import argparse
import sys

from kiwi_catalog.config import DEFAULT_DB_PATH


def main() -> None:
    parser = argparse.ArgumentParser(description="kiwi-catalog standalone service")
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH), help="Catalog SQLite file")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8600)
    parser.add_argument(
        "--check-config",
        action="store_true",
        dest="check_config",
        help="Preflight only: validate issuance-required config (issuer key + public origin),"
        " exit 1 on failure; never serves.",
    )
    args = parser.parse_args()

    # 预检（A40-3）：只读受控配置，不触网、不碰 DB、不输出私钥材料。
    from kiwi_catalog.a2a.launch_preflight import (
        format_preflight_lines,
        issuance_preflight,
        preflight_failed,
    )

    checks = issuance_preflight()
    if args.check_config:
        for line in format_preflight_lines(checks):
            print(line)
        raise SystemExit(1 if preflight_failed(checks) else 0)

    # serving 路径：配置缺失只**显式警告**、不阻断启动——签发仍是运行时
    # fail-closed（语义不变），但不再静默（A37：91 次 403 无启动期信号）。
    if preflight_failed(checks):
        print(
            "kiwi-catalog launch preflight WARNING — issuance-required config is"
            " incomplete; runtime-bindings issuance will fail until fixed"
            " (run `kiwi-catalog-api --check-config` for details):",
            file=sys.stderr,
        )
        for line in format_preflight_lines(checks):
            print(f"  {line}", file=sys.stderr)

    try:
        import uvicorn
    except ImportError:
        raise SystemExit(
            "uvicorn is required to serve the kiwi-catalog API. "
            "Install shopping-cli[api] (or pip install uvicorn)."
        )

    from kiwi_catalog.api.app import create_catalog_app

    uvicorn.run(create_catalog_app(args.db), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
