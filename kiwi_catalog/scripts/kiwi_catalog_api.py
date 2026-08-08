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
"""

from __future__ import annotations

import argparse

from kiwi_catalog.config import DEFAULT_DB_PATH


def main() -> None:
    parser = argparse.ArgumentParser(description="kiwi-catalog standalone service")
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH), help="Catalog SQLite file")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8600)
    args = parser.parse_args()

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
