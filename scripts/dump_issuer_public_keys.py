#!/usr/bin/env python3
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

"""导出 Catalog 发行者**公钥集合**（SIG-04 的受控分发面）。

买方与各 Runtime 需要「kid → 公钥」才能验签绑定声明；设计 §11.6/§12.1 明确这份
信任根必须来自**受控渠道**，绝不根据声明里的任意 URL 去下载。本脚本就是那个渠道的
取数端：把当前密钥集合的公开部分打出来，交给发布流程分发。

三条纪律（都写进实现，不靠约定）：

1. **只输出公开部分**：`IssuerKeySet.public_keys()` 只含 `{state, jwk}`，不含任何私钥
   参数；本脚本额外做一次兜底扫描，出现 `d` 参数或 PEM 头即失败退出（而不是打印出来）。
2. **未配置即失败**：没有受控密钥文件/单密钥 env 时以非零码退出——不生成临时钥匙，
   也不输出一份"看起来像公钥集合"的空文档。
3. **不带任何私钥路径之外的元数据**：输出只有 kid → {state, jwk}，不泄漏文件布局。

用法::

    KIWI_CATALOG_ISSUER_KEYS_FILE=… python3 scripts/dump_issuer_public_keys.py
    python3 scripts/dump_issuer_public_keys.py --out issuer-public-keys.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kiwi_catalog.a2a.binding_claims import IssuerKeySet, load_issuer_key_set  # noqa: E402
from kiwi_catalog.core.errors import ShoppingCliError  # noqa: E402


def assert_public_only(key_set: IssuerKeySet) -> None:
    """兜底扫描：输出里出现任何私钥痕迹就以失败退出（不打印、不降级为警告）。"""
    serialized = json.dumps(key_set.public_keys(), ensure_ascii=False)
    for forbidden in ('"d"', "PRIVATE KEY", "private_key", "BEGIN "):
        if forbidden in serialized:
            raise SystemExit(
                f"refusing to emit issuer key set: output contains private material ({forbidden})"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        help="写入文件（缺省打印到 stdout；父目录必须已存在，不自动创建）",
    )
    args = parser.parse_args()

    try:
        key_set = load_issuer_key_set()
    except ShoppingCliError as exc:
        # 未配置/配置非法：以非零码退出，绝不输出空集合冒充成功。
        print(f"issuer key set is not usable: {exc}", file=sys.stderr)
        return 2

    assert_public_only(key_set)
    document = {
        "schema_version": "0.1.2",
        "source": "catalog-issuer-key-set",
        "keys": key_set.public_keys(),
    }
    payload = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.out is not None:
        if not args.out.parent.is_dir():
            print(f"output directory does not exist: {args.out.parent}", file=sys.stderr)
            return 2
        args.out.write_text(payload, encoding="utf-8")
        print(f"wrote {len(document['keys'])} public key(s) to {args.out}")
    else:
        sys.stdout.write(payload)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
