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

"""HTTP 缓存原语（§18 响应校验器 + 内容哈希）。

只保留被消费的函数（fallback_asgi 的 ETag 304、agent_verification 的
snapshot content_hash）。§18 三态新鲜度机制（CacheState /
build_conditional_headers / snapshot_meta / compute_cache_state / CacheDirective）
的服务层落地不在本版本——已删除，避免死代码与实现的假象。
"""
from __future__ import annotations

import hashlib


def compute_content_hash(content: str | bytes) -> str:
    """Compute a SHA-256 hex digest of the raw response body."""
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def compute_etag(content: str | bytes) -> str:
    """Compute a strong ETag (quoted content hash) for an HTTP response body.

    §18 — server-side generated validator: the same content always yields the
    same ETag, and the value is opaque to clients (they only echo it back).
    """
    return f'"{compute_content_hash(content)}"'


def etag_matches(if_none_match: str, etag: str) -> bool:
    """True when an ``If-None-Match`` header value matches *etag*.

    Handles strong and weak ETags and the ``*`` wildcard.  The header is
    untrusted request data; every comparison is against the server's own
    computed *etag*, so a malformed header simply never matches.
    """
    expected = etag.strip('"')
    for raw in if_none_match.split(","):
        token = raw.strip()
        if token == "*":
            return True
        if token.startswith("W/"):
            token = token[2:].strip()
        token = token.strip('"')
        if token and token == expected:
            return True
    return False
