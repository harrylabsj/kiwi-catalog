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

"""Runtime metrics registry for the Agent Catalog (§24).

进程内、线程安全的运行时指标。与 ``agent_catalog_metrics`` 的静态 SQL
统计正交：本模块只记录进程存活期间的运行时活动（fetch/search 延迟、
队列深度、hosted gateway 请求、发现→协商漏斗），不触碰数据库。

隐私边界与存量 metrics 模块一致：指标只含聚合数字，绝不包含 URL、
域名、merchant 身份、observation 内容等私货。

设计决策（docstring 固化）
--------------------------
1. 延迟只保留 count/sum/max，avg 由 snapshot 计算——不留全量样本，
   打点是 O(1) 锁内操作，不进入网络热路径的开销失控。
2. ratio 指标（direct_a2a_ratio / hosted_gateway_ratio）：direct 侧当前
   没有运行时调用路径（v3.0 无 direct A2A 客户端，catalog 只有数据形态），
   所以两个 ratio 由 catalog 数据的 hosting_mode 分布推导（在
   ``catalog_stats()`` 里计算），这里只记录 hosted gateway 的真实运行时
   请求计数 ``hosted_gateway_requests``。
3. 漏斗事件点映射：``discovery`` = register 成功；``verified`` = 验证管线
   达到任一 verified 状态（domain/agent/commerce_verified）；``compatible``
   当前没有运行时事件点（v3.0 无兼容性评估阶段，只有 CandidateAgent DTO
   数据形态），故不计数；``connected`` = 会话创建（buyer↔merchant 连接）；
   ``negotiation_started`` = 会话创建时携带首条 buyer 文本消息。
4. 除零边界：错误率/转化率分母为 0 时返回 0.0（snapshot 固化）。
"""

from __future__ import annotations

import threading
from typing import Any

# §24 漏斗 stage（compatible 无事件点，见模块 docstring）。
FUNNEL_STAGES = ("discovery", "verified", "connected", "negotiation_started")


class RuntimeMetricsRegistry:
    """Thread-safe in-process metrics registry.

    Holds three primitive types plus the §24 funnel:

    - counters: monotonically increasing integers (``increment_counter``).
    - latency recorders: per-name count/sum/max; avg is computed at snapshot
      time (``record_latency``).
    - gauges: last-value-wins floats (``set_gauge``).
    - funnel: per-stage counters (``increment_funnel``).

    All mutation happens under a single ``threading.Lock``; every operation
    is O(1) so worker and API threads can call it freely.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = {}
        self._latency: dict[str, dict[str, float]] = {}
        self._gauges: dict[str, float] = {}
        self._funnel: dict[str, int] = {}

    # ── Mutation (O(1), lock-guarded) ─────────────────────────────────────

    def increment_counter(self, name: str, delta: int = 1) -> None:
        """Increment counter *name* by *delta* (default 1)."""
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + delta

    def record_latency(self, name: str, duration_s: float) -> None:
        """Record one latency sample; keeps count/sum/max only."""
        if duration_s < 0:
            # 审查 P3：指标埋点不得打挂被埋点请求——负值（时钟异常）按 0 记
            return
        with self._lock:
            rec = self._latency.get(name)
            if rec is None:
                self._latency[name] = {"count": 1.0, "sum": duration_s, "max": duration_s}
                return
            rec["count"] += 1.0
            rec["sum"] += duration_s
            if duration_s > rec["max"]:
                rec["max"] = duration_s

    def set_gauge(self, name: str, value: float) -> None:
        """Set gauge *name* to *value* (last write wins)."""
        with self._lock:
            self._gauges[name] = float(value)

    def increment_funnel(self, stage: str) -> None:
        """Increment one funnel stage counter (unknown stages are ignored)."""
        if stage not in FUNNEL_STAGES:
            return
        with self._lock:
            self._funnel[stage] = self._funnel.get(stage, 0) + 1

    # ── Snapshot ──────────────────────────────────────────────────────────

    def snapshot(self) -> dict[str, Any]:
        """Return a deep copy of the registry state.

        Structure::

            {
                "counters": {name: int, ...},
                "latency": {name: {"count": n, "sum": s, "max": m, "avg": a}, ...},
                "gauges": {name: float, ...},
                "funnel": {stage: int, ...},   # only stages with event points
            }

        ``avg`` is computed here; a recorder with count == 0 is not present.
        """
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
            funnel = dict(self._funnel)
            latency: dict[str, Any] = {}
            for name, rec in self._latency.items():
                count = rec["count"]
                latency[name] = {
                    "count": int(count),
                    "sum": rec["sum"],
                    "max": rec["max"],
                    "avg": rec["sum"] / count,
                }
        return {"counters": counters, "latency": latency, "gauges": gauges, "funnel": funnel}

    def reset(self) -> None:
        """Clear every metric (tests and process-restart semantics)."""
        with self._lock:
            self._counters.clear()
            self._latency.clear()
            self._gauges.clear()
            self._funnel.clear()


# ── Single global instance ────────────────────────────────────────────────────

_REGISTRY = RuntimeMetricsRegistry()


def get_runtime_metrics() -> RuntimeMetricsRegistry:
    """Return the process-wide metrics registry."""
    return _REGISTRY


def reset_runtime_metrics() -> None:
    """Reset the process-wide registry (tests)."""
    _REGISTRY.reset()


def snapshot_runtime_metrics() -> dict[str, Any]:
    """Snapshot the process-wide registry (counters/latency/gauges/funnel)."""
    return _REGISTRY.snapshot()


# ── Instrumentation helpers (fixed metric names, §24) ─────────────────────────

# 计数：profile_fetch_latency 按成功/失败分开（error rate 由 snapshot 计算）。
_PROFILE_FETCH_OK = "profile_fetch_ok"
_PROFILE_FETCH_ERROR = "profile_fetch_error"


def record_profile_fetch(duration_s: float, *, ok: bool) -> None:
    """Record one profile fetch: latency + ok/error counter (§24).

    ``ok`` covers both 2xx success and 304 not-modified (a conditional
    request that hit the cache).  Errors are SSRF blocks, transport failures,
    limit rejections, and non-2xx/304 HTTP statuses.
    """
    _REGISTRY.record_latency("profile_fetch_latency", duration_s)
    _REGISTRY.increment_counter(_PROFILE_FETCH_OK if ok else _PROFILE_FETCH_ERROR)


def record_search(duration_s: float, result_count: int) -> None:
    """Record one catalog search: latency + total result count (§24)."""
    _REGISTRY.record_latency("catalog_search_latency", duration_s)
    _REGISTRY.increment_counter("catalog_search_result_count", result_count)


def set_queue_depth(n: int) -> None:
    """Set the verification queue depth gauge (§24)."""
    _REGISTRY.set_gauge("verification_queue_depth", float(n))


def record_hosted_gateway_request() -> None:
    """Count one hosted gateway request (§24 hosted_gateway_ratio runtime side)."""
    _REGISTRY.increment_counter("hosted_gateway_requests")


def record_funnel(stage: str) -> None:
    """Count one funnel event (§24).  Stage must be in FUNNEL_STAGES."""
    _REGISTRY.increment_funnel(stage)


def derived_metrics(snapshot: dict[str, Any] | None = None) -> dict[str, float]:
    """Compute §24 derived metrics from a registry snapshot.

    Returns::

        {
            "profile_fetch_error_rate": error/(ok+error) or 0.0,
            "catalog_to_connection_conversion": connected/discovery or 0.0,
        }

    Division-by-zero resolves to 0.0 (decision fixed in module docstring).
    """
    snap = snapshot if snapshot is not None else snapshot_runtime_metrics()
    counters = snap["counters"]
    ok_count = counters.get(_PROFILE_FETCH_OK, 0)
    error_count = counters.get(_PROFILE_FETCH_ERROR, 0)
    total = ok_count + error_count
    error_rate = (error_count / total) if total else 0.0
    funnel = snap["funnel"]
    discovery = funnel.get("discovery", 0)
    connected = funnel.get("connected", 0)
    conversion = (connected / discovery) if discovery else 0.0
    return {
        "profile_fetch_error_rate": round(error_rate, 6),
        "catalog_to_connection_conversion": round(conversion, 6),
    }


__all__ = [
    "FUNNEL_STAGES",
    "RuntimeMetricsRegistry",
    "derived_metrics",
    "get_runtime_metrics",
    "record_funnel",
    "record_hosted_gateway_request",
    "record_profile_fetch",
    "record_search",
    "reset_runtime_metrics",
    "set_queue_depth",
    "snapshot_runtime_metrics",
]
