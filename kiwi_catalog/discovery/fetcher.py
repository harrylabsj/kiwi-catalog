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

"""ProfileFetcher — SSRF-safe HTTP fetcher for A2A Agent Cards and UCP profiles.

Design: docs/shopping-cli-a2a-upgrade-design-v1.2.1.md §17.1, §17.2

This module contains the ONLY code path that makes outbound HTTP requests
for external profile discovery.  Every other module MUST go through the
ProfileFetcher rather than calling urllib / httpx directly.

Security invariants
-------------------
1. Default HTTPS — ``require_https=True`` rejects plaintext HTTP.
2. DNS resolve → IP validation BEFORE connect (private/loopback/link-local/
   metadata addresses are blocked).
3. DNS rebinding protection — the connection is made to the verified IP
   address, not to the hostname.  The underlying library never gets a chance
   to re-resolve and land on a different address.
4. Redirect targets are re-validated with the same checks as the original URL.
5. Response body is stream-truncated at ``max_profile_bytes``.
6. JSON depth and node count are bounded to prevent stack exhaustion attacks.
7. Non-http(s) schemes (file://, ftp://, etc.) are rejected.
8. Ports are constrained to ``allowed_ports``.

Trade-off noted
---------------
Connecting to a verified IP and using SNI with the original hostname for TLS
works correctly with all mainstream TLS implementations and CDNs (the SNI
field carries the hostname so the server presents the right certificate).
The trade-off is that TLS certificate Subject Alternative Name validation
happens against the hostname (SNI), not the IP — which is exactly what we
want: we verify the *logical* identity, not the *network* identity.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import concurrent.futures
import threading
import ssl
import time as _time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from kiwi_catalog.discovery._bounded_dns import BoundedResolver
from kiwi_catalog.discovery.trust import TrustPolicy
from kiwi_catalog.services.catalog_runtime_metrics import record_profile_fetch

# ── Blocked / internal address ranges (§17.1) ─────────────────────────────────

# We use ipaddress's built-in properties plus an explicit metadata block.
_METADATA_IP = ipaddress.IPv4Address("169.254.169.254")

# Additional private-like ranges to block even when is_private is False in
# some environments (e.g. Docker's default bridge). 审查 P3：补齐保留/特殊段
# （类 E、TEST-NET、已废弃 site-local、组播）。
_EXTRA_BLOCKED_V4 = [
    ipaddress.IPv4Network("0.0.0.0/8"),  # "This host on this network"
    ipaddress.IPv4Network("100.64.0.0/10"),  # CGNAT (RFC 6598)
    ipaddress.IPv4Network("198.18.0.0/15"),  # Benchmarking (RFC 2544)
    ipaddress.IPv4Network("240.0.0.0/4"),  # Class E reserved
    ipaddress.IPv4Network("198.51.100.0/24"),  # TEST-NET-2 (RFC 5737)
    ipaddress.IPv4Network("203.0.113.0/24"),  # TEST-NET-3 (RFC 5737)
]

_LINK_LOCAL_V6 = ipaddress.IPv6Network("fe80::/10")
# 已废弃 site-local（RFC 3879）与组播段——不可路由但显式封堵更稳
_EXTRA_BLOCKED_V6 = [
    ipaddress.IPv6Network("fec0::/10"),  # deprecated site-local
    ipaddress.IPv6Network("ff00::/8"),  # multicast
]
# NAT64 well-known prefix（RFC 6052）与 IPv4-compatible（RFC 4291 已废弃）：
# 低 32 位内嵌 IPv4，is_private 对二者均返回 False——需提取后按 IPv4 黑名单
# 判定（审查 M1：NAT64 网络下域名解析到 64:ff9b::<私网v4> 可穿透黑名单）。
_NAT64_V6 = ipaddress.IPv6Network("64:ff9b::/96")
_IPV4_COMPATIBLE_V6 = ipaddress.IPv6Network("::/96")

# ── Verified IP store (shared across handler and redirect handler) ─────────────
# Two fixed daemon workers, with six physical running/queued items total.
# Cancelled queued items keep their admission slot until a worker removes them.
_DNS_EXECUTOR = BoundedResolver()
_DNS_ADMISSION = _DNS_EXECUTOR.admission
_DNS_MAX_QUEUED = 4
_DNS_EXECUTOR_QUEUE = _DNS_EXECUTOR._work_queue


class _RequestLifecycle:
    """A single request owns its sockets and one absolute deadline timer."""

    def __init__(self, deadline: float) -> None:
        self.deadline = deadline
        self._lock = threading.Lock()
        self._sockets: list[socket.socket] = []
        self._closed = False
        self._timer = threading.Timer(max(deadline - _time.monotonic(), 0.001), self._expire)
        self._timer.daemon = True

    @staticmethod
    def _abort(sock: socket.socket) -> None:
        # close alone leaves makefile() I/O references alive. shutdown wakes
        # header/chunk framing reads before close relinquishes ownership.
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def register(self, sock: socket.socket) -> None:
        with self._lock:
            late = self._closed or _time.monotonic() >= self.deadline
            if not late:
                self._sockets.append(sock)
        if late:
            self._abort(sock)
            raise FetchError("total fetch duration exceeded while connecting")

    def _expire(self) -> None:
        with self._lock:
            self._closed = True
            sockets, self._sockets = self._sockets, []
        for sock in sockets:
            self._abort(sock)

    def check(self) -> None:
        if _time.monotonic() >= self.deadline:
            raise FetchError("total fetch duration exceeded")

    def __enter__(self):
        self.check()
        self._timer.start()
        return self

    def __exit__(self, *exc) -> None:
        self._timer.cancel()
        # If expiry already started, wait for its bounded socket cleanup;
        # cancellation alone does not prove the callback has stopped.
        self._timer.join()
        self._expire()


# Maps (hostname, port) → verified IP string.  Populated by the redirect handler
# when a redirect target is validated; consulted by the HTTPS handler to pick the
# correct verified IP for each request.  Fail-closed: a host not in the store is
# rejected with SSRFBlockError.
_VerifiedIPStore = dict[tuple[str, int], str]

# ── Default limits ────────────────────────────────────────────────────────────
_DEFAULT_JSON_MAX_DEPTH = 20
_DEFAULT_JSON_MAX_NODES = 10_000
_DEFAULT_FETCH_TIMEOUT = 10.0
# 审查 P2（慢滴漏）：单次 socket 操作超时之上再加总时长上限——1 B/s 滴漏
# 响应体在 timeout 内永不超时，可把 fetch 线程钉住数天（1 MiB ≈ 12 天）。
_MAX_FETCH_DURATION_SECONDS = 30.0


# ── Errors ────────────────────────────────────────────────────────────────────


class FetchError(RuntimeError):
    """Base error for any fetch failure (SSRF block, timeout, etc.)."""


class SSRFBlockError(FetchError):
    """Raised when a URL or resolved IP is blocked by SSRF policy."""


class FetchLimitError(FetchError):
    """Raised when a response exceeds size/depth/node limits."""


# ── IP validation ─────────────────────────────────────────────────────────────


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Return a reason string if *ip* is blocked, or None if it is allowed.

    Covers loopback, private, link-local, metadata, and extra blocked ranges.
    """
    if ip.is_loopback:
        return "loopback address"
    if ip == _METADATA_IP:
        return "cloud metadata endpoint"
    if ip.is_private:
        return "private network address"
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.is_link_local or ip in _LINK_LOCAL_V6:
            return "link-local address"
        for net_v6 in _EXTRA_BLOCKED_V6:
            if ip in net_v6:
                return f"blocked range {net_v6}"
        # IPv4-mapped IPv6 (::ffff:a.b.c.d) — extract and check the v4 part
        if ip.ipv4_mapped:
            v4 = ip.ipv4_mapped
            if v4 is not None:
                reason = _is_blocked_ip(v4)
                if reason:
                    return f"IPv4-mapped {reason}"
        # NAT64（64:ff9b::/96）与 IPv4-compatible（::/96）：低 32 位内嵌 IPv4。
        # is_private 对二者均返回 False（6to4 2002::/16 已被 is_private 全拦，
        # 无需单独提取）——需手动提取内嵌 IPv4 按黑名单判定。
        if ip in _NAT64_V6 or ip in _IPV4_COMPATIBLE_V6:
            v4 = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
            reason = _is_blocked_ip(v4)
            if reason:
                return f"embedded-IPv4 {reason}"
    else:
        if ip.is_link_local:
            return "link-local address"
        # Extra blocked v4 ranges
        for net_v4 in _EXTRA_BLOCKED_V4:
            if ip in net_v4:
                return f"blocked range {net_v4}"
    return None


def _is_public_routable(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True when *ip* passes all SSRF blocklist checks."""
    return _is_blocked_ip(ip) is None


def _validate_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    """Raise SSRFBlockError if *ip* is in a blocked range."""
    reason = _is_blocked_ip(ip)
    if reason is not None:
        raise SSRFBlockError(f"IP {ip} is blocked: {reason}")


# ── URL validation ────────────────────────────────────────────────────────────


def _validate_scheme(scheme: str, allowed_schemes: tuple[str, ...]) -> None:
    """Raise SSRFBlockError if *scheme* is not in *allowed_schemes*."""
    if scheme not in allowed_schemes:
        raise SSRFBlockError(
            f"Scheme '{scheme}' is not allowed (allowed: {', '.join(sorted(allowed_schemes))})"
        )


def _validate_port(port: int, allowed_ports: tuple[int, ...]) -> None:
    """Raise SSRFBlockError if *port* is not in *allowed_ports*."""
    if port not in allowed_ports:
        raise SSRFBlockError(
            f"Port {port} is not allowed (allowed: {', '.join(str(p) for p in sorted(allowed_ports))})"
        )


def _port_of(parsed: Any, scheme: str) -> int:
    """``parsed.port`` 对非法端口（如 ``https://host:abc/``）抛 ValueError。

    审查 P1-2：恶意 URL（注册或重定向目标）不得以未捕获 ValueError 逃逸成
    500——映射为 SSRFBlockError（fail-closed 语义）。
    """
    try:
        return parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise SSRFBlockError(f"invalid port in URL: {exc}") from exc


# ── DNS resolution ────────────────────────────────────────────────────────────


def _resolve_hostname(hostname: str, port: int, *, deadline: float | None = None) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve *hostname* and return all IP addresses.

    review 2-36（A316 收窄）：getaddrinfo 本身无超时——有 deadline 时在
    worker 线程解析并以剩余预算等待，超时即 FetchError（总 deadline 贯穿
    初始 DNS 阶段，DNS 挂起不再绕过 30s 上限）。

    Raises SSRFBlockError when the hostname cannot be resolved.
    """
    try:
        if deadline is not None:
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                raise FetchError("total fetch duration exceeded before DNS resolution")
            try:
                future = _DNS_EXECUTOR.submit(
                    socket.getaddrinfo, hostname, port, proto=socket.IPPROTO_TCP,
                    admission_timeout=remaining,
                )
            except concurrent.futures.TimeoutError as exc:
                raise FetchError("total fetch duration exceeded waiting for DNS admission") from exc
            except Exception as exc:
                raise FetchError(f"DNS submission failed: {exc}") from exc
            try:
                # Admission itself may have consumed the budget.
                remaining = deadline - _time.monotonic()
                if remaining <= 0:
                    raise concurrent.futures.TimeoutError()
                infos = future.result(timeout=remaining)
            except concurrent.futures.TimeoutError as exc:
                cancelled = future.cancel()
                kind = "cancelled queued" if cancelled else "abandoned running"
                raise FetchError(
                    f"total fetch duration exceeded during DNS resolution ({kind}; "
                    "running getaddrinfo finishes in background)"
                ) from exc
        else:
            infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise SSRFBlockError(f"Cannot resolve hostname '{hostname}': {exc}") from exc

    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if ip not in ips:
            ips.append(ip)
    return ips


def _resolve_and_validate(
    hostname: str,
    port: int,
    *,
    deadline: float | None = None,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Resolve *hostname*, validate all IPs, and return the first valid IP.

    Raises SSRFBlockError if any resolved IP is blocked or the hostname
    cannot be resolved.
    """
    ips = _resolve_hostname(hostname, port, deadline=deadline)
    if not ips:
        raise SSRFBlockError(f"No IP addresses resolved for '{hostname}'")
    for ip in ips:
        _validate_ip(ip)
    return ips[0]


# ── DNS-rebinding-proof HTTPS connection ──────────────────────────────────────


class _ProtectedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection to a pre-validated IP address.

    审查 P2（http 支持真实化）：permissive_local 策略声明支持 http://，但
    opener 从未注册 HTTPHandler——所有 http 请求走 UnknownHandler 恒失败
    （``unknown url type: http``）。此连接与 HTTPS 侧同防 DNS rebinding：
    直连已验证 IP，不让 OS resolver 二次选址。无 TLS 包装。
    """

    def __init__(self, host: str, verified_ip: str, *, lifecycle: _RequestLifecycle | None = None, **kwargs: Any) -> None:
        self._ssrf_verified_ip = str(verified_ip)
        self._lifecycle = lifecycle
        super().__init__(host, **kwargs)

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._ssrf_verified_ip, self.port),
            self.timeout,
        )
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # review 2-36（A328）：登记活跃 socket 供 deadline watchdog 关闭
        if self._lifecycle is not None:
            self._lifecycle.register(self.sock)
        if self._tunnel_host:  # type: ignore[attr-defined]
            self._tunnel()  # type: ignore[attr-defined]


class _ProtectedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that connects to a pre-validated IP address.

    This is the DNS rebinding defence (§17.1): by the time we open the TCP
    socket we have already resolved the hostname and validated every
    returned IP against the blocklist.  We now connect to that verified IP
    directly rather than letting the OS resolver (or a follow-up library
    call) pick a potentially different address.

    TLS SNI still uses the original *host* so the server presents the
    correct certificate and the TLS handshake verifies the logical identity.
    """

    def __init__(self, host: str, verified_ip: str, *, lifecycle: _RequestLifecycle | None = None, **kwargs: Any) -> None:
        self._ssrf_verified_ip = str(verified_ip)
        self._lifecycle = lifecycle
        super().__init__(host, **kwargs)

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._ssrf_verified_ip, self.port),
            self.timeout,
        )
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # review 2-36（A328）：同 HTTP 侧——登记活跃 socket 供 watchdog 关闭
        if self._lifecycle is not None:
            self._lifecycle.register(self.sock)

        if self._tunnel_host:  # type: ignore[attr-defined]
            self._tunnel()  # type: ignore[attr-defined]

        # review 2-34：尊重 https_open 传入的 context（do_open 存在 self._context）；
        # 未提供时回落默认 context。此前每次新建默认 context——未来自定义 CA/
        # 策略配置会被静默丢弃，且每连接重复构建。
        ctx = getattr(self, "_context", None) or ssl.create_default_context()
        # SNI carries self.host (the original hostname); cert validation
        # is against that hostname, not the IP.
        self.sock = ctx.wrap_socket(self.sock, server_hostname=self.host,
                                    do_handshake_on_connect=False)
        # wrap_socket detaches the raw socket. Register the actual SSL owner
        # before the handshake, which itself is subject to the same deadline.
        if self._lifecycle is not None:
            self._lifecycle.register(self.sock)
        self.sock.do_handshake()


# ── Custom URL opener ─────────────────────────────────────────────────────────


class _SSRFRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that re-validates every redirect target.

    Each redirect URL goes through the same scheme/port/IP checks as the
    original URL.  The validated IP is stored in *ip_store* so the HTTPS
    handler can use the correct address for the new host.

    The *redirect_limit* caps the maximum number of redirects followed;
    exceeding it raises SSRFBlockError.
    """

    def __init__(
        self,
        redirect_limit: int,
        validator: Callable[[str], ipaddress.IPv4Address | ipaddress.IPv6Address],
        ip_store: _VerifiedIPStore,
        *,
        deadline: float | None = None,
    ):
        self._redirect_limit = redirect_limit
        self._redirect_count = 0
        self._validator = validator
        self._ip_store = ip_store
        # review 2-36（返修）：总 deadline 由 redirect handler 持有——每一跳
        # redirect 发生前先扣减剩余预算，重定向链不再各自获得完整 socket
        # timeout（A313 独验：opener/DNS/header 阶段超总 deadline 仍阻塞 caller）。
        self._deadline = deadline
        super().__init__()

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self._redirect_count += 1
        if self._redirect_count > self._redirect_limit:
            raise SSRFBlockError(
                f"Redirect limit ({self._redirect_limit}) exceeded"
            )
        if self._deadline is not None:
            remaining = self._deadline - _time.monotonic()
            if remaining <= 0:
                raise FetchError(
                    "total fetch duration exceeded (_MAX_FETCH_DURATION_SECONDS) on redirect"
                )
        # Re-validate the redirect target and store the verified IP so
        # the HTTPS handler uses the correct address for the new host.
        verified_ip = self._validator(newurl)
        parsed = urllib.parse.urlparse(newurl)
        hostname = parsed.hostname
        port = _port_of(parsed, parsed.scheme)
        assert hostname is not None  # validator guarantees a hostname is present
        self._ip_store[(hostname, port)] = str(verified_ip)
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and self._deadline is not None:
            remaining = self._deadline - _time.monotonic()
            if remaining <= 0:
                raise FetchError(
                    "total fetch duration exceeded (_MAX_FETCH_DURATION_SECONDS) on redirect"
                )
            # urllib later reopens using the original req.timeout; a newly
            # created Request need not carry a timeout attribute yet.
            req.timeout = min(float(getattr(req, "timeout", remaining) or remaining), remaining)
            redirected.timeout = req.timeout
        return redirected


def _build_opener(
    initial_verified_ip: str,
    initial_hostname: str,
    initial_port: int,
    redirect_limit: int,
    redirect_validator: Callable[[str], ipaddress.IPv4Address | ipaddress.IPv6Address],
    *,
    lifecycle_deadline: float | None = None,
    lifecycle: _RequestLifecycle | None = None,
) -> urllib.request.OpenerDirector:
    """Build a ``urllib`` opener that uses verified IPs for every connection.

    The *initial* URL's verified IP is pre-seeded into a shared store.
    When a redirect targets a different host, the redirect handler
    validates the target and stores its verified IP so the HTTPS handler
    can pick the correct address instead of the (now-stale) original one.
    """

    # Shared store: (hostname, port) → verified_ip_str.
    # Pre-populated with the initial URL's mapping so the first request works.
    ip_store: _VerifiedIPStore = {(initial_hostname, initial_port): str(initial_verified_ip)}

    # Custom HTTPS/HTTP handlers that look up verified IPs from the shared store.
    class _Handler(urllib.request.HTTPSHandler, urllib.request.HTTPHandler):
        def _verified_connection(self, req_hostname: str, req_port: int, scheme: str):
            # Look up the verified IP for this host:port.
            # Fail-closed: a host not in the store is a sign that it was never
            # validated and the connection must be blocked.
            verified_ip = ip_store.get((req_hostname, req_port))
            if verified_ip is None:
                raise SSRFBlockError(
                    f"No verified IP for {req_hostname}:{req_port} — "
                    f"connection blocked (fail-closed)"
                )
            if scheme == "https":
                return lambda host, **kw: _ProtectedHTTPSConnection(
                    host, verified_ip=verified_ip, lifecycle=lifecycle, **kw
                )
            # 审查 P2（http 支持真实化）：permissive_local 声明的 http:// 走
            # 同样的 verified-IP 直连（防 DNS rebinding），不再 UnknownHandler
            # 恒失败。默认 require_https 策略在 scheme 校验层已拦截 http。
            return lambda host, **kw: _ProtectedHTTPConnection(
                host, verified_ip=verified_ip, lifecycle=lifecycle, **kw
            )

        def https_open(self, req):
            # Determine the hostname and port for the current request.
            parsed = urllib.parse.urlparse(req.full_url)
            req_hostname = parsed.hostname
            req_port = _port_of(parsed, "https")
            assert req_hostname is not None  # req.full_url always has a hostname
            return self.do_open(
                self._verified_connection(req_hostname, req_port, "https"),
                req,
                context=self._context,  # type: ignore[attr-defined]
            )

        def http_open(self, req):
            parsed = urllib.parse.urlparse(req.full_url)
            req_hostname = parsed.hostname
            req_port = _port_of(parsed, "http")
            assert req_hostname is not None  # req.full_url always has a hostname
            return self.do_open(
                self._verified_connection(req_hostname, req_port, "http"),
                req,
            )

    redirect_handler = _SSRFRedirectHandler(
        redirect_limit, redirect_validator, ip_store, deadline=lifecycle_deadline
    )

    opener = urllib.request.OpenerDirector()
    opener.add_handler(_Handler())
    opener.add_handler(urllib.request.UnknownHandler())
    opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
    opener.add_handler(redirect_handler)
    opener.add_handler(urllib.request.HTTPErrorProcessor())
    return opener


# ── JSON structure validation ─────────────────────────────────────────────────


def _validate_json_structure(
    obj: Any,
    max_depth: int = _DEFAULT_JSON_MAX_DEPTH,
    max_nodes: int = _DEFAULT_JSON_MAX_NODES,
) -> int:
    """Walk *obj* and raise FetchLimitError on depth/node violations.

    Returns the total node count (for diagnostics).
    """
    node_count = 0

    def _walk(o: Any, depth: int) -> None:
        nonlocal node_count
        if depth > max_depth:
            raise FetchLimitError(f"JSON exceeds max depth of {max_depth}")
        node_count += 1
        if node_count > max_nodes:
            raise FetchLimitError(f"JSON exceeds max node count of {max_nodes}")
        if isinstance(o, dict):
            for v in o.values():
                _walk(v, depth + 1)
        elif isinstance(o, list):
            for v in o:
                _walk(v, depth + 1)

    _walk(obj, 0)
    return node_count


# ── Fetch result ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class FetchResult:
    """Result of a single profile fetch.

    Fields are designed to map directly to ``agent_profile_snapshots`` columns
    (§18 catalog snapshot metadata).
    """

    # ── Response identity ─────────────────────────────────────────────────
    url: str
    """Final URL after redirects."""

    status_code: int
    """HTTP status code (200, 304, etc.)."""

    # ── Body ──────────────────────────────────────────────────────────────
    body: str = ""
    """Raw response body (as a UTF-8 string), or empty for 304."""

    raw_bytes: bytes = b""
    """Raw response bytes (useful for content_hash computation)."""

    # ── Cache metadata (§18) ──────────────────────────────────────────────
    etag: str | None = None
    """ETag from the response (for conditional requests)."""

    last_modified: str | None = None
    """Last-Modified from the response."""

    cache_control: str | None = None
    """Raw Cache-Control header value."""

    max_age: int | None = None
    """Parsed max-age seconds."""

    fetched_at: float = field(default_factory=lambda: __import__("time").time())
    """Unix timestamp when the response was received."""

    # ── Parsed JSON (post-validation) ─────────────────────────────────────
    parsed: Any = None
    """Parsed JSON body (only set when body is non-empty and valid JSON)."""

    @property
    def is_not_modified(self) -> bool:
        """True when the server returned 304 Not Modified."""
        return self.status_code == 304

    @property
    def is_success(self) -> bool:
        """True when the response is a successful fetch (200) or 304."""
        return self.status_code in (200, 304)

    def compute_fresh_until(self, policy_max_age_seconds: int) -> float:
        """Compute the ``fresh_until`` timestamp from Cache-Control or policy."""
        age = self.max_age if self.max_age is not None else policy_max_age_seconds
        return self.fetched_at + age


# ── ProfileFetcher ────────────────────────────────────────────────────────────


class ProfileFetcher:
    """SSRF-safe HTTP fetcher for A2A Agent Cards and UCP profiles.

    This is the single choke-point for all outbound discovery HTTP.  Every
    request is validated against the ``TrustPolicy`` before a single byte
    leaves the machine.

    Usage::

        policy = TrustPolicy.defaults()
        fetcher = ProfileFetcher(policy)
        result = fetcher.fetch("https://example.com/.well-known/agent-card.json")
        if result.is_not_modified:
            print("Cache is still fresh (304)")
        else:
            print(f"Body: {result.body[:200]}...")
    """

    def __init__(
        self,
        policy: TrustPolicy,
        *,
        timeout: float = _DEFAULT_FETCH_TIMEOUT,
        json_max_depth: int = _DEFAULT_JSON_MAX_DEPTH,
        json_max_nodes: int = _DEFAULT_JSON_MAX_NODES,
    ) -> None:
        self._policy = policy
        self._timeout = float(timeout)
        self._json_max_depth = json_max_depth
        self._json_max_nodes = json_max_nodes
        if self._timeout <= 0:
            raise ValueError("timeout must be > 0")

    # ── Public API ────────────────────────────────────────────────────────

    def fetch(
        self,
        url: str,
        *,
        etag: str | None = None,
        last_modified: str | None = None,
    ) -> FetchResult:
        """Fetch a profile from *url* with optional conditional GET headers.

        Args:
            url: The full URL to fetch (must use an allowed scheme).
            etag: If set, sent as ``If-None-Match`` for 304 support.
            last_modified: If set, sent as ``If-Modified-Since``.

        Returns:
            ``FetchResult`` with status, body, and cache metadata.

        Raises:
            SSRFBlockError: The URL or a resolved IP is blocked.
            FetchLimitError: Response exceeds size/depth/node limits.
            FetchError: Any other transport error.
        """
        import time as _time

        start = _time.monotonic()
        try:
            result = self._fetch(url, etag=etag, last_modified=last_modified)
        except FetchError:
            record_profile_fetch(_time.monotonic() - start, ok=False)
            raise
        # 2xx success and 304 not-modified both count as successful fetches.
        record_profile_fetch(_time.monotonic() - start, ok=result.is_success or result.is_not_modified)
        return result

    def post_json(self, url: str, body: dict[str, Any], *, timeout: float = 5.0) -> FetchResult:
        """SSRF-safe bounded JSON POST; redirects are rejected for possession challenges."""
        parsed = self._validate_url(url)
        scheme, hostname = parsed.scheme, parsed.hostname
        assert hostname is not None
        port = _port_of(parsed, scheme)
        if self._policy.require_https and scheme != "https":
            raise SSRFBlockError("HTTPS is required")
        _validate_port(port, self._policy.allowed_ports)
        # review 2-36：DNS 与后续 _make_request 共享同一 fetch deadline。
        fetch_deadline = _time.monotonic() + _MAX_FETCH_DURATION_SECONDS
        verified_ip = _resolve_and_validate(hostname, port, deadline=fetch_deadline)
        payload = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(payload) > self._policy.max_profile_bytes:
            raise FetchLimitError("POST body exceeds configured limit")
        # review 2-36（A328 余项）：POST 与 GET 同单生命周期——初始 DNS 后的
        # 剩余预算传入 _make_request，不再重获完整预算。
        return self._make_request(url, str(verified_ip), hostname, port, None, None,
                                  _time.time(), method="POST", data=payload,
                                  timeout=min(float(timeout), self._timeout), redirect_limit=0,
                                  deadline=fetch_deadline)

    def _fetch(
        self,
        url: str,
        *,
        etag: str | None = None,
        last_modified: str | None = None,
    ) -> FetchResult:
        """Uninstrumented fetch implementation (see :meth:`fetch`)."""
        import time as _time

        # 1. Validate URL (scheme, port)
        parsed = self._validate_url(url)
        scheme = parsed.scheme
        hostname = parsed.hostname
        assert hostname is not None  # _validate_url guarantees a hostname is present
        port = _port_of(parsed, scheme)

        # 2. Enforce HTTPS requirement
        if self._policy.require_https and scheme != "https":
            raise SSRFBlockError(f"HTTPS is required; got scheme '{scheme}'")

        # 3. Validate port
        _validate_port(port, self._policy.allowed_ports)

        # 4. Resolve DNS and validate all IPs — review 2-36：与 _make_request
        # 共享同一 fetch deadline（getaddrinfo 受剩余预算约束）。
        fetch_deadline = _time.monotonic() + _MAX_FETCH_DURATION_SECONDS
        verified_ip = _resolve_and_validate(hostname, port, deadline=fetch_deadline)

        # 5. Make the request with DNS-rebinding protection
        # review 2-36（A326）：初始 DNS 消耗掉的预算必须延续——fetch_deadline
        # 传入 _make_request（不再重置 30s），header/redirect/body 全部从同一
        # caller 总期限扣减。
        fetched_at = _time.time()
        try:
            result = self._make_request(url, str(verified_ip), hostname, port, etag, last_modified, fetched_at, deadline=fetch_deadline)
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise FetchError(f"Fetch failed for '{url}': {exc}") from exc

        return result

    # ── Internal helpers ──────────────────────────────────────────────────

    def _validate_url(self, url: str) -> urllib.parse.ParseResult:
        """Parse and validate *url* against the trust policy."""
        if not url or not isinstance(url, str):
            raise SSRFBlockError("URL must be a non-empty string")

        try:
            parsed = urllib.parse.urlparse(url)
        except ValueError as exc:
            raise SSRFBlockError(f"Invalid URL '{url}': {exc}") from exc

        scheme = parsed.scheme.lower()

        # Block non-http(s) schemes explicitly
        if scheme not in ("http", "https"):
            raise SSRFBlockError(
                f"Scheme '{scheme}' is not supported (only http/https)"
            )

        # Validate against allowed schemes
        _validate_scheme(scheme, self._policy.allowed_schemes)

        if not parsed.hostname:
            raise SSRFBlockError(f"URL '{url}' has no hostname")

        return parsed

    def _validate_redirect_target(
        self,
        redirect_url: str,
        *,
        deadline: float | None = None,
    ) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        """Validate a redirect target URL with full SSRF checks.

        Called by the redirect handler before each redirect is followed.
        Returns the first verified IP for the new hostname.
        ``deadline``（review 2-36）承载 caller 剩余预算，贯穿本跳 DNS。
        """
        parsed = self._validate_url(redirect_url)
        scheme = parsed.scheme
        hostname = parsed.hostname
        assert hostname is not None  # _validate_url guarantees a hostname is present
        port = _port_of(parsed, scheme)

        if self._policy.require_https and scheme != "https":
            raise SSRFBlockError(f"Redirect to non-HTTPS URL blocked: {redirect_url}")

        _validate_port(port, self._policy.allowed_ports)
        # review 2-36（A323 校准）：重定向跳的 DNS 解析继承 caller deadline
        #（剩余预算），不再每跳独立获得完整 socket timeout（A317 raw C5
        # 实测 1.227s）。
        return _resolve_and_validate(hostname, port, deadline=deadline)

    def _make_request(
        self,
        url: str,
        verified_ip: str,
        hostname: str,
        port: int,
        etag: str | None,
        last_modified: str | None,
        fetched_at: float,
        *, method: str = "GET", data: bytes | None = None, timeout: float | None = None,
        redirect_limit: int | None = None,
        deadline: float | None = None,
    ) -> FetchResult:
        """Execute the HTTP request with all SSRF protections in place."""
        # Build request with conditional headers
        # review 2-35（返修）：非默认端口时 Host 头带端口（HTTP/1.1）。原返修
        # 把请求 port 与同源 URL 解析出的 port 自比较——恒等、8443 等非默认
        # 端口永不带出；且 IPv6 主机名须加方括号。A313 独验实证两者皆错。
        url_scheme = urllib.parse.urlparse(url).scheme or "https"
        default_port = 443 if url_scheme == "https" else 80
        host_name = f"[{hostname}]" if ":" in hostname else hostname
        host_header = host_name if port == default_port else f"{host_name}:{port}"
        req_headers: dict[str, str] = {
            "Accept": "application/json",
            "Host": host_header,
        }
        if data is not None:
            req_headers["Content-Type"] = "application/json"
        if etag:
            req_headers["If-None-Match"] = etag
        if last_modified:
            req_headers["If-Modified-Since"] = last_modified

        request = urllib.request.Request(url, data=data, headers=req_headers, method=method)

        # review 2-36（返修）：总时长 monotonic deadline 从请求构建起贯穿全部
        # 阶段——opener 建连/DNS/header（open socket 超时=剩余预算）、每一跳
        # redirect（handler 持有同一 deadline 并逐跳收缩）、body 读取。此前
        # 只约束 body 读取，A313 独验实证 opener/DNS/header 阶段仍可阻塞
        # caller 超 30s。
        # review 2-36（A326）：caller 传入的总期限优先（初始 DNS 已消耗预算）；
        # 无 caller 期限（内部直连路径）才以当前时刻起算。
        lifecycle_deadline = deadline if deadline is not None else _time.monotonic() + _MAX_FETCH_DURATION_SECONDS
        open_timeout = min(
            float(timeout or self._timeout),
            max(lifecycle_deadline - _time.monotonic(), 0.001),
        )

        # Build opener with verified-IP connection
        # review 2-36（A323 校准）：per-request 闭包携带 deadline——重定向跳的
        # DNS 解析继承剩余预算（并发 fetch 不共享可变 deadline）。
        def redirect_validator(redirect_url: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
            return self._validate_redirect_target(redirect_url, deadline=lifecycle_deadline)
        lifecycle = _RequestLifecycle(lifecycle_deadline)
        opener = _build_opener(
            verified_ip, hostname, port,
            self._policy.redirect_limit if redirect_limit is None else redirect_limit, redirect_validator,
            lifecycle_deadline=lifecycle_deadline, lifecycle=lifecycle,
        )
        try:
            with lifecycle:
                try:
                    response = opener.open(request, timeout=open_timeout)
                except urllib.error.HTTPError as exc:
                    try:
                        try:
                            raw_bytes = _read_limited(exc, self._policy.max_profile_bytes,
                                                      deadline=lifecycle_deadline)
                        except FetchLimitError:
                            raw_bytes = b""
                        lifecycle.check()
                        return FetchResult(url=url, status_code=exc.code, body="",
                                           raw_bytes=raw_bytes, fetched_at=fetched_at)
                    finally:
                        exc.close()
                with response:
                    lifecycle.check()
                    result = self._process_response(response, response.geturl(), fetched_at,
                                                    deadline=lifecycle_deadline)
                    lifecycle.check()
                    return result
        except (SSRFBlockError, FetchError):
            raise
        except urllib.error.URLError as exc:
            # urllib wraps TLS/connection failures in URLError. HTTPError is
            # handled above while this request's body deadline is still live.
            raise FetchError(f"Fetch failed for '{url}': {exc}") from exc
        except (OSError, http.client.HTTPException) as exc:
            raise FetchError(f"fetch aborted (deadline or connection error): {exc}") from exc

    def _process_response(
        self,
        response: http.client.HTTPResponse,
        final_url: str,
        fetched_at: float,
        *,
        deadline: float | None = None,
    ) -> FetchResult:
        """Read, validate, and parse the HTTP response."""
        status = response.status

        # 304 — nothing to read
        if status == 304:
            return FetchResult(
                url=final_url,
                status_code=304,
                fetched_at=fetched_at,
            )

        # Extract response headers
        resp_headers: dict[str, str] = {}
        for key, value in response.getheaders():
            resp_headers[key.lower()] = value

        etag_val = resp_headers.get("etag") or None
        last_mod = resp_headers.get("last-modified") or None
        cache_ctrl = resp_headers.get("cache-control") or None

        # Stream-read with byte limit
        # review 2-36（A323 校准）：滴漏 body 的阻塞点是 socket recv（每次
        # 等满 socket timeout 才返回）——读前把 socket 超时压到**剩余预算**，
        # 滴漏在 deadline 到点即被 socket 层打断（A317 raw C3 实测 5.089s）。
        remaining = (
            deadline - _time.monotonic() if deadline is not None else None
        )
        if remaining is not None and remaining <= 0:
            raise FetchError("total fetch duration exceeded before body read")
        if remaining is not None:
            # review 2-36（A326）：首个 header→body 间隙同样压到剩余预算；
            # 每次 recv 内的剩余超时由 _read_limited 内 deadline 驱动循环接管。
            sock = _response_socket(response)
            if sock is not None:
                try:
                    sock.settimeout(max(remaining, 0.001))
                except OSError:
                    pass  # socket 已关闭等场景——deadline 检查仍兜底
        max_bytes = self._policy.max_profile_bytes
        raw_bytes = _read_limited(
            response,
            max_bytes,
            deadline=deadline if deadline is not None else _time.monotonic() + _MAX_FETCH_DURATION_SECONDS,
        )

        # Parse JSON with structure limits
        body = ""
        parsed = None
        if raw_bytes:
            body = raw_bytes.decode("utf-8", errors="replace")
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError as exc:
                raise FetchLimitError(f"Response is not valid JSON: {exc}") from exc
            except RecursionError as exc:
                # 审查 P1-2：深嵌套 JSON 在解析阶段就触发 RecursionError（深度
                # 防护在 parse 之后），映射为 FetchLimitError 而非未捕获 500。
                raise FetchLimitError("Response JSON is too deeply nested") from exc
            if parsed is not None:
                _validate_json_structure(parsed, self._json_max_depth, self._json_max_nodes)

        # Parse max-age
        max_age = None
        if cache_ctrl:
            max_age = _parse_max_age_from_header(cache_ctrl)
            # 审查 P3：远端 max-age 无上限——恶意源站可声明 10 年，拉长重验证
            # 节奏。cap 到策略新鲜期上限的 2 倍（证据 24h 过期不受影响）。
            if max_age is not None:
                max_age = min(max_age, self._policy.profile_max_age_seconds * 2)

        return FetchResult(
            url=final_url,
            status_code=status,
            body=body,
            raw_bytes=raw_bytes,
            etag=etag_val,
            last_modified=last_mod,
            cache_control=cache_ctrl,
            max_age=max_age,
            fetched_at=fetched_at,
            parsed=parsed,
        )


# ── Streaming body read with hard byte limit ──────────────────────────────────


class _ReadableBody(Protocol):
    """Minimal read interface shared by ``http.client.HTTPResponse`` and
    ``urllib.error.HTTPError`` (4xx error bodies).

    Only ``read(size)`` is needed here — the byte limit and the total-fetch
    deadline live in :func:`_read_limited`, so both success and error bodies
    stay bounded under the same policy.
    """

    def read(self, amt: int) -> bytes: ...


def _read_limited(
    response: _ReadableBody,
    max_bytes: int,
    *,
    deadline: float | None = None,
) -> bytes:
    """Read the response body in chunks, truncating at *max_bytes*.

    Raises FetchLimitError if the body exceeds the limit or the total read
    exceeds *deadline* (monotonic clock) — 审查 P2（慢滴漏）：socket timeout
    只约束单次 read，1 B/s 滴漏源站可把请求线程钉住数天；总时长上限保证
    fetch 线程按秒级回收。
    """
    chunks: list[bytes] = []
    total = 0
    chunk_size = 8192

    # review 2-36（A326 faulthandler 实证）：`response.read(n)`（BufferedReader
    # 语义）会**凑满 n 字节才返回**——滴流源站每 0.05s 供 1B 时每次 recv 都
    # 「有数据」，socket 超时永不触发、循环顶部 deadline 检查永远到不了
    # （实测 450s+）。改用 **read1**（至多一次底层 recv，返回现有可用字节）：
    # 每轮循环必回到 deadline 检查，socket 超时同时压到剩余预算——绝对 wall
    # deadline 真正围住持续滴流。
    sock = _response_socket(response)
    read1 = getattr(response, "read1", None)
    if read1 is None and deadline is not None and sock is None:
        raise FetchError("response wrapper cannot provide a bounded read")

    while True:
        if deadline is not None and _time.monotonic() > deadline:
            raise FetchLimitError("Response body read exceeded the total fetch duration")
        if sock is not None and deadline is not None:
            try:
                # 响应读完（content-length 满足）后 socket 可能已关闭——
                # EBADF 等忽略，循环顶部绝对 deadline 仍兜底。
                sock.settimeout(max(deadline - _time.monotonic(), 0.001))
            except OSError:
                pass
        remaining = max_bytes - total + 1  # +1 to detect overflow
        read_size = min(chunk_size, max(remaining, 1))
        chunk = read1(read_size) if read1 is not None else response.read(read_size)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise FetchLimitError(
                f"Response body exceeds max_profile_bytes ({max_bytes})"
            )
        chunks.append(chunk)

    return b"".join(chunks)


def _response_socket(response: _ReadableBody) -> socket.socket | None:
    """从 http.client.HTTPResponse 取底层 socket（形状防御，取不到返回 None）。"""
    pending: list[Any] = [response]
    seen: set[int] = set()
    # HTTPError.fp -> HTTPResponse.fp -> BufferedReader.raw -> SocketIO._sock.
    # Bound traversal and tolerate cycles in custom wrappers.
    for _ in range(16):
        if not pending:
            break
        node = pending.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, socket.socket):
            return node
        for attr in ("fp", "raw", "_sock"):
            child = getattr(node, attr, None)
            if child is not None and id(child) not in seen:
                pending.append(child)
    return None


def _parse_max_age_from_header(cache_control: str) -> int | None:
    """Extract max-age value from a Cache-Control header."""
    lower = cache_control.lower()
    for part in lower.split(","):
        part = part.strip()
        if part.startswith("max-age="):
            try:
                return int(part.split("=", 1)[1].strip())
            except (ValueError, IndexError):
                return None
    return None
