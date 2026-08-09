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
import ssl
import time as _time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

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

# ── Verified IP store (shared across handler and redirect handler) ─────────────
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
        for net in _EXTRA_BLOCKED_V6:
            if ip in net:
                return f"blocked range {net}"
        # IPv4-mapped IPv6 (::ffff:a.b.c.d) — extract and check the v4 part
        if ip.ipv4_mapped:
            v4 = ip.ipv4_mapped
            if v4 is not None:
                reason = _is_blocked_ip(v4)
                if reason:
                    return f"IPv4-mapped {reason}"
    else:
        if ip.is_link_local:
            return "link-local address"
        # Extra blocked v4 ranges
        for net in _EXTRA_BLOCKED_V4:
            if ip in net:
                return f"blocked range {net}"
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


def _resolve_hostname(hostname: str, port: int) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve *hostname* and return all IP addresses.

    Raises SSRFBlockError when the hostname cannot be resolved.
    """
    try:
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


def _resolve_and_validate(hostname: str, port: int) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Resolve *hostname*, validate all IPs, and return the first valid IP.

    Raises SSRFBlockError if any resolved IP is blocked or the hostname
    cannot be resolved.
    """
    ips = _resolve_hostname(hostname, port)
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

    def __init__(self, host: str, verified_ip: str, **kwargs: Any) -> None:
        self._ssrf_verified_ip = str(verified_ip)
        super().__init__(host, **kwargs)

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._ssrf_verified_ip, self.port),
            self.timeout,
        )
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
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

    def __init__(self, host: str, verified_ip: str, **kwargs: Any) -> None:
        self._ssrf_verified_ip = str(verified_ip)
        super().__init__(host, **kwargs)

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._ssrf_verified_ip, self.port),
            self.timeout,
        )
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        if self._tunnel_host:  # type: ignore[attr-defined]
            self._tunnel()  # type: ignore[attr-defined]

        ctx = ssl.create_default_context()
        # SNI carries self.host (the original hostname); cert validation
        # is against that hostname, not the IP.
        self.sock = ctx.wrap_socket(self.sock, server_hostname=self.host)


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
    ):
        self._redirect_limit = redirect_limit
        self._redirect_count = 0
        self._validator = validator
        self._ip_store = ip_store
        super().__init__()

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self._redirect_count += 1
        if self._redirect_count > self._redirect_limit:
            raise SSRFBlockError(
                f"Redirect limit ({self._redirect_limit}) exceeded"
            )
        # Re-validate the redirect target and store the verified IP so
        # the HTTPS handler uses the correct address for the new host.
        verified_ip = self._validator(newurl)
        parsed = urllib.parse.urlparse(newurl)
        hostname = parsed.hostname
        port = _port_of(parsed, parsed.scheme)
        assert hostname is not None  # validator guarantees a hostname is present
        self._ip_store[(hostname, port)] = str(verified_ip)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _build_opener(
    initial_verified_ip: str,
    initial_hostname: str,
    initial_port: int,
    redirect_limit: int,
    redirect_validator: Callable[[str], ipaddress.IPv4Address | ipaddress.IPv6Address],
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
                    host, verified_ip=verified_ip, **kw
                )
            # 审查 P2（http 支持真实化）：permissive_local 声明的 http:// 走
            # 同样的 verified-IP 直连（防 DNS rebinding），不再 UnknownHandler
            # 恒失败。默认 require_https 策略在 scheme 校验层已拦截 http。
            return lambda host, **kw: _ProtectedHTTPConnection(
                host, verified_ip=verified_ip, **kw
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

    redirect_handler = _SSRFRedirectHandler(redirect_limit, redirect_validator, ip_store)

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

        # 4. Resolve DNS and validate all IPs
        verified_ip = _resolve_and_validate(hostname, port)

        # 5. Make the request with DNS-rebinding protection
        fetched_at = _time.time()
        try:
            result = self._make_request(url, str(verified_ip), hostname, port, etag, last_modified, fetched_at)
        except urllib.error.HTTPError as exc:
            # Pass through HTTP errors with their status code.  Error bodies are
            # read under the same byte limit as success bodies — 恶意源站返回
            # 超大 4xx 错误体时，无上限的 exc.read() 是请求线程内存 DoS。
            try:
                body_bytes = _read_limited(
                    exc,
                    self._policy.max_profile_bytes,
                    deadline=_time.monotonic() + _MAX_FETCH_DURATION_SECONDS,
                )
            except FetchLimitError:
                body_bytes = b""
            return FetchResult(
                url=url,
                status_code=exc.code,
                body="",
                raw_bytes=body_bytes,
                fetched_at=fetched_at,
            )
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

    def _validate_redirect_target(self, redirect_url: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        """Validate a redirect target URL with full SSRF checks.

        Called by the redirect handler before each redirect is followed.
        Returns the first verified IP for the new hostname.
        """
        parsed = self._validate_url(redirect_url)
        scheme = parsed.scheme
        hostname = parsed.hostname
        assert hostname is not None  # _validate_url guarantees a hostname is present
        port = _port_of(parsed, scheme)

        if self._policy.require_https and scheme != "https":
            raise SSRFBlockError(f"Redirect to non-HTTPS URL blocked: {redirect_url}")

        _validate_port(port, self._policy.allowed_ports)
        return _resolve_and_validate(hostname, port)

    def _make_request(
        self,
        url: str,
        verified_ip: str,
        hostname: str,
        port: int,
        etag: str | None,
        last_modified: str | None,
        fetched_at: float,
    ) -> FetchResult:
        """Execute the HTTP request with all SSRF protections in place."""
        # Build request with conditional headers
        req_headers: dict[str, str] = {
            "Accept": "application/json",
            "Host": hostname,
        }
        if etag:
            req_headers["If-None-Match"] = etag
        if last_modified:
            req_headers["If-Modified-Since"] = last_modified

        request = urllib.request.Request(url, headers=req_headers)

        # Build opener with verified-IP connection
        redirect_validator = self._validate_redirect_target
        opener = _build_opener(
            verified_ip, hostname, port,
            self._policy.redirect_limit, redirect_validator,
        )

        try:
            with opener.open(request, timeout=self._timeout) as response:
                # 审查 P3：response.geturl() 是重定向后的终址——此前传初请求
                # URL，快照/审计记录的是跳转前地址。
                return self._process_response(response, response.geturl(), fetched_at)
        except SSRFBlockError:
            raise
        except FetchLimitError:
            raise
        except urllib.error.HTTPError:
            # Re-raise to be caught by fetch()
            raise
        except TimeoutError as exc:
            raise FetchError(f"Request timed out after {self._timeout}s: {exc}") from exc

    def _process_response(
        self,
        response: http.client.HTTPResponse,
        final_url: str,
        fetched_at: float,
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
        max_bytes = self._policy.max_profile_bytes
        raw_bytes = _read_limited(
            response,
            max_bytes,
            deadline=_time.monotonic() + _MAX_FETCH_DURATION_SECONDS,
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


def _read_limited(
    response: http.client.HTTPResponse,
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

    while True:
        if deadline is not None and _time.monotonic() > deadline:
            raise FetchLimitError("Response body read exceeded the total fetch duration")
        remaining = max_bytes - total + 1  # +1 to detect overflow
        read_size = min(chunk_size, max(remaining, 1))
        chunk = response.read(read_size)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise FetchLimitError(
                f"Response body exceeds max_profile_bytes ({max_bytes})"
            )
        chunks.append(chunk)

    return b"".join(chunks)


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
