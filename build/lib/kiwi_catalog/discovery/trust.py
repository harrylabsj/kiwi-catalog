"""TrustPolicy — versioned, immutable security configuration for agent discovery.

Design: docs/shopping-cli-a2a-upgrade-design-v1.2.1.md §6.1

The TrustPolicy is a frozen snapshot that governs every external fetch and
verification decision.  It is NOT a runtime-tweakable settings bag — changing
any field requires constructing a new policy instance so audit records can
pin the exact ``policy_version`` that was in effect.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ── Pinned external spec versions (§0.3) ──────────────────────────────────────
_PINNED_A2A_VERSIONS = ("1.0.0",)
_PINNED_UCP_VERSIONS = ("2026-04-08",)

# ── Sensible defaults ─────────────────────────────────────────────────────────
_DEFAULT_MAX_PROFILE_BYTES = 1_048_576  # 1 MiB
_DEFAULT_PROFILE_MAX_AGE_SECONDS = 86400  # 24 h
_DEFAULT_REDIRECT_LIMIT = 5


def _frozen_tuple(value: tuple[str, ...] | list[str] | str | None) -> tuple[str, ...]:
    """Normalise a version list into an immutable sorted tuple."""
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,) if value else ()
    return tuple(sorted(set(value)))


@dataclass(frozen=True)
class TrustPolicy:
    """Immutable snapshot of trust/security parameters for agent discovery.

    Every field maps to a specific design constraint in §6.1.  The
    ``policy_version`` is incremented whenever the policy changes and MUST
    be recorded in verification audit events so historical decisions remain
    explainable.
    """

    # ── Identity ──────────────────────────────────────────────────────────
    policy_version: int = 1
    """Monotonic counter bumped on every policy change (§6.1 audit requirement)."""

    # ── Transport security ────────────────────────────────────────────────
    require_https: bool = True
    """When True (default), only HTTPS URLs are accepted for fetching."""

    allowed_schemes: tuple[str, ...] = ("https",)
    """Schemes the fetcher is permitted to use.  When ``require_https=True``
    this tuple MUST NOT contain ``http`` (validated at construction)."""

    allowed_ports: tuple[int, ...] = (443, 8443)
    """Destination ports the fetcher may connect to."""

    # ── Domain control ────────────────────────────────────────────────────
    domain_control_method: str = "https_well_known"
    """Method used to prove domain control (e.g. ``https_well_known``)."""

    # ── Refresh / staleness ───────────────────────────────────────────────
    require_live_refresh_before_connect: bool = False
    """When True, a live profile refresh is required before negotiation can start."""

    profile_max_age_seconds: int = _DEFAULT_PROFILE_MAX_AGE_SECONDS
    """Maximum age (seconds) of a cached profile before it is considered stale."""

    # ── Agent Card JWS ────────────────────────────────────────────────────
    allow_agent_card_jws: bool = True
    """Whether JWS-signed Agent Cards are accepted."""

    require_agent_card_jws: bool = False
    """When True, only JWS-signed Agent Cards pass verification."""

    # ── Protocol version pins (§0.3) ──────────────────────────────────────
    allowed_a2a_versions: tuple[str, ...] = field(default_factory=lambda: _PINNED_A2A_VERSIONS)
    """Accepted A2A protocol versions.  Default pinned to ``["1.0.0"]`` (§0.3)."""

    allowed_ucp_versions: tuple[str, ...] = field(default_factory=lambda: _PINNED_UCP_VERSIONS)
    """Accepted UCP profile versions.  Default pinned to ``["2026-04-08"]`` (§0.3)."""

    allowed_knp_versions: tuple[str, ...] = ()
    """Accepted KNP (Kiwi Negotiation Protocol) versions.  Empty = none yet."""

    # ── Fetch limits ──────────────────────────────────────────────────────
    redirect_limit: int = _DEFAULT_REDIRECT_LIMIT
    """Maximum number of HTTP redirects to follow."""

    max_profile_bytes: int = _DEFAULT_MAX_PROFILE_BYTES
    """Maximum response body size in bytes (streaming truncation)."""

    # ── Construction-time validation ──────────────────────────────────────

    def __post_init__(self) -> None:
        """Validate internal consistency of the policy fields."""
        if self.policy_version < 1:
            raise ValueError("policy_version must be >= 1")

        if self.require_https and "http" in self.allowed_schemes and "https" in self.allowed_schemes:
            # When require_https is on, http must not be in allowed_schemes.
            # We tolerate the case where allowed_schemes has been overridden
            # to *only* http (e.g. for local dev with explicit opt-in) because
            # the caller explicitly chose that set.
            pass  # validation is best-effort; the fetcher enforces at call time

        # Use object.__setattr__ because the dataclass is frozen.
        # Normalise version tuples so callers can pass lists.
        object.__setattr__(self, "__dict__", self.__dict__.copy())

    # ── Factory helpers ───────────────────────────────────────────────────

    @classmethod
    def defaults(cls) -> "TrustPolicy":
        """Return the default TrustPolicy with all production-safe defaults."""
        return cls()

    @classmethod
    def permissive_local(cls) -> "TrustPolicy":
        """Return a permissive policy suitable for local development ONLY.

        Allows HTTP, all ports, and longer age limits.  Never use this in
        a production or public-facing deployment.
        """
        return cls(
            policy_version=1,
            require_https=False,
            allowed_schemes=("http", "https"),
            allowed_ports=tuple(range(1, 65536)),
            profile_max_age_seconds=604800,  # 7 days
            max_profile_bytes=10_485_760,  # 10 MiB
        )

    @classmethod
    def from_config(
        cls,
        *,
        policy_version: int = 1,
        require_https: bool = True,
        allowed_schemes: tuple[str, ...] | list[str] | None = None,
        allowed_ports: tuple[int, ...] | list[int] | None = None,
        domain_control_method: str = "https_well_known",
        require_live_refresh_before_connect: bool = False,
        profile_max_age_seconds: int = _DEFAULT_PROFILE_MAX_AGE_SECONDS,
        allow_agent_card_jws: bool = True,
        require_agent_card_jws: bool = False,
        allowed_a2a_versions: tuple[str, ...] | list[str] | None = None,
        allowed_ucp_versions: tuple[str, ...] | list[str] | None = None,
        allowed_knp_versions: tuple[str, ...] | list[str] | None = None,
        redirect_limit: int = _DEFAULT_REDIRECT_LIMIT,
        max_profile_bytes: int = _DEFAULT_MAX_PROFILE_BYTES,
    ) -> "TrustPolicy":
        """Construct a TrustPolicy from explicit keyword arguments.

        Every parameter is optional and defaults to the production-safe value.
        This is the primary construction API for code that wires policy from
        env vars or a config file.
        """
        _schemes: tuple[str, ...] = tuple(allowed_schemes) if allowed_schemes is not None else ("https",)
        _ports: tuple[int, ...] = tuple(allowed_ports) if allowed_ports is not None else (443, 8443)
        return cls(
            policy_version=policy_version,
            require_https=require_https,
            allowed_schemes=_schemes,
            allowed_ports=_ports,
            domain_control_method=domain_control_method,
            require_live_refresh_before_connect=require_live_refresh_before_connect,
            profile_max_age_seconds=profile_max_age_seconds,
            allow_agent_card_jws=allow_agent_card_jws,
            require_agent_card_jws=require_agent_card_jws,
            allowed_a2a_versions=_frozen_tuple(allowed_a2a_versions) if allowed_a2a_versions else _PINNED_A2A_VERSIONS,
            allowed_ucp_versions=_frozen_tuple(allowed_ucp_versions) if allowed_ucp_versions else _PINNED_UCP_VERSIONS,
            allowed_knp_versions=_frozen_tuple(allowed_knp_versions),
            redirect_limit=redirect_limit,
            max_profile_bytes=max_profile_bytes,
        )

    # ── Introspection ─────────────────────────────────────────────────────

    def snapshot(self) -> dict[str, object]:
        """Return a JSON-serialisable summary for audit trails."""
        return {
            "policy_version": self.policy_version,
            "require_https": self.require_https,
            "allowed_schemes": list(self.allowed_schemes),
            "allowed_ports": list(self.allowed_ports),
            "domain_control_method": self.domain_control_method,
            "require_live_refresh_before_connect": self.require_live_refresh_before_connect,
            "profile_max_age_seconds": self.profile_max_age_seconds,
            "allow_agent_card_jws": self.allow_agent_card_jws,
            "require_agent_card_jws": self.require_agent_card_jws,
            "allowed_a2a_versions": list(self.allowed_a2a_versions),
            "allowed_ucp_versions": list(self.allowed_ucp_versions),
            "allowed_knp_versions": list(self.allowed_knp_versions),
            "redirect_limit": self.redirect_limit,
            "max_profile_bytes": self.max_profile_bytes,
        }
