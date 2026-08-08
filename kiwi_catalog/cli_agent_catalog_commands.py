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

"""Agent Catalog CLI command handlers — search/get/register/refresh/verify/claim/stats/doctor.

Search and get are read-only (§10.1); register (§10.2), refresh/verify (§10.3)
and claim (§10.4) operate directly on the local SQLite store through the shared
service layer (``services/agent_catalog_writes.py`` and the W3 verification
service).  The CLI deliberately does NOT enqueue into the bounded verification
queue — the caller runs ``agent catalog verify`` / ``refresh`` explicitly so the
result is reported synchronously.  ``stats`` / ``doctor`` are local
observability helpers (§24) over the same store.
"""

from __future__ import annotations

import argparse
from typing import Any

from kiwi_catalog.cli_common import db_path_from_args, emit
from kiwi_catalog.core.errors import NotFoundError
from kiwi_catalog.db.session import db_session
from kiwi_catalog.services import agent_catalog_writes
from kiwi_catalog.services.agent_catalog import get_catalog_agent, search_catalog_agents
from kiwi_catalog.services.agent_catalog_metrics import catalog_doctor_report, catalog_stats
from kiwi_catalog.services.agent_verification import (
    InvalidStateTransitionError,
    VerificationService,
)


def _format_verification(agent: dict[str, Any]) -> str:
    """Human-readable verification status + last_verified_at (§28 DoD#15)."""
    ver = agent.get("verification", {}) or {}
    status = ver.get("status", "discovered")
    last_verified = ver.get("last_verified_at", "")
    if last_verified:
        return f"{status} (last verified: {last_verified})"
    return status


def _format_hosting(agent: dict[str, Any]) -> str:
    hosting = agent.get("hosting", {}) or {}
    return hosting.get("mode", "unknown")


def _format_capabilities(agent: dict[str, Any]) -> str:
    caps = agent.get("capabilities", []) or []
    if not caps:
        return "-"
    return ", ".join(str(c) for c in caps)


def _format_protocols(agent: dict[str, Any]) -> str:
    protos = agent.get("protocols", {}) or {}
    if not protos:
        return "-"
    parts = []
    for proto, versions in protos.items():
        if versions:
            parts.append(f"{proto} ({', '.join(versions)})")
        else:
            parts.append(proto)
    return "; ".join(parts)


def _format_merchant(agent: dict[str, Any]) -> str:
    merchant = agent.get("merchant", {}) or {}
    name = merchant.get("name", "")
    domain = merchant.get("domain", "")
    if name and domain:
        return f"{name} ({domain})"
    if name:
        return name
    if domain:
        return domain
    return "-"


def cmd_agent_catalog_search(args: argparse.Namespace) -> None:
    with db_session(db_path_from_args(args)) as conn:
        result = search_catalog_agents(
            conn,
            q=args.q or "",
            category=args.category or "",
            skill=args.skill or "",
            capability=args.capability or "",
            protocol=args.protocol or "",
            hosting_mode=args.hosting_mode or "",
            verification_status=args.verification_status or "",
            verified_after=args.verified_after or "",
            limit=args.limit,
            cursor=args.cursor or "",
        )

    results: list[dict[str, Any]] = result.get("results", []) or []
    next_cursor = result.get("next_cursor")

    if args.format == "text":
        if not results:
            print("No catalog agents found.")
            return
        print(
            f"{'CATALOG_AGENT_ID':<24} "
            f"{'MERCHANT':<30} "
            f"{'VERIFICATION':<40} "
            f"{'HOSTING':<12} "
            f"{'CAPABILITIES'}"
        )
        for agent in results:
            print(
                f"{agent.get('catalog_agent_id', ''):<24} "
                f"{_format_merchant(agent):<30} "
                f"{_format_verification(agent):<40} "
                f"{_format_hosting(agent):<12} "
                f"{_format_capabilities(agent)}"
            )
        if next_cursor:
            print(f"\nNext cursor: {next_cursor}")
        return

    response: dict[str, Any] = {"ok": True, "results": results}
    if next_cursor:
        response["next_cursor"] = next_cursor
    emit(response, args.format)


def _cli_actor(args: argparse.Namespace, merchant_id: str = "") -> str:
    """Best-effort audit actor from optional CLI tokens (default ``cli``)."""
    if getattr(args, "admin_token", ""):
        return "admin"
    if getattr(args, "owner_token", "") and merchant_id:
        return f"merchant:{merchant_id}"
    return "cli"


def _print_catalog_agent(agent: dict[str, Any]) -> None:
    print(f"Catalog Agent: {agent.get('catalog_agent_id', '')}")
    merchant = agent.get("merchant", {}) or {}
    print(f"Merchant: {merchant.get('name', '-')} ({merchant.get('id', '-')})")
    domain = agent.get("canonical_domain", "")
    if not domain:
        domain = (agent.get("discovery", {}) or {}).get("canonical_domain", "")
    if domain:
        print(f"Domain: {domain}")
    verification = agent.get("verification", {}) or {}
    print(f"Verification Status: {verification.get('status', 'discovered')}")


def _verification_response_json(
    catalog_agent_id: str, result: Any
) -> dict[str, Any]:
    return {
        "ok": True,
        "catalog_agent_id": catalog_agent_id,
        "previous_status": result.previous_status,
        "verification_status": result.status,
        "stages": [
            {
                "stage": stage.stage,
                "outcome": stage.outcome,
                "target_status": stage.target_status,
                "reason": stage.reason,
                "verification_id": stage.verification_id,
                "snapshot_ids": list(stage.snapshot_ids),
            }
            for stage in result.stages
        ],
    }


def cmd_agent_catalog_register(args: argparse.Namespace) -> None:
    """Create a DISCOVERED self_registered catalog agent (§10.2)."""
    with db_session(db_path_from_args(args)) as conn:
        result = agent_catalog_writes.register_catalog_agent(
            conn,
            domain=args.domain,
            agent_card_url=getattr(args, "agent_card_url", "") or "",
            ucp_profile_url=getattr(args, "ucp_profile_url", "") or "",
            merchant_id=getattr(args, "merchant_id", "") or "",
            actor=_cli_actor(args, getattr(args, "merchant_id", "") or ""),
        )
    if args.format == "text":
        print(f"Registered catalog agent: {result.get('catalog_agent_id', '')}")
        _print_catalog_agent(result)
        return
    emit({"ok": True, "catalog_agent": result}, args.format)


def cmd_agent_catalog_verify(args: argparse.Namespace) -> None:
    """Run the §6 verification ladder synchronously (§10.3)."""
    catalog_agent_id = str(args.catalog_agent_id).strip()
    with db_session(db_path_from_args(args)) as conn:
        service = VerificationService(conn)
        try:
            result = service.verify(
                catalog_agent_id,
                actor=_cli_actor(args),
                force=bool(getattr(args, "force", False)),
            )
        except InvalidStateTransitionError as exc:
            raise SystemExit(str(exc))
    if args.format == "text":
        print(_format_verification_result(result))
        return
    emit(_verification_response_json(catalog_agent_id, result), args.format)


def cmd_agent_catalog_refresh(args: argparse.Namespace) -> None:
    """Re-fetch profiles and re-run the full ladder (§10.3 refresh)."""
    catalog_agent_id = str(args.catalog_agent_id).strip()
    with db_session(db_path_from_args(args)) as conn:
        service = VerificationService(conn)
        try:
            result = service.refresh(catalog_agent_id, actor=_cli_actor(args))
        except InvalidStateTransitionError as exc:
            raise SystemExit(str(exc))
    if args.format == "text":
        print(_format_verification_result(result))
        return
    emit(_verification_response_json(catalog_agent_id, result), args.format)


def cmd_agent_catalog_claim(args: argparse.Namespace) -> None:
    """Claim ownership of a catalog agent (§10.4, §6.2)."""
    catalog_agent_id = str(args.catalog_agent_id).strip()
    merchant_id = str(args.merchant_id or "").strip()
    with db_session(db_path_from_args(args)) as conn:
        result = agent_catalog_writes.claim_catalog_agent(
            conn,
            catalog_agent_id=catalog_agent_id,
            merchant_id=merchant_id,
            actor=_cli_actor(args, merchant_id),
        )
    if args.format == "text":
        print(f"Claimed catalog agent: {result.get('catalog_agent_id', '')}")
        _print_catalog_agent(result)
        return
    emit({"ok": True, "catalog_agent": result}, args.format)


def cmd_agent_catalog_suspend(args: argparse.Namespace) -> None:
    """Suspend a catalog agent (v3.0 moderation, §10.4 P2)."""
    catalog_agent_id = str(args.catalog_agent_id).strip()
    reason = str(getattr(args, "reason", "") or "").strip()
    with db_session(db_path_from_args(args)) as conn:
        service = VerificationService(conn)
        try:
            result = service.suspend(catalog_agent_id, actor=_cli_actor(args), reason=reason)
        except InvalidStateTransitionError as exc:
            raise SystemExit(str(exc))
    if args.format == "text":
        print(_format_verification_result(result))
        return
    emit(_verification_response_json(catalog_agent_id, result), args.format)


def cmd_agent_catalog_reinstate(args: argparse.Namespace) -> None:
    """Reinstate a suspended catalog agent (v3.0 moderation, §10.4 P2).

    SUSPENDED → ACTIVE；保留 verification_level 与 freshness（三域模型：
    证据未失效，级别不应丢失，折叠投影恢复后回到原级别）。
    """
    catalog_agent_id = str(args.catalog_agent_id).strip()
    reason = str(getattr(args, "reason", "") or "").strip()
    with db_session(db_path_from_args(args)) as conn:
        service = VerificationService(conn)
        try:
            result = service.reinstate(catalog_agent_id, actor=_cli_actor(args), reason=reason)
        except InvalidStateTransitionError as exc:
            raise SystemExit(str(exc))
    if args.format == "text":
        print(_format_verification_result(result))
        print("Re-verification required: run `kiwi-catalog agent catalog verify <id>`")
        return
    emit(_verification_response_json(catalog_agent_id, result), args.format)


def _format_verification_result(result: Any) -> str:
    lines = [
        f"Catalog Agent: {result.catalog_agent_id}",
        f"Verification Status: {result.status} (was {result.previous_status})",
    ]
    for stage in result.stages:
        reason = f" — {stage.reason}" if stage.reason else ""
        lines.append(f"  {stage.stage}: {stage.outcome} -> {stage.target_status}{reason}")
    return "\n".join(lines)


def cmd_agent_catalog_get(args: argparse.Namespace) -> None:
    catalog_agent_id = str(args.catalog_agent_id).strip()
    with db_session(db_path_from_args(args)) as conn:
        try:
            agent = get_catalog_agent(conn, catalog_agent_id)
        except NotFoundError:
            raise SystemExit(f"Unknown catalog agent: {catalog_agent_id}")

    if args.format == "text":
        print(f"Catalog Agent: {agent.get('catalog_agent_id', '')}")
        merchant = agent.get("merchant", {}) or {}
        print(f"Merchant: {merchant.get('name', '-')} ({merchant.get('id', '-')})")
        if merchant.get("domain"):
            print(f"Domain: {merchant['domain']}")
        if merchant.get("city"):
            print(f"City: {merchant['city']}")
        if merchant.get("service_area"):
            print(f"Service Area: {merchant['service_area']}")

        verification = agent.get("verification", {}) or {}
        print(f"Verification Status: {verification.get('status', 'discovered')}")
        last_verified = verification.get("last_verified_at", "")
        if last_verified:
            print(f"Last Verified: {last_verified}")

        hosting = agent.get("hosting", {}) or {}
        print(f"Hosting Mode: {hosting.get('mode', 'unknown')}")

        caps = agent.get("capabilities", []) or []
        print(f"Capabilities: {', '.join(str(c) for c in caps) if caps else '-'}")

        protos = agent.get("protocols", {}) or {}
        if protos:
            print("Protocols:")
            for proto, versions in protos.items():
                ver_str = f" ({', '.join(versions)})" if versions else ""
                print(f"  {proto}{ver_str}")

        discovery = agent.get("discovery", {}) or {}
        if discovery:
            print("Discovery:")
            for key, value in discovery.items():
                if isinstance(value, list):
                    for url in value:
                        print(f"  {key}: {url}")
                else:
                    print(f"  {key}: {value}")

        tags = merchant.get("tags", []) or []
        if tags:
            print(f"Tags: {', '.join(str(t) for t in tags)}")
        return

    emit({"ok": True, "agent": agent}, args.format)


def _print_stats_text(stats: dict[str, Any]) -> None:
    print("Agent Catalog Stats")
    print("===================")
    print(f"Catalog agents:        {stats['catalog_agent_count']}")
    print(f"Verified agents:       {stats['verified_agent_count']}")
    print(f"Unverified agents:     {stats['unverified_agent_count']}")
    print(f"Stale agents:          {stats['stale_agent_count']}")
    print(f"Suspended agents:      {stats['suspended_agent_count']}")
    print(f"Rejected agents:       {stats['rejected_agent_count']}")
    print()

    def _distribution(title: str, dist: dict[str, Any]) -> None:
        print(f"{title}:")
        if not dist:
            print("  (none)")
            return
        for key in sorted(dist):
            print(f"  {key:<24} {dist[key]}")

    _distribution("Verification status", stats["verification_status_distribution"])
    print()
    _distribution("Hosting mode", stats["hosting_mode_distribution"])
    print()
    _distribution("Source type", stats["source_type_distribution"])
    print()
    print(f"Capabilities:          {stats['capability_count']}")
    print(f"Endpoints:             {stats['endpoint_count']}")
    print(f"Skills:                {stats['skill_count']}")
    print(f"Profile snapshots:     {stats['profile_snapshot_count']}")

    runtime = stats.get("runtime_metrics", {})
    print()
    print("Runtime metrics (this process)")
    print("------------------------------")
    counters = runtime.get("counters", {})
    if counters:
        _distribution("Counters", counters)
    else:
        print("Counters:  (none)")
    latency = runtime.get("latency", {})
    if latency:
        print("Latency:")
        for name in sorted(latency):
            rec = latency[name]
            print(f"  {name:<24} count={rec['count']} avg={rec['avg']:.3f}s max={rec['max']:.3f}s")
    else:
        print("Latency:   (none)")
    gauges = runtime.get("gauges", {})
    for name in sorted(gauges):
        print(f"Gauge:                 {name} = {gauges[name]:g}")
    funnel = runtime.get("funnel", {})
    if funnel:
        _distribution("Funnel", funnel)
    derived = runtime.get("derived", {})
    if derived:
        print("Derived:")
        for name in sorted(derived):
            print(f"  {name:<28} {derived[name]:g}")


def cmd_agent_catalog_stats(args: argparse.Namespace) -> None:
    """Local §24 metric subset for the local catalog store."""
    with db_session(db_path_from_args(args)) as conn:
        stats = catalog_stats(conn)
    if args.format == "text":
        _print_stats_text(stats)
        return
    stats.setdefault("ok", True)
    emit(stats, args.format)


def _print_doctor_text(report: dict[str, Any]) -> None:
    print("Catalog Doctor")
    print("==============")

    def _line(label: str, value: int, *, flag: str = "") -> None:
        suffix = f"   [{flag}]" if flag else ""
        print(f"{label:<28} {value}{suffix}")

    _line("Total agents", report["total_agents"])
    _line("Stale agents", report["stale_agents"], flag="ISSUE" if report["stale_agents"] else "")
    _line(
        "Unverified registrations",
        report["unverified_registrations"],
        flag="ISSUE" if report["unverified_registrations"] else "",
    )
    _line(
        "Expired snapshots",
        report["expired_profile_snapshots"],
        flag="ISSUE" if report["expired_profile_snapshots"] else "",
    )
    _line("Unreachable agents", report["unreachable_agents"], flag="ISSUE" if report["unreachable_agents"] else "")
    _line("Suspended agents", report["suspended_agents"], flag="ISSUE" if report["suspended_agents"] else "")
    _line("Rejected agents", report["rejected_agents"], flag="ISSUE" if report["rejected_agents"] else "")
    _line(
        "Missing canonical domain",
        report["missing_canonical_domain"],
        flag="ISSUE" if report["missing_canonical_domain"] else "",
    )
    _line(
        "Agents without endpoints",
        report["agents_without_endpoints"],
        flag="WARN" if report["agents_without_endpoints"] else "",
    )
    print()
    for issue in report.get("issues", []):
        print(f"  [ISSUE] {issue}")
    for warning in report.get("warnings", []):
        print(f"  [WARN]  {warning}")
    if report["healthy"]:
        print("\nHealth: OK")
    else:
        print(f"\nHealth: {len(report.get('issues', []))} issue(s) found")


def cmd_agent_catalog_doctor(args: argparse.Namespace) -> None:
    """Local catalog health check (§24): stale/unverified/expired-snapshot counts.

    Exits with status 1 when any issue is found so scripts/CI can react.
    """
    with db_session(db_path_from_args(args)) as conn:
        report = catalog_doctor_report(conn)
    if args.format == "text":
        _print_doctor_text(report)
    else:
        emit(report, args.format)
    if not report["healthy"]:
        raise SystemExit(1)
