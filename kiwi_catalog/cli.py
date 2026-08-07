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

"""kiwi-catalog CLI (extracted from shopping-cli cli.py, phase 3).

Only the Agent Catalog command group is served: search/get/register/
verify/refresh/claim/suspend/reinstate/stats/doctor.  Audit actor
resolution uses catalog-owner tokens (phase-3 auth, 方案 i) instead of
shopping-cli merchant tokens.
"""

from __future__ import annotations

import argparse
import sys

from kiwi_catalog import VERSION
from kiwi_catalog.cli_common import non_negative_int, positive_int
from kiwi_catalog.cli_agent_catalog_commands import (
    cmd_agent_catalog_claim,
    cmd_agent_catalog_doctor,
    cmd_agent_catalog_get,
    cmd_agent_catalog_refresh,
    cmd_agent_catalog_register,
    cmd_agent_catalog_reinstate,
    cmd_agent_catalog_search,
    cmd_agent_catalog_stats,
    cmd_agent_catalog_suspend,
    cmd_agent_catalog_verify,
)
from kiwi_catalog.core.errors import ShoppingCliError

DEFAULT_DB_PATH = "kiwi-catalog.sqlite"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="kiwi-catalog — standalone Agent Catalog service.", add_help=True)
    parser.add_argument("--db", help=f"SQLite database path. Default: {DEFAULT_DB_PATH}")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    catalog = subparsers.add_parser("catalog", help="Agent Catalog commands (registration/verification/search/governance)")
    agent_catalog_sub = catalog.add_subparsers(dest="agent_catalog_command", required=True)
    agent_catalog_search = agent_catalog_sub.add_parser("search", help="Search catalog agents")
    agent_catalog_search.add_argument("--q", default="", help="Free-text search across display name and merchant name")
    agent_catalog_search.add_argument("--category", default="", help="Filter by agent category")
    agent_catalog_search.add_argument("--skill", default="", help="Filter by skill id or name")
    agent_catalog_search.add_argument("--capability", default="", help="Filter by fully-qualified capability identifier")
    agent_catalog_search.add_argument("--protocol", default="", help="Filter by protocol (e.g. a2a, ucp)")
    agent_catalog_search.add_argument("--hosting-mode", default="", dest="hosting_mode", help="Filter by hosting mode (hosted, direct)")
    agent_catalog_search.add_argument("--verification-status", default="", dest="verification_status", help="Filter by verification status")
    agent_catalog_search.add_argument("--verified-after", default="", dest="verified_after", help="Only agents verified after this ISO-8601 timestamp")
    agent_catalog_search.add_argument("--limit", type=positive_int, default=20, help="Max results (1-100)")
    agent_catalog_search.add_argument("--cursor", default="", help="Pagination cursor from a previous search")
    agent_catalog_search.add_argument("--format", choices=["text", "json"], default="text")
    agent_catalog_search.set_defaults(func=cmd_agent_catalog_search)
    agent_catalog_get = agent_catalog_sub.add_parser("get", help="Show one catalog agent by id")
    agent_catalog_get.add_argument("catalog_agent_id", help="Catalog agent id (e.g. cagt_...)")
    agent_catalog_get.add_argument("--format", choices=["text", "json"], default="text")
    agent_catalog_get.set_defaults(func=cmd_agent_catalog_get)
    agent_catalog_register = agent_catalog_sub.add_parser("register", help="Register a self_registered catalog agent (§10.2)")
    agent_catalog_register.add_argument("--domain", required=True, help="Canonical bare domain (e.g. merchant.example)")
    agent_catalog_register.add_argument("--agent-card-url", default="", dest="agent_card_url", help="Optional public Agent Card URL")
    agent_catalog_register.add_argument("--ucp-profile-url", default="", dest="ucp_profile_url", help="Optional public UCP Profile URL")
    agent_catalog_register.add_argument("--merchant-id", default="", dest="merchant_id", help="Optional merchant binding")
    agent_catalog_register.add_argument("--admin-token", default="", dest="admin_token", help="Admin token for audit actor resolution")
    agent_catalog_register.add_argument("--merchant-token", default="", dest="merchant_token", help="Merchant token for audit actor resolution")
    agent_catalog_register.add_argument("--format", choices=["text", "json"], default="text")
    agent_catalog_register.set_defaults(func=cmd_agent_catalog_register)
    agent_catalog_verify = agent_catalog_sub.add_parser("verify", help="Run the §6 verification ladder synchronously (§10.3)")
    agent_catalog_verify.add_argument("catalog_agent_id", help="Catalog agent id (e.g. cagt_...)")
    agent_catalog_verify.add_argument("--force", action="store_true", help="Re-verify even when the profile cache is fresh")
    agent_catalog_verify.add_argument("--admin-token", default="", dest="admin_token")
    agent_catalog_verify.add_argument("--owner-token", default="", dest="owner_token")
    agent_catalog_verify.add_argument("--format", choices=["text", "json"], default="text")
    agent_catalog_verify.set_defaults(func=cmd_agent_catalog_verify)
    agent_catalog_refresh = agent_catalog_sub.add_parser("refresh", help="Re-fetch profiles and re-run the full ladder (§10.3)")
    agent_catalog_refresh.add_argument("catalog_agent_id", help="Catalog agent id (e.g. cagt_...)")
    agent_catalog_refresh.add_argument("--admin-token", default="", dest="admin_token")
    agent_catalog_refresh.add_argument("--owner-token", default="", dest="owner_token")
    agent_catalog_refresh.add_argument("--format", choices=["text", "json"], default="text")
    agent_catalog_refresh.set_defaults(func=cmd_agent_catalog_refresh)
    agent_catalog_claim = agent_catalog_sub.add_parser("claim", help="Claim ownership of a catalog agent (§10.4, §6.2)")
    agent_catalog_claim.add_argument("catalog_agent_id", help="Catalog agent id (e.g. cagt_...)")
    agent_catalog_claim.add_argument("--merchant-id", required=True, dest="merchant_id", help="Merchant to claim the agent for")
    agent_catalog_claim.add_argument("--admin-token", default="", dest="admin_token")
    agent_catalog_claim.add_argument("--owner-token", default="", dest="owner_token")
    agent_catalog_claim.add_argument("--format", choices=["text", "json"], default="text")
    agent_catalog_claim.set_defaults(func=cmd_agent_catalog_claim)
    agent_catalog_suspend = agent_catalog_sub.add_parser("suspend", help="Suspend a catalog agent (v3.0 moderation, §10.4 P2)")
    agent_catalog_suspend.add_argument("catalog_agent_id", help="Catalog agent id (e.g. cagt_...)")
    agent_catalog_suspend.add_argument("--reason", default="", help="Optional suspension reason (recorded in §23 audit)")
    agent_catalog_suspend.add_argument("--admin-token", default="", dest="admin_token")
    agent_catalog_suspend.add_argument("--owner-token", default="", dest="owner_token")
    agent_catalog_suspend.add_argument("--format", choices=["text", "json"], default="text")
    agent_catalog_suspend.set_defaults(func=cmd_agent_catalog_suspend)
    agent_catalog_reinstate = agent_catalog_sub.add_parser("reinstate", help="Reinstate a suspended catalog agent (v3.0 moderation, §10.4 P2)")
    agent_catalog_reinstate.add_argument("catalog_agent_id", help="Catalog agent id (e.g. cagt_...)")
    agent_catalog_reinstate.add_argument("--reason", default="", help="Optional reinstate reason (recorded in §23 audit)")
    agent_catalog_reinstate.add_argument("--admin-token", default="", dest="admin_token")
    agent_catalog_reinstate.add_argument("--owner-token", default="", dest="owner_token")
    agent_catalog_reinstate.add_argument("--format", choices=["text", "json"], default="text")
    agent_catalog_reinstate.set_defaults(func=cmd_agent_catalog_reinstate)
    agent_catalog_stats = agent_catalog_sub.add_parser("stats", help="Local catalog metrics (§24)")
    agent_catalog_stats.add_argument("--format", choices=["text", "json"], default="text")
    agent_catalog_stats.set_defaults(func=cmd_agent_catalog_stats)
    agent_catalog_doctor = agent_catalog_sub.add_parser("doctor", help="Local catalog health check (§24); exits 1 on issues")
    agent_catalog_doctor.add_argument("--format", choices=["text", "json"], default="text")
    agent_catalog_doctor.set_defaults(func=cmd_agent_catalog_doctor)


    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args_list = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(args_list)
    try:
        args.func(args)
    except ShoppingCliError as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
