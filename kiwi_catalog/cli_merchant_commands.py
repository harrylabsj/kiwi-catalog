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

"""Merchant token 分发 CLI 命令（docs/kiwi-catalog-token-portal-design-v0.1 §9）。

本地运营命令，与 HTTP handler 共用 services/merchant_tokens.py 同一实现：
- ``catalog merchant applications list/approve/reject`` —— 申请工单管理；
- ``catalog merchant token rotate/revoke`` —— 令牌轮换/吊销（明文 token
  只在 approve/rotate 输出一次）；
- ``catalog merchant status`` —— 商家自查（--token 即身份；本地信任边界
  也可 --merchant-id 查任意商家）。

本地 CLI 直连 SQLite（--admin-token 只作 actor 标注不校验——既有约定，
CLAUDE.md「已知设计取舍」）。
"""

from __future__ import annotations

import argparse
import sqlite3

from kiwi_catalog.cli_common import db_path_from_args, emit
from kiwi_catalog.db.session import db_session
from kiwi_catalog.services import merchant_tokens as tokens_service


def cmd_merchant_applications_list(args: argparse.Namespace) -> None:
    """catalog merchant applications list [--status pending]"""
    with db_session(db_path_from_args(args)) as conn:
        results = tokens_service.list_applications(conn, status=args.status, limit=args.limit)
    if args.format == "json":
        emit({"ok": True, "results": results}, args.format)
        return
    if not results:
        print("(no applications)")
        return
    for application in results:
        status = application["status"].ljust(8)
        print(
            f"#{application['application_id']} {status} "
            f"{application['agent_name']} <{application['contact_email']}> "
            f"({application['domain']})"
        )
        if application["merchant_id"]:
            print(f"    merchant: {application['merchant_id']}")
        if application["review_note"]:
            print(f"    note: {application['review_note']}")


def cmd_merchant_applications_approve(args: argparse.Namespace) -> None:
    """catalog merchant applications approve <id>

    签发商家 ID 与令牌；明文 token 只在本命令输出一次。
    """
    with db_session(db_path_from_args(args)) as conn:
        issued = tokens_service.approve_application(conn, args.application_id)
    if args.format == "json":
        emit({"ok": True, **issued}, args.format)
        return
    print(f"approved application #{issued['application_id']}")
    print(f"merchant id: {issued['merchant_id']}")
    print(f"token:       {issued['token']}  (show only once — save it now)")


def cmd_merchant_applications_reject(args: argparse.Namespace) -> None:
    """catalog merchant applications reject <id> [--note ...]"""
    with db_session(db_path_from_args(args)) as conn:
        tokens_service.reject_application(conn, args.application_id, args.note)
    emit(
        {"ok": True, "message": f"rejected application #{args.application_id}"},
        args.format,
    )


def cmd_merchant_token_rotate(args: argparse.Namespace) -> None:
    """catalog merchant token rotate <merchant_id>

    新令牌覆盖旧令牌（旧 hash 作废）；明文 token 只在本命令输出一次。
    """
    with db_session(db_path_from_args(args)) as conn:
        rotated = tokens_service.rotate_token(conn, args.merchant_id)
    if args.format == "json":
        emit({"ok": True, **rotated}, args.format)
        return
    print(f"rotated token for {rotated['merchant_id']}")
    print(f"token: {rotated['token']}  (show only once — save it now)")


def cmd_merchant_token_revoke(args: argparse.Namespace) -> None:
    """catalog merchant token revoke <merchant_id>

    吊销令牌；之后所有带该令牌的写请求 fail-closed。重复吊销幂等。
    """
    with db_session(db_path_from_args(args)) as conn:
        token_status = tokens_service.revoke_token(conn, args.merchant_id)
    emit(
        {
            "ok": True,
            "message": f"token for {args.merchant_id}: {token_status}",
            "merchant_id": args.merchant_id,
            "token_status": token_status,
        },
        args.format,
    )


def cmd_merchant_status(args: argparse.Namespace) -> None:
    """catalog merchant status [--token ... | --merchant-id ...]

    商家自查：--token 即身份（与 HTTP /v1/merchants/self 同语义）；本地
    信任边界也可 --merchant-id 直接查任意商家（服务端该路径需 admin）。
    """
    with db_session(db_path_from_args(args)) as conn:
        token_row: sqlite3.Row | None = None
        if args.merchant_id:
            token_row = tokens_service.require_token_row(conn, args.merchant_id)
        else:
            token_row = tokens_service.resolve_merchant_by_token(conn, args.token)
            if token_row is None:
                raise SystemExit("invalid owner token")
        assert token_row is not None  # 两条分支都保证非空（fail-closed）
        status = tokens_service.merchant_status(conn, token_row)
    if args.format == "json":
        emit({"ok": True, **status}, args.format)
        return
    print(f"merchant id:    {status['merchant_id']}")
    print(f"token status:   {status['token_status']}")
    print(f"issued at:      {status['issued_at']}")
    if status["rotated_at"]:
        print(f"rotated at:     {status['rotated_at']}")
    if status["revoked_at"]:
        print(f"revoked at:     {status['revoked_at']}")
    print(f"agents:         {status['agents_count']}")
    print(f"listings:       {status['listings_count']}")
