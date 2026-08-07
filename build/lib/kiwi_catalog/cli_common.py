"""Shared argparse helpers and output utilities for shopping-cli commands."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

from kiwi_catalog.config import DEFAULT_DB_PATH

MAX_SQLITE_INTEGER = 2**63 - 1


def emit_json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, default=str))


def emit(value: Any, fmt: str) -> None:
    if fmt == "json":
        emit_json(value)
    else:
        if isinstance(value, dict) and isinstance(value.get("message"), str):
            print(value["message"])
        else:
            print(json.dumps(value, ensure_ascii=False, sort_keys=True, default=str))


def yes_no(value: Any) -> str:
    return "yes" if value else "no"


def positive_int(value: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("must be a whole number") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    if number > MAX_SQLITE_INTEGER:
        raise argparse.ArgumentTypeError(f"must be <= {MAX_SQLITE_INTEGER}")
    return number


def non_negative_int(value: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("must be a whole number") from exc
    if number < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    if number > MAX_SQLITE_INTEGER:
        raise argparse.ArgumentTypeError(f"must be <= {MAX_SQLITE_INTEGER}")
    return number


def positive_float(value: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(number):
        raise argparse.ArgumentTypeError("must be finite")
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return number


def float_value(value: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc


def positive_seconds(value: str) -> int:
    try:
        seconds = int(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("must be a whole number") from exc
    if seconds <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return seconds


def positive_int_at_most(maximum: int) -> Any:
    def parse(value: str) -> int:
        number = positive_int(value)
        if number > maximum:
            raise argparse.ArgumentTypeError(f"must be <= {maximum}")
        return number

    return parse


def non_negative_int_at_most(maximum: int) -> Any:
    def parse(value: str) -> int:
        number = non_negative_int(value)
        if number > maximum:
            raise argparse.ArgumentTypeError(f"must be <= {maximum}")
        return number

    return parse


def non_negative_float_at_most(maximum: float) -> Any:
    def parse(value: str) -> float:
        try:
            number = float(value)
        except (TypeError, ValueError) as exc:
            raise argparse.ArgumentTypeError("must be a number") from exc
        if not math.isfinite(number):
            raise argparse.ArgumentTypeError("must be finite")
        if number < 0:
            raise argparse.ArgumentTypeError("must be non-negative")
        if number > maximum:
            raise argparse.ArgumentTypeError(f"must be <= {maximum:g}")
        return number

    return parse


def tcp_port(value: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("must be a whole number") from exc
    if port < 1 or port > 65535:
        raise argparse.ArgumentTypeError("must be between 1 and 65535")
    return port


def db_path_from_args(args: argparse.Namespace) -> Path:
    return Path(getattr(args, "agent_db", None) or args.db or args.data or DEFAULT_DB_PATH).expanduser()
