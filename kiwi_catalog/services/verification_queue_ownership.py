"""Single-owner lock for the process-local verification scheduler."""

import errno
import os
import sqlite3
from pathlib import Path

from kiwi_catalog.core.errors import ConflictError


def acquire_worker_lock(db_path: Path) -> sqlite3.Connection:
    """Hold an SQLite write lock on a separate file until every runner exits."""
    target = db_path.with_name(f"{db_path.name}.verification-worker.sqlite")
    write_error = f"verification worker requires a writable lock file and directory: {target}"
    try:
        fd = os.open(target, os.O_CREAT | os.O_RDONLY, 0o600)
        os.close(fd)
    except OSError as exc:
        if isinstance(exc, PermissionError) or exc.errno == errno.EROFS:
            raise RuntimeError(write_error) from exc
        raise
    conn = None
    try:
        conn = sqlite3.connect(target, timeout=0, check_same_thread=False)
        conn.execute("BEGIN IMMEDIATE")
    except sqlite3.Error as exc:
        if conn is not None:
            conn.close()
        code = (getattr(exc, "sqlite_errorcode", 0) or 0) & 0xFF
        if code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
            raise ConflictError("a verification worker already owns this catalog database") from exc
        if code in {sqlite3.SQLITE_CANTOPEN, sqlite3.SQLITE_READONLY, sqlite3.SQLITE_PERM}:
            raise RuntimeError(write_error) from exc
        raise
    return conn
