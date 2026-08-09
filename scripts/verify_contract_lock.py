"""Verify the pinned kiwi contract bundle, optionally against a local manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")


def bundle_digest(manifest: dict) -> str:
    rows = sorted((item["path"], item["sha256"]) for item in manifest["contracts"])
    payload = "".join(f"{path}\0{digest}\n" for path, digest in rows).encode()
    return hashlib.sha256(payload).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    lock_path = Path(__file__).resolve().parents[1] / "kiwi_catalog" / "contracts" / "kiwi-contracts.lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if lock.get("lock_version") != 1 or lock.get("source_repository") != "harrylabsj/kiwi":
        raise SystemExit("invalid kiwi contract lock metadata")
    if not HEX40.fullmatch(lock.get("source_commit", "")):
        raise SystemExit("source_commit must be a full 40-character SHA")
    if not HEX64.fullmatch(lock.get("bundle_sha256", "")):
        raise SystemExit("bundle_sha256 must be a lowercase SHA-256")
    if args.manifest:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        if bundle_digest(manifest) != lock["bundle_sha256"]:
            raise SystemExit("local kiwi manifest does not match pinned bundle")
    print(f"kiwi contract lock verified: {lock['bundle_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
