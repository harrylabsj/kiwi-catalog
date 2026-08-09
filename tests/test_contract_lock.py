from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_contract_lock_matches_kiwi_manifest_when_checkout_is_available() -> None:
    lock = json.loads((ROOT / "kiwi_catalog/contracts/kiwi-contracts.lock.json").read_text())
    kiwi_manifest = ROOT.parent / "kiwi" / "contracts/manifest.json"
    args = [sys.executable, str(ROOT / "scripts/verify_contract_lock.py")]
    if kiwi_manifest.exists():
        args.extend(["--manifest", str(kiwi_manifest)])
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr or result.stdout
    assert lock["source_repository"] == "harrylabsj/kiwi"
