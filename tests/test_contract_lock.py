from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import jsonschema

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


def test_candidate_agent_vectors_match_python_schema_when_available() -> None:
    candidates = [ROOT.parent / "kiwi" / "contracts", ROOT.parent / "contracts"]
    contracts = next((path for path in candidates if path.exists()), None)
    if contracts is None:
        return
    from kiwi_catalog.agent_catalog.candidate_dto import CANDIDATE_AGENT_SCHEMA

    valid = json.loads((contracts / "vectors/candidate-agent.valid.json").read_text())
    invalid = json.loads((contracts / "vectors/candidate-agent.invalid-private-field.json").read_text())
    jsonschema.validate(valid, CANDIDATE_AGENT_SCHEMA)
    try:
        jsonschema.validate(invalid, CANDIDATE_AGENT_SCHEMA)
    except jsonschema.ValidationError:
        return
    raise AssertionError("private-field vector was accepted by the catalog schema")
