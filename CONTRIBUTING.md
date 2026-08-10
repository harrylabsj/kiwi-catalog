# Contributing

1. Keep changes focused and update the contract lock when wire behavior changes.
2. Run `uv sync --locked --extra api --extra dev`, then `uv run --locked python scripts/verify_contract_lock.py` and `uv run --locked python -m pytest -q` before opening a pull request.
3. Never commit credentials, private host details, local filesystem paths, generated databases, or personal contact information.
4. Do not add mutable GitHub Actions references; workflow actions must remain pinned to full commit SHAs.
