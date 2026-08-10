# Pull Request

## Summary

<!-- What does this change do and why? Keep it focused and link to issues/docs when relevant. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor (no behavior / public API change)
- [ ] Docs / templates / release config
- [ ] Contract change (wire / kiwi schema)

## Contract lock

- [ ] `uv run --locked python scripts/verify_contract_lock.py` passes.
- [ ] If wire behavior changed, `kiwi_catalog/contracts/kiwi-contracts.lock.json` is aligned with the authoritative kiwi repo schema.

## Validation

- [ ] `uv sync --locked --extra api --extra dev`
- [ ] `uv run --locked python -m ruff check kiwi_catalog tests scripts`
- [ ] `uv run --locked python -m mypy kiwi_catalog`
- [ ] `uv run --locked python -m pytest -q`

## Security & hygiene

- [ ] No credentials, tokens, private host details, local filesystem paths, or personal contact information are committed.
- [ ] No mutable GitHub Actions references; workflow actions remain pinned to full 40-character SHAs.
- [ ] No generated databases, build artifacts, or `.env*` files are committed.

## Checklist

- [ ] My change follows the conventions in `CLAUDE.md`.
- [ ] I have not changed dependency versions or public API outside the intended scope.
