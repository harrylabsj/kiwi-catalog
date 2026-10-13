# Changelog

## 0.5.6 — 2026-10-13

- Registration and welcome emails. `notify_admin_new_registration` emails the operations inbox (`KIWI_CATALOG_ADMIN_NOTIFY_EMAIL`) after a merchant account commits — the subject carries「邮箱待验证」because the account exists but `email_verified` is still 0 at that moment, so the merchant cannot log in yet. `send_welcome_email` sends a one-off welcome note to the merchant on first successful email verification (smtp mode only; console/未配置模式返回 False). Both are side-channel: they never raise, so an SMTP failure cannot affect registration or verification — deliberately the opposite of the verification code's fail-closed semantics — and both are called **after** the `db_session` transaction commits.
- **Repo/main alignment**: this behaviour shipped to production on 2026-10-09 as a runtime `patch` applied directly to `/opt/kiwi-catalog-0.5.5/.venv/.../site-packages` (see `runtime-email.patch`), which is why the running service sends the notification while `main` did not. The ported functions are byte-identical to the deployed code apart from docstrings/comments; the two call sites are otherwise unchanged.

## 0.5.5 — 2026-10-01

- Launch preflight: new `kiwi_catalog.a2a.launch_preflight.issuance_preflight` reuses the existing fail-closed validators (`load_issuer_key_set`, `catalog_public_origin`) to check the issuance-required configuration — issuer key set (exactly one ACTIVE key via `KIWI_CATALOG_ISSUER_KEYS_FILE` or the single-key env fallback) and `KIWI_CATALOG_PUBLIC_ORIGIN` — and reports fixed codes (`ISSUER_KEY_OK`/`ISSUER_KEY_REJECTED`, `PUBLIC_ORIGIN_OK`/`PUBLIC_ORIGIN_REJECTED`). Read-only: no network access, no key generation, no private-key material or key-file paths in the report.
- `kiwi-catalog-api --check-config` exits 0 only when both checks pass, 1 otherwise (usable as a systemd `ExecStartPre` or deployment-checklist step). The serving path prints a stderr warning at startup when the configuration is incomplete but keeps serving — issuance stays fail-closed at request time, semantics unchanged. The packaged systemd unit gains an `ExecStartPre` line so a misconfigured host refuses to start instead of silently returning 403 on `runtime-bindings` (A37: 91×403 with no startup-period signal).

## 0.5.4 — 2026-09-30

- Runtime-binding denial diagnostics: every 403 branch on the enrollment bind path now logs a fixed own error code (`BIND_GRANT_UNAVAILABLE`, `BIND_MATERIAL_MISMATCH`, `BIND_CHALLENGE_DELIVERY_FAILED`, …) with a safe stage label before responding; response bodies and status codes are unchanged. Log lines contain no grant, request JWS, key material, or remote error text.
- Converge `urllib.error.URLError` (TLS-handshake-timeout shape) in `ProfileFetcher._make_request` to `FetchError`, matching the existing `_fetch` convention: challenge-egress network failures return the existing diagnosable 409 instead of leaking an unhandled 500. HTTPError status passthrough, SSRF/HTTPS/port/timeout policies unchanged.

## 0.5.3 — 2026-09-30

- Move the merchant portal HTML pages (`/portal/*`, `handlers/portal.py`, `handlers/portal_kit.py`) out of the package: they are provided by the private `kiwi-catalog-admin` extension. Core keeps only the `/v1` business APIs. This is the same move that was released as 0.5.1 but was never merged into `main`, so 0.5.2 re-shipped the in-package portal — whose base routes shadow the extension's routes and silently reverted merchant pages on hosts that installed it.
- Guard the public-package boundary in tests: no `/portal*` route, no portal handler module, and no `admin_reports` reference may return to the package.
- Keep the 0.5.2 `GET /v1/accounts/me/service-status` API in the route table.

## 0.5.2 — 2026-09-29

- Include the read-only `GET /v1/accounts/me/service-status` API for merchant onboarding, publication, heartbeat presence, and product-quota status.
- Prepare the package version for the protected portfolio PyPI release. Production hosts must install this release from PyPI only.
