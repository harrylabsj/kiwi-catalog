# Merchant credential and audit display contract

## Authentication compatibility (3-60)

Network callers pass their real connection to `require_merchant_token`.
Transport uses `payload_with_auth` to strip client-supplied `_auth_token` and
inject the actual Authorization Bearer value. Nonempty JSON `owner_token` takes
precedence over that value, including conflict: an invalid body credential does
not try an otherwise valid Bearer. Do not send both credentials accidentally.

If any `merchant_tokens` row exists for the merchant, only its active random
credential digest can authorize. A rotated, revoked, or wrong credential never
falls back to derived HMAC, even when legacy compatibility is enabled. Active
random tokens can be supplied in body or as Bearer; new integrations should use
Bearer and omit `owner_token`.

Only merchants with no token row and legacy enabled may use the derived HMAC.
That legacy path remains **body-only**. A Bearer containing a legacy HMAC does
not acquire new compatibility. `KIWI_CATALOG_LEGACY_HMAC_AUTH=off` disables the
with-connection no-row fallback, without disabling active random tokens.
The old trusted local `conn=None` helper remains body-HMAC-only and does not
consult row status or the database-backed legacy-off path; it is not appropriate
for network authorization. No header legacy support is introduced.

## New issue/rotate audit fingerprints (3-62)

New `merchant_token_issued` and `merchant_token_rotated` audit details contain
`token_fingerprint`, formatted **`sha256:v1:` + 64 lowercase hexadecimal digits**.
It is full SHA-256 of UTF-8 token bytes prefixed with
`kiwi-catalog-merchant-audit-v1` and one NUL byte. This domain separation avoids
reusing the authentication digest as a display identifier. Repeated observations
of the same token can correlate; a new rotated token has a different identifier.
No substring of the bearer token, including its old 24-character prefix, is
written by these two new audit events. This is an irreversible correlation
fingerprint for high-entropy random tokens, not an encryption envelope or a
statement about password hashing.

The audit event envelope/schema_version remains 1; the fingerprint value carries
its own algorithm/format version. Historical details may still have `token_prefix`.
Readers should prefer a recognized `token_fingerprint`, otherwise label a legacy
`token_prefix` as a historical hint, without interpreting it as authorization or
rewriting old rows. Unknown fingerprint versions are display-only opaque values.
No tokens are rotated and no audit history is scrubbed by this change.

Authenticated issue/rotate results retain the existing `token` and `token_prefix`
response fields for client compatibility; accounts may legitimately recover their
own active token under the existing authenticated session. That is distinct from
audit display. New fingerprint generation does not change credential hashes,
Fernet storage, authentication precedence, or who can obtain a token.

The local proof reads real synthetic SQLite audit rows. No user-facing HTTP route
reading catalog `audit_events` was found in this repository's API handlers/routes;
`conversation_audit_events` is an abstract repository boundary. This is not a
claim about deployment-specific DB/admin access or proof an unauthorized user
could previously read audit data. The change minimizes new audit secret material
without asserting a discovered production leak.
