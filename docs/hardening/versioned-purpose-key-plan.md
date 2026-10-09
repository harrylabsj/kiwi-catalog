# Versioned purpose keys: design and offline compatibility proof (3-63)

**Design only.** Production env reading, current HMAC/Fernet/grant functions,
schema versions, and existing databases are unchanged. Do not rotate the current
`KIWI_CATALOG_OWNER_TOKEN_SECRET` merely to apply this document. A root compromise
can affect all three present uses; existing message prefixes/KDF separation do
not make one root into independently revocable purpose keys. No cross-purpose
forgery or production secret exposure is claimed.

## Proposed representation

Use independently generated, high-entropy keys per purpose and lifecycle, with
explicit active-writer key ID and read/verify-only old IDs. Restrict IDs to short
safe configuration labels and never expose key material in config summaries.
Protect the keyring outside the DB with the existing operational secret controls.
Do not silently generate a missing key or try all keys for an unknown explicit ID.

* Account token encryption: new envelope `enc:v3:<key-id>:<Fernet ciphertext>`,
  with a 32-byte random encryption key per ID. The reader recognizes v3 and its
  exact key; it also retains current `v2:` scrypt and unprefixed SHA-256-derived
  legacy Fernet readers under the pinned old root. Unknown version/key, corruption
  or unavailable old key is an explicit failure, never empty token/success.
* Legacy owner HMAC: existing unversioned credentials cannot identify a key ID.
  During an explicitly approved transition window, a narrowly configured
  verify-only legacy key set may validate body-only credentials for eligible
  no-token-row merchants. Random-token rows remain authoritative; revoked/rotated
  rows and legacy-off still refuse fallback. Do not extend header compatibility.
  Random owner-token issuance does not need this HMAC root.
* Enrollment grant: keep the public grant opaque. A future internal
  `grant_key_version` on each enrollment determines deterministic derivation;
  old rows with missing metadata mean the pinned legacy root/domain, not the
  current active writer. New rows atomically record their key version before
  grant/digest creation. Pending rows continue the same grant after writer changes.
  Unknown/unavailable row key is an explicit reconciliation failure; do not mint
  a replacement grant or change an existing digest to make a poll succeed.
  Adding this internal metadata requires a separately reviewed source migration
  and rollout, not a migration in this change.

## Safe rollout and rollback order

1. Inventory old encrypted values and pending enrollment/key dependencies using
   authorized tooling; back up encrypted data and recoverable key material under
   approved secret procedures. Do not export plaintext tokens for inventory.
2. Deploy readers/verifiers that understand both legacy and new formats while
   writers still use old formats. Verify failure behavior and old-row preservation.
3. After separately approved schema/config deployment, set new purpose writer IDs.
   Keep old encryption keys until all old ciphertext is independently confirmed
   migrated/readable; keep old grant keys until every dependent pending enrollment
   is authoritatively terminal. Owner legacy acceptance follows its explicit
   eligibility/window policy, not an automatic token-row fallback.
4. Re-encrypt only via a future bounded, audited, transactional migration after
   authorization. Neither this document nor the proof rewrites a row.
5. Roll back the active writer to an older retained ID if needed, but retain readers
   for *all* versions already written. An old binary that cannot parse v3 is not a
   safe rollback once any v3 ciphertext exists. Never remove the new read key just
   because the active writer changed. A lost key cannot be repaired with another
   secret, an empty return value, a new grant or automatic re-drive.

Retirement requires zero dependent ciphertext/pending rows and an explicit
operational decision. Compromise response may intentionally revoke credentials
or invalidate grants, but that is a separate authorized action, not transparent
compatibility. Encryption-key, owner-legacy and grant rotations have independent
schedules; fingerprint audit IDs need no secret key or automatic historical rewrite.

## What the proof demonstrates

`tests/test_a388_key_design.py` is an offline sketch, not imported by production.
It exercises real cryptography and the current legacy functions with fake-only
roots: old v1/v2 ciphertext and two proposed v3 IDs decrypt; wrong/missing key or
version fails; read compatibility survives writer rollback; current legacy HMAC
is body-only-compatible under the explicit old window and never overrides a
random-token row; legacy pending grants and version-tagged pending grants remain
stable when the active writer changes. Removing a needed grant key refuses a
replacement. No production key API, env option, DB migration, auto re-encryption,
secret rotation, or claim clearing is implemented or implied.
