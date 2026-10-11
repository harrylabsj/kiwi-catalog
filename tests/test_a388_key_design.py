"""Offline executable design sketch, NOT production env parsing or migration.
All roots/keys are synthetic. Production accounts/auth/enrollments stay unchanged.
"""

import base64
import hashlib
import hmac
import pytest
from cryptography.fernet import Fernet, InvalidToken
from kiwi_catalog.services import accounts, enrollments
from kiwi_catalog.api import auth


# Future explicit envelope/key metadata; no production call imports this sketch.
def enc(value, kid, keys):
    return "enc:v3:" + kid + ":" + Fernet(keys[kid]).encrypt(value.encode()).decode()


def dec(value, keys, legacy_reader):
    if value.startswith("enc:"):
        prefix, version, kid, payload = value.split(":", 3)
        if version != "v3" or kid not in keys:
            raise ValueError("unknown encryption version/key")
        return Fernet(keys[kid]).decrypt(payload.encode()).decode()
    return legacy_reader(value)


def grant(kid, enrollment, device_hash, keys, legacy):
    if kid is None:
        return legacy(enrollment, device_hash)
    if kid not in keys:
        raise ValueError("unknown grant key; do not issue a replacement")
    data = f"kiwi-catalog-enrollment-v2:{kid}:{enrollment}:{device_hash}".encode()
    return hmac.new(keys[kid], data, hashlib.sha256).hexdigest()


def legacy_owner(body_token, merchant, roots, enabled=True, has_random_row=False):
    if not enabled or has_random_row:
        return False
    message = f"kiwi-catalog-owner:{merchant}".encode()
    return any(
        hmac.compare_digest(body_token, hmac.new(root.encode(), message, hashlib.sha256).hexdigest()) for root in roots
    )


@pytest.fixture
def synthetic(monkeypatch):
    monkeypatch.setenv("KIWI_CATALOG_OWNER_TOKEN_SECRET", "synthetic-legacy-a388")
    return "synthetic-legacy-a388"


def test_old_v1_and_v2_real_ciphertext_and_two_new_key_versions_read_without_reencrypt(synthetic):
    token = "mkt_SYNTHETIC_ONLY_NOT_A_CREDENTIAL"
    legacy_v1 = accounts._fernet_v1().encrypt(token.encode()).decode()
    legacy_v2 = accounts.encrypt_merchant_token(token)
    keys = {
        k: base64.urlsafe_b64encode(hashlib.sha256(("synthetic-" + k).encode()).digest()) for k in ["enc-A", "enc-B"]
    }
    new_a = enc(token, "enc-A", keys)
    new_b = enc(token, "enc-B", keys)
    for value in [legacy_v1, legacy_v2, new_a, new_b]:
        assert dec(value, keys, accounts.decrypt_merchant_token) == token
    # Changing the writer back to A keeps B readable only while reader retains B.
    assert dec(new_b, keys, accounts.decrypt_merchant_token) == token
    with pytest.raises(ValueError):
        dec(new_b, {"enc-A": keys["enc-A"]}, accounts.decrypt_merchant_token)
    with pytest.raises(ValueError):
        dec(new_b.replace("enc:v3:", "enc:v99:"), keys, accounts.decrypt_merchant_token)
    with pytest.raises(InvalidToken):
        dec(new_b, {"enc-B": keys["enc-A"]}, accounts.decrypt_merchant_token)


def test_legacy_body_credentials_retained_only_in_explicit_old_window_and_never_override_random_rows(synthetic):
    old = auth.owner_token("merchant")
    assert legacy_owner(old, "merchant", [synthetic])
    assert not legacy_owner(old, "other", [synthetic])
    assert not legacy_owner(old, "merchant", [synthetic], enabled=False)
    assert not legacy_owner(old, "merchant", [synthetic], has_random_row=True)
    assert not legacy_owner(old, "merchant", ["new-root"])
    assert legacy_owner(old, "merchant", [synthetic, "new-root"])


def test_pending_grant_uses_persisted_version_and_legacy_rows_use_pinned_legacy_root(synthetic):
    keys = {"grant-A": b"synthetic-purpose-grant-A", "grant-B": b"synthetic-purpose-grant-B"}
    old = enrollments._stable_grant("enrollment", "devicehash")
    assert grant(None, "enrollment", "devicehash", keys, enrollments._stable_grant) == old
    pending = grant("grant-A", "enrollment", "devicehash", keys, enrollments._stable_grant)
    new = grant("grant-B", "enrollment", "devicehash", keys, enrollments._stable_grant)
    assert pending != new and old not in [pending, new]
    # Active writer changing to B does not change an existing row tagged A.
    assert grant("grant-A", "enrollment", "devicehash", keys, enrollments._stable_grant) == pending
    with pytest.raises(ValueError):
        grant("grant-A", "enrollment", "devicehash", {"grant-B": keys["grant-B"]}, enrollments._stable_grant)
    assert not legacy_owner(new, "merchant", [synthetic])
