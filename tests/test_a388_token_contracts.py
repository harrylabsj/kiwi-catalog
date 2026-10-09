import json
import sqlite3
import pytest
from kiwi_catalog.api import auth
from kiwi_catalog.core import tokens
from kiwi_catalog.core.errors import AuthError
from kiwi_catalog.db.session import init_db
from kiwi_catalog.services import merchant_tokens

@pytest.fixture
def db(monkeypatch):
    monkeypatch.setenv('KIWI_CATALOG_OWNER_TOKEN_SECRET','synthetic-a388-owner-only')
    monkeypatch.setenv('KIWI_CATALOG_LEGACY_HMAC_AUTH','on')
    conn=sqlite3.connect(':memory:');conn.row_factory=sqlite3.Row;init_db(conn)
    yield conn
    conn.close()

def test_legacy_body_only_and_conflict_priority(db,monkeypatch):
    legacy=auth.owner_token('legacy')
    auth.require_merchant_token({'owner_token':legacy},'legacy',db)
    with pytest.raises(AuthError):auth.require_merchant_token(auth.payload_with_auth({},'Bearer '+legacy,''),'legacy',db)
    # The documented body choice wins, even when the bearer is otherwise valid.
    random=tokens.generate_merchant_token()
    db.execute("insert into merchant_tokens(merchant_id,token_hash,status,issued_at) values (?,?, 'active','synthetic')",('active',tokens.token_digest(random)))
    auth.require_merchant_token(auth.payload_with_auth({},'Bearer '+random,''),'active',db)
    with pytest.raises(AuthError):auth.require_merchant_token(auth.payload_with_auth({'owner_token':'wrong'},'Bearer '+random,''),'active',db)
    auth.require_merchant_token(auth.payload_with_auth({'owner_token':random},'Bearer wrong',''),'active',db)
    # A client JSON copy is not a transport header credential.
    assert '_auth_token' not in auth.payload_with_auth({'_auth_token':random},'','')
    monkeypatch.setenv('KIWI_CATALOG_LEGACY_HMAC_AUTH','off')
    with pytest.raises(AuthError):auth.require_merchant_token({'owner_token':legacy},'legacy',db)
    auth.require_merchant_token(auth.payload_with_auth({},'Bearer '+random,''),'active',db)

def test_revoked_rotated_never_fall_back_to_legacy(db):
    legacy=auth.owner_token('m')
    first=tokens.generate_merchant_token();second=tokens.generate_merchant_token()
    db.execute("insert into merchant_tokens(merchant_id,token_hash,status,issued_at) values (?,?,'active','synthetic')",('m',tokens.token_digest(first)))
    for presented in [legacy,first]:
        if presented==first:auth.require_merchant_token({'owner_token':presented},'m',db)
        else:
            with pytest.raises(AuthError):auth.require_merchant_token({'owner_token':presented},'m',db)
    db.execute("update merchant_tokens set token_hash=? where merchant_id='m'",(tokens.token_digest(second),))
    for old in [legacy,first]:
        with pytest.raises(AuthError):auth.require_merchant_token({'owner_token':old},'m',db)
    auth.require_merchant_token(auth.payload_with_auth({},'Bearer '+second,''),'m',db)
    db.execute("update merchant_tokens set status='revoked' where merchant_id='m'")
    for old in [legacy,first,second]:
        with pytest.raises(AuthError):auth.require_merchant_token({'owner_token':old},'m',db)

def test_real_issue_rotate_audit_fingerprints_no_raw_or_24_prefix_and_old_rows_unchanged(db):
    app=db.execute("insert into merchant_applications(domain,agent_name,contact_email,created_at) values ('synthetic.invalid','a388','nobody@synthetic.invalid','t')").lastrowid
    old=json.dumps({'token_prefix':'historical-display-prefix','schema_version':1})
    db.execute("insert into audit_events(conversation_id,actor,event,details_json,created_at) values ('','admin','historical',?,'t')",(old,))
    issued=merchant_tokens.approve_application(db,app);rotated=merchant_tokens.rotate_token(db,issued['merchant_id'])
    rows=db.execute("select event,details_json from audit_events where event in ('merchant_token_issued','merchant_token_rotated') order by id").fetchall()
    assert len(rows)==2
    for row,result in zip(rows,[issued,rotated]):
        details=json.loads(row['details_json'])
        assert 'token_prefix' not in details
        fingerprint=details['token_fingerprint']
        assert fingerprint.startswith('sha256:v1:') and len(fingerprint)==74
        assert fingerprint==tokens.merchant_token_audit_fingerprint(result['token'])
        assert result['token'] not in row['details_json'] and result['token'][:24] not in row['details_json']
        assert details['merchant_id']==issued['merchant_id']
    assert rows[0]['details_json']!=rows[1]['details_json']
    assert db.execute("select details_json from audit_events where event='historical'").fetchone()[0]==old
    # Authenticated issue response compatibility is independent of audit display.
    assert issued['token_prefix']==issued['token'][:24]


def test_fingerprint_is_stable_versioned_and_not_an_auth_digest_or_raw_prefix():
    first = 'mkt_' + 'A' * 40
    second = first[:24] + 'B' * 20
    a = tokens.merchant_token_audit_fingerprint(first)
    b = tokens.merchant_token_audit_fingerprint(second)
    assert a == tokens.merchant_token_audit_fingerprint(first)
    assert a != b and a != 'sha256:v1:' + tokens.token_digest(first)
    assert len(a) == 74 and all(c in '0123456789abcdef' for c in a[10:])
    assert first[:24] not in a and second[:24] not in b
