from __future__ import annotations
import json
import tempfile
import threading
import unittest
from pathlib import Path
from kiwi_catalog.db.session import open_connection
from kiwi_catalog.services.agent_catalog_writes import register_catalog_agent
from kiwi_catalog.services.agent_verification import VerificationService
from kiwi_catalog.discovery.fetcher import FetchResult
from kiwi_catalog.core.errors import ConflictError, ValidationError
from kiwi_catalog.discovery.verifier import VerificationEvidence

CARD = {"name": "Synthetic", "version": "1.0.0", "url": "https://slow.example/a2a", "skills": [], "capabilities": {}}
UCP = {
    "specificationVersion": "2026-04-08",
    "serviceIdentity": {"id": "slow.example", "name": "Synthetic"},
    "services": [
        {
            "id": "commerce",
            "type": "commerce",
            "capabilities": [],
            "endpoints": [{"uri": "https://slow.example/a2a", "protocol": "a2a"}],
        }
    ],
}


class SlowFetcher:
    def __init__(self, entered, release):
        self.entered = entered
        self.release = release
        self.calls = []
        self.connection = None
        self.domain_transaction = None

    def fetch(self, url, **kwargs):
        self.calls.append(url)
        if url.endswith("/profile-card.json"):
            data = CARD
        elif url.endswith("/profile-ucp.json"):
            data = UCP
        else:
            self.domain_transaction = self.connection.in_transaction
            self.entered.set()
            if not self.release.wait(3):
                raise AssertionError("owned domain barrier timed out")
            return FetchResult(url=url, status_code=503)
        raw = json.dumps(data).encode()
        return FetchResult(url=url, status_code=200, parsed=data, raw_bytes=raw, body=raw.decode(), max_age=60)


class VerificationTransactionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "catalog.sqlite"
        c = open_connection(self.path)
        c.execute("CREATE TABLE caller_scratch(value text)")
        self.agent = register_catalog_agent(
            c,
            domain="slow.example",
            agent_card_url="https://slow.example/profile-card.json",
            ucp_profile_url="https://slow.example/profile-ucp.json",
        )["catalog_agent_id"]
        c.commit()
        c.close()

    def test_other_real_connection_can_write_while_domain_fetch_is_blocked(self):
        entered = threading.Event()
        release = threading.Event()
        fetch = SlowFetcher(entered, release)
        errors = []

        def run():
            c = open_connection(self.path)
            fetch.connection = c
            try:
                VerificationService(c, fetcher=fetch).verify(self.agent, force=True)
            except BaseException as e:
                errors.append(e)
            finally:
                c.rollback()
                c.close()

        thread = threading.Thread(target=run)
        thread.start()
        try:
            self.assertTrue(entered.wait(2), errors)
            c = open_connection(self.path)
            c.execute("PRAGMA busy_timeout=30")
            try:
                c.execute("INSERT INTO caller_scratch VALUES ('other-writer')")
                c.commit()
                self.assertFalse(fetch.domain_transaction)
            finally:
                c.rollback()
                c.close()
        finally:
            release.set()
            thread.join(4)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])

    def test_domain_aba_cannot_substitute_later_domain_for_captured_subject(self):
        c = open_connection(self.path)
        other = open_connection(self.path)
        fetch = SlowFetcher(threading.Event(), threading.Event())
        fetch.connection = c
        fetch.release.set()
        service = VerificationService(c, fetcher=fetch)
        original_load = service._load_profiles
        domains = []

        def load_then_change(agent_id):
            profiles = original_load(agent_id)
            other.execute(
                "UPDATE catalog_agents SET canonical_domain='other.example' WHERE catalog_agent_id=?", (self.agent,)
            )
            other.commit()
            return profiles

        def acquire(domain, declared=None):
            domains.append(domain)
            other.execute(
                "UPDATE catalog_agents SET canonical_domain='slow.example' WHERE catalog_agent_id=?", (self.agent,)
            )
            other.commit()
            return VerificationEvidence("domain_control", "failed", "synthetic failed evidence", {})

        service._load_profiles = load_then_change
        service._identity_verifier.verify_domain_control = acquire
        try:
            service.verify(self.agent, force=True)
            self.assertEqual(domains, ["slow.example"])
        finally:
            c.rollback()
            c.close()
            other.close()

    def test_identity_governance_and_endpoint_mutations_reject_before_passed_evidence(self):
        for mutation in ("endpoint", "merchant", "governance"):
            with self.subTest(mutation=mutation):
                c = open_connection(self.path)
                other = open_connection(self.path)
                fetch = SlowFetcher(threading.Event(), threading.Event())
                fetch.connection = c
                fetch.release.set()
                service = VerificationService(c, fetcher=fetch)

                def acquire(domain, declared=None):
                    self.assertFalse(c.in_transaction)
                    if mutation == "endpoint":
                        other.execute(
                            "UPDATE agent_endpoints SET url='https://slow.example/changed-card.json' WHERE catalog_agent_id=? AND kind='agent_card'",
                            (self.agent,),
                        )
                    elif mutation == "merchant":
                        other.execute(
                            "UPDATE catalog_agents SET merchant_id='synthetic-changed-owner' WHERE catalog_agent_id=?",
                            (self.agent,),
                        )
                    else:
                        other.execute(
                            "UPDATE catalog_agents SET administrative_state='suspended' WHERE catalog_agent_id=?",
                            (self.agent,),
                        )
                    other.commit()
                    return VerificationEvidence("domain_control", "passed", "synthetic passed evidence", {})

                service._identity_verifier.verify_domain_control = acquire
                try:
                    with self.assertRaises(ConflictError):
                        service.verify(self.agent, force=True)
                    self.assertEqual(
                        c.execute(
                            "SELECT count(*) FROM agent_verifications WHERE catalog_agent_id=? AND result='passed'",
                            (self.agent,),
                        ).fetchone()[0],
                        0,
                    )
                finally:
                    c.rollback()
                    other.execute(
                        "UPDATE catalog_agents SET merchant_id=NULL, administrative_state='active' WHERE catalog_agent_id=?",
                        (self.agent,),
                    )
                    other.execute(
                        "UPDATE agent_endpoints SET url='https://slow.example/profile-card.json' WHERE catalog_agent_id=? AND kind='agent_card'",
                        (self.agent,),
                    )
                    other.commit()
                    c.close()
                    other.close()

    def test_rejected_final_guard_releases_its_owned_writer_without_caller_cleanup(self):
        c = open_connection(self.path)
        other = open_connection(self.path)
        fetch = SlowFetcher(threading.Event(), threading.Event())
        fetch.connection = c
        fetch.release.set()
        service = VerificationService(c, fetcher=fetch)

        def acquire(domain, declared=None):
            other.execute(
                "UPDATE agent_endpoints SET url='https://slow.example/changed.json' WHERE catalog_agent_id=? AND kind='agent_card'",
                (self.agent,),
            )
            other.commit()
            return VerificationEvidence("domain_control", "failed", "synthetic evidence", {})

        service._identity_verifier.verify_domain_control = acquire
        try:
            with self.assertRaises(ConflictError):
                service.verify(self.agent, force=True)
            # This assertion precedes finally: caller rollback is not the fix.
            self.assertFalse(c.in_transaction)
            other.execute("PRAGMA busy_timeout=30")
            other.execute("INSERT INTO caller_scratch VALUES ('after rejected verification')")
            other.commit()
        finally:
            c.rollback()
            c.close()
            other.close()

    def test_outer_caller_write_transaction_is_neither_committed_nor_rolled_back_and_fetch_zero(self):
        c = open_connection(self.path)
        fetch = SlowFetcher(threading.Event(), threading.Event())
        fetch.connection = c
        fetch.release.set()
        c.execute("INSERT INTO caller_scratch VALUES ('caller-uncommitted')")
        try:
            with self.assertRaises(ValidationError):
                VerificationService(c, fetcher=fetch).verify(self.agent, force=True)
            self.assertTrue(c.in_transaction)
            self.assertEqual(fetch.calls, [])
            self.assertEqual(c.execute("SELECT value FROM caller_scratch").fetchall()[0]["value"], "caller-uncommitted")
            observer = open_connection(self.path)
            try:
                self.assertEqual(observer.execute("SELECT count(*) FROM caller_scratch").fetchone()[0], 0)
            finally:
                observer.close()
            c.rollback()
            self.assertEqual(c.execute("SELECT count(*) FROM caller_scratch").fetchone()[0], 0)
        finally:
            c.rollback()
            c.close()


if __name__ == "__main__":
    unittest.main()
