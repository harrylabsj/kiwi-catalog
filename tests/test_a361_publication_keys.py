"""Publication field boundaries: benign extensions pass; secrets stay blocked."""

import unittest
from kiwi_catalog.a2a.card_store import scan_publication_leaks
from tests import test_cloud_card_publication as fixture


class PublicationKeyBoundaryTest(unittest.TestCase):
    def test_benign_substrings_in_nested_keys_pass(self):
        value = {
            "capabilities": {
                "extensions": [
                    {
                        "params": {
                            "tokenize": True,
                            "tokenizer": "words",
                            "secretary": "assistant",
                            "costume": "fabric",
                            "privateer": False,
                            "flooring": "wood",
                        }
                    }
                ]
            }
        }
        self.assertEqual(scan_publication_leaks(value), [])

    def test_sensitive_words_and_known_compounds_reject_even_non_string_values(self):
        for key in (
            "owner_token",
            "token",
            "private",
            "floor",
            "api_key",
            "api-key",
            "APIKey",
            "privateKey",
            "clientSecret",
            "priceFloor",
            "minUnitPrice",
            "apikey",
            "credentials",
            "accessToken",
            "tokens",
            "access_token",
        ):
            with self.subTest(key=key):
                value = {"extensions": [{"params": {key: {"masked": True}}}]}
                self.assertIn("extensions.0.params." + key, scan_publication_leaks(value))

    def test_plain_text_value_is_not_field_name_matching(self):
        self.assertEqual(scan_publication_leaks({"description": "tokenize private flooring"}), [])

    def test_secret_value_under_neutral_field_still_rejects(self):
        self.assertIn(
            "extensions.0.note", scan_publication_leaks({"extensions": [{"note": "Bearer abcdefghijklmnopqrstuvwxyz"}]})
        )

    def test_signed_publication_allows_benign_extension_params(self):
        h = fixture.CloudCardPublicationTest()
        h.setUp()
        self.addCleanup(h.doCleanups)
        card = fixture._card(
            extra={
                "capabilities": {
                    "extensions": [
                        {
                            "uri": "https://example.org/extensions/tokenizer",
                            "params": {"tokenize": True, "secretary": "assistant", "flooring": "wood"},
                        }
                    ]
                }
            }
        )
        status, payload, _, _ = h._publish(card)
        self.assertEqual(status, 200, payload)

    def test_sensitive_extension_rejects_without_replacing_active_card(self):
        h = fixture.CloudCardPublicationTest()
        h.setUp()
        self.addCleanup(h.doCleanups)
        self.assertEqual(h._publish()[0], 200)
        self.assertEqual(h._activate(revision=1, expected_revision=0)[0], 200)
        status, original, _, _ = h._read()
        self.assertEqual(status, 200)
        card = fixture._card(
            extra={
                "capabilities": {
                    "extensions": [
                        {
                            "uri": "https://example.org/extensions/quote",
                            "params": {"priceFloor": 100},
                        }
                    ]
                }
            }
        )
        status, payload, _, _ = h._publish(card, expected_revision=1)
        self.assertEqual(status, 400, payload)
        status, after, _, _ = h._read()
        self.assertEqual(status, 200)
        self.assertEqual(after, original)
