from __future__ import annotations

import unittest
from unittest.mock import patch

from kiwi_catalog.discovery.fetcher import FetchError, FetchResult, ProfileFetcher
from kiwi_catalog.discovery.trust import TrustPolicy


class PublicInquiryTransportTest(unittest.TestCase):
    def test_forwards_exact_body_and_only_signed_headers_via_pinned_no_redirect_transport(self) -> None:
        fetcher = ProfileFetcher(TrustPolicy.defaults())
        body = b'{ "jsonrpc": "2.0", "method": "SendMessage" }'
        headers = {"content-type": "application/json", "content-digest": "sha-256=:abc:",
                   "signature": "sig1=:abc:", "signature-input": 'sig1=("@method")'}
        result = FetchResult(url="https://shop.example/a2a", status_code=200, body="{}")
        with patch("kiwi_catalog.discovery.fetcher._resolve_and_validate", return_value="8.8.8.8"), \
             patch.object(fetcher, "_make_request", return_value=result) as send:
            self.assertIs(fetcher.post_signed_a2a("https://shop.example/a2a?sharecode=secret", body, headers), result)
        self.assertEqual(send.call_args.kwargs["data"], body)
        self.assertEqual(send.call_args.kwargs["signed_headers"], headers)
        self.assertEqual(send.call_args.kwargs["redirect_limit"], 0)

    def test_rejects_unsigned_credentials_and_header_injection(self) -> None:
        fetcher = ProfileFetcher(TrustPolicy.defaults())
        headers = {"content-type": "application/json", "content-digest": "x",
                   "signature": "x", "signature-input": "x"}
        for bad in ({**headers, "authorization": "private"}, {**headers, "signature": "x\r\ny"},
                    {k: v for k, v in headers.items() if k != "signature"}):
            with self.subTest(bad=bad), self.assertRaises(FetchError):
                fetcher.post_signed_a2a("https://shop.example/a2a", b"{}", bad)


if __name__ == "__main__":
    unittest.main()
