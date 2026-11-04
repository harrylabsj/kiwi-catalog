# Copyright 2026 harrylabsj
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest import mock

from kiwi_catalog.discovery.fetcher import ProfileFetcher
from kiwi_catalog.discovery.trust import TrustPolicy
from kiwi_catalog.services import runtime_keepalive

_HOST = "linkluck-reception.app.workbuddy.host"
_ORIGIN = f"https://{_HOST}"
_SECRET = "test-only-sharecode"


class FakeFetcher:
    def __init__(self, status: int = 200, error: Exception | None = None) -> None:
        self.status = status
        self.error = error
        self.calls: list[str] = []

    def fetch_no_redirect(self, url: str, *, timeout: float = 5.0):
        self.calls.append(url)
        if self.error is not None:
            raise self.error
        return SimpleNamespace(status_code=self.status)


class GatewayTest(unittest.TestCase):
    def _gateway(self, fetcher: FakeFetcher) -> runtime_keepalive.WorkBuddyKeepaliveGateway:
        return runtime_keepalive.WorkBuddyKeepaliveGateway(
            trusted_hosts=[_HOST], fetcher=fetcher
        )

    def test_uses_fixed_merchant_path_and_returns_request_sent_on_200(self) -> None:
        fetcher = FakeFetcher(200)
        result = self._gateway(fetcher).wake(
            agent_id="cagt_x", runtime_origin=_ORIGIN, secret=_SECRET
        )
        self.assertEqual(result, "request_sent")
        self.assertEqual(len(fetcher.calls), 1)
        self.assertTrue(fetcher.calls[0].startswith(f"{_ORIGIN}/merchant/?"))
        self.assertIn("sharecode=", fetcher.calls[0])

    def test_302_is_not_followed_or_treated_as_success(self) -> None:
        fetcher = FakeFetcher(302)
        with self.assertRaises(runtime_keepalive.KeepaliveDeliveryError) as raised:
            self._gateway(fetcher).wake(agent_id="cagt_x", runtime_origin=_ORIGIN, secret=_SECRET)
        self.assertEqual(str(raised.exception), "delivery_failed")
        self.assertEqual(len(fetcher.calls), 1)

    def test_untrusted_host_is_rejected_before_fetch(self) -> None:
        fetcher = FakeFetcher(200)
        for origin in (
            "https://evil.example",
            "https://linkluck-reception.app.workbuddy.host.evil.example",
            "http://linkluck-reception.app.workbuddy.host",
            "https://linkluck-reception.app.workbuddy.host/path",
            "https://linkluck-reception.app.workbuddy.host/?x=1",
            "https://user:pass@linkluck-reception.app.workbuddy.host",
        ):
            with self.assertRaises(runtime_keepalive.KeepaliveDeliveryError):
                self._gateway(fetcher).wake(agent_id="cagt_x", runtime_origin=origin, secret=_SECRET)
        self.assertEqual(fetcher.calls, [])

    def test_transport_error_is_redacted(self) -> None:
        fetcher = FakeFetcher(error=RuntimeError(f"failed {_ORIGIN} sharecode={_SECRET}"))
        with self.assertRaises(runtime_keepalive.KeepaliveDeliveryError) as raised:
            self._gateway(fetcher).wake(agent_id="cagt_x", runtime_origin=_ORIGIN, secret=_SECRET)
        self.assertEqual(str(raised.exception), "delivery_failed")
        self.assertNotIn(_SECRET, str(raised.exception))
        self.assertNotIn(_HOST, str(raised.exception))

    def test_gateway_requires_explicit_host_allowlist(self) -> None:
        with self.assertRaises(runtime_keepalive.ValidationError):
            runtime_keepalive.WorkBuddyKeepaliveGateway(trusted_hosts=[])
        with self.assertRaises(runtime_keepalive.ValidationError):
            runtime_keepalive.WorkBuddyKeepaliveGateway(trusted_hosts=["*.app.workbuddy.host"])

    def test_fetch_no_redirect_pins_dns_and_sets_zero_redirect_limit(self) -> None:
        fetcher = ProfileFetcher(TrustPolicy.defaults(), timeout=5)
        sentinel = SimpleNamespace(status_code=200)
        with mock.patch.object(
            fetcher,
            "_validate_url",
            return_value=SimpleNamespace(scheme="https", hostname=_HOST, port=443),
        ):
            with mock.patch("kiwi_catalog.discovery.fetcher._resolve_and_validate", return_value="203.0.113.1"):
                with mock.patch.object(fetcher, "_make_request", return_value=sentinel) as make:
                    result = fetcher.fetch_no_redirect(f"{_ORIGIN}/merchant/", timeout=4)
        self.assertIs(result, sentinel)
        self.assertEqual(make.call_args.kwargs["method"], "GET")
        self.assertEqual(make.call_args.kwargs["redirect_limit"], 0)
        self.assertEqual(make.call_args.kwargs["timeout"], 4)


if __name__ == "__main__":
    unittest.main()
