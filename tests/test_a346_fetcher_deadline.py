"""Real local HTTP/TLS deadline controls; fixture release/stop/join is bounded."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from contextlib import nullcontext
from pathlib import Path
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

from kiwi_catalog.discovery import fetcher as f


class WireServer:
    def __init__(self, tls=None):
        self.stop = threading.Event()
        self.safety = threading.Timer(3, self.stop.set)
        self.safety.daemon = True
        self.safety.start()
        self.hits = []
        self.active = set()
        self.lock = threading.Lock()
        outer = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                sock = self.request
                with outer.lock:
                    outer.active.add(sock)
                try:
                    sock.settimeout(2)
                    wire = b""
                    while b"\r\n\r\n" not in wire:
                        chunk = sock.recv(4096)
                        if not chunk:
                            return
                        wire += chunk
                    method, path, _ = wire.split(b"\r\n", 1)[0].split(b" ")
                    mode = path.decode().strip("/")
                    outer.hits.append((method.decode(), mode))
                    if mode.startswith("delay"):
                        if outer.stop.wait(float(mode.split("-")[1])):
                            return
                        mode = "ok"
                    error = mode.startswith("error-") or mode == "error"
                    mode = mode.removeprefix("error-")
                    status = b"503 Unavailable" if error else b"200 OK"
                    prefix = b"HTTP/1.1 " + status + b"\r\n"
                    if mode == "header":
                        sock.sendall(prefix + b"X-Slow: ")
                    elif mode in ("chunk-size", "trailer", "chunk-body"):
                        sock.sendall(prefix + b"Transfer-Encoding: chunked\r\n\r\n")
                        if mode == "trailer":
                            sock.sendall(b"0\r\nX-Slow: ")
                        elif mode == "chunk-body":
                            sock.sendall(b"10000\r\n")
                    elif mode == "body":
                        sock.sendall(prefix + b"Content-Length: 65536\r\n\r\n")
                    elif mode == "chunk-ok":
                        sock.sendall(prefix + b'Transfer-Encoding: chunked\r\n\r\nB\r\n{"ok":true}\r\n0\r\n\r\n')
                        return
                    elif mode == "redirect":
                        sock.sendall(b"HTTP/1.1 302 Found\r\nLocation: /ok\r\nContent-Length: 0\r\n\r\n")
                        return
                    elif mode == "cap":
                        sock.sendall(prefix + b"Content-Length: 500000\r\n\r\n" + b"x" * 500000)
                        return
                    else:
                        body = b'{"ok":true}'
                        sock.sendall(
                            prefix
                            + b"Content-Type: application/json\r\nContent-Length: "
                            + str(len(body)).encode()
                            + b"\r\n\r\n"
                            + body
                        )
                        return
                    while not outer.stop.wait(0.015):
                        sock.sendall(b"1" if mode == "chunk-size" else b"x")
                except (OSError, ssl.SSLError):
                    pass
                finally:
                    with outer.lock:
                        outer.active.discard(sock)

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = False
            block_on_close = True

            def handle_error(self, *args):
                pass

        self.server = Server(("127.0.0.1", 0), Handler)
        if tls:
            self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.02), daemon=True)
        self.thread.start()
        self.base = (
            f"{'https' if tls else 'http'}://{'localhost' if tls else '127.0.0.1'}:{self.server.server_address[1]}"
        )

    def close(self):
        self.safety.cancel()
        self.safety.join()
        self.stop.set()
        with self.lock:
            for sock in self.active:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        assert not self.thread.is_alive() and not self.active, "wire fixture did not drain"


class DeadlineTests(unittest.TestCase):
    def setUp(self):
        patch = mock.patch.object(f, "_is_blocked_ip", return_value=None)
        patch.start()
        self.addCleanup(patch.stop)
        self.fetcher = f.ProfileFetcher(f.TrustPolicy.permissive_local())

    def direct(self, server, mode, budget):
        url = server.base + "/" + mode
        return self.fetcher._make_request(
            url,
            "127.0.0.1",
            "localhost" if url.startswith("https") else "127.0.0.1",
            server.server.server_address[1],
            None,
            None,
            time.time(),
            deadline=time.monotonic() + budget,
        )

    def assert_drip(self, mode, tls=None):
        server = WireServer(tls)
        created = []
        real = getattr(f, "_RequestLifecycle", None)

        def owner(deadline):
            obj = real(deadline)
            created.append(obj)
            return obj

        try:
            started = time.monotonic()
            with mock.patch.object(f, "_RequestLifecycle", side_effect=owner) if real else nullcontext():
                with self.assertRaises(f.FetchError) as failure:
                    self.direct(server, mode, 0.25)
            elapsed = time.monotonic() - started
            self.assertEqual(len(server.hits), 1, f"fixture never reached wire phase: {failure.exception}")
            self.assertLess(elapsed, 0.7)
            self.assertGreater(elapsed, 0.18, "failed before the sustained-byte phase")
            self.assertTrue(all(not o._timer.is_alive() for o in created))
            self.assertTrue(all(not o._sockets for o in created))
        finally:
            server.close()

    def test_header(self):
        self.assert_drip("header")

    def test_chunk_size(self):
        self.assert_drip("chunk-size")

    def test_chunk_body(self):
        self.assert_drip("chunk-body")

    def test_trailer(self):
        self.assert_drip("trailer")

    def test_body(self):
        self.assert_drip("body")

    def test_error_header(self):
        self.assert_drip("error-header")

    def test_error_body_wrapper(self):
        self.assert_drip("error-body")

    def test_error_chunk_wrapper(self):
        self.assert_drip("error-chunk-size")

    def test_error_trailer_wrapper(self):
        self.assert_drip("error-trailer")

    def test_owned_read_fallback_still_has_wall_deadline(self):
        with mock.patch.object(f.http.client.HTTPResponse, "read1", None):
            self.assert_drip("body")

    def test_verified_tls_header_and_chunk(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "key.pem"
            cert = Path(directory) / "cert.pem"
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                    "-days",
                    "1",
                    "-subj",
                    "/CN=localhost",
                    "-addext",
                    "subjectAltName=DNS:localhost",
                ],
                check=True,
                capture_output=True,
            )
            server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server.load_cert_chain(cert, key)
            client = ssl.create_default_context(cafile=str(cert))
            self.assertTrue(client.check_hostname)
            self.assertEqual(client.verify_mode, ssl.CERT_REQUIRED)
            untrusted = WireServer(server)
            try:
                with self.assertRaises(f.FetchError):
                    self.direct(untrusted, "ok", 1)
                self.assertEqual(untrusted.hits, [], "untrusted TLS reached HTTP")
            finally:
                untrusted.close()
            with (
                mock.patch.object(f.ssl, "create_default_context", return_value=client),
                mock.patch.object(f.http.client, "_create_https_context", return_value=client),
            ):
                positive = WireServer(server)
                try:
                    self.assertEqual(self.direct(positive, "ok", 1).status_code, 200)
                finally:
                    positive.close()
                self.assert_drip("header", server)
                self.assert_drip("chunk-size", server)

    def test_parallel_short_deadline_does_not_close_long_request(self):
        server = WireServer()
        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                slow = pool.submit(self.direct, server, "delay-.45", 1.0)
                until = time.monotonic() + 2
                while not server.hits and time.monotonic() < until:
                    time.sleep(0.005)
                self.assertTrue(server.hits, "parallel fixture did not reach server")
                short = pool.submit(self.direct, server, "header", 0.2)
                with self.assertRaises(f.FetchError):
                    short.result(timeout=2)
                self.assertEqual(slow.result(timeout=2).status_code, 200)
        finally:
            server.close()

    def test_fast_request_does_not_disarm_slow_request(self):
        server = WireServer()
        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                slow = pool.submit(self.direct, server, "header", 0.3)
                until = time.monotonic() + 2
                while not server.hits and time.monotonic() < until:
                    time.sleep(0.005)
                self.assertTrue(server.hits, "parallel fixture did not reach server")
                self.assertEqual(self.direct(server, "ok", 1).status_code, 200)
                started = time.monotonic()
                with self.assertRaises(f.FetchError):
                    slow.result(timeout=1)
                self.assertLess(time.monotonic() - started, 0.6)
        finally:
            server.close()

    def test_get_post_error_redirect_positive_and_cap(self):
        server = WireServer()
        try:
            self.assertEqual(self.fetcher.fetch(server.base + "/ok").status_code, 200)
            self.assertEqual(self.fetcher.post_json(server.base + "/ok", {"test": 1}).status_code, 200)
            self.assertEqual(self.fetcher.fetch(server.base + "/error").status_code, 503)
            result = self.fetcher.fetch(server.base + "/redirect")
            self.assertEqual(result.status_code, 200)
            self.assertTrue(result.url.endswith("/ok"))
            self.assertEqual(self.fetcher.fetch(server.base + "/chunk-ok").status_code, 200)
            capped = f.ProfileFetcher(replace(f.TrustPolicy.permissive_local(), max_profile_bytes=100))
            with self.assertRaisesRegex(f.FetchLimitError, "max_profile_bytes"):
                capped.fetch(server.base + "/cap")
            self.assertEqual(capped.fetch(server.base + "/error-cap").raw_bytes, b"")
            with self.assertRaises(f.SSRFBlockError):
                self.fetcher.post_json(server.base + "/redirect", {})
            self.assertIn(("POST", "ok"), server.hits)
        finally:
            server.close()

    def test_public_post_dns_and_request_share_deadline(self):
        server = WireServer()
        real = f.socket.getaddrinfo
        calls = []

        def slow(*args, **kwargs):
            calls.append(args[0])
            # Only initial DNS consumes the synthetic delay; numeric-IP
            # create_connection may also call getaddrinfo internally.
            if len(calls) == 1:
                time.sleep(0.16)
            return real(*args, **kwargs)

        try:
            with (
                mock.patch.object(f, "_MAX_FETCH_DURATION_SECONDS", 0.25),
                mock.patch.object(f.socket, "getaddrinfo", side_effect=slow),
            ):
                started = time.monotonic()
                with self.assertRaises(f.FetchError):
                    self.fetcher.post_json(server.base + "/header", {})
                self.assertLess(time.monotonic() - started, 0.4)
                self.assertIn(("POST", "header"), server.hits)
        finally:
            server.close()

    def test_wrapper_socket_walk_is_bounded_and_fallback_rejects_unowned(self):
        a, b = socket.socketpair()
        try:
            wrapper = types.SimpleNamespace(
                fp=types.SimpleNamespace(fp=types.SimpleNamespace(raw=types.SimpleNamespace(_sock=a)))
            )
            self.assertIs(f._response_socket(wrapper), a)
            cyclic = types.SimpleNamespace()
            cyclic.fp = cyclic
            self.assertIsNone(f._response_socket(cyclic))
            with self.assertRaises(f.FetchError):
                f._read_limited(types.SimpleNamespace(read=lambda n: b"x"), 10, deadline=time.monotonic() + 1)
        finally:
            a.close()
            b.close()


def drain_dns():
    q = f._DNS_EXECUTOR_QUEUE
    if hasattr(q, "join"):
        q.join()
    else:
        until = time.monotonic() + 3
        while q.qsize() and time.monotonic() < until:
            time.sleep(0.01)
        time.sleep(0.03)


class DNSBoundTests(unittest.TestCase):
    def test_cancelled_work_keeps_physical_slots_until_dequeued(self):
        gate = threading.Event()
        entered = threading.Event()
        count = []

        def resolver(*args, **kwargs):
            count.append(1)
            if len(count) == 2:
                entered.set()
            gate.wait(3)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]

        try:
            with mock.patch.object(f.socket, "getaddrinfo", side_effect=resolver):

                def call():
                    try:
                        f._resolve_hostname("fixture.invalid", 443, deadline=time.monotonic() + 0.04)
                    except f.FetchError:
                        pass

                with ThreadPoolExecutor(max_workers=2) as pool:
                    jobs = [pool.submit(call) for _ in range(2)]
                    self.assertTrue(entered.wait(1))
                    for job in jobs:
                        job.result(1)
                for _ in range(12):
                    call()
                self.assertLessEqual(f._DNS_EXECUTOR_QUEUE.qsize(), 4)
                self.assertEqual(len(count), 2)
                self.assertFalse(f._DNS_ADMISSION.acquire(blocking=False))
        finally:
            gate.set()
            drain_dns()
        self.assertTrue(f._DNS_ADMISSION.acquire(blocking=False))
        f._DNS_ADMISSION.release()

    def test_admission_wait_is_not_added_again_to_result_budget(self):
        for _ in range(6):
            self.assertTrue(f._DNS_ADMISSION.acquire())
        gate = threading.Event()
        released = threading.Event()

        def free_one():
            f._DNS_ADMISSION.release()
            released.set()

        timer = threading.Timer(0.18, free_one)
        timer.start()

        def resolver(*args, **kwargs):
            gate.wait(2)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]

        try:
            with mock.patch.object(f.socket, "getaddrinfo", side_effect=resolver):
                started = time.monotonic()
                with self.assertRaises(f.FetchError):
                    f._resolve_hostname("fixture.invalid", 443, deadline=time.monotonic() + 0.25)
                self.assertLess(time.monotonic() - started, 0.35)
        finally:
            gate.set()
            timer.join()
            drain_dns()
            for _ in range(5):
                f._DNS_ADMISSION.release()

    def test_submission_failure_returns_the_acquired_slot(self):
        with mock.patch.object(f._DNS_EXECUTOR_QUEUE, "put_nowait", side_effect=RuntimeError("submit-fault")):
            with self.assertRaises(f.FetchError):
                f._resolve_hostname("fixture.invalid", 443, deadline=time.monotonic() + 0.2)
        slots = []
        try:
            for _ in range(6):
                slots.append(f._DNS_ADMISSION.acquire(blocking=False))
            self.assertEqual(slots, [True] * 6)
        finally:
            for ok in slots:
                if ok:
                    f._DNS_ADMISSION.release()
