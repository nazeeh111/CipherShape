"""Authenticated loopback API, one owner/program/key epoch per process.

The demo's authentication key exists only in process memory and an anonymous
pipe. HTTP is deliberately restricted to loopback; remote transport is out of
scope. All application results remain encrypted across this interface.
"""
from __future__ import annotations
import base64
from contextlib import contextmanager
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import math
import multiprocessing
from pathlib import Path
import secrets
import signal
import tempfile
import time
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler

from .runtime import ProtocolError, evaluate_server, read_json, write_json


def signature(key: bytes, timestamp: str, nonce: str, body: bytes) -> str:
    message = b"CipherShape-v1\nPOST\n/v1/evaluate\n" + timestamp.encode() + b"\n" + nonce.encode() + b"\n" + body
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def pack(directory: Path, metadata: dict | None = None) -> bytes:
    envelope = read_json(directory / "envelope.json")
    files = {name: base64.b64encode((directory / name).read_bytes()).decode("ascii") for name in envelope["ciphertexts"]}
    return json.dumps({"envelope": envelope, "files": files, "server_metadata": metadata or {}}, separators=(",", ":"), allow_nan=False).encode()


def unpack(body: bytes, directory: Path, limit: int):
    try:
        data = json.loads(body)
        envelope, files = data["envelope"], data["files"]
        if not isinstance(envelope, dict) or not isinstance(files, dict) or len(files) > 256:
            raise ValueError
        expected = {f"{i}.bin" for i in range(len(files))}
        if set(files) != expected or set(envelope["ciphertexts"]) != expected:
            raise ValueError
        total = 0
        decoded = {}
        for name, value in files.items():
            blob = base64.b64decode(value, validate=True)
            total += len(blob)
            if total > limit or not blob:
                raise ValueError
            decoded[name] = blob
        directory.mkdir()
        for name, blob in decoded.items():
            (directory / name).write_bytes(blob)
        write_json(directory / "envelope.json", envelope)
    except (ValueError, TypeError, KeyError) as exc:
        raise ProtocolError("invalid API request") from exc


def _serve(public: str, key: bytes, ready):
    def terminate(*_):
        raise SystemExit(0)  # Unwind native() and kill its process group.
    signal.signal(signal.SIGTERM, terminate)
    public_path = Path(public)
    manifest = read_json(public_path / "manifest.json")
    limit = manifest["max_payload_bytes"]
    seen: dict[str, float] = {}

    class Handler(BaseHTTPRequestHandler):
        def handle(self):
            # Absolute pre-auth deadline also defeats continuously dripped data.
            signal.setitimer(signal.ITIMER_REAL, 10)
            try:
                super().handle()
            except TimeoutError:
                self.close_connection = True
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)

        def log_message(self, *_):
            pass  # Neither request bodies, authentication nor errors are logged.

        def reply(self, status: int, body: bytes):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            self.connection.settimeout(5)
            try:
                if self.path != "/v1/evaluate" or self.headers.get("Transfer-Encoding"):
                    raise ProtocolError("invalid request")
                length = int(self.headers.get("Content-Length", "-1"))
                if not 0 < length <= limit * 4 // 3 + 1_000_000:
                    self.reply(413, b'{"error":"request rejected"}')
                    return
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ProtocolError("truncated body")
                timestamp = self.headers.get("X-CS-Time", "")
                nonce = self.headers.get("X-CS-Nonce", "")
                now = time.time()
                for old in list(seen):
                    if seen[old] < now - 60:
                        del seen[old]
                stamp = float(timestamp)
                if (not math.isfinite(stamp) or abs(now - stamp) > 30 or len(nonce) != 32 or nonce in seen or
                        len(seen) >= 4096 or not hmac.compare_digest(
                            signature(key, timestamp, nonce, body), self.headers.get("X-CS-Signature", ""))):
                    self.reply(401, b'{"error":"authentication failed"}')
                    return
                seen[nonce] = now
                signal.setitimer(signal.ITIMER_REAL, 0)
                with tempfile.TemporaryDirectory(prefix="ciphershape-api-") as temp:
                    temp = Path(temp)
                    request, response = temp / "request", temp / "response"
                    unpack(body, request, limit)
                    metadata = evaluate_server(public_path, request, response)
                    self.reply(200, pack(response, metadata))
            except (OSError, ValueError, TypeError, KeyError):
                self.reply(400, b'{"error":"request rejected"}')

    class BoundedServer(HTTPServer):
        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(5)
            return connection, address
    server = BoundedServer(("127.0.0.1", 0), Handler)
    def deadline(*_):
        raise TimeoutError("request deadline exceeded")
    signal.signal(signal.SIGALRM, deadline)
    ready.send(server.server_address[1])
    ready.close()
    try:
        server.serve_forever(poll_interval=.1)
    finally:
        server.server_close()


@contextmanager
def local_endpoint(public: Path):
    """Start an owner-scoped server in a separate process; always stop on exit."""
    key = secrets.token_bytes(32)
    ctx = multiprocessing.get_context("spawn")
    parent, child = ctx.Pipe(duplex=False)
    process = ctx.Process(target=_serve, args=(str(public.resolve()), key, child))
    process.start()
    child.close()
    try:
        if not parent.poll(10):
            raise ProtocolError("API server startup failed")
        port = parent.recv()
        yield f"http://127.0.0.1:{port}/v1/evaluate", key
    finally:
        parent.close()
        process.terminate()
        process.join(5)
        if process.is_alive():
            process.kill()
            process.join()


def evaluate_http(url: str, key: bytes, request: Path, response: Path, limit: int = 64*1024**2) -> dict:
    parsed = urlsplit(url)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port is None or
            parsed.username is not None or parsed.password is not None or
            parsed.path != "/v1/evaluate" or parsed.query or parsed.fragment):
        raise ProtocolError("only the local encrypted demonstration endpoint is supported")
    body = pack(request)
    timestamp, nonce = str(time.time()), secrets.token_hex(16)
    headers = {"Content-Type": "application/json", "X-CS-Time": timestamp, "X-CS-Nonce": nonce,
               "X-CS-Signature": signature(key, timestamp, nonce, body)}
    start = time.perf_counter()
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, *_args, **_kwargs):
            raise ProtocolError("API redirects are not supported")
    with build_opener(NoRedirect).open(Request(url, body, headers, method="POST"), timeout=65) as answer:
        data = answer.read(limit*4//3 + 1_000_001)
        if len(data) > limit*4//3 + 1_000_000:
            raise ProtocolError("API response too large")
    unpack(data, response, limit)
    return {**json.loads(data).get("server_metadata", {}), "http_roundtrip_seconds": time.perf_counter() - start,
            "http_request_body_bytes": len(body), "http_response_body_bytes": len(data)}
