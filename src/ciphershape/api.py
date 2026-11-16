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
import os
from pathlib import Path
import secrets
import signal
import tempfile
import time
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler

from .runtime import (ProtocolError, evaluate_server, read_json, write_json, parse_json,
                      validate_envelope, server_metadata, _ciphertexts, _public_manifest)
from .artifacts import MAX_ARTIFACT, read_bytes, staged_artifacts, new_destination, separate_paths


def signature(key: bytes, timestamp: str, nonce: str, body: bytes) -> str:
    message = b"CipherShape-v1\nPOST\n/v1/evaluate\n" + timestamp.encode() + b"\n" + nonce.encode() + b"\n" + body
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def pack(directory: Path, metadata: dict | None = None, *, limit: int = MAX_ARTIFACT) -> bytes:
    metadata = server_metadata(metadata if metadata is not None else {})
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        raw = read_bytes(Path("envelope.json"), min(limit, 1_000_000), dir_fd=fd)
        envelope = validate_envelope(parse_json(raw))
        expected = set(envelope["ciphertexts"]) | {"envelope.json"}
        names = set()
        with os.scandir(fd) as entries:
            for entry in entries:
                names.add(entry.name)
                if len(names) > 257 or entry.name not in expected:
                    raise ProtocolError("artifact set mismatch")
        if names != expected:
            raise ProtocolError("artifact set mismatch")
        files, total = {}, len(raw)
        for name, fingerprint in envelope["ciphertexts"].items():
            blob = read_bytes(Path(name), min(MAX_ARTIFACT, limit - total), dir_fd=fd)
            if not blob or hashlib.sha256(blob).hexdigest() != fingerprint:
                raise ProtocolError("ciphertext integrity mismatch")
            total += len(blob)
            files[name] = base64.b64encode(blob).decode("ascii")
    finally:
        os.close(fd)
    return json.dumps({"envelope": envelope, "files": files, "server_metadata": metadata},
                      separators=(",", ":"), allow_nan=False).encode()


def unpack(body: bytes, directory: Path, limit: int, *, expected: dict | None = None,
           count: int | None = None, request_id: str | None = None,
           operation: str = "request", on_prepared=None) -> dict:
    new_destination(directory)
    try:
        if len(body) > limit * 4 // 3 + 1_000_000:
            raise ValueError
        data = parse_json(body)
        if set(data) - {"envelope", "files", "server_metadata"}:
            raise ValueError
        envelope, files = data["envelope"], data["files"]
        envelope = validate_envelope(envelope, count, expected, request_id)
        if not isinstance(files, dict) or set(files) != set(envelope["ciphertexts"]):
            raise ValueError
        metadata = server_metadata(data.get("server_metadata", {}))
        if operation not in {"request", "response"} or (operation == "request" and metadata):
            raise ValueError
        encoded = (json.dumps(envelope, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
        total = len(encoded)
        decoded = {}
        for name, value in files.items():
            if not isinstance(value, str):
                raise ValueError
            blob = base64.b64decode(value, validate=True)
            total += len(blob)
            if (total > limit or not blob or
                    hashlib.sha256(blob).hexdigest() != envelope["ciphertexts"][name]):
                raise ValueError
            decoded[name] = blob
    except (ValueError, TypeError, KeyError) as exc:
        raise ProtocolError("invalid API request") from exc
    with staged_artifacts(operation, **{operation: directory},
                          byte_limits={operation: limit}, on_prepared=on_prepared) as stage:
        payload = stage[operation]
        for name, blob in decoded.items():
            (payload / name).write_bytes(blob)
        (payload / "envelope.json").write_bytes(encoded)
        _ciphertexts(payload, {**envelope, "max_payload_bytes": limit}, len(decoded), request_id)
    return metadata


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
                    unpack(body, request, limit, expected=manifest, count=manifest.get("input_count"))
                    metadata = evaluate_server(public_path, request, response)
                    self.reply(200, pack(response, metadata, limit=limit))
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


def evaluate_http(url: str, key: bytes, request: Path, response: Path, limit: int = 64*1024**2,
                  *, public: Path | None = None, on_prepared=None) -> dict:
    """Bind the reply before publication; public configuration also checks output arity.

    Legacy callers without public configuration still bind the request/context and
    payload integrity. Their expected output count is established by decrypt().
    """
    parsed = urlsplit(url)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port is None or
            parsed.username is not None or parsed.password is not None or
            parsed.path != "/v1/evaluate" or parsed.query or parsed.fragment):
        raise ProtocolError("only the local encrypted demonstration endpoint is supported")
    separate_paths(request, response, *([public] if public is not None else []))
    new_destination(response)
    body = pack(request, limit=limit)
    original = parse_json(body)["envelope"]
    manifest = _public_manifest(public) if public is not None else None
    if manifest is not None:
        validate_envelope(original, manifest["input_count"], manifest)
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
    metadata = unpack(data, response, limit, expected=original,
                      count=len(manifest["outputs"]) if manifest is not None else None,
                      request_id=original["request_id"], operation="response", on_prepared=on_prepared)
    return {**metadata, "http_roundtrip_seconds": time.perf_counter() - start,
            "http_request_body_bytes": len(body), "http_response_body_bytes": len(data)}
