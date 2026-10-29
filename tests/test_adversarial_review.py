"""Independent contract checks, including a real OpenFHE path when installed.

The native tests use synthetic private inputs and fresh key directories only.
No result or decryption diagnostic is sent back to the evaluator.
"""
from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import secrets
import socket
import threading
import http.client
from urllib.parse import urlsplit
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from ciphershape.apps import analytics, analytics_reference, trained_model, model_reference
from ciphershape.graph import Budget, Workload, evaluate, private, scale, sum_
from ciphershape.planner import Costs, choose, compile_plan
from ciphershape import runtime as rt


def _send_auth_request(url, key, body=b"{}", timestamp=None, nonce=None):
    from ciphershape.api import signature
    timestamp = str(time.time()) if timestamp is None else timestamp
    nonce = secrets.token_hex(16) if nonce is None else nonce
    request = Request(url, body, {"X-CS-Time": timestamp, "X-CS-Nonce": nonce,
                      "X-CS-Signature": signature(key, timestamp, nonce, body)}, method="POST")
    try:
        with urlopen(request, timeout=8) as reply:
            return reply.status
    except HTTPError as exc:
        return exc.code


@pytest.fixture
def auth_endpoint(tmp_path):
    from ciphershape.api import local_endpoint
    public = tmp_path / "api-public"
    public.mkdir()
    rt.write_json(public / "manifest.json", {"max_payload_bytes": 10000})
    with local_endpoint(public) as endpoint:
        yield endpoint


def test_http_wrong_authentication_key_rejected(auth_endpoint):
    url, key = auth_endpoint
    assert _send_auth_request(url, b"wrong-synthetic-auth-key") == 401


def test_http_stale_and_nonfinite_timestamps_rejected(auth_endpoint):
    url, key = auth_endpoint
    for timestamp in (str(time.time() - 120), "nan", "inf", "-inf"):
        assert _send_auth_request(url, key, timestamp=timestamp) == 401


def test_http_nonce_replay_rejected_before_evaluation(auth_endpoint):
    url, key = auth_endpoint
    nonce, timestamp = secrets.token_hex(16), str(time.time())
    # Authenticated but malformed body is rejected without touching native code.
    assert _send_auth_request(url, key, timestamp=timestamp, nonce=nonce) == 400
    assert _send_auth_request(url, key, timestamp=timestamp, nonce=nonce) == 401


def test_http_excessive_declared_body_rejected_before_evaluation(auth_endpoint):
    url, key = auth_endpoint
    parts = urlsplit(url)
    # Send only the excessive length header. Sending megabytes after the server
    # has already replied can make urllib observe BrokenPipe before reading 413.
    connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=5)
    try:
        connection.putrequest("POST", "/v1/evaluate")
        connection.putheader("Content-Length", "1100000")
        connection.endheaders()
        assert connection.getresponse().status == 413
    finally:
        connection.close()


def test_http_incomplete_headers_timeout_without_blocking_next_request(auth_endpoint):
    url, key = auth_endpoint
    parts = urlsplit(url)
    with socket.create_connection((parts.hostname, parts.port), timeout=2) as incomplete:
        incomplete.sendall(b"POST /v1/evaluate HTTP/1.1\r\nX-Unfinished: ")
        time.sleep(5.3)  # Server's accepted-socket bound is five seconds.
        assert _send_auth_request(url, b"wrong-synthetic-auth-key") == 401


def test_http_continuous_slow_body_has_absolute_deadline(auth_endpoint):
    url, key = auth_endpoint
    parts = urlsplit(url)
    stop = threading.Event()
    with socket.create_connection((parts.hostname, parts.port), timeout=2) as slow:
        slow.sendall(b"POST /v1/evaluate HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 100000\r\n\r\n")
        def drip():
            while not stop.wait(.2):
                try:
                    slow.sendall(b"x")
                except OSError:
                    return
        sender = threading.Thread(target=drip, daemon=True)
        sender.start()
        try:
            time.sleep(10.6)  # More than total preauthentication deadline, with no idle gap.
            start = time.monotonic()
            assert _send_auth_request(url, b"wrong-synthetic-auth-key") == 401
            assert time.monotonic() - start < 3, "slow unauthenticated body still monopolized the server"
        finally:
            stop.set()
            sender.join(1)


def test_http_owner_shutdown_cancels_active_native_process(tmp_path, monkeypatch):
    from ciphershape.api import local_endpoint, pack
    public, request, _ = _fake_envelope(tmp_path)
    manifest = rt.read_json(public / "manifest.json")
    manifest["max_memory_bytes"] = 1024**3
    rt.write_json(public / "manifest.json", manifest)
    rt.write_json(public / "plan.json", {"stats": {"peak_live_ciphertexts": 1}})
    bins = tmp_path / "synthetic-workers"
    bins.mkdir()
    started, late = tmp_path / "worker-started", tmp_path / "worker-ran-after-shutdown"
    worker = bins / "ciphershape-server"
    worker.write_text("#!" + sys.executable + "\nimport pathlib,time\npathlib.Path(" +
                      repr(str(started)) + ").touch()\ntime.sleep(2)\npathlib.Path(" + repr(str(late)) + ").touch()\n")
    worker.chmod(0o700)
    monkeypatch.setenv("CIPHERSHAPE_NATIVE", str(bins))
    errors = []
    def send(url, key):
        try:
            _send_auth_request(url, key, body=pack(request))
        except Exception as exc:
            errors.append(type(exc).__name__)
    with local_endpoint(public) as (url, key):
        thread = threading.Thread(target=send, args=(url, key), daemon=True)
        thread.start()
        deadline = time.monotonic() + 8
        while not started.exists() and time.monotonic() < deadline:
            time.sleep(.02)
        assert started.exists(), "control worker never started; cancellation was not exercised"
    thread.join(3)
    time.sleep(2.1)
    assert not late.exists(), "native worker outlived owner-scoped HTTP server shutdown"


def test_impossible_total_memory_budget_is_infeasible():
    w = replace(analytics(4), budget=Budget(max_memory_bytes=1))
    with pytest.raises(ValueError, match="budget|memory|feasible"):
        choose(w, Costs())


@pytest.mark.parametrize("costs", [
    Costs(op_seconds={"input": -1.0}, measured=True),
    Costs(op_seconds={"input": float("nan")}, measured=True),
    Costs(ciphertext_bytes=-1, measured=True),
    Costs(op_seconds={"input": .001}, measured=True),
])
def test_invalid_or_incomplete_calibration_cannot_select_a_plan(costs):
    with pytest.raises(ValueError):
        choose(analytics(4), costs)


def test_planner_respects_declared_deployment_horizon():
    w = replace(analytics(4), budget=replace(Budget(), requests=123,
                                             upload_bytes_per_second=321.0))
    _, candidates = choose(w, Costs())
    assert all(row["requests"] == 123 for row in candidates)


def test_small_shared_graph_does_not_expand_exponentially():
    code = '''from ciphershape.graph import private,Workload,sum_
x=private("x",1,(-1e-6,1e-6))
n=x
for i in range(24): n=n+n
w=Workload("shared",(x,),(("answer",sum_(n)),))
assert len(w.validate().nodes)==26
'''
    env = dict(os.environ, PYTHONPATH=str(Path(rt.__file__).resolve().parent.parent))
    try:
        completed = subprocess.run([sys.executable, "-c", code], env=env,
                                   capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        pytest.fail("26-node shared graph exceeded ten seconds; check recursive hashing on Python <3.14")
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize("field,value", [
    ("max_nodes", True), ("max_outputs", 2.5), ("requests", 2.5),
    ("max_memory_bytes", 1.5), ("max_payload_bytes", True),
])
def test_discrete_resource_limits_require_integers(field, value):
    w = replace(trained_model(), budget=replace(Budget(), **{field: value}))
    with pytest.raises(ValueError):
        w.validate()


def test_public_constant_exceeding_native_parser_contract_is_rejected():
    x = private("x", 4)
    with pytest.raises(ValueError):
        w = Workload("large_constant", (x,), (("answer", sum_(scale(x, 1e9))),))
        w.validate()


def test_forged_plan_rejected_before_key_generation(tmp_path, monkeypatch):
    w = analytics(4)
    plan = compile_plan(w)
    forged = replace(plan, instructions=("input 0 0", "output 0 0"))
    monkeypatch.setattr(rt, "native", lambda *a, **k: pytest.fail("native was reached"))
    with pytest.raises(rt.ProtocolError):
        rt.setup(w, forged, tmp_path / "public", tmp_path / "private")


def test_different_workload_plan_rejected_before_key_generation(tmp_path, monkeypatch):
    w = trained_model()
    foreign = compile_plan(analytics(4))
    monkeypatch.setattr(rt, "native", lambda *a, **k: pytest.fail("native was reached"))
    with pytest.raises(rt.ProtocolError):
        rt.setup(w, foreign, tmp_path / "public", tmp_path / "private")


def test_timeout_terminates_native_process_before_late_side_effect(tmp_path):
    # This disposable helper represents a hung native worker, not HE execution.
    helper, marker = tmp_path / "hung.py", tmp_path / "should-not-exist"
    helper.write_text("import time,pathlib\ntime.sleep(0.7)\npathlib.Path(" + repr(str(marker)) + ").touch()\n")
    with pytest.raises(rt.ProtocolError, match="timed out"):
        rt.native(Path(sys.executable), [str(helper)], timeout=.05)
    time.sleep(.8)
    assert not marker.exists()


def test_native_wrapper_can_start_a_real_control_process(tmp_path):
    helper = tmp_path / "control.py"
    helper.write_text('print(\'{"started": true}\')\n')
    result, _ = rt.native(Path(sys.executable), [str(helper)], timeout=5)
    assert result["started"] is True
    assert result["peak_rss_bytes"] > 0


def _fake_envelope(tmp_path):
    """Only malformed-envelope tests use fake ciphertext bytes; never HE claims."""
    public, request = tmp_path / "public", tmp_path / "request"
    public.mkdir()
    request.mkdir()
    (public / "context.bin").write_bytes(b"not-a-native-context")
    (public / "plan.txt").write_text("input 0 0\nmask 1 0\noutput 1 0\n")
    (request / "0.bin").write_bytes(b"not-a-native-ciphertext")
    binding = dict(version=1, program_id="a" * 64, epoch="owner-epoch-a",
                   context_id=rt.digest(public / "context.bin"))
    manifest = dict(**binding, plan_sha256=rt.digest(public / "plan.txt"),
                    input_count=1, outputs=["answer"], max_payload_bytes=10000,
                    max_seconds=10, max_live_bytes=10_000_000)
    envelope = dict(**binding, request_id="request-a",
                    ciphertexts={"0.bin": rt.digest(request / "0.bin")})
    rt.write_json(public / "manifest.json", manifest)
    rt.write_json(request / "envelope.json", envelope)
    return public, request, envelope


@pytest.mark.parametrize("field,value", [
    ("version", 999), ("epoch", "wrong-epoch"),
    ("program_id", "wrong-program"), ("context_id", "wrong-context"),
])
def test_request_binding_rejected_before_native(tmp_path, monkeypatch, field, value):
    public, request, envelope = _fake_envelope(tmp_path)
    envelope[field] = value
    rt.write_json(request / "envelope.json", envelope)
    monkeypatch.setattr(rt, "native", lambda *a, **k: pytest.fail("native was reached"))
    with pytest.raises(rt.ProtocolError):
        rt.evaluate_server(public, request, tmp_path / "response")


def test_truncated_or_changed_payload_rejected_before_native(tmp_path, monkeypatch):
    public, request, _ = _fake_envelope(tmp_path)
    (request / "0.bin").write_bytes(b"truncated")
    monkeypatch.setattr(rt, "native", lambda *a, **k: pytest.fail("native was reached"))
    with pytest.raises(rt.ProtocolError):
        rt.evaluate_server(public, request, tmp_path / "response")


def test_symlink_payload_rejected_before_native(tmp_path, monkeypatch):
    public, request, _ = _fake_envelope(tmp_path)
    (request / "0.bin").unlink()
    target = tmp_path / "elsewhere.bin"
    target.write_bytes(b"not-a-native-ciphertext")
    (request / "0.bin").symlink_to(target)
    monkeypatch.setattr(rt, "native", lambda *a, **k: pytest.fail("native was reached"))
    with pytest.raises(rt.ProtocolError):
        rt.evaluate_server(public, request, tmp_path / "response")


@pytest.mark.parametrize("malformed", [{}, [], None, {"version": 1}])
def test_malformed_envelope_has_consistent_protocol_error(tmp_path, monkeypatch, malformed):
    public, request, _ = _fake_envelope(tmp_path)
    rt.write_json(request / "envelope.json", malformed)
    monkeypatch.setattr(rt, "native", lambda *a, **k: pytest.fail("native was reached"))
    with pytest.raises(rt.ProtocolError):
        rt.evaluate_server(public, request, tmp_path / "response")


@pytest.fixture(scope="module")
def installed_native():
    bins = rt.binary_dir()
    if not all((bins / name).is_file() for name in ("ciphershape-client", "ciphershape-server")):
        pytest.skip("OpenFHE binaries not yet installed; no encrypted claim from skip")
    return bins


@pytest.fixture(scope="module")
def real_protocol(tmp_path_factory, installed_native):
    root = tmp_path_factory.mktemp("independent-ckks")
    w = analytics(4)
    plan = compile_plan(w)
    public, private = root / "public", root / "client-only"
    rt.setup(w, plan, public, private, installed_native)
    return root, w, plan, public, private, installed_native


@pytest.mark.parametrize("case,inputs", [
    ("bounds", {"x": [1., -1., 1., -1.], "y": [-1., 1., -1., 1.]}),
    ("changed", {"x": [.25] * 4, "y": [-.5] * 4}),
    ("cancellation", {"x": [1., -1., 1e-7, -1e-7], "y": [1., 1., -1., -1.]}),
])
def test_real_changed_inputs_three_paths_and_all_unused_slots(real_protocol, case, inputs):
    root, w, plan, public, private, bins = real_protocol
    request, response = root / f"request-{case}", root / f"response-{case}"
    rt.encrypt(w, plan, public, private, inputs, request, bins)
    # Server staging includes only the exported public artifacts and ciphertexts.
    server = root / f"server-{case}"
    shutil.copytree(public, server / "public")
    shutil.copytree(request, server / "request")
    assert not list(server.rglob("secret.bin"))
    rt.evaluate_server(server / "public", server / "request", response, bins)
    actual, client_metrics = rt.decrypt(public, private, request, response, bins)
    original, approximated = analytics_reference(inputs), evaluate(w, inputs)
    for name in actual:
        assert approximated[name] == pytest.approx(original[name], abs=1e-12)
        assert actual[name] == pytest.approx(approximated[name], abs=w.tolerance)
    assert client_metrics["max_nonresult_slot"] < w.tolerance


def test_real_native_rejects_unmasked_export(real_protocol):
    root, w, plan, public, private, bins = real_protocol
    request = root / "request-unmasked"
    rt.encrypt(w, plan, public, private, {"x": [.1, .2, .3, .4], "y": [0.] * 4}, request, bins)
    forged = root / "unmasked.txt"
    forged.write_text("input 0 0\noutput 0 0\n")
    completed = subprocess.run([str(bins / "ciphershape-server"), str(public), str(forged),
                                str(request), str(root / "unmasked-response")],
                               capture_output=True, text=True, timeout=30)
    assert completed.returncode != 0, "native boundary exported all private input slots without masking"


def test_real_native_rejects_insufficient_rotation_keys(real_protocol):
    root, w, plan, public, private, bins = real_protocol
    request = root / "request-rotation"
    rt.encrypt(w, plan, public, private, {"x": [.1] * 4, "y": [.2] * 4}, request, bins)
    forged = root / "missing-rotation.txt"
    forged.write_text("input 0 0\nrotate 1 0 3\nmask 2 1\noutput 2 0\n")
    completed = subprocess.run([str(bins / "ciphershape-server"), str(public), str(forged),
                                str(request), str(root / "rotation-response")],
                               capture_output=True, text=True, timeout=30)
    assert completed.returncode != 0


def test_real_native_rejects_exhausted_depth(real_protocol):
    root, w, plan, public, private, bins = real_protocol
    request = root / "request-depth"
    rt.encrypt(w, plan, public, private, {"x": [.1] * 4, "y": [.2] * 4}, request, bins)
    forged = root / "depth.txt"
    forged.write_text("input 0 0\n" + "".join(f"mul {i} {i-1} {i-1}\n" for i in range(1, 10)) +
                      "mask 10 9\noutput 10 0\n")
    completed = subprocess.run([str(bins / "ciphershape-server"), str(public), str(forged),
                                str(request), str(root / "depth-response")],
                               capture_output=True, text=True, timeout=30)
    assert completed.returncode != 0


def test_real_wrong_native_key_rejected_despite_valid_envelope(real_protocol):
    root, w, plan, public, private, bins = real_protocol
    other_public, other_private = root / "other-public", root / "other-client-only"
    rt.setup(w, plan, other_public, other_private, bins)
    inputs = {"x": [.1] * 4, "y": [.2] * 4}
    request, foreign = root / "request-wrong-key", root / "foreign-request"
    rt.encrypt(w, plan, public, private, inputs, request, bins)
    rt.encrypt(w, plan, other_public, other_private, inputs, foreign, bins)
    shutil.copy2(foreign / "0.bin", request / "0.bin")
    envelope = rt.read_json(request / "envelope.json")
    envelope["ciphertexts"]["0.bin"] = rt.digest(request / "0.bin")
    rt.write_json(request / "envelope.json", envelope)
    with pytest.raises(rt.ProtocolError):
        rt.evaluate_server(public, request, root / "wrong-key-response", bins)


def test_real_truncation_rejected_by_native_with_updated_digest(real_protocol):
    root, w, plan, public, private, bins = real_protocol
    request = root / "request-native-truncation"
    rt.encrypt(w, plan, public, private, {"x": [.1] * 4, "y": [.2] * 4}, request, bins)
    ciphertext = request / "0.bin"
    ciphertext.write_bytes(ciphertext.read_bytes()[:64])
    envelope = rt.read_json(request / "envelope.json")
    envelope["ciphertexts"]["0.bin"] = rt.digest(ciphertext)
    rt.write_json(request / "envelope.json", envelope)
    with pytest.raises(rt.ProtocolError):
        rt.evaluate_server(public, request, root / "truncation-response", bins)
