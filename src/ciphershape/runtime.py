"""Separated, stateless file protocol; native subprocesses have no fallback."""
from __future__ import annotations

from dataclasses import asdict
import json
import math
import os
import re
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time
import uuid
from typing import Mapping, Sequence

from .graph import Workload, evaluate
from .planner import Plan
from .artifacts import (MAX_ARTIFACT, ProtocolError, digest, read_bytes,
                        separate_paths, staged_artifacts)

VERSION = 1


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def parse_json(data: bytes):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ProtocolError("duplicate JSON member")
            result[key] = value
        return result

    def finite(value):
        number = float(value)
        if not math.isfinite(number):
            raise ProtocolError("nonfinite JSON number")
        return number

    try:
        result = json.loads(data, object_pairs_hook=unique, parse_float=finite,
                            parse_constant=finite)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ProtocolError("invalid envelope") from exc
    if not isinstance(result, dict):
        raise ProtocolError("envelope must be an object")
    return result


def read_json(path: Path, limit: int = 1_000_000):
    return parse_json(read_bytes(path, limit))


def _limits(memory_bytes: int):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_ARTIFACT, MAX_ARTIFACT))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    # Darwin rejects finite RLIMIT_DATA here and does not enforce RLIMIT_AS.
    # Do not describe that platform as having a hard native allocation cap.
    if sys.platform != "darwin":
        resource.setrlimit(resource.RLIMIT_DATA, (memory_bytes, memory_bytes))
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))


def native(binary: Path, args: list[str], *, stdin: str | None = None,
           timeout: float = 30, cwd: Path | None = None,
           memory_bytes: int = 1024**3) -> tuple[dict, float]:
    start = time.perf_counter()
    p = None
    try:
        # time obtains resource usage from its own child via wait4. This does
        # not inspect unrelated host processes and gives client-stage peak RSS.
        meter = ["/usr/bin/time", "-l"] if sys.platform == "darwin" else ["/usr/bin/time", "-f", "CS_RSS_KB=%M"]
        p = subprocess.Popen([*meter, str(binary.resolve()), *args], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                             cwd=cwd, start_new_session=True,
                             preexec_fn=lambda: _limits(memory_bytes))
        first = True
        while True:
            try:
                stdout, stderr = p.communicate(input=stdin if first else None, timeout=.1)
                break
            except subprocess.TimeoutExpired:
                first = False
                if time.perf_counter() - start > timeout:
                    raise ProtocolError("native operation timed out")
        if p.returncode:
            raise ProtocolError("native operation failed")
        result = json.loads(stdout) if stdout.strip() else {}
        pattern = r"(\d+)\s+maximum resident set size" if sys.platform == "darwin" else r"CS_RSS_KB=(\d+)"
        measured = re.search(pattern, stderr)
        if measured is None:
            raise ProtocolError("native resource accounting unavailable")
        rss = int(measured.group(1)) * (1 if sys.platform == "darwin" else 1024)
        result["peak_rss_bytes"] = max(result.get("peak_rss_bytes", 0), rss)
        if result.get("peak_rss_bytes", 0) > memory_bytes:
            raise ProtocolError("native memory budget exceeded")
    except (subprocess.SubprocessError, json.JSONDecodeError) as exc:
        # Do not reflect native diagnostics or client answers to a remote peer.
        raise ProtocolError("native operation failed") from exc
    finally:
        if p is not None and p.poll() is None:
            os.killpg(p.pid, signal.SIGKILL)
            p.communicate()
    return result, time.perf_counter() - start


def binary_dir() -> Path:
    supplied = os.environ.get("CIPHERSHAPE_NATIVE")
    if supplied:
        return Path(supplied).resolve()
    return Path(__file__).resolve().parents[2] / ".runtime/bin"


def setup(w: Workload, plan: Plan, public: Path, private: Path,
          binaries: Path | None = None, *, on_prepared=None) -> dict:
    """Client operation: export only public context and evaluation keys."""
    analysis = w.validate()
    _canonical(w, plan)
    bins = binaries or binary_dir()
    with staged_artifacts("setup", public=public, private=private,
                          byte_limits={"public": w.budget.max_setup_bytes, "private": MAX_ARTIFACT},
                          on_prepared=on_prepared) as stage:
        public, private = stage["public"], stage["private"]
        meta, elapsed = native(bins / "ciphershape-client",
                               ["keygen", str(public), str(private), "4", *map(str, plan.basis)], timeout=120,
                               memory_bytes=w.budget.max_memory_bytes)
        public_files = {"context.bin", "public.bin", "mult.bin"} | ({"rot.bin"} if plan.basis else set())
        _files(public, public_files, w.budget.max_setup_bytes)
        _files(private, {"secret.bin"}, MAX_ARTIFACT)
        (public / "plan.txt").write_text(plan.text())
        manifest = {"version": VERSION, "program_id": plan.program_id, "epoch": str(uuid.uuid4()),
                    "context_id": digest(public / "context.bin"), "plan_sha256": digest(public / "plan.txt"),
                    "outputs": plan.outputs, "input_count": len(plan.inputs), "parameters": meta,
                    "max_payload_bytes": w.budget.max_payload_bytes,
                    "max_seconds": min(w.budget.max_seconds, 60),
                    "max_live_bytes": w.budget.max_live_bytes,
                    "max_memory_bytes": w.budget.max_memory_bytes,
                    "setup_seconds": elapsed}
        write_json(public / "manifest.json", manifest)
        write_json(private / "binding.json", _binding(manifest))
        write_json(public / "plan.json", asdict(plan))
        indices = {node: i for i, node in enumerate(analysis.nodes)}
        write_json(public / "workload.json", {"version": VERSION, "name": w.name,
                   "tolerance": w.tolerance, "depth_including_mask": analysis.output_depth,
                   "mask_semantics": "only physical slot zero is an allowed scalar result",
                   "numerical_contract": "client verifies approximation plus encryption error against tolerance; no universal error proof",
                   "nodes": [{"id": indices[n], "op": n.op,
                              "args": [indices[a] for a in n.args], "public_value": n.value,
                              "shape": analysis.metadata[n].shape,
                              "estimated_depth": analysis.metadata[n].depth,
                              "interval": analysis.metadata[n].bounds} for n in analysis.nodes],
                   "allowed_outputs": {name: indices[n] for name, n in w.outputs}})
        _files(public, public_files | {"plan.txt", "manifest.json", "plan.json", "workload.json"},
               w.budget.max_setup_bytes)
        _files(private, {"secret.bin", "binding.json"}, MAX_ARTIFACT)
    return manifest


def _binding(manifest: dict) -> dict:
    try:
        result = {k: manifest[k] for k in ("version", "program_id", "epoch", "context_id")}
        if type(result["version"]) is not int or not all(isinstance(result[k], str) for k in ("program_id", "epoch", "context_id")):
            raise ValueError
        return result
    except (KeyError, TypeError, ValueError) as exc:
        raise ProtocolError("invalid binding") from exc


def validate_envelope(envelope: dict, count: int | None = None,
                      expected: dict | None = None, request_id: str | None = None) -> dict:
    """Shared file/HTTP shape and binding admission, independent of publication."""
    try:
        binding = _binding(envelope)
        if (binding["version"] != VERSION or set(envelope) !=
                {"version", "program_id", "epoch", "context_id", "request_id", "ciphertexts"}):
            raise ValueError
        if expected is not None and binding != _binding(expected):
            raise ProtocolError("artifact binding mismatch")
        ident, members = envelope["request_id"], envelope["ciphertexts"]
        if not isinstance(ident, str) or not 1 <= len(ident) <= 128:
            raise ProtocolError("request identity mismatch")
        if request_id is not None and ident != request_id:
            raise ProtocolError("request identity mismatch")
        if not isinstance(members, dict) or not 1 <= len(members) <= 256:
            raise ValueError
        if count is not None and (type(count) is not int or len(members) != count):
            raise ProtocolError("ciphertext set mismatch")
        if set(members) != {f"{i}.bin" for i in range(len(members))}:
            raise ProtocolError("ciphertext set mismatch")
        if any(not isinstance(h, str) or re.fullmatch(r"[0-9a-f]{64}", h) is None
               for h in members.values()):
            raise ValueError
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, ProtocolError):
            raise
        raise ProtocolError("invalid ciphertext envelope") from exc
    return envelope


def server_metadata(value: dict) -> dict:
    """Pinned backend telemetry cannot supply client verdicts or arbitrary fields."""
    fields = {"evaluation_seconds", "peak_live_ciphertexts", "peak_coefficient_bytes",
              "peak_rss_bytes", "trace", "server_process_seconds", "response_bytes"}
    if not isinstance(value, dict) or (value and set(value) != fields):
        raise ProtocolError("invalid server telemetry")
    if not value:
        return {}
    for key in fields - {"trace"}:
        n = value[key]
        integer = key not in {"evaluation_seconds", "server_process_seconds"}
        if (type(n) not in ((int,) if integer else (int, float)) or n < 0 or
                (type(n) is float and not math.isfinite(n))):
            raise ProtocolError("invalid server telemetry")
    trace = value["trace"]
    if not isinstance(trace, list) or len(trace) > 4096:
        raise ProtocolError("invalid server trace")
    for row in trace:
        if (not isinstance(row, dict) or set(row) !=
                {"op", "id", "seconds", "level", "scale", "noise_scale_degree"} or
                not isinstance(row["op"], str) or
                row["op"] not in {"input", "add", "sub", "mul", "scale", "weights", "rotate", "mask"}):
            raise ProtocolError("invalid server trace")
        for key in {"id", "seconds", "level", "scale", "noise_scale_degree"}:
            n = row[key]
            integer = key in {"id", "level", "noise_scale_degree"}
            if (type(n) not in ((int,) if integer else (int, float)) or n < 0 or
                    (type(n) is float and not math.isfinite(n))):
                raise ProtocolError("invalid server trace")
    return value


def _canonical(w: Workload, plan: Plan):
    from .planner import compile_plan
    for basis in ("direct", "unit", "sparse"):
        candidate = compile_plan(w, plan.layout, basis, plan.sharing, plan.retention)
        if candidate == plan:
            if len(plan.instructions) > 4096 or len(plan.inputs) > 256:
                raise ProtocolError("lowered plan exceeds native work limit")
            return
    raise ProtocolError("plan is not a canonical compilation of this workload")


def encrypt(w: Workload, plan: Plan, public: Path, private: Path,
            inputs: Mapping[str, Sequence[float]], request: Path,
            binaries: Path | None = None, *, on_prepared=None) -> dict:
    """Validate public range contract locally; serialize ciphertexts only."""
    evaluate(w, inputs)  # Validation/reference is client-only and never serialized.
    _canonical(w, plan)
    separate_paths(public, private, request)
    manifest = _public_manifest(public)
    if read_json(private / "binding.json") != _binding(manifest) or plan.program_id != manifest["program_id"]:
        raise ProtocolError("key/program binding mismatch")
    bins = binaries or binary_dir()
    elapsed = 0.0
    peak_rss = 0
    with staged_artifacts("request", request=request,
                          byte_limits={"request": manifest["max_payload_bytes"]},
                          on_prepared=on_prepared) as stage:
        request = stage["request"]
        for i, (name, element) in enumerate(plan.inputs):
            values = list(inputs[name]) if element is None else [inputs[name][element]]
            text = str(len(values)) + " " + " ".join(map(repr, values)) + "\n"
            resource_report, dt = native(bins / "ciphershape-client", ["encrypt", str(public.resolve()),
                           str(request / f"{i}.bin")], stdin=text,
                           memory_bytes=manifest["max_memory_bytes"])
            elapsed += dt
            peak_rss = max(peak_rss, resource_report["peak_rss_bytes"])
        envelope = _seal_ciphertexts(request, manifest, str(uuid.uuid4()), len(plan.inputs))
        report = {"encryption_seconds": elapsed, "encryption_peak_rss_bytes": peak_rss,
                  "request_bytes": folder_bytes(request), "request_id": envelope["request_id"]}
    return report


def folder_bytes(path: Path) -> int:
    return sum(p.stat().st_size for p in path.iterdir() if p.is_file())


def _files(path: Path, expected: set[str], limit: int):
    if path.is_symlink() or not path.is_dir():
        raise ProtocolError("invalid artifact directory")
    actual = set()
    total = 0
    for p in path.iterdir():
        if p.name not in expected or len(actual) >= len(expected):
            raise ProtocolError("artifact set mismatch")
        if p.is_symlink() or not p.is_file():
            raise ProtocolError("invalid artifact")
        actual.add(p.name)
        total += p.stat().st_size
        if total > limit or p.stat().st_size == 0:
            raise ProtocolError("payload limit exceeded")
    if actual != expected:
        raise ProtocolError("artifact set mismatch")


def _public_manifest(public: Path) -> dict:
    manifest = read_json(public / "manifest.json")
    if manifest["version"] != VERSION or digest(public / "context.bin") != manifest["context_id"]:
        raise ProtocolError("context/version mismatch")
    if digest(public / "plan.txt") != manifest["plan_sha256"]:
        raise ProtocolError("compiled artifact mismatch")
    return manifest


def _ciphertexts(path: Path, manifest: dict, count: int, request_id: str | None = None) -> dict:
    envelope = validate_envelope(read_json(path / "envelope.json"), count, manifest, request_id)
    expected = {f"{i}.bin" for i in range(count)}
    _files(path, expected | {"envelope.json"}, manifest["max_payload_bytes"])
    if set(envelope["ciphertexts"]) != expected:
        raise ProtocolError("ciphertext set mismatch")
    if any(digest(path / name) != envelope["ciphertexts"][name] for name in expected):
        raise ProtocolError("ciphertext integrity mismatch")
    return envelope


def _seal_ciphertexts(path: Path, manifest: dict, request_id: str, count: int) -> dict:
    expected = {f"{i}.bin" for i in range(count)}
    _files(path, expected, manifest["max_payload_bytes"])
    envelope = {**_binding(manifest), "request_id": request_id,
                "ciphertexts": {name: digest(path / name) for name in sorted(expected)}}
    write_json(path / "envelope.json", envelope)
    return _ciphertexts(path, manifest, count, request_id)


def evaluate_server(public: Path, request: Path, response: Path,
                    binaries: Path | None = None, *, on_prepared=None) -> dict:
    """Server operation. No private directory, plaintext input or secret key argument."""
    separate_paths(public, request, response)
    manifest = _public_manifest(public)
    envelope = _ciphertexts(request, manifest, manifest["input_count"])
    expected = {f"{i}.bin" for i in range(manifest["input_count"])}
    plan = read_json(public / "plan.json")
    # Admission estimate uses serialized ciphertext bytes, a conservative upper
    # bound on coefficient storage for this pinned backend/parameter profile.
    per_ct = max((request / n).stat().st_size for n in expected)
    if plan["stats"]["peak_live_ciphertexts"] * per_ct > manifest["max_live_bytes"]:
        raise ProtocolError("live ciphertext budget exceeded before evaluation")
    # A new native process per request prevents cross-owner/key-epoch cache reuse.
    bins = binaries or binary_dir()
    with staged_artifacts("response", response=response,
                          byte_limits={"response": manifest["max_payload_bytes"]},
                          on_prepared=on_prepared) as stage:
        response = stage["response"]
        report, elapsed = native(bins / "ciphershape-server", [str(public.resolve()),
                                 str((public / "plan.txt").resolve()), str(request.resolve()),
                                 str(response)], timeout=manifest["max_seconds"], cwd=public,
                                 memory_bytes=manifest["max_memory_bytes"])
        if report["peak_coefficient_bytes"] > manifest["max_live_bytes"]:
            raise ProtocolError("live ciphertext budget exceeded")
        _seal_ciphertexts(response, manifest, envelope["request_id"], len(manifest["outputs"]))
        report = server_metadata({**report, "server_process_seconds": elapsed,
                                  "response_bytes": folder_bytes(response)})
    return report


def decrypt(public: Path, private: Path, request: Path, response: Path,
            binaries: Path | None = None) -> tuple[dict[str, float], dict]:
    """Client-only answers and slot diagnostics. There is no server callback."""
    manifest = _public_manifest(public)
    if read_json(private / "binding.json") != _binding(manifest):
        raise ProtocolError("key binding mismatch")
    original = _ciphertexts(request, manifest, manifest["input_count"])
    _ciphertexts(response, manifest, len(manifest["outputs"]), original["request_id"])
    bins = binaries or binary_dir()
    answers = {}
    max_extra = 0.0
    elapsed = 0.0
    peak_rss = 0
    for i, name in enumerate(manifest["outputs"]):
        result, dt = native(bins / "ciphershape-client", ["decrypt", str(public.resolve()),
                            str(private.resolve()), str((response / f"{i}.bin").resolve())],
                            memory_bytes=manifest["max_memory_bytes"])
        answers[name] = result["value"]
        max_extra = max(max_extra, result["max_nonresult_slot"])
        elapsed += dt
        peak_rss = max(peak_rss, result["peak_rss_bytes"])
    return answers, {"decryption_seconds": elapsed, "decryption_peak_rss_bytes": peak_rss,
                     "max_nonresult_slot": max_extra}
