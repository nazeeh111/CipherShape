"""Separated, stateless file protocol; native subprocesses have no fallback."""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
import re
from pathlib import Path
import resource
import signal
import shutil
import subprocess
import sys
import time
import uuid
from typing import Mapping, Sequence

from .graph import Workload, evaluate
from .planner import Plan

VERSION = 1
MAX_ARTIFACT = 256 * 1024 * 1024


class ProtocolError(ValueError):
    pass


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def read_json(path: Path, limit: int = 1_000_000):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ProtocolError("invalid envelope")
    try:
        result = json.loads(path.read_text())
    except (ValueError, UnicodeError) as exc:
        raise ProtocolError("invalid envelope") from exc
    if not isinstance(result, dict):
        raise ProtocolError("envelope must be an object")
    return result


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
          binaries: Path | None = None) -> dict:
    """Client operation: export only public context and evaluation keys."""
    analysis = w.validate()
    _canonical(w, plan)
    if public.exists() or private.exists():
        raise ProtocolError("setup destinations must be new")
    public = public.resolve()
    private = private.resolve()
    if public == private or public in private.parents or private in public.parents:
        raise ProtocolError("client and server artifacts require separate directories")
    public.mkdir(parents=True)
    private.mkdir(parents=True, mode=0o700)
    bins = binaries or binary_dir()
    meta, elapsed = native(bins / "ciphershape-client",
                           ["keygen", str(public), str(private), "4", *map(str, plan.basis)], timeout=120,
                           memory_bytes=w.budget.max_memory_bytes)
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
    write_json(private / "binding.json", {k: manifest[k] for k in ("version", "program_id", "epoch", "context_id")})
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
    return manifest


def _binding(manifest: dict) -> dict:
    try:
        result = {k: manifest[k] for k in ("version", "program_id", "epoch", "context_id")}
        if type(result["version"]) is not int or not all(isinstance(result[k], str) for k in ("program_id", "epoch", "context_id")):
            raise ValueError
        return result
    except (KeyError, TypeError, ValueError) as exc:
        raise ProtocolError("invalid binding") from exc


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
            binaries: Path | None = None) -> dict:
    """Validate public range contract locally; serialize ciphertexts only."""
    evaluate(w, inputs)  # Validation/reference is client-only and never serialized.
    _canonical(w, plan)
    manifest = read_json(public / "manifest.json")
    if read_json(private / "binding.json") != _binding(manifest) or plan.program_id != manifest["program_id"]:
        raise ProtocolError("key/program binding mismatch")
    if request.exists():
        raise ProtocolError("request destination must be new")
    request.mkdir(parents=True)
    bins = binaries or binary_dir()
    elapsed = 0.0
    peak_rss = 0
    for i, (name, element) in enumerate(plan.inputs):
        values = list(inputs[name]) if element is None else [inputs[name][element]]
        text = str(len(values)) + " " + " ".join(map(repr, values)) + "\n"
        resource_report, dt = native(bins / "ciphershape-client", ["encrypt", str(public.resolve()),
                       str((request / f"{i}.bin").resolve())], stdin=text,
                       memory_bytes=manifest["max_memory_bytes"])
        elapsed += dt
        peak_rss = max(peak_rss, resource_report["peak_rss_bytes"])
    envelope = {**_binding(manifest), "request_id": str(uuid.uuid4()),
                "ciphertexts": {f"{i}.bin": digest(request / f"{i}.bin") for i in range(len(plan.inputs))}}
    write_json(request / "envelope.json", envelope)
    return {"encryption_seconds": elapsed, "encryption_peak_rss_bytes": peak_rss,
            "request_bytes": folder_bytes(request), "request_id": envelope["request_id"]}


def folder_bytes(path: Path) -> int:
    return sum(p.stat().st_size for p in path.iterdir() if p.is_file())


def _files(path: Path, expected: set[str], limit: int):
    if path.is_symlink() or not path.is_dir():
        raise ProtocolError("invalid artifact directory")
    actual = set()
    total = 0
    for p in path.iterdir():
        if p.is_symlink() or not p.is_file():
            raise ProtocolError("invalid artifact")
        actual.add(p.name)
        total += p.stat().st_size
        if total > limit or p.stat().st_size == 0:
            raise ProtocolError("payload limit exceeded")
    if actual != expected:
        raise ProtocolError("artifact set mismatch")


def evaluate_server(public: Path, request: Path, response: Path,
                    binaries: Path | None = None) -> dict:
    """Server operation. No private directory, plaintext input or secret key argument."""
    manifest = read_json(public / "manifest.json")
    if manifest["version"] != VERSION or digest(public / "context.bin") != manifest["context_id"]:
        raise ProtocolError("context/version mismatch")
    if digest(public / "plan.txt") != manifest["plan_sha256"]:
        raise ProtocolError("compiled artifact mismatch")
    envelope = read_json(request / "envelope.json")
    if _binding(envelope) != _binding(manifest):
        raise ProtocolError("request binding mismatch")
    expected = {f"{i}.bin" for i in range(manifest["input_count"])}
    _files(request, expected | {"envelope.json"}, manifest["max_payload_bytes"])
    if set(envelope["ciphertexts"]) != expected:
        raise ProtocolError("ciphertext set mismatch")
    if any(digest(request / name) != envelope["ciphertexts"][name] for name in expected):
        raise ProtocolError("ciphertext integrity mismatch")
    plan = read_json(public / "plan.json")
    # Admission estimate uses serialized ciphertext bytes, a conservative upper
    # bound on coefficient storage for this pinned backend/parameter profile.
    per_ct = max((request / n).stat().st_size for n in expected)
    if plan["stats"]["peak_live_ciphertexts"] * per_ct > manifest["max_live_bytes"]:
        raise ProtocolError("live ciphertext budget exceeded before evaluation")
    if response.exists():
        raise ProtocolError("response destination must be new")
    # A new native process per request prevents cross-owner/key-epoch cache reuse.
    bins = binaries or binary_dir()
    report, elapsed = native(bins / "ciphershape-server", [str(public.resolve()),
                             str((public / "plan.txt").resolve()), str(request.resolve()),
                             str(response.resolve())], timeout=manifest["max_seconds"], cwd=public,
                             memory_bytes=manifest["max_memory_bytes"])
    if report["peak_coefficient_bytes"] > manifest["max_live_bytes"]:
        raise ProtocolError("live ciphertext budget exceeded")
    _files(response, {f"{i}.bin" for i in range(len(manifest["outputs"]))}, manifest["max_payload_bytes"])
    write_json(response / "envelope.json", {**_binding(manifest), "request_id": envelope["request_id"],
               "ciphertexts": {f"{i}.bin": digest(response / f"{i}.bin") for i in range(len(manifest["outputs"]))}})
    return {**report, "server_process_seconds": elapsed, "response_bytes": folder_bytes(response)}


def decrypt(public: Path, private: Path, request: Path, response: Path,
            binaries: Path | None = None) -> tuple[dict[str, float], dict]:
    """Client-only answers and slot diagnostics. There is no server callback."""
    manifest = read_json(public / "manifest.json")
    if read_json(private / "binding.json") != _binding(manifest):
        raise ProtocolError("key binding mismatch")
    original = read_json(request / "envelope.json")
    envelope = read_json(response / "envelope.json")
    if _binding(envelope) != _binding(manifest) or envelope["request_id"] != original["request_id"]:
        raise ProtocolError("response binding mismatch")
    expected = {f"{i}.bin" for i in range(len(manifest["outputs"]))}
    _files(response, expected | {"envelope.json"}, manifest["max_payload_bytes"])
    if set(envelope["ciphertexts"]) != expected or any(digest(response / n) != envelope["ciphertexts"][n] for n in expected):
        raise ProtocolError("response integrity mismatch")
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
