"""Bounded deployment search; no claim to invent packing or graph sharing."""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from itertools import product
import hashlib
import json
import math
from typing import Any

from .graph import Node, Workload


@dataclass(frozen=True)
class Costs:
    """Public development calibration, seconds/bytes at fixed CKKS parameters."""
    op_seconds: dict[str, float] = field(default_factory=lambda: {
        "input": .003, "add": .002, "sub": .002, "mul": .025,
        "scale": .003, "weights": .008, "rotate": .015, "mask": .008,
    })
    base_setup_seconds: float = .4
    rotation_setup_seconds: float = .08
    base_setup_bytes: int = 8_000_000
    rotation_key_bytes: int = 3_000_000
    ciphertext_bytes: int = 1_300_000
    live_ciphertext_bytes: int = 1_300_000
    request_base_seconds: float = 0.0
    rotation_load_seconds: float = 0.0
    encryption_seconds_per_ciphertext: float = 0.0
    decryption_seconds_per_ciphertext: float = 0.0
    measured: bool = False

    def validate(self):
        if type(self.measured) is not bool:
            raise ValueError("calibration measured flag must be boolean")
        required = {"input", "add", "sub", "mul", "scale", "weights", "rotate", "mask"}
        if set(self.op_seconds) != required:
            raise ValueError("calibration requires every supported operation")
        times = [*self.op_seconds.values(), self.base_setup_seconds, self.rotation_setup_seconds,
                 self.request_base_seconds, self.rotation_load_seconds,
                 self.encryption_seconds_per_ciphertext, self.decryption_seconds_per_ciphertext]
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0 for v in times):
            raise ValueError("calibration times must be finite and nonnegative")
        sizes = [self.base_setup_bytes, self.rotation_key_bytes, self.ciphertext_bytes, self.live_ciphertext_bytes]
        if any(type(v) is not int or v <= 0 for v in sizes):
            raise ValueError("calibration byte counts must be positive integers")


@dataclass(frozen=True)
class Plan:
    version: int
    workload: str
    layout: str
    basis: tuple[int, ...]
    sharing: str
    retention: str
    instructions: tuple[str, ...]
    # Maps a ciphertext index to public input name and optional element index.
    inputs: tuple[tuple[str, int | None], ...]
    outputs: tuple[str, ...]
    stats: dict[str, Any]

    @property
    def program_id(self) -> str:
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True).encode()).hexdigest()

    def text(self) -> str:
        return "\n".join(self.instructions) + "\n"


def compile_plan(w: Workload, layout: str = "packed", basis_kind: str = "direct",
                 sharing: str = "shared", retention: str = "last-use") -> Plan:
    w.validate()
    if layout not in {"packed", "scalar"} or basis_kind not in {"direct", "unit", "sparse"}:
        raise ValueError("unsupported layout/key basis")
    if sharing not in {"shared", "per-output"} or retention not in {"retain", "last-use"}:
        raise ValueError("unsupported sharing/schedule")
    n = max(x.shape[0] for x in w.inputs)
    rotations = tuple(1 << i for i in range(n.bit_length() - 1)) if layout == "packed" else ()
    basis = rotations if basis_kind == "direct" else ((1,) if rotations else ())
    if basis_kind == "sparse" and len(rotations) > 1:
        basis = (1, rotations[-1])
    lines: list[str] = []
    incoming: list[tuple[str, int | None]] = []
    incoming_index: dict[tuple[str, int | None], int] = {}
    memo: dict[Node, tuple[int, ...]] = {}
    next_id = 0

    def emit(op: str, *args: Any) -> int:
        nonlocal next_id
        i = next_id
        next_id += 1
        lines.append(" ".join(map(str, (op, i, *args))))
        return i

    def rotate(a: int, step: int) -> int:
        # Positive public steps; compose only keys actually exported.
        while step:
            k = max(x for x in basis if x <= step)
            a = emit("rotate", a, k)
            step -= k
        return a

    def lower(node: Node) -> tuple[int, ...]:
        if node in memo:
            return memo[node]
        op = node.op
        if op == "input":
            indices = range(node.shape[0]) if layout == "scalar" else (None,)
            result = []
            for elem in indices:
                binding = (str(node.value), elem)
                if binding not in incoming_index:
                    incoming_index[binding] = len(incoming)
                    incoming.append(binding)
                result.append(emit("input", incoming_index[binding]))
        elif op in {"add", "sub", "mul"}:
            a, b = (lower(x) for x in node.args)
            result = [emit(op, x, y) for x, y in zip(a, b, strict=True)]
        elif op == "scale":
            result = [emit("scale", x, repr(node.value)) for x in lower(node.args[0])]
        elif op == "weights":
            a = lower(node.args[0])
            if layout == "scalar":
                result = [emit("scale", x, repr(v)) for x, v in zip(a, node.value, strict=True)]
            else:
                result = [emit("weights", a[0], len(node.value), *map(repr, node.value))]
        elif op == "sum":
            a = list(lower(node.args[0]))
            if layout == "scalar":
                while len(a) > 1:
                    a = [emit("add", a[i], a[i+1]) for i in range(0, len(a), 2)]
                result = a
            else:
                x = a[0]
                size = node.args[0].shape[0]
                for step in (1 << i for i in range(size.bit_length() - 1)):
                    x = emit("add", x, rotate(x, step))
                result = [x]
        else:
            raise ValueError(f"unsupported op: {op}")
        memo[node] = tuple(result)
        return tuple(result)

    for index, (_, node) in enumerate(w.outputs):
        if sharing == "per-output":
            memo.clear()
        result = lower(node)
        if len(result) != 1:
            raise ValueError("only scalar endpoints supported")
        masked = emit("mask", result[0])
        lines.append(f"output {masked} {index}")

    def dependencies(line: str) -> list[int]:
        p = line.split()
        if p[0] in {"add", "sub", "mul"}:
            return [int(p[2]), int(p[3])]
        if p[0] in {"scale", "weights", "rotate", "mask"}:
            return [int(p[2])]
        if p[0] == "output":
            return [int(p[1])]
        return []

    uses = Counter(x for line in lines for x in dependencies(line))
    scheduled: list[str] = []
    live: set[int] = set()
    peak = 0
    counts: Counter[str] = Counter()
    for line in lines:
        p = line.split()
        op, i = p[0], int(p[1])
        scheduled.append(line)
        counts[op] += 1
        if op != "output":
            live.add(i)
        peak = max(peak, len(live))
        for dep in dependencies(line):
            uses[dep] -= 1
            if uses[dep] == 0 and retention == "last-use":
                scheduled.append(f"drop {dep}")
                live.remove(dep)
    return Plan(1, w.name, layout, basis, sharing, retention, tuple(scheduled),
                tuple(incoming), tuple(name for name, _ in w.outputs),
                {"counts": dict(counts), "peak_live_ciphertexts": peak,
                 "ciphertext_inputs": len(incoming), "rotation_keys": len(basis),
                 "rescale_policy": "OpenFHE FLEXIBLEAUTO; actual levels in native trace",
                 "relinearizations": counts["mul"], "output_masks": counts["mask"],
                 "layout_conversions": 0, "security": "HEStd_128_classic",
                 "depth": 4, "scale_bits": 45, "slots": "ring_dimension/2"})


def estimate(plan: Plan, costs: Costs, requests: int = 10,
             bandwidth: float = 10_000_000) -> dict[str, float]:
    costs.validate()
    online = (sum(count * costs.op_seconds.get(op, 0) for op, count in plan.stats["counts"].items()) +
              costs.request_base_seconds + len(plan.basis) * costs.rotation_load_seconds)
    setup_bytes = costs.base_setup_bytes + len(plan.basis) * costs.rotation_key_bytes
    upload = len(plan.inputs) * costs.ciphertext_bytes
    output = len(plan.outputs) * costs.ciphertext_bytes
    setup = costs.base_setup_seconds + len(plan.basis) * costs.rotation_setup_seconds
    return {"setup_bytes": setup_bytes, "request_bytes": upload, "response_bytes": output,
            "online_seconds": online, "peak_live_bytes": plan.stats["peak_live_ciphertexts"] * costs.live_ciphertext_bytes,
            "total_seconds": setup + setup_bytes / bandwidth + requests * (
                online + len(plan.inputs) * costs.encryption_seconds_per_ciphertext +
                len(plan.outputs) * costs.decryption_seconds_per_ciphertext + (upload + output) / bandwidth),
            "requests": requests, "calibrated": costs.measured}


def choose(w: Workload, costs: Costs, requests: int | None = None,
           bandwidth: float | None = None) -> tuple[Plan, list[dict[str, Any]]]:
    w.validate()
    requests = w.budget.requests if requests is None else requests
    bandwidth = w.budget.upload_bytes_per_second if bandwidth is None else bandwidth
    if type(requests) is not int or requests < 1 or requests > 1_000_000 or bandwidth <= 0:
        raise ValueError("invalid deployment horizon/bandwidth")
    candidates = []
    feasible = []
    for layout, basis, share, retain in product(("packed", "scalar"), ("direct", "unit", "sparse"),
                                               ("shared", "per-output"), ("retain", "last-use")):
        plan = compile_plan(w, layout, basis, share, retain)
        e = estimate(plan, costs, requests, bandwidth)
        budget = w.budget
        valid = (e["setup_bytes"] <= budget.max_setup_bytes and
                 e["request_bytes"] <= budget.max_upload_bytes and
                 max(e["request_bytes"], e["response_bytes"]) <= budget.max_payload_bytes and
                 e["peak_live_bytes"] <= budget.max_live_bytes and
                 e["peak_live_bytes"] + e["setup_bytes"] <= budget.max_memory_bytes and
                 len(plan.instructions) <= 4096 and len(plan.inputs) <= 256 and
                 e["online_seconds"] <= min(budget.max_online_seconds, budget.max_seconds))
        row = {"layout": layout, "basis": plan.basis, "sharing": share,
               "retention": retain, "feasible": valid, **e}
        candidates.append(row)
        if valid:
            feasible.append((e["total_seconds"], e["peak_live_bytes"], e["setup_bytes"], plan.program_id, plan))
    if not feasible:
        raise ValueError("no supported plan meets deployment budget")
    return min(feasible, key=lambda x: x[:-1])[-1], candidates
