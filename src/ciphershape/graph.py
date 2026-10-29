"""A small, closed numerical language. Nothing evaluates Python source code."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import math
import re
from typing import Mapping, Sequence

Value = str | float | tuple[float, ...] | None
Bounds = tuple[float, float]


@dataclass(frozen=True, eq=False)
class Node:
    op: str
    args: tuple[Node, ...] = ()
    value: Value = None
    shape: tuple[int, ...] = ()
    bounds: Bounds | None = None
    _identity: bytes = field(init=False, repr=False)

    def __post_init__(self):
        if not isinstance(self.args, tuple) or any(not isinstance(a, Node) for a in self.args):
            raise ValueError("node arguments must be immutable graph nodes")
        # Cached structural identity avoids exponential recursive dataclass
        # hashing/equality for shared DAGs on Python 3.11-3.13.
        key = (self.op, tuple(a._identity for a in self.args), self.value, self.shape, self.bounds)
        object.__setattr__(self, "_identity", hashlib.sha256(repr(key).encode()).digest())

    def __hash__(self):
        return hash(self._identity)

    def __eq__(self, other):
        return isinstance(other, Node) and self._identity == other._identity

    def __add__(self, other: Node) -> Node:
        return add(self, other)

    def __sub__(self, other: Node) -> Node:
        return sub(self, other)

    def __mul__(self, other: Node) -> Node:
        return mul(self, other)


@dataclass(frozen=True)
class Meta:
    shape: tuple[int, ...]
    depth: int
    bounds: Bounds


@dataclass(frozen=True)
class Budget:
    max_nodes: int = 256
    max_outputs: int = 16
    max_payload_bytes: int = 64 * 1024 * 1024
    max_seconds: float = 30.0
    max_memory_bytes: int = 1024 * 1024 * 1024
    requests: int = 10
    max_setup_bytes: int = 256 * 1024 * 1024
    max_upload_bytes: int = 256 * 1024 * 1024
    max_live_bytes: int = 256 * 1024 * 1024
    max_online_seconds: float = 60.0
    upload_bytes_per_second: float = 10_000_000.0


@dataclass(frozen=True)
class Analysis:
    nodes: tuple[Node, ...]
    metadata: Mapping[Node, Meta]
    output_depth: int


def _finite(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("expected a finite real number")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("expected a finite real number")
    return result


def _name(name: object) -> str:
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,47}", name):
        raise ValueError("names must be simple identifiers of at most 48 characters")
    return name


def private(name: str, n: int, bounds: Bounds = (-1.0, 1.0)) -> Node:
    _name(name)
    if isinstance(n, bool) or not isinstance(n, int) or not 1 <= n <= 64 or n & (n - 1):
        raise ValueError("input length must be a power of two from 1 through 64")
    lo, hi = map(_finite, bounds)
    if lo > hi:
        raise ValueError("input lower bound exceeds upper bound")
    return Node("input", value=name, shape=(n,), bounds=(lo, hi))


def _binary(op: str, a: Node, b: Node) -> Node:
    if not isinstance(a, Node) or not isinstance(b, Node) or a.shape != b.shape:
        raise ValueError("binary operations require identical declared shapes")
    return Node(op, (a, b), shape=a.shape)


def add(a: Node, b: Node) -> Node:
    return _binary("add", a, b)


def sub(a: Node, b: Node) -> Node:
    return _binary("sub", a, b)


def mul(a: Node, b: Node) -> Node:
    return _binary("mul", a, b)


def scale(a: Node, value: float) -> Node:
    return Node("scale", (a,), _finite(value), a.shape)


def weights(a: Node, values: Sequence[float]) -> Node:
    values = tuple(map(_finite, values))
    if a.shape != (len(values),):
        raise ValueError("public weights must match a vector's declared length")
    return Node("weights", (a,), values, a.shape)


def sum_(a: Node) -> Node:
    if len(a.shape) != 1:
        raise ValueError("sum requires a vector")
    return Node("sum", (a,))


def dot(a: Node, values: Sequence[float]) -> Node:
    return sum_(weights(a, values))


def metadata(node: Node, memo: dict[Node, Meta] | None = None) -> Meta:
    """Recheck the closed grammar, shape, interval and conservative level budget."""
    memo = {} if memo is None else memo
    if node in memo:
        return memo[node]
    if not isinstance(node, Node) or not isinstance(node.args, tuple):
        raise ValueError("invalid graph node")
    if node.op == "input":
        if node.args or len(node.shape) != 1 or node.bounds is None:
            raise ValueError("invalid private input")
        checked = private(node.value, node.shape[0], node.bounds)  # type: ignore[arg-type]
        if checked != node:
            raise ValueError("noncanonical input")
        result = Meta(node.shape, 0, checked.bounds)  # type: ignore[arg-type]
    else:
        arity = {"add": 2, "sub": 2, "mul": 2, "scale": 1, "weights": 1, "sum": 1}
        if node.op not in arity or len(node.args) != arity[node.op] or node.bounds is not None:
            raise ValueError("unsupported operation or invalid arity")
        args = tuple(metadata(a, memo) for a in node.args)
        a = args[0]
        lo, hi = a.bounds
        depth = max(v.depth for v in args)
        shape = a.shape
        if node.op in ("add", "sub", "mul"):
            if node.value is not None or a.shape != args[1].shape:
                raise ValueError("invalid binary node")
            bl, bh = args[1].bounds
            if node.op == "add":
                bounds = (lo + bl, hi + bh)
            elif node.op == "sub":
                bounds = (lo - bh, hi - bl)
            else:
                products = (lo * bl, lo * bh, hi * bl, hi * bh)
                bounds = (min(products), max(products))
                depth += 1
        elif node.op == "scale":
            factor = _finite(node.value)
            bounds = tuple(sorted((lo * factor, hi * factor)))
            depth += 1
        elif node.op == "weights":
            if not isinstance(node.value, tuple) or shape != (len(node.value),):
                raise ValueError("invalid public weights")
            products = [x * y for x in (lo, hi) for y in map(_finite, node.value)]
            bounds = (min(products), max(products))
            depth += 1
        else:
            if node.value is not None or len(shape) != 1:
                raise ValueError("invalid reduction")
            bounds = (lo * shape[0], hi * shape[0])
            shape = ()
        if shape != node.shape or not all(math.isfinite(x) for x in bounds):
            raise ValueError("invalid shape or nonfinite interval")
        result = Meta(shape, depth, bounds)  # type: ignore[arg-type]
    memo[node] = result
    return result


@dataclass(frozen=True)
class Workload:
    name: str
    inputs: tuple[Node, ...]
    outputs: tuple[tuple[str, Node], ...]
    tolerance: float = 1e-4
    max_depth: int = 4
    budget: Budget = field(default_factory=Budget)

    def validate(self) -> Analysis:
        _name(self.name)
        if not isinstance(self.inputs, tuple) or not isinstance(self.outputs, tuple):
            raise ValueError("input and output declarations must be immutable tuples")
        if not self.inputs or not self.outputs or len(self.inputs) > 8:
            raise ValueError("workloads require 1-8 inputs and at least one output")
        if not 0 < _finite(self.tolerance) <= 0.1:
            raise ValueError("tolerance must be positive and at most 0.1")
        if isinstance(self.max_depth, bool) or not isinstance(self.max_depth, int) or not 1 <= self.max_depth <= 4:
            raise ValueError("supported depth budget is 1-4 levels")
        b = self.budget
        integer_fields = ("max_nodes", "max_outputs", "max_payload_bytes", "requests",
                          "max_memory_bytes", "max_setup_bytes", "max_upload_bytes", "max_live_bytes")
        if not isinstance(b, Budget) or any(type(getattr(b, key)) is not int for key in integer_fields):
            raise ValueError("discrete resource limits require integers")
        if (not isinstance(b, Budget) or not 1 <= b.max_nodes <= 1024 or
                not 1 <= b.max_outputs <= 32 or not 1 <= b.max_payload_bytes <= 128 * 1024 * 1024 or
                not 0 < _finite(b.max_seconds) <= 300 or not 1 <= b.requests <= 1_000_000 or
                not 1 <= b.max_memory_bytes <= 8 * 1024**3 or
                not 1 <= b.max_setup_bytes <= 8 * 1024**3 or
                not 1 <= b.max_upload_bytes <= 8 * 1024**3 or
                not 1 <= b.max_live_bytes <= 8 * 1024**3 or
                not 0 < _finite(b.max_online_seconds) <= 300 or
                not 0 < _finite(b.upload_bytes_per_second) <= 1e12):
            raise ValueError("invalid resource limits")
        if len(self.outputs) > b.max_outputs:
            raise ValueError("output budget exceeded")
        if any(n.op != "input" for n in self.inputs):
            raise ValueError("declared inputs must be private input nodes")
        input_names = [n.value for n in self.inputs]
        if len(set(input_names)) != len(input_names):
            raise ValueError("duplicate input name")
        names = [_name(k) for k, _ in self.outputs]
        if len(set(names)) != len(names):
            raise ValueError("duplicate output name")
        memo: dict[Node, Meta] = {}
        try:
            for inp in self.inputs:
                metadata(inp, memo)
            for _, node in self.outputs:
                if metadata(node, memo).shape != ():
                    raise ValueError("only explicitly allowed scalar outputs are supported")
        except RecursionError as exc:
            raise ValueError("graph nesting exceeds supported bounds") from exc
        if len(memo) > b.max_nodes:
            raise ValueError("graph node budget exceeded")
        for node, meta in memo.items():
            constants = node.value if isinstance(node.value, tuple) else (node.value,)
            if (any(abs(x) > 1e8 for x in meta.bounds) or
                    any(isinstance(x, (int, float)) and abs(x) > 1e8 for x in constants)):
                raise ValueError("public ranges/constants exceed native numerical limits")
        actual_inputs = {n for n in memo if n.op == "input"}
        if actual_inputs != set(self.inputs):
            raise ValueError("graph references an undeclared input")
        # Reserve one plaintext multiplication for a full-packing final output mask.
        output_depth = max(memo[n].depth for _, n in self.outputs) + 1
        if output_depth > self.max_depth:
            raise ValueError("depth budget exhausted, including final output masking")
        return Analysis(tuple(memo), memo, output_depth)


def validate_inputs(workload: Workload, inputs: Mapping[str, Sequence[float]]) -> dict[str, tuple[float, ...]]:
    """Client-side range checks. The server cannot inspect encrypted values."""
    workload.validate()
    if set(inputs) != {n.value for n in workload.inputs}:
        raise ValueError("private input names do not match the workload")
    result: dict[str, tuple[float, ...]] = {}
    for node in workload.inputs:
        values = tuple(map(_finite, inputs[str(node.value)]))
        if len(values) != node.shape[0]:
            raise ValueError("private input length does not match the public shape")
        assert node.bounds is not None
        if any(v < node.bounds[0] or v > node.bounds[1] for v in values):
            raise ValueError("private input is outside its declared range")
        result[str(node.value)] = values
    return result


def evaluate(workload: Workload, inputs: Mapping[str, Sequence[float]]) -> dict[str, float]:
    checked = validate_inputs(workload, inputs)
    memo: dict[Node, tuple[float, ...]] = {}

    def visit(n: Node) -> tuple[float, ...]:
        if n in memo:
            return memo[n]
        if n.op == "input":
            value = checked[str(n.value)]
        else:
            a = visit(n.args[0])
            if n.op == "sum":
                value = (math.fsum(a),)
            elif n.op == "scale":
                value = tuple(v * float(n.value) for v in a)  # type: ignore[arg-type]
            elif n.op == "weights":
                value = tuple(x * y for x, y in zip(a, n.value))  # type: ignore[arg-type]
            else:
                b = visit(n.args[1])
                if n.op == "add":
                    value = tuple(x + y for x, y in zip(a, b))
                elif n.op == "sub":
                    value = tuple(x - y for x, y in zip(a, b))
                else:
                    value = tuple(x * y for x, y in zip(a, b))
        memo[n] = value
        return value

    return {name: visit(node)[0] for name, node in workload.outputs}
