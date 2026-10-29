"""Check lowered algebra and allocation schedules, without claiming HE execution."""
from dataclasses import replace
from itertools import product
import math

import pytest

from ciphershape.apps import analytics, analytics_reference, trained_model
from ciphershape.graph import Budget, evaluate
from ciphershape.planner import Costs, choose, compile_plan, estimate


def execute_public_algebra(plan, values, slots=128):
    """Independent slot-level interpreter for the exported instruction language."""
    live, output, masked = {}, {}, set()
    peak = 0
    for line in plan.instructions:
        p = line.split()
        op, i = p[0], int(p[1])
        if op == "drop":
            assert i in live, "schedule freed a missing ciphertext"
            del live[i]
            continue
        if op == "output":
            assert i in masked, "exported output lacks its full-slot mask"
            output[plan.outputs[int(p[2])]] = live[i][0]
            assert all(v == 0 for v in live[i][1:])
            continue
        assert i not in live
        if op == "input":
            name, element = plan.inputs[int(p[2])]
            x = list(values[name]) if element is None else [values[name][element]]
            v = x + [0.0] * (slots - len(x))
        else:
            a = live[int(p[2])]
            if op in {"add", "sub", "mul"}:
                b = live[int(p[3])]
                if op == "add":
                    v = [x + y for x, y in zip(a, b)]
                elif op == "sub":
                    v = [x - y for x, y in zip(a, b)]
                else:
                    v = [x * y for x, y in zip(a, b)]
            elif op == "rotate":
                step = int(p[3])
                assert step in plan.basis, "instruction requests an unexported key"
                v = a[step:] + a[:step]
            elif op == "scale":
                v = [x * float(p[3]) for x in a]
            elif op == "weights":
                n = int(p[3])
                weights = list(map(float, p[4:]))
                assert len(weights) == n
                v = [x * y for x, y in zip(a, weights + [0] * (slots - n))]
            elif op == "mask":
                v = [a[0]] + [0.0] * (slots - 1)
                masked.add(i)
            else:
                pytest.fail(f"unsupported lowered instruction {op}")
        live[i] = v
        peak = max(peak, len(live))
    assert peak == plan.stats["peak_live_ciphertexts"]
    return output


@pytest.mark.parametrize("layout,basis,sharing,retention", list(product(
    ("packed", "scalar"), ("direct", "unit", "sparse"),
    ("shared", "per-output"), ("retain", "last-use"))))
def test_all_bounded_plans_preserve_multioutput_semantics_and_release_safely(layout, basis, sharing, retention):
    w = analytics(8)
    values = {"x": [1, -1, 1e-7, -1e-7, .25, -.25, .5, -.5],
              "y": [-1, 1, -.5, .5, 0, 0, .75, -.75]}
    plan = compile_plan(w, layout, basis, sharing, retention)
    actual = execute_public_algebra(plan, values)
    assert actual == pytest.approx(analytics_reference(values), abs=1e-12)
    assert len(plan.inputs) == len(set(plan.inputs)), "per-output compilation duplicated private uploads"


def test_single_output_has_no_sharing_benefit():
    w = trained_model()
    shared = compile_plan(w, sharing="shared")
    independent = compile_plan(w, sharing="per-output")
    assert shared.instructions == independent.instructions
    assert shared.inputs == independent.inputs
    assert shared.stats == independent.stats


def test_rotation_basis_counts_both_key_bytes_and_online_composition():
    w = analytics(8)
    direct = compile_plan(w, basis_kind="direct")
    unit = compile_plan(w, basis_kind="unit")
    assert len(direct.basis) > len(unit.basis)
    assert direct.stats["counts"]["rotate"] < unit.stats["counts"]["rotate"]
    direct_cost, unit_cost = estimate(direct, Costs()), estimate(unit, Costs())
    assert direct_cost["setup_bytes"] > unit_cost["setup_bytes"]
    assert direct_cost["online_seconds"] < unit_cost["online_seconds"]


def test_last_use_release_reduces_live_storage_without_changing_outputs():
    w = analytics(8)
    retain = compile_plan(w, retention="retain")
    released = compile_plan(w, retention="last-use")
    assert released.stats["peak_live_ciphertexts"] < retain.stats["peak_live_ciphertexts"]
    values = {"x": [.2] * 8, "y": [-.4] * 8}
    assert execute_public_algebra(retain, values) == execute_public_algebra(released, values)


def test_planner_returns_minimum_feasible_objective_with_fixed_security():
    w = replace(analytics(8), budget=replace(Budget(), requests=100))
    costs = Costs()
    selected, rows = choose(w, costs)
    expected = min(row["total_seconds"] for row in rows if row["feasible"])
    assert estimate(selected, costs, requests=100)["total_seconds"] == pytest.approx(expected)
    assert len(rows) == 24
    assert selected.stats["security"] == "HEStd_128_classic"
    assert selected.stats["depth"] == 4 and selected.stats["scale_bits"] == 45
    assert all(math.isfinite(row["total_seconds"]) for row in rows)


def test_scalar_layout_trades_upload_for_rotation_key_setup():
    w = analytics(4)
    packed, scalar = compile_plan(w), compile_plan(w, layout="scalar")
    assert scalar.basis == () and scalar.stats["counts"].get("rotate", 0) == 0
    assert len(scalar.inputs) > len(packed.inputs)
    assert estimate(scalar, Costs())["request_bytes"] > estimate(packed, Costs())["request_bytes"]


def test_plan_is_rejected_when_upload_and_setup_budget_cannot_both_be_met():
    w = replace(analytics(4), budget=replace(Budget(), max_upload_bytes=1, max_setup_bytes=1))
    with pytest.raises(ValueError, match="budget"):
        choose(w, Costs())
